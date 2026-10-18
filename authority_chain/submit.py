"""The write path: submit_event (ticket check, tier check, length gate, conflict queue),
patch semantics and bootstrap."""
import hashlib
import json
import os
import sqlite3
import sys
import time
from pathlib import Path

from .config import (RESEARCH_ROOT, TIER0, TIER1, DOC_TO_PATH, NEVER_DOCS,
                     SINGLE_HASH_DOCS, AGENT_ENV_VARS, SIGNER_DB)
from .schema import get_conn, init_schema, now_iso
from .state import get_current_revision
from .hashing import hash_event, next_sequence, chain_head
from .writers import (policy_rules, gate_enforced, verify_approval_token, _consume_approval_token,
                      runtime_session_id, verify_signer_message, _auto_post_write,
                      _log_submit_reject)
from .projection import render_projection
from .verify import _find_prior_superseder


# -- Length gate (content constraint, deliberately not a concurrency rule) -------------
# Why: writes through the trusted path were unbounded while a weaker path was already
# blocked - the gate was on the wrong door. This closes the write path itself.
# Exactly one predicate (do not split it into two parallel rules):
#     reject <=> (new_len > old_len) AND (new_len > cap)
# Any non-growing write passes, so an over-limit document can always be trimmed:
# blocking shrinkage too would leave no way back under the cap.
# Measured object = the rendered projection (GENERATED header + body), because that is
# what gets injected. verify_projections() reports body length; the header adds a fixed
# number of characters, so the two numbers are not interchangeable.
# Old and new lengths must come from the same render_projection(): header digits change
# with the revision, and both sides have to count them identically to be comparable.
# A rejection is logged to length_gate.log only - a length breach is a content problem,
# not a concurrency conflict, so nothing enters conflict_queue.
# Caps live in configuration (length_caps.json), not in code: changing a cap is a config change.
# A doc_key without an entry is uncapped: one global number would freeze live documents.
# force does not bypass this gate: force is a concurrency escape hatch, this is content
#   only; non-growing writes always pass, so a repair path always exists.
LENGTH_CAPS_FILE = RESEARCH_ROOT / 'continuity' / 'length_caps.json'
LENGTH_GATE_LOG = RESEARCH_ROOT / 'continuity' / 'length_gate.log'


def length_caps():
    """doc_key -> character cap for the rendered document. No entry = no cap.

    A missing or corrupt config file also returns {}: a config fault must not block writes.
    """
    try:
        caps = json.loads(LENGTH_CAPS_FILE.read_text(encoding='utf-8'))
        return {k: int(v) for k, v in caps.items() if isinstance(k, str) and not k.startswith('_')}
    except Exception:
        return {}


def _log_length_reject(rec):
    try:
        LENGTH_GATE_LOG.parent.mkdir(parents=True, exist_ok=True)
        with LENGTH_GATE_LOG.open('a', encoding='utf-8') as fh:
            fh.write(json.dumps(rec, ensure_ascii=False) + '\n')
    except Exception:
        pass


def _reject_integrity(conn, event_id, seq, exc, writer_id, doc_key, event_type):
    """Concurrent collision (events.sequence UNIQUE) -> reject, log, return a failure.

    A UNIQUE collision is a normal race outcome, not a bug: two writers took the same
    sequence and SQLite stopped the second one. The old behaviour let the exception
    escape, so the write was refused but the writer process died with it.
    Rule: store no event, queue nothing (same shape as MISSING_TICKET / stale write).
    Acceptance: two processes, 8 concurrent rounds -> one accepted, one rejected, no crash.
    """
    rec = {'ts': now_iso(), 'writer_id': writer_id, 'doc_key': doc_key,
           'event_type': event_type, 'would_be_event_id': event_id, 'sequence': seq,
           'exception': type(exc).__name__, 'detail': str(exc)[:300], 'verdict': 'REJECTED'}
    _log_submit_reject(rec)
    try:
        conn.rollback()
        conn.close()
    except Exception:
        pass
    return {'ok': False, 'error': 'CONFLICT_SEQUENCE',
            'detail': f'{event_id} (sequence={seq}) is already taken by another writer: {exc} - '
                      f'the chain head moved; re-read the latest entry before writing. Logged to submit_reject.log, no event stored.',
            'conflict': True, 'sequence': seq}


def length_gate(conn, doc_key, patch, event_type, cur_rev, ts):
    """Pre-write length gate: None = pass, dict = reject (handed straight to the caller).

    Applies only to doc_keys listed in the config table. One predicate, see above.
    """
    cap = length_caps().get(doc_key)
    if cap is None:
        return None
    row = conn.execute('SELECT value_json, revision, updated_at FROM canonical_state WHERE doc_key=?',
                       (doc_key,)).fetchone()
    old_value = (row[0] if row else '') or ''
    try:
        new_value = apply_patch(old_value or None, patch, event_type)
    except Exception:
        return None                      # patch failures are reported by the write path, not here
    if not isinstance(new_value, str):
        new_value = json.dumps(new_value, ensure_ascii=False)
    old_len = len(render_projection(row[1] if row else 0, (row[2] if row else '') or '', old_value))
    new_len = len(render_projection(cur_rev + 1, ts, new_value))
    if new_len > old_len and new_len > cap:
        _log_length_reject({'ts': ts, 'doc_key': doc_key, 'event_type': event_type,
                            'old_rev': row[1] if row else 0, 'patch_op': (patch or {}).get('op'),
                            'old_rendered': old_len, 'new_rendered': new_len, 'cap': cap,
                            'verdict': 'REJECTED'})
        return {'ok': False, 'error': 'DOC_LENGTH_GATE',
                'detail': f'{doc_key} renders to {new_len} > cap {cap}, and is longer than the current {old_len} - '
                          f'the gate measures the rendered length (GENERATED header included), not the body. '
                          f'A non-growing write always passes: shrink first, then add. Logged to length_gate.log, not queued.',
                'old_rendered': old_len, 'new_rendered': new_len, 'cap': cap}
    return None


# Event type semantics: only these update canonical_state
_CANONICAL_EVENT_TYPES = {'INIT', 'ACCEPTED_STATE_CHANGE', 'PATCH', 'DECISION'}

# Protected docs (tier 0 plus policy): a change is rendered only after a countersign.
# submit classifies writes to these docs as constitutional amendments: they enter the
# chain with status=pending_countersign, do not update canonical_state, and are not rendered;
# they apply only when a COUNTERSIGN event naming that event id arrives.


def _enqueue_conflict(conn, doc_key, writer_id, base_revision, current_revision, patch):
    """Queue a conflict as a work item. Never resolve it silently.

    The row is a pending ticket: merging two divergent versions of an authoritative
    document is a judgement call, not a whitelist action.
    Dropping the write is equally wrong: a non-empty queue is a live ticket.
    """
    conn.execute(
        'INSERT INTO conflict_queue (event_id, doc_key, reason, status, writer_id, '
        'base_revision, current_revision, patch_json, created_at, resolution, resolved_at) '
        'VALUES (?,?,?,?,?,?,?,?,?,?,?)',
        (f'CONFLICT-{int(time.time() * 1000)}', doc_key,
         f'REJECT_STALE_WRITE: base={base_revision} current={current_revision}',
         'pending', writer_id, base_revision, current_revision,
         json.dumps(patch, ensure_ascii=False), now_iso(), None, None))
    conn.commit()


def _log_force(conn, writer_id, doc_key, reason, event_id, sequence):
    """Record an escape-hatch write.

    Every force call must state a reason; otherwise "no ticket" was merely renamed.
    The ledger is consumed by an external notifier that opens a ticket per row,
    and a weekly report accounts for every non-zero count.
    """
    conn.execute(
        'INSERT INTO force_log (ts, writer_id, doc_key, reason, event_id, sequence) VALUES (?,?,?,?,?,?)',
        (now_iso(), writer_id, doc_key, str(reason).strip(), event_id, sequence))


def classify_entry(patch):
    """Classify an entry by its fields, never by keywords in its prose.

    'verdict'       carries decision_quote
    'exec_verdict'  carries caused_by (execution of a decision)
    'exec'          carries only source_msg_id
    'unknown'       none of the three (the caller decides whether to accept)

    With both fields present it counts as 'verdict': an entry that quotes a decision
    is both a claim and an action, so the stricter requirement applies.
    """
    if not isinstance(patch, dict):
        return 'unknown'
    if str(patch.get('decision_quote') or '').strip():
        return 'verdict'
    if str(patch.get('caused_by') or '').strip():
        return 'exec_verdict'
    if str(patch.get('source_msg_id') or '').strip():
        return 'exec'
    return 'unknown'


def submit_event(writer_id, doc_key, patch, base_revision=None, event_type='PATCH',
                 evidence='', caused_by='', surface_id=None, session_id=None, force=False,
                 force_reason='', approval_token=None, approval_prompt=None, manual_tty=None,
                 expected_prev_hash=None):
    conn = get_conn(); init_schema(conn)
    # 1. Writer permissions
    w = conn.execute('SELECT surface_id, role, tier, status FROM writer_registry WHERE writer_id=?', (writer_id,)).fetchone()
    if not w:
        return {'ok': False, 'error': f'UNREGISTERED_WRITER:{writer_id} - register the writer first'}
    surface_id = surface_id or w[0]; role, tier, wstatus = w[1], w[2], w[3]
    if wstatus != 'active':
        return {'ok': False, 'error': f'WRITER_INACTIVE:{writer_id}'}
    # 2. Tier permissions
    if doc_key in TIER0 and tier != 'tier0':
        return {'ok': False, 'error': f'PERMISSION_DENIED: {doc_key} is tier0, writer {writer_id} is {tier}'}
    if doc_key in TIER1 and tier == 'tier2':
        return {'ok': False, 'error': f'PERMISSION_DENIED: {doc_key} is tier1, writer {writer_id} is {tier}'}
    # 2.5 Single-hash document protection: section ops look for "## " boundaries,
    #     so on a document that uses "# " headings they swallow everything after the marker.
    #     Such ops are not buggy here, they are unusable: refuse them at the door.
    #     append / insert_after stay allowed because they cannot truncate.
    #     Fixing boundary detection is engineering work; refusing the op is one line.
    _SINGLE_HASH_DOCS = SINGLE_HASH_DOCS
    # 2.5b Whole-file overwrite is refused; INIT is allowed only for an empty document.
    #     The only way around the blocked operations is a one-time code issued out of band;
    #     the database keeps its SHA-256 and the code is burned on use.




    _approval_sha = None
    # 2.4 Manual-terminal channel: a human at a real terminal has no agent runtime env,
    #     so "the code must come from a human" and "the session id must be injected" collide.
    #     This channel resolves the collision without opening a bypass: every call still
    #     needs a valid one-time code, and the code never passes through the model.
    #     Gate = (1) no agent env vars, (2) a real TTY, (3) a valid unused code.

    _manual_tty = (manual_tty or '').strip()
    if _manual_tty:
        _env_hit = [k for k in AGENT_ENV_VARS if (os.environ.get(k) or '').strip()]
        if _env_hit:
            conn.close()
            return {'ok': False, 'error': 'MANUAL_TTY_REFUSED_AGENT_ENV',
                    'detail': f'agent runtime env vars detected: {_env_hit} - '
                              'the manual channel is for a real terminal without an agent runtime.'}
        if not (sys.stdin.isatty() and sys.stdout.isatty()):
            conn.close()
            return {'ok': False, 'error': 'MANUAL_TTY_REFUSED_NO_TTY',
                    'detail': 'stdin/stdout is not a TTY - run this in a real terminal window.'}
        if not (approval_token or '').strip() and approval_prompt is not None:
            approval_token = approval_prompt()
        if not (approval_token or '').strip():
            conn.close()
            return {'ok': False, 'error': 'MANUAL_TTY_NEEDS_TOKEN',
                    'detail': 'the manual channel always requires a valid one-time code; there is no bypass.'}
        _m_ok, _m_err, _m_sha = verify_approval_token(conn, approval_token)
        if not _m_ok:
            conn.close()
            return {'ok': False, 'error': f'MANUAL_TTY_{_m_err}',
                    'detail': 'approval code rejected (unknown or already used).'}
        _approval_sha = _m_sha           # reused; burned by _consume_approval_token on write
        evidence = (evidence + ' | ' if evidence else '') + 'manual_tty=' + _manual_tty
    if doc_key in _SINGLE_HASH_DOCS and isinstance(patch, dict):
        _op = patch.get('op')
        _needs_approval = (_op in ('replace_section', 'delete_section', 'replace_text')) or \
                          (_op == 'full' and not (event_type == 'INIT'
                                                  and not get_current_revision(conn, doc_key)))
        if _needs_approval:
            if not (approval_token or '').strip() and approval_prompt is not None:
                # Read the code from the TTY only: a value passed on the command line ends up
                # in the agent's own logs, which hands approval power to the approved party.
                approval_token = approval_prompt()
            _t_ok, _t_err, _t_sha = verify_approval_token(conn, approval_token)
            if not _t_ok:
                conn.close()
                if _t_err == 'APPROVAL_TOKEN_REQUIRED':
                    if _op == 'full':
                        return {'ok': False, 'error': 'FORBIDDEN_OP: whole-file overwrite is disabled for this document.'
                                'INIT is only for an empty document; use append/insert_after; restores need a one-time code.'}
                    if _op == 'replace_text':
                        return {'ok': False, 'error': f'FORBIDDEN_OP: replace_text on {doc_key} requires a one-time approval code.'}
                    return {'ok': False, 'error': f'FORBIDDEN_OP: {_op} is disabled on {doc_key} '
                            f'(single-hash headings make it swallow everything after the marker). Use append/insert_after; restores need a one-time code.'}
                return {'ok': False, 'error': f'{_t_err}: approval code rejected (unknown or used); codes are issued out of band, once.'}
            if _op == 'replace_text':
                _find = patch.get('find', '')
                if not _find:
                    conn.close()
                    return {'ok': False, 'error': 'REPLACE_TEXT_MISSING_FIND: find is empty'}
                _crow = conn.execute('SELECT value_json FROM canonical_state WHERE doc_key=?', (doc_key,)).fetchone()
                _cv = _crow[0] if _crow else ''
                _n_hits = _cv.count(_find)
                if _n_hits != 1:
                    conn.close()
                    return {'ok': False, 'error': f'REPLACE_TEXT_BAD_MATCH: find occurs {_n_hits} times in {doc_key}'
                            f'(exactly 1 required; nothing written, code not consumed)'}
            _approval_sha = _t_sha
    # 2.6 Escape-hatch cost: force is kept, but it must not be free.
    #     Otherwise a rejected write passes by adding --force, which only renames the rule:
    #     (1) a reason is required, recorded in the event and in the force_log ledger
    #     (2) each call opens a ticket for human review
    #     (3) a weekly report accounts for every non-zero count
    #     (4) automation may not call it; only a human present at a terminal may.
    #     Falsifiable form: this gate names exactly what it refuses - a reasonless force.
    if force and not str(force_reason).strip():
        conn.close()
        return {'ok': False, 'error': 'FORCE_REQUIRES_REASON',
                'detail': 'force is an escape hatch, not a back door: pass a reason (--force-reason "...").'
                          'The reason is recorded in the event and opens a review ticket.'}
    # 3. Revision ticket: reading issues the ticket, writing hands it back.
    #    Hard rule: a state-changing write must carry base_revision, and submit must never
    #    read it itself: two numbers that are equal by construction can never conflict. The
    #    same failure shape appeared twice before (a lease that was only observed, a token
    #    check with no token). Append-only events (claims, observations, proposals, rejected
    #    changes) cannot fork and need no ticket; COUNTERSIGN checks its own target document.
    cur_rev = get_current_revision(conn, doc_key)
    _needs_ticket = event_type in _CANONICAL_EVENT_TYPES and event_type != 'COUNTERSIGN'
    # A ticketed event must carry a session id injected by the runtime, so parallel writers
    # are nameable on the chain. Without it a row of events shared one NULL session id and
    # a single-window decision had nothing observable to attach to.
    # Scope: every ticketed type, not only decisions; the value comes from the environment only.
    if _needs_ticket or event_type == 'SIGNATURE':
        _sid = runtime_session_id()
        if _manual_tty:
            # manual channel: session_id is the audit attestation (manual_tty:<host>:<pid>:<time>)
            session_id = _manual_tty
        elif not _sid:
            conn.close()
            return {'ok': False, 'error': 'MISSING_RUNTIME_SESSION_ID',
                    'detail': 'a ticketed event needs a runtime-injected session id: '
                              f'{" / ".join(AGENT_ENV_VARS)} are all empty. '
                              'A caller-supplied session id is refused: the model must not mint one.'
                              '(a human terminal must use --manual-tty with a one-time code.)'}
        else:
            session_id = _sid
    if _needs_ticket and base_revision is None and not force:
        conn.close()
        return {'ok': False, 'error': 'MISSING_TICKET',
                'detail': f'a state-changing write needs a ticket: get({doc_key}) for the revision first, then send it back as base_revision. '
                          f' current_revision={cur_rev} writer={writer_id}',
                'current_revision': cur_rev}
    if base_revision is not None and base_revision != cur_rev and not force:
        _enqueue_conflict(conn, doc_key, writer_id, base_revision, cur_rev, patch)
        conn.close()
        return {'ok': False, 'error': 'REJECT_STALE_WRITE',
                'detail': f'base={base_revision} current={cur_rev} doc={doc_key} writer={writer_id}'
                          f' - queued in conflict_queue for a decision (write refused, state unchanged)',
                'conflict': True, 'current_revision': cur_rev}
    # 3.6 A SIGNATURE record must trace back to a message the human actually wrote.
    #     It does not count as a decision state; its force comes from the message, not a paraphrase.
    if event_type == 'SIGNATURE':
        _mid = patch.get('signer_message_id') if isinstance(patch, dict) else None
        _signs = patch.get('signs') if isinstance(patch, dict) else None
        if not _signs or not isinstance(_signs, (list, tuple)):
            conn.close()
            return {'ok': False, 'error': 'SIGNATURE_MISSING_TARGETS',
                    'detail': 'a SIGNATURE needs patch["signs"] = [{"event_id": ..., "sha256": ...}, ...] '
                              '- one record signs only the objects it names.'}
        _ids, _bad = [], []
        for _s in _signs:
            _eid = _s.get('event_id') if isinstance(_s, dict) else str(_s)
            _sha = _s.get('sha256') if isinstance(_s, dict) else None
            if not _eid or not _sha:
                conn.close()
                return {'ok': False, 'error': 'SIGNATURE_MALFORMED',
                        'detail': 'each target must look like {"event_id": "evXXXXXX", "sha256": "<sha256 of patch_json>"}'}
            _row = conn.execute("SELECT patch_json FROM events WHERE event_id=?", (_eid,)).fetchone()
            if not _row:
                conn.close()
                return {'ok': False, 'error': 'SIGNATURE_TARGET_NOT_FOUND', 'detail': _eid}
            _real = hashlib.sha256(_row[0].encode('utf-8')).hexdigest()
            if _real != str(_sha):
                conn.close()
                return {'ok': False, 'error': 'SIGNATURE_SHA_MISMATCH',
                        'detail': f'{_eid} declares {_sha[:16]}.. but the chain holds {_real[:16]}..'}
            _ids.append(_eid)
        _ok, _info = verify_signer_message(_mid, require_session=session_id,
                                           required_event_ids=_ids)
        if not _ok:
            conn.close()
            return {'ok': False, 'error': f'SIGNATURE_NOT_TRACEABLE:{_info}',
                    'detail': 'a SIGNATURE needs signer_message_id; the message must exist in the evidence store, be from the human, '
                              'express consent, and name every event_id in signs; the session must match this event. '
                              'Reason: a signature in someone else\'s name, or "any mention of signing", is not evidence.'}
    # 3.5 supersedes / amends reference checks, applied on the write path.
    #     Cross-document supersedes used to live only in prose and were never checked here,
    #     which is how two windows could overturn each other: both pointed at the same event,
    #     and the ticket only guarded the revision of one document.
    #     Rule: a reference is structured - [{'event_id': ..., 'hash': ...}, ...] - and must
    #     (1) exist, (2) carry the hash actually on the chain, so "the version I read" is proven,
    #     (3) be superseded only once (amends is a note and is exempt).
    for _key in ('supersedes', 'amends'):
        _refs = patch.get(_key) if isinstance(patch, dict) else None
        if not _refs:
            continue
        if not isinstance(_refs, (list, tuple)):
            conn.close()
            return {'ok': False, 'error': f'{_key.upper()}_MALFORMED',
                    'detail': f'patch["{_key}"] must be a list of {{"event_id": ..., "hash": ...}}'}
        for _r in _refs:
            if not isinstance(_r, dict) or not _r.get('event_id') or not _r.get('hash'):
                conn.close()
                return {'ok': False, 'error': f'{_key.upper()}_MALFORMED',
                        'detail': 'each reference needs {"event_id": "evXXXXXX", "hash": "<16-char chain hash>"}; '
                                  'a reference without a hash cannot be verified.'}
            _t = conn.execute("SELECT hash, doc_key FROM events WHERE event_id=?",
                              (str(_r['event_id']),)).fetchone()
            if not _t:
                conn.close()
                return {'ok': False, 'error': 'UNKNOWN_REFERENCE',
                        'detail': f'{_key} points at an event that does not exist: {_r["event_id"]}'}
            if str(_t[0]) != str(_r['hash']):
                conn.close()
                return {'ok': False, 'error': 'STALE_REFERENCE',
                        'detail': f'{_key} hash mismatch for {_r["event_id"]}: '
                                  f'declared {_r["hash"]}, chain has {_t[0]} - this is not the version on the chain'}
            if _key == 'supersedes':
                _prior = _find_prior_superseder(conn, str(_r['event_id']))
                if _prior:
                    conn.close()
                    return {'ok': False, 'error': 'ALREADY_SUPERSEDED',
                            'detail': f'{_r["event_id"]} was already superseded by {_prior}; it cannot be superseded twice. '
                                      f'Supersede the superseder instead - two writers replacing the same event '
                                      f'is how two contradictory decisions end up coexisting.'}
    # 3.11 A canonical write that changes nothing must not advance the revision.
    #      An unknown op used to fall through apply_patch unchanged and still bump the
    #      revision, so a malformed patch looked exactly like an accepted edit.
    if event_type in _CANONICAL_EVENT_TYPES:
        _noop = _no_change_refusal(conn, doc_key, patch, event_type)
        if _noop:
            conn.close()
            return _noop
    # 4.0 Length gate, evaluated before the event is stored: a rejection leaves no event,
    #     same shape as a missing ticket or a stale write (no event, no queue entry, log only).
    #     Protected docs are skipped here: their patch applies at COUNTERSIGN, which checks again.
    if event_type in _CANONICAL_EVENT_TYPES and doc_key not in NEVER_DOCS:
        _gate = length_gate(conn, doc_key, patch, event_type, cur_rev, now_iso())
        if _gate:
            conn.close()
            return _gate

    # 3.9 Chain-head CAS: a write is bound to the head it claims to extend.
    #     Why: the chain is only worth something if it records who wrote what on top of which
    #     state. A writer holding a stale head records a prev_hash that is no longer the tail:
    #     the links still connect, but it appended to a page that was already turned.
    #     Predicate: the recorded previous hash must equal the current head, otherwise refuse.
    #     The refusal tells the writer to re-read the latest entry before retrying.
    #     Strength: decisions must carry expected_prev_hash; ordinary writes may omit it.
    #     Boundary, stated plainly: this prevents misattribution and interleaving, not forgery.
    head_hash = chain_head(conn)
    _cls = classify_entry(patch)
    if expected_prev_hash is not None:
        if (expected_prev_hash or '') != (head_hash or ''):
            conn.close()
            _log_submit_reject({'ts': now_iso(), 'writer_id': writer_id, 'doc_key': doc_key,
                                'event_type': event_type, 'error': 'CONFLICT_CHAIN_HEAD',
                                'expected_prev_hash': expected_prev_hash, 'head_hash': head_hash})
            return {'ok': False, 'error': 'CONFLICT_CHAIN_HEAD',
                    'detail': f'the chain head moved; re-read the latest entry before writing ({expected_prev_hash!r} '
                              f'!= current head {head_hash!r})'}
    elif _cls == 'verdict':
        conn.close()
        _log_submit_reject({'ts': now_iso(), 'writer_id': writer_id, 'doc_key': doc_key,
                            'event_type': event_type, 'error': 'VERDICT_NEEDS_EXPECTED_PREV_HASH',
                            'head_hash': head_hash})
        return {'ok': False, 'error': 'VERDICT_NEEDS_EXPECTED_PREV_HASH',
                'detail': f'a verdict entry (with decision_quote) must carry expected_prev_hash - '
                          f'current head {head_hash!r}; call chain_head() first'}
    elif _cls == 'unknown':
        # None of the three fields: an old-style free-text patch. Do not block, just classify.
        pass

    # 3.10 Policy gate, advisory by default:
    #     It records what it would refuse in an append-only log and lets the write through:
    #     new rules stay advisory until their acceptance checks pass.
    #     It blocks only when explicitly enabled; force may override it and is logged.
    #     Four checks: (1) a writer filling countersigned_by itself, (2) decision wording with
    #     no quote or evidence, (3) a quote must occur verbatim in the human message, (4) the parent must be verified.
    _enforce = gate_enforced()
    _gate_err = None
    _ev_payload = None
    if policy_rules is not None:
        _g = patch if isinstance(patch, dict) else {}
        _body = str(_g.get('content') or '')
        _quote = str(_g.get('decision_quote') or '').strip()
        _caused = str(_g.get('caused_by') or '').strip()
        _smi = str(_g.get('source_msg_id') or '').strip()
        if _g.get('countersigned_by'):
            _gate_err = ('COUNTERSIGN_BY_WRITER_REJECTED',
                         'countersigned_by may only be set by countersign_entry(), after the'
                         'human message naming the event was verified. Direct writes are refused.')
        if _gate_err is None and not _quote and not _caused:
            _hit, _kw = policy_rules.is_decision_claim(_body)
            if _hit:
                _gate_err = ('DECIDE_CLAIM_WITHOUT_EVIDENCE',
                             f'body contains decision wording "{_kw}" with neither decision_quote nor caused_by => refuse.'
                             '(a keyword list is a tripwire, not a complete filter.)')
        if _gate_err is None and _quote:
            if not _smi:
                _gate_err = ('VERDICT_NEEDS_SOURCE_MSG_ID', 'a quoted decision must carry source_msg_id')
            else:
                _ok, _info = policy_rules.user_message(_smi, state_db=str(SIGNER_DB or ''))
                if not _ok:
                    _gate_err = ('VERDICT_SOURCE_UNVERIFIED', f'{_info}（source_msg_id={_smi}）')
                else:
                    _qok, _why = policy_rules.validate_quote(_quote, _info['content'], doc_key)
                    _ev_payload = policy_rules.evidence_payload(_smi, 'quote_ok' if _qok else _why, _qok)
                    if not _qok:
                        _gate_err = ('VERDICT_QUOTE_INVALID', f'{_why} (quote={_quote[:40]!r})')
        if _gate_err is None and _caused:
            _p = conn.execute('SELECT status FROM events WHERE event_id=?', (_caused,)).fetchone()
            if not _p:
                _gate_err = ('CAUSED_BY_NOT_FOUND', _caused)
            elif _p[0] not in ('verified', 'countersigned'):
                _gate_err = ('PARENT_NOT_VERIFIED', f'{_caused} status={_p[0]} - parent not verified, child refused')
        if _gate_err is None and _smi and _ev_payload is None:
            _ev_payload = policy_rules.evidence_payload(_smi, 'verdict_ok' if _quote else 'exec_ok', None)
    if _gate_err:
        _log_submit_reject({'ts': now_iso(), 'writer_id': writer_id, 'doc_key': doc_key,
                            'event_type': event_type, 'error': _gate_err[0], 'gate': 'policy',
                            'detail': _gate_err[1][:300], 'enforced': bool(_enforce and not force),
                            'force': bool(force)})
        if _enforce and not force:
            conn.close()
            return {'ok': False, 'error': _gate_err[0], 'detail': _gate_err[1],
                    'gate': 'policy', 'enforced': True,
                    'hint': 'the gate is advisory by default; this run enabled it explicitly'}
    if _ev_payload and not evidence:
        evidence = _ev_payload

    # 4. Append the event (hash chain: prev_hash = previous event hash)
    seq = next_sequence(conn)
    ts = now_iso()
    patch_json = json.dumps(patch, ensure_ascii=False)
    event_id = f'ev{seq:06d}'
    prev = conn.execute('SELECT hash FROM events WHERE sequence=?', (seq - 1,)).fetchone()
    prev_hash = prev[0] if prev else None
    h = hash_event(writer_id, doc_key, ts, seq, patch_json, prev_hash or '')
    is_constitutional = doc_key in NEVER_DOCS and event_type in _CANONICAL_EVENT_TYPES
    is_countersign = event_type == 'COUNTERSIGN'

    # 4.5 COUNTERSIGN: sign a pending amendment and apply its patch
    if is_countersign:
        target = patch.get('target') if isinstance(patch, dict) else None
        if not target:
            conn.close()
            return {'ok': False, 'error': 'COUNTERSIGN_MISSING_TARGET: patch needs {"op":"countersign","target":"evXXXXXX"}'}
        trow = conn.execute("SELECT event_id, status, doc_key, patch_json, event_type FROM events WHERE event_id=?", (target,)).fetchone()
        if not trow:
            conn.close()
            return {'ok': False, 'error': f'COUNTERSIGN_TARGET_NOT_FOUND:{target}'}
        if trow[1] != 'pending_countersign':
            conn.close()
            return {'ok': False, 'error': f'COUNTERSIGN_TARGET_NOT_PENDING:{target} status={trow[1]} - only pending_countersign can be signed'}
        t_doc, t_patch, t_type = trow[2], json.loads(trow[3]), trow[4]
        if t_doc not in NEVER_DOCS:
            conn.close()
            return {'ok': False, 'error': f'COUNTERSIGN_TARGET_NOT_NEVER_DOC:{t_doc}'}
        # A countersign applies t_patch to t_doc, i.e. it changes shared state, so it must
        # carry the ticket of t_doc (the document being changed), not of this event's doc_key.
        t_cur = get_current_revision(conn, t_doc)
        if base_revision is None and not force:
            conn.close()
            return {'ok': False, 'error': 'MISSING_TICKET',
                    'detail': f'COUNTERSIGN changes shared state in {t_doc}, so its ticket is required: '
                              f'get({t_doc}).revision={t_cur}',
                    'current_revision': t_cur}
        if base_revision is not None and base_revision != t_cur and not force:
            _enqueue_conflict(conn, t_doc, writer_id, base_revision, t_cur, t_patch)
            conn.close()
            return {'ok': False, 'error': 'REJECT_STALE_WRITE',
                    'detail': f'COUNTERSIGN ticket is stale: base={base_revision} current={t_cur} doc={t_doc}'
                              f' - queued in conflict_queue',
                    'conflict': True, 'current_revision': t_cur}
        # Length gate: a countersign really applies t_patch to t_doc, so the gate is
        # evaluated against t_doc, not this event's doc_key; a rejection leaves no event.
        _gate = length_gate(conn, t_doc, t_patch, t_type, t_cur, ts)
        if _gate:
            conn.close()
            return _gate
        _noop = _no_change_refusal(conn, t_doc, t_patch, t_type)
        if _noop:
            conn.close()
            return _noop
        # Store the COUNTERSIGN event first: the chain must contain the signing record
        try:
            conn.execute('INSERT INTO events (event_id, sequence, ts, writer_id, surface_id, session_id, base_revision, event_type, doc_key, patch_json, evidence_refs, caused_by, status, reject_reason, prev_hash, hash) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)',
                         (event_id, seq, ts, writer_id, surface_id, session_id, base_revision,
                          event_type, doc_key, patch_json, evidence or None, caused_by or None,
                          'accepted', None, prev_hash, h))
        except sqlite3.IntegrityError as _ie:
            # Sequence collision: another writer took the slot -> refuse, do not crash.
            return _reject_integrity(conn, event_id, seq, _ie, writer_id, doc_key, event_type)
        # Then apply the target patch to canonical state and mark the target signed
        old = conn.execute('SELECT value_json FROM canonical_state WHERE doc_key=?', (t_doc,)).fetchone()
        new_value = apply_patch(old[0] if old else None, t_patch, t_type)
        cur_rev = get_current_revision(conn, t_doc)
        new_rev = cur_rev + 1
        stored = new_value if isinstance(new_value, str) else json.dumps(new_value, ensure_ascii=False)
        conn.execute('INSERT OR REPLACE INTO canonical_state VALUES (?,?,?,?,?)',
                     (t_doc, new_rev, stored, trow[0], ts))
        conn.execute("UPDATE events SET status='countersigned', countersigned_by=? WHERE event_id=?", (event_id, target))
        if force:
            _log_force(conn, writer_id, doc_key, force_reason, event_id, seq)
        # Burn the one-time code in this same transaction, exactly as the normal write path
        # does: a code that is validated but never consumed can sign again.
        if _approval_sha:
            _rc = _consume_approval_token(conn, _approval_sha, doc_key, patch.get('op'), patch_json, event_id)
            if not _rc:
                conn.rollback(); conn.close()
                return {'ok': False, 'error': 'APPROVAL_TOKEN_RACE: the code was consumed mid-write; nothing was stored.'}
        conn.commit(); conn.close()
        _pw = _auto_post_write(event_id, _cls, _gate_err, force)
        _out = {'ok': True, 'event_id': event_id, 'sequence': seq, 'doc_key': doc_key,
                'countersigned': target, 'applied_doc': t_doc, 'revision': new_rev,
                'hash': h, 'prev_hash': prev_hash}
        if _pw:
            _out['post_write'] = _pw      # chain first, files second: status is returned, not printed
        return _out

    # 4.6 Amendments: enter the chain as pending_countersign, not rendered until signed
    ev_status = 'pending_countersign' if is_constitutional else 'accepted'
    try:
        conn.execute('INSERT INTO events (event_id, sequence, ts, writer_id, surface_id, session_id, base_revision, event_type, doc_key, patch_json, evidence_refs, caused_by, status, reject_reason, prev_hash, hash) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)',
                     (event_id, seq, ts, writer_id, surface_id, session_id, base_revision,
                      event_type, doc_key, patch_json, evidence or None, caused_by or None,
                      ev_status, None, prev_hash, h))
    except sqlite3.IntegrityError as _ie:
        # Sequence collision: another writer took the slot -> refuse, do not crash.
        return _reject_integrity(conn, event_id, seq, _ie, writer_id, doc_key, event_type)
    # 5. Apply to canonical_state only for _CANONICAL_EVENT_TYPES.
    #    Claims, observations, proposals and rejected changes stay in the event history:
    #    traceable, but not facts. Protected docs are skipped until countersigned.
    if event_type in _CANONICAL_EVENT_TYPES and not is_constitutional:
        old = conn.execute('SELECT value_json FROM canonical_state WHERE doc_key=?', (doc_key,)).fetchone()
        new_value = apply_patch(old[0] if old else None, patch, event_type)
        new_rev = cur_rev + 1
        stored = new_value if isinstance(new_value, str) else json.dumps(new_value, ensure_ascii=False)
        conn.execute('INSERT OR REPLACE INTO canonical_state VALUES (?,?,?,?,?)',
                     (doc_key, new_rev, stored, event_id, ts))
    else:
        new_rev = cur_rev
    if force:
        _log_force(conn, writer_id, doc_key, force_reason, event_id, seq)
    if _approval_sha:
        _rc = _consume_approval_token(conn, _approval_sha, doc_key, patch.get('op'), patch_json, event_id)
        if not _rc:
            conn.rollback(); conn.close()
            return {'ok': False, 'error': 'APPROVAL_TOKEN_RACE: the code was consumed mid-write; nothing was stored.'}
    conn.commit(); conn.close()
    _pw = _auto_post_write(event_id, _cls, _gate_err, force)
    _out = {'ok': True, 'event_id': event_id, 'sequence': seq, 'doc_key': doc_key,
            'revision': new_rev, 'hash': h, 'prev_hash': prev_hash, 'status': ev_status}
    if _pw:
        _out['post_write'] = _pw          # chain first, files second: status is returned, not printed
    return _out

_PATCH_OPS = {'full', 'append', 'insert_after', 'replace_section', 'delete_section', 'replace_text'}


def _no_change_refusal(conn, doc_key, patch, event_type):
    """None = the patch changes canonical state; dict = refusal (state and revision untouched).

    INIT carries whole content and ignores op, so only non-INIT writes need a known op.
    """
    if event_type != 'INIT':
        _op = patch.get('op') if isinstance(patch, dict) else None
        if _op not in _PATCH_OPS:
            return {'ok': False, 'error': 'UNKNOWN_PATCH_OP',
                    'detail': f'patch op {_op!r} is not one of {sorted(_PATCH_OPS)}; nothing written.'}
    row = conn.execute('SELECT value_json FROM canonical_state WHERE doc_key=?', (doc_key,)).fetchone()
    if row is None:
        return None
    new_value = apply_patch(row[0], patch, event_type)
    stored = new_value if isinstance(new_value, str) else json.dumps(new_value, ensure_ascii=False)
    if stored == row[0]:
        return {'ok': False, 'error': 'NO_CHANGE',
                'detail': f'the patch leaves {doc_key} exactly as it is (for example a missing marker, '
                          f'or a find text that does not occur exactly once); revision not advanced.'}
    return None


def apply_patch(old_json, patch, event_type):
    """Patch semantics:
       - {op:'full', content: str}  - INIT only
       - {op:'append', content: str}  - append text
       - {op:'replace_section', marker, content} - replace the section after marker
       - {op:'delete_section', marker: str}
    """
    if event_type == 'INIT' or patch.get('op') == 'full':
        return patch.get('content', '')
    old = old_json or ''
    if not isinstance(old, str):
        try: old = json.loads(old)
        except: old = str(old)
    op = patch.get('op')
    if op == 'append':
        return old + patch.get('content', '')
    if op == 'insert_after':
        marker = patch.get('marker', '')
        content = patch.get('content', '')
        if marker and marker in old:
            head, _, tail = old.partition(marker)
            return head + marker + '\n\n' + content + tail
        return old + '\n' + content
    if op == 'replace_section':
        marker = patch.get('marker', '')
        content = patch.get('content', '')
        if marker and marker in old:
            head, _, tail = old.partition(marker)
            # Replace the marker line and everything after it (up to the next "## " or EOF)
            after = tail.split('\n## ', 1)
            rest = ('\n## ' + after[1]) if len(after) > 1 else ''
            return head + marker + '\n' + content + rest
        return old + '\n' + content
    if op == 'delete_section':
        marker = patch.get('marker', '')
        if marker and marker in old:
            head, _, tail = old.partition(marker)
            after = tail.split('\n## ', 1)
            rest = ('\n## ' + after[1]) if len(after) > 1 else ''
            return head + rest
        return old
    if op == 'replace_text':
        # Literal replacement: find must occur exactly once (other docs need a one-time code).
        find = patch.get('find', '')
        repl = patch.get('replace', '')
        if find and old.count(find) == 1:
            return old.replace(find, repl, 1)
        return old
    return old


def bootstrap(force=False):
    """First import: existing documents -> INIT events (revision 1). Idempotent."""
    conn = get_conn(); init_schema(conn)
    imported = []
    for doc_key, path in DOC_TO_PATH.items():
        if conn.execute('SELECT 1 FROM canonical_state WHERE doc_key=?', (doc_key,)).fetchone():
            continue
        p = Path(path)
        if not p.exists():
            print(f'  SKIP {doc_key}: file not found {path}')
            continue
        content = p.read_text(encoding='utf-8', errors='replace')
        seq = next_sequence(conn); ts = now_iso()
        event_id = f'ev{seq:06d}'
        prev = conn.execute('SELECT hash FROM events WHERE sequence=?', (seq - 1,)).fetchone()
        prev_hash = prev[0] if prev else None
        patch_json = json.dumps({'op': 'full', 'content': content}, ensure_ascii=False)
        h = hash_event('continuity_bootstrap', doc_key, ts, seq, patch_json, prev_hash or '')
        conn.execute('INSERT INTO events (event_id, sequence, ts, writer_id, surface_id, session_id, base_revision, event_type, doc_key, patch_json, evidence_refs, caused_by, status, reject_reason, prev_hash, hash) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)',
                     (event_id, seq, ts, 'continuity_bootstrap', 'bootstrap', None, 0,
                      'INIT', doc_key, json.dumps({'op': 'full', 'content': content}, ensure_ascii=False),
                      f'BOOTSTRAP:{path}', None, 'accepted', None, prev_hash, h))
        # Raw text, exactly like the other write paths: a JSON-encoded string here turned
        # every newline into a literal "\n", so section ops could not find "\n## " any more.
        conn.execute('INSERT OR REPLACE INTO canonical_state VALUES (?,?,?,?,?)',
                     (doc_key, 1, content, event_id, ts))
        imported.append(doc_key)
    conn.commit(); conn.close()
    return {'imported': imported}
