#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""AUTHORITY_CHAIN V1 - one authoritative event sequence per document.

Design:
  - One owner, many entry points: every caller is a surface, never a separate self.
  - events: append-only history of factual changes, never overwritten.
  - canonical_state: the single current value per document (doc_key -> revision -> value).
  - surface_cursors: how far each surface has read the history.
  - writer_registry: who may write which document, with tiers.
  - conflict_queue: conflicts that need a human decision (no silent auto-resolution).
  - Revision check + patch/event writes; whole-file rewrites are forbidden except INIT.

Usage:
  python chaincore.py bootstrap      # import the configured documents as revision 1
  python continuity_core.py register <wid> <surface> <role> <tier>
  python continuity_core.py submit <wid> <doc> '<patch-json>' [--base <rev>] [--evidence "..."] [--approval-token <one-time>]
  python continuity_core.py get <doc>
  python continuity_core.py delta <surface>
  python chaincore.py materialize    # render projections and re-verify them
  python chaincore.py audit          # audit view
"""
import argparse, getpass, hashlib, json, sqlite3, sys, time, datetime, os, re
from pathlib import Path
from config import (RESEARCH_ROOT, TIER0, TIER1, TIER2, DOC_TO_PATH, NEVER_DOCS,
                    SINGLE_HASH_DOCS, AGENT_ENV_VARS, SIGNER_DB,
                    load_policy_module, load_post_write_hook)

try:
    policy_rules = load_policy_module()   # optional: a missing module degrades to observe-only
except Exception:  # noqa: BLE001  never crash at import because a policy module is absent
    policy_rules = None

try:
    post_write_hook = load_post_write_hook()   # optional; None means "do nothing after a write"
except Exception:  # noqa: BLE001
    post_write_hook = None

DB_PATH = RESEARCH_ROOT / 'continuity' / 'continuity.db'
PROJECTION_DIR = RESEARCH_ROOT / 'continuity' / 'projections'

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
# Concurrent-write rejection log (events.sequence UNIQUE collision).
# Same JSONL shape as length_gate.log; used to prove "one accepted, one rejected, both logged".
SUBMIT_REJECT_LOG = RESEARCH_ROOT / 'continuity' / 'submit_reject.log'

# -- Gate switch: the switch is a state file, not an environment variable. --------------
# An env var only affects the process that set it, and independent writers each start
# their own process - an env-only switch would silently be a no-op.
# File first (the only cross-process form); env only for local debugging.
GATE_STATE_DIR = Path(os.environ.get('CHAIN_GATE_DIR') or (RESEARCH_ROOT / 'continuity'))
try:
    if not GATE_STATE_DIR.exists():
        GATE_STATE_DIR = RESEARCH_ROOT / 'continuity'
except Exception:
    GATE_STATE_DIR = RESEARCH_ROOT / 'continuity'
GATE_ENFORCE_FLAG = GATE_STATE_DIR / 'GATE_ENFORCE.on'
GATE_OBSERVE_MARKER = GATE_STATE_DIR / 'GATE_OBSERVE_SINCE.json'


def gate_enforced():
    """Whether the gate actually blocks:
    1) state file present and its content is not 0/off/false -> block (file = audit trail);
    2) otherwise the env flag (current process only, for tests and debugging);
    3) otherwise record only, never block (pending activation).
    Unreadable flag -> False: a writer must not fail because the flag could not be read.
    """
    try:
        if GATE_ENFORCE_FLAG.exists():
            txt = GATE_ENFORCE_FLAG.read_text(encoding='utf-8').strip().lower()
            return txt not in ('0', 'off', 'false', 'no')
    except Exception:
        pass
    return os.environ.get('CHAIN_GATE_ENFORCE', '').strip().lower() in ('1', 'true', 'yes')


def render_projection(rev, updated, value):
    """The one renderer, shared with materialize(): GENERATED header + body.

    The length gate must measure exactly this string, not the body alone.
    Pure computation: no file is written, so unknown doc keys still render.
    """
    try:
        body = json.loads(value) if isinstance(value, str) else value
    except Exception:
        body = value
    if not isinstance(body, str):
        body = json.dumps(body, ensure_ascii=False, indent=2)
    header = (f'<!-- GENERATED_FROM_CONTINUITY_CORE REVISION={rev} UPDATED={updated} '
              f'DO_NOT_DIRECT_WRITE: all changes must go through chaincore.py submit -->\n')
    return header + body


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


def _log_submit_reject(rec):
    """Rejection log (append-only JSONL). A logging failure must not break the caller."""
    try:
        SUBMIT_REJECT_LOG.parent.mkdir(parents=True, exist_ok=True)
        with SUBMIT_REJECT_LOG.open('a', encoding='utf-8') as fh:
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


def now_iso():
    return datetime.datetime.now(datetime.timezone(datetime.timedelta(hours=8))).isoformat(timespec='seconds')

def get_conn():
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(DB_PATH), timeout=30)
    conn.execute('PRAGMA journal_mode=WAL')
    conn.execute('PRAGMA busy_timeout=30000')
    return conn

def init_schema(conn):
    conn.executescript('''
    CREATE TABLE IF NOT EXISTS events (
      event_id TEXT PRIMARY KEY,
      sequence INTEGER NOT NULL UNIQUE,
      ts TEXT NOT NULL,
      writer_id TEXT NOT NULL,
      surface_id TEXT NOT NULL,
      session_id TEXT,
      base_revision INTEGER,
      event_type TEXT NOT NULL,          -- INIT / PATCH / PROPOSAL / OBSERVATION / DECISION / EXTERNAL_CLAIM / REJECTED_CHANGE / ACCEPTED_STATE_CHANGE
      doc_key TEXT NOT NULL,
      patch_json TEXT,                   -- structured change (no whole-file overwrite except INIT)
      evidence_refs TEXT,
      caused_by TEXT,
      status TEXT NOT NULL DEFAULT 'accepted',   -- accepted / rejected
      reject_reason TEXT,
      prev_hash TEXT,                    -- hash chain: previous event hash (non-overwrite audit)
      hash TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS canonical_state (
      doc_key TEXT PRIMARY KEY,
      revision INTEGER NOT NULL,
      value_json TEXT NOT NULL,
      updated_event_id TEXT,
      updated_at TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS surface_cursors (
      surface_id TEXT PRIMARY KEY,
      last_seen_revision INTEGER NOT NULL DEFAULT 0,
      updated_at TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS writer_registry (
      writer_id TEXT PRIMARY KEY,
      surface_id TEXT NOT NULL,
      role TEXT NOT NULL,                -- core_writer / session / worker / observer
      tier TEXT NOT NULL,                -- tier0 / tier1 / tier2
      status TEXT NOT NULL DEFAULT 'active',
      registered_at TEXT NOT NULL,
      last_seen TEXT
    );
    CREATE TABLE IF NOT EXISTS conflict_queue (
      conflict_id INTEGER PRIMARY KEY AUTOINCREMENT,
      event_id TEXT NOT NULL,
      doc_key TEXT NOT NULL,
      reason TEXT NOT NULL,
      status TEXT NOT NULL DEFAULT 'pending',   -- pending / resolved / rejected
      resolution TEXT,
      resolved_at TEXT,
      writer_id TEXT,
      base_revision INTEGER,
      current_revision INTEGER,
      patch_json TEXT,
      created_at TEXT
    );
    CREATE INDEX IF NOT EXISTS idx_events_doc ON events(doc_key, sequence);
    CREATE INDEX IF NOT EXISTS idx_events_surface ON events(surface_id, sequence);
    -- Escape-hatch ledger: force is kept, but it has to cost something.
    -- A rejected write that passes by adding --force means the rule was only renamed.
    -- So every force carries a reason, a ledger row, and is forbidden to automation.
    CREATE TABLE IF NOT EXISTS force_log (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      ts TEXT NOT NULL,
      writer_id TEXT,
      doc_key TEXT,
      reason TEXT NOT NULL,
      event_id TEXT,
      sequence INTEGER
    );
    -- One-time approval ledger: destructive restores need an out-of-band code.
    -- Only the SHA-256 is stored, never the code itself; use burns it (consumed_* fields).
    CREATE TABLE IF NOT EXISTS approval_tokens (
      token_sha256 TEXT PRIMARY KEY,
      created_at TEXT NOT NULL,
      created_by TEXT,
      label TEXT,
      consumed_at TEXT,
      consumed_event TEXT,
      consumed_doc TEXT,
      consumed_op TEXT,
      consumed_patch_sha TEXT
    );
    ''')
    # migration: add prev_hash for older databases (hash chain)
    cols = [r[1] for r in conn.execute('PRAGMA table_info(events)').fetchall()]
    if 'prev_hash' not in cols:
        conn.execute('ALTER TABLE events ADD COLUMN prev_hash TEXT')
    # migration: countersign record column
    if 'countersigned_by' not in cols:
        conn.execute('ALTER TABLE events ADD COLUMN countersigned_by TEXT')
    # migration: conflict_queue ownership fields, so a conflict can become a ticket
    cq_cols = [r[1] for r in conn.execute('PRAGMA table_info(conflict_queue)').fetchall()]
    for _name, _type in (('writer_id', 'TEXT'), ('base_revision', 'INTEGER'),
                         ('current_revision', 'INTEGER'), ('patch_json', 'TEXT'),
                         ('created_at', 'TEXT')):
        if _name not in cq_cols:
            conn.execute(f'ALTER TABLE conflict_queue ADD COLUMN {_name} {_type}')
    conn.commit()

def hash_event(writer_id, doc_key, ts, seq, patch_json, prev_hash=''):
    return hashlib.sha256(f'{prev_hash}|{writer_id}|{doc_key}|{ts}|{seq}|{patch_json}'.encode()).hexdigest()[:16]

# Event type semantics: only these update canonical_state
_CANONICAL_EVENT_TYPES = {'INIT', 'ACCEPTED_STATE_CHANGE', 'PATCH', 'DECISION'}

# Protected docs (tier 0 plus policy): a change is rendered only after a countersign.
# submit classifies writes to these docs as constitutional amendments: they enter the
# chain with status=pending_countersign, do not update canonical_state, and are not rendered;
# they apply only when a COUNTERSIGN event naming that event id arrives.

def next_sequence(conn):
    row = conn.execute('SELECT COALESCE(MAX(sequence),0) FROM events').fetchone()
    return row[0] + 1

def register_writer(writer_id, surface_id, role, tier, status='active'):
    conn = get_conn(); init_schema(conn)
    conn.execute('INSERT OR REPLACE INTO writer_registry VALUES (?,?,?,?,?,?,?)',
                 (writer_id, surface_id, role, tier, status, now_iso(), now_iso()))
    conn.commit(); conn.close()
    return {'ok': True, 'writer': writer_id, 'surface': surface_id, 'role': role, 'tier': tier}

def get_current_revision(conn, doc_key):
    row = conn.execute('SELECT revision FROM canonical_state WHERE doc_key=?', (doc_key,)).fetchone()
    return row[0] if row else 0

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


def verify_approval_token(conn, token):
    """Verify a one-time approval code.
    The code is issued out of band; the database stores its SHA-256 only;
    it is burned on use and replay is refused. Registration is a manual, out-of-band step.
    Returns (ok, error_code, token_sha256).
    """
    t = (token or '').strip()
    if not t:
        return (False, 'APPROVAL_TOKEN_REQUIRED', None)
    sha = hashlib.sha256(t.encode('utf-8')).hexdigest()
    row = conn.execute('SELECT consumed_at FROM approval_tokens WHERE token_sha256=?', (sha,)).fetchone()
    if not row:
        return (False, 'APPROVAL_TOKEN_UNKNOWN', sha)
    if row[0]:
        return (False, 'APPROVAL_TOKEN_USED', sha)
    return (True, '', sha)

def _consume_approval_token(conn, token_sha, doc_key, op, patch_json, event_id):
    """Burn the code in the same transaction; rowcount=0 means a race, so the caller rolls back."""
    cur = conn.execute(
        'UPDATE approval_tokens SET consumed_at=?, consumed_event=?, consumed_doc=?, '
        'consumed_op=?, consumed_patch_sha=? WHERE token_sha256=? AND consumed_at IS NULL',
        (now_iso(), event_id, doc_key, str(op),
         hashlib.sha256(patch_json.encode('utf-8')).hexdigest(), token_sha))
    return cur.rowcount

def runtime_session_id():
    """Session identifier injected by the runtime, never supplied by the caller.

    Reading it from the environment keeps the model from minting its own identity.
      - AGENT_SESSION_ID           interactive session (configurable via agent_env_vars)
      - AGENT_CRON_SESSION         scheduled session
      - AGENT_PARENT_START_MARKER  fallback: parent start marker (distinguishes processes)
    All empty -> None, and ticketed writes are refused.
    """
    for k in AGENT_ENV_VARS[:-1]:
        v = (os.environ.get(k) or '').strip()
        if v:
            return v
    m = (os.environ.get(AGENT_ENV_VARS[-1]) or '').strip()
    return ('proc:' + m) if m else None


def verify_signer_message(message_id, require_session=None, required_event_ids=None):
    """Resolve the referenced user message and prove it names the events being signed.

    The point is traceability: a signature must point at something the human wrote.
    An agent's paraphrase is not evidence - an event can claim a signature that no message
    supports, and the chain alone cannot tell the difference.

    Naming check: "contains the word sign" is a tautology - "do not sign 223 yet" would
    pass, and so would a question about signing. The message must list each event id,
    and only named events are registered.
    """
    if not message_id:
        return False, 'MISSING_SIGNER_MESSAGE_ID'
    if not SIGNER_DB:
        return False, 'SIGNER_DB_NOT_CONFIGURED'
    db = Path(SIGNER_DB)
    if not db.exists():
        return False, 'STATE_DB_NOT_FOUND'
    try:
        c = sqlite3.connect(f'file:{db}?mode=ro', uri=True)
        row = c.execute("SELECT session_id, role, content FROM messages WHERE id=?",
                        (message_id,)).fetchone()
        c.close()
    except Exception as _e:
        return False, f'STATE_DB_ERROR:{_e}'
    if not row:
        return False, 'SIGNER_MESSAGE_NOT_FOUND'
    sess, role, content = row
    if role != 'user':
        return False, f'SIGNER_MESSAGE_NOT_USER:role={role}'
    if require_session and sess and sess != require_session:
        return False, f'SIGNER_MESSAGE_SESSION_MISMATCH:{sess}!={require_session}'
    content = str(content or '')
    if not re.search(r'approve|signed|sign here|confirm|consent', content, re.I):
        return False, 'SIGNER_MESSAGE_NO_SIGNAL'
    _missing = [e for e in (required_event_ids or []) if e and e not in content]
    if _missing:
        return False, 'SIGNER_MESSAGE_DOES_NOT_NAME:' + ','.join(_missing)
    return True, {'session_id': sess, 'role': role, 'named': list(required_event_ids or [])}


def _superseded_map(conn):
    """Scan all events and return {superseded event_id: superseding event_id}.

    Only the structured supersedes field counts: [{'event_id': ..., 'hash': ...}, ...].
    Prose is not parsed: a claim in prose cannot be verified, and that gap is exactly how
    contradictory decisions once coexisted. A reference must carry the hash it saw.
    """
    out = {}
    try:
        for eid, pj in conn.execute("SELECT event_id, patch_json FROM events"):
            try:
                p = json.loads(pj)
            except Exception:
                continue
            if not isinstance(p, dict):
                continue
            refs = p.get('supersedes')
            if isinstance(refs, (list, tuple)):
                for r in refs:
                    if isinstance(r, dict) and r.get('event_id'):
                        out[str(r['event_id'])] = eid
                    elif isinstance(r, str):
                        out[r] = eid
    except Exception:
        pass
    return out


def _find_prior_superseder(conn, target_event_id):
    """Has an eligible event already superseded this target? Returns its id, else None.

    Eligible = the declarer is itself in force (signed, or legacy before the effective line).

    Without that check, an unsigned event from a parallel session can claim to supersede a
    signed decision and thereby gain a veto it never earned: an unsigned writer must not
    overturn a signed one. This is the second door of the same hole.
    """
    decl = signature_declarations(conn)
    for eid, seq, etype, pj, text in _iter_events(conn):
        if target_event_id in _declaration_targets(seq, pj, text) \
                and is_qualified(conn, eid, seq, pj, decl):
            return eid
    return None


def chain_head(conn):
    """Current chain head hash (None on an empty chain). Writers read it and hand it back."""
    row = conn.execute('SELECT hash FROM events ORDER BY sequence DESC LIMIT 1').fetchone()
    return row[0] if row else None


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


def _auto_post_write(event_id, cls, gate_err=None, force=False):
    """Post-write hook: runs after a successful write.

    Why in the core instead of a scheduled job: it is a smaller change, and every writer
    gets it, rather than depending on someone remembering a manual follow-up step.
    The hook is late-bound to avoid a circular import; any exception is logged only -
    a successful write must never be turned into a failure by its own hook.
    """
    try:
        if post_write_hook is None:
            return None
        return post_write_hook(event_id, cls, gate_err=gate_err, force=force)
    except Exception as _e:
        try:
            _log_submit_reject({'ts': now_iso(), 'event_id': event_id,
                                'error': 'POST_WRITE_SKIPPED', 'detail': repr(_e)[:200]})
        except Exception:
            pass
        return None


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
                              'CHAIN_SESSION_ID / CHAIN_CRON_SESSION / CHAIN_PARENT_START_MARKER are all empty. '
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

def get_canonical(doc_key):
    conn = get_conn(); init_schema(conn)
    row = conn.execute('SELECT revision, value_json, updated_at FROM canonical_state WHERE doc_key=?', (doc_key,)).fetchone()
    conn.close()
    if not row: return None
    return {'doc_key': doc_key, 'revision': row[0], 'value': row[1], 'updated_at': row[2]}

def get_surface_delta(surface_id):
    """Events from cursor to latest for a surface (accepted only)."""
    conn = get_conn(); init_schema(conn)
    cur = conn.execute('SELECT last_seen_revision FROM surface_cursors WHERE surface_id=?', (surface_id,)).fetchone()
    from_rev = cur[0] if cur else 0
    latest = conn.execute('SELECT COALESCE(MAX(sequence),0) FROM events').fetchone()[0]
    rows = conn.execute('''SELECT sequence, ts, writer_id, event_type, doc_key, patch_json, evidence_refs, hash
                           FROM events WHERE sequence>? AND status IN ('accepted','countersigned') ORDER BY sequence''', (from_rev,)).fetchall()
    conn.close()
    return {'surface': surface_id, 'from': from_rev, 'to': latest,
            'events': [{'sequence': r[0], 'ts': r[1], 'writer': r[2], 'type': r[3],
                        'doc': r[4], 'patch': json.loads(r[5]) if r[5] else None,
                        'evidence': r[6], 'hash': r[7]} for r in rows]}

def advance_cursor(surface_id, to_rev=None):
    conn = get_conn(); init_schema(conn)
    if to_rev is None:
        to_rev = conn.execute('SELECT COALESCE(MAX(sequence),0) FROM events').fetchone()[0]
    conn.execute('INSERT OR REPLACE INTO surface_cursors VALUES (?,?,?)', (surface_id, to_rev, now_iso()))
    conn.commit(); conn.close()
    return {'surface': surface_id, 'last_seen': to_rev}

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
        conn.execute('INSERT OR REPLACE INTO canonical_state VALUES (?,?,?,?,?)',
                     (doc_key, 1, json.dumps(content, ensure_ascii=False), event_id, ts))
        imported.append(doc_key)
    conn.commit(); conn.close()
    return {'imported': imported}

def _unlock(path: Path):
    """Clear the read-only attribute (physical lock; internal writers only)."""
    try:
        if path.exists():
            os.chmod(path, 0o666)
    except Exception:
        pass

def _lock(path: Path):
    """Set the read-only attribute so no process can rewrite a projection in place."""
    try:
        if path.exists():
            os.chmod(path, 0o444)
    except Exception:
        pass

def projection_path(doc_key):
    """Projection filename: characters that are illegal on Windows are replaced by their
    full-width look-alikes, otherwise write_text raises OSError for keys containing "/" or ":"
    (observed on a batch of legacy keys). Projections are generated output, so nothing is lost."""
    name = doc_key
    for a, b in (('\\', '＼'), ('/', '／'), (':', '：'), ('*', '＊'), ('?', '？'),
                 ('"', '＂'), ('<', '＜'), ('>', '＞'), ('|', '｜')):
        name = name.replace(a, b)
    return PROJECTION_DIR / (name + '.md')


def _verify_projection(content, expect_rev=None):
    """Pre-write self-check: catch malformed content before it reaches the disk.

    Motivation: an ad-hoc script once called render_projection(rev, updated, value) as
    (rev, value, updated); the header line was swallowed by the body and the document
    became unreadable. Bad content must not reach the disk."""
    if not content:
        return False, 'content is empty'
    head = content.split('\n', 1)[0]
    if not head.startswith('<!-- GENERATED_FROM_CONTINUITY_CORE REVISION='):
        return False, 'bad header prefix: %r' % head[:80]
    for need in ('REVISION=', 'UPDATED=', 'DO_NOT_DIRECT_WRITE'):
        if need not in head:
            return False, 'header missing %s: %r' % (need, head[:80])
    seg = head.split('REVISION=', 1)[1].split(' ', 1)[0]
    if not seg.isdigit():
        return False, 'REVISION is not a number: %r' % seg
    if expect_rev is not None and int(seg) != int(expect_rev):
        return False, 'REVISION=%s does not match canonical %s' % (seg, expect_rev)
    return True, ''


def atomic_write_verified(path, content, verify=None):
    """Write a temp copy, read it back byte for byte, validate, then replace atomically.

    If any step fails, the real file is not touched at all."""
    path = Path(path)
    tmp = path.with_name(path.name + '.tmp')
    # newline='' disables newline translation: Path.write_text turns \n into \r\n on
    # Windows, so a strict byte comparison would report false mismatches.
    with open(tmp, 'w', encoding='utf-8', newline='') as fh:
        fh.write(content)
    with open(tmp, 'r', encoding='utf-8', newline='') as fh:
        back = fh.read()
    if back != content:
        _rm(tmp)
        raise IOError('temp copy does not read back as written: %s' % tmp)
    if verify is not None:
        ok, why = verify(back)
        if not ok:
            _rm(tmp)
            raise ValueError('pre-write validation failed (%s): %s' % (why, path))
    os.replace(str(tmp), str(path))
    return True


def _rm(p):
    try:
        Path(p).unlink()
    except OSError:
        pass


MATERIALIZE_STATUS = None  # resolved lazily: <data dir>/canonical/materialize_last_run.json


def _status_path():
    global MATERIALIZE_STATUS
    if MATERIALIZE_STATUS is None:
        MATERIALIZE_STATUS = Path(DB_PATH).parent / 'materialize_last_run.json'
    return MATERIALIZE_STATUS


def _record_materialize_run(docs, failures, scope='all'):
    """Record the last materialize run in a machine-readable file.
    Projection write failures used to be silent: documents had no projection and nobody"""
    out = {'ts': now_iso(), 'scope': scope, 'docs': docs,
           'fail_count': len(failures), 'failures': failures}
    try:
        p = _status_path()
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(json.dumps(out, ensure_ascii=False, indent=1), encoding='utf-8')
    except OSError as e:
        sys.stderr.write('[materialize] failed to record run status: %s\n' % e)
    return out
def materialize_doc(doc_key, write_projections=True, write_sources=True, lock_sources=True):
    """Materialize a single document.

    This logic must exist in exactly one place: callers that re-implemented the render
    order corrupted the header more than once.
    """
    conn = get_conn(); init_schema(conn)
    row = conn.execute('SELECT revision, value_json, updated_at FROM canonical_state WHERE doc_key=?',
                       (doc_key,)).fetchone()
    conn.close()
    if row is None:
        return None
    rev, value, updated = row
    content = render_projection(rev, updated, value)
    _vok, _vwhy = _verify_projection(content, expect_rev=rev)   # bad content must not reach disk
    if not _vok:
        _rec = [{'doc': doc_key, 'reason': 'VERIFY_FAILED', 'error': _vwhy}]
        _record_materialize_run(1, _rec, scope=doc_key)
        raise ValueError('pre-materialize validation failed (%s): %s' % (_vwhy, doc_key))
    failures = []
    if write_projections:
        PROJECTION_DIR.mkdir(parents=True, exist_ok=True)
        try:
            atomic_write_verified(projection_path(doc_key), content,
                                  verify=lambda c: _verify_projection(c, rev))
        except Exception as e:
            failures.append({'doc': doc_key, 'reason': 'PROJECTION_WRITE_FAILED', 'error': str(e)})
    if write_sources and doc_key in DOC_TO_PATH:
        src = Path(DOC_TO_PATH[doc_key])
        src.parent.mkdir(parents=True, exist_ok=True)
        try:
            _unlock(src)
            atomic_write_verified(src, content, verify=lambda c: _verify_projection(c, rev))
            if lock_sources:
                _lock(src)
        except Exception as e:
            failures.append({'doc': doc_key, 'reason': 'SOURCE_WRITE_FAILED', 'error': str(e)})
    _record_materialize_run(1, failures, scope=doc_key)
    return {'revision': rev, 'projected': not failures, 'locked': lock_sources,
            'failures': failures}


def materialize(write_projections=True, write_sources=True, lock_sources=True):
    """Generate projection files from canonical_state.
    write_projections=True: write to projections/ (GENERATED header, writable)
    write_sources=True: write back to the source files (header + OS read-only lock)

    A single failing document used to abort the whole run (a legacy key containing "/" cannot
    be a filename on Windows), leaving every other document on an old revision. Failures are
    now isolated per document and collected in out['__failures__'].
    """
    conn = get_conn(); init_schema(conn)
    rows = conn.execute('SELECT doc_key, revision, value_json, updated_at FROM canonical_state').fetchall()
    conn.close()
    out = {}
    failures = []
    for doc_key, rev, value, updated in rows:
        # The length gate measures this same rendering, so it is defined once, here:
        # duplicating the header elsewhere makes the two measurements drift apart.
        content = render_projection(rev, updated, value)
        _vok, _vwhy = _verify_projection(content, expect_rev=rev)   # bad content must not reach disk
        if not _vok:
            failures.append({'doc': doc_key, 'reason': 'VERIFY_FAILED', 'error': _vwhy})
            out[doc_key] = {'revision': rev, 'projected': False, 'locked': False}
            continue
        if write_projections:
            PROJECTION_DIR.mkdir(parents=True, exist_ok=True)
            try:
                atomic_write_verified(projection_path(doc_key), content,
                                      verify=lambda c: _verify_projection(c, rev))
            except Exception as e:
                failures.append({'doc': doc_key, 'reason': 'PROJECTION_WRITE_FAILED', 'error': str(e)})
        if write_sources and doc_key in DOC_TO_PATH:
            src = Path(DOC_TO_PATH[doc_key])
            src.parent.mkdir(parents=True, exist_ok=True)
            try:
                _unlock(src)
                atomic_write_verified(src, content, verify=lambda c: _verify_projection(c, rev))
                if lock_sources:
                    _lock(src)
            except Exception as e:
                failures.append({'doc': doc_key, 'reason': 'SOURCE_WRITE_FAILED', 'error': str(e)})
        out[doc_key] = {'revision': rev, 'projected': True, 'locked': lock_sources}
    out['__failures__'] = failures
    out['__status__'] = _record_materialize_run(len(rows), failures)
    return out

def verify_projections():
    """Compare canonical_state with the projection on disk (reverse overwrite / drift)."""
    conn = get_conn(); init_schema(conn)
    rows = conn.execute('SELECT doc_key, value_json FROM canonical_state').fetchall()
    conn.close()
    mismatches = []
    checked = 0
    for doc_key, value_json in rows:
        path = DOC_TO_PATH.get(doc_key)
        if not path:
            continue
        p = Path(path)
        if not p.exists():
            mismatches.append({'doc': doc_key, 'reason': 'MISSING', 'path': str(p)})
            continue
        try:
            canonical_content = json.loads(value_json)
        except Exception:
            canonical_content = value_json
        disk = p.read_text(encoding='utf-8', errors='replace')
        disk_body = re.sub(r'^<!-- GENERATED_FROM_CONTINUITY_CORE.*?-->\n', '', disk, count=1, flags=re.S)
        if canonical_content.rstrip('\r\n') != disk_body.rstrip('\r\n'):
            mismatches.append({'doc': doc_key, 'reason': 'CONTENT_MISMATCH',
                               'path': str(p),
                               'canonical_len': len(canonical_content),
                               'disk_len': len(disk)})
        checked += 1
    return {'projections_checked': checked, 'mismatches': mismatches}


# -- Signature status derivation for decisions ----------------------------------------
# If a pending signature exists only in prose, no executor reading the chain can tell
# whether a decision is signed; it can only guess. A rule with no machine-readable
# anchor is a rule in name only. State is computed here, never asserted.
SIGNATURES_FILE = RESEARCH_ROOT / 'SIGNATURES.jsonl'


def load_signature_shas():
    """Collect every signed sha256. One source: the chain. Empty = nothing is signed."""
    shas = set()
    # (1) The signing record on the chain is the only authority, read as structured signs:
    #
    # the write path verifies patch['signs'] + message id + naming + sha256, while a reader
# that regex-scans content for any 64-char hex was on a different contract. That gap left
# a path around every write-side check: an OBSERVATION (append-only, no ticket) whose
# doc_key starts with SIGNATURE and whose body contains a hex string was accepted.
# Reproduced on a scratch database: the writer let it through, the target turned SIGNED.
# No access to the evidence store was needed at any point.
# Fix: the reader accepts only structured signs from event_type='SIGNATURE'.
    try:
        _c = get_conn()
        for (_pj, _et) in _c.execute("SELECT patch_json, event_type FROM events"):
            if _et != 'SIGNATURE':
                continue
            try:
                _p = json.loads(_pj)
            except Exception:
                continue
            if not isinstance(_p, dict):
                continue
            for _s in (_p.get('signs') or []):
                if isinstance(_s, dict) and _s.get('sha256'):
                    shas.add(str(_s['sha256']).strip().lower())
        _c.close()
    except Exception:
        pass
    # (2) SIGNATURES.jsonl: a legacy source (markdown hashes), no longer authoritative
    try:
        if SIGNATURES_FILE.exists():
            for line in SIGNATURES_FILE.read_text(encoding='utf-8').splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    d = json.loads(line)
                except Exception:
                    continue
                if isinstance(d, dict):
                    for _v in (d.get('files') or {}).values():
                        if isinstance(_v, dict) and _v.get('sha256'):
                            shas.add(str(_v['sha256']).strip().lower())
                    for _s in re.findall(r'\b([0-9a-f]{64})\b', str(d.get('note') or '')):
                        shas.add(_s.lower())
    except Exception:
        pass
    return shas


def decision_signature_status(regime_start=None):
    """Derive one of three states (never retroactive):

      LEGACY  : decisions written before the effective line; valid from their own date
      SIGNED  : the body sha256 is signed;
                weakening hypotheses also count after 72h without objection;
      PENDING : written after the effective line and unsigned - the only state that alerts.

    Why three states: older decisions were in force from their own date, while the signing
    rule arrived much later. Applying "only SIGNED may act" literally would invalidate
    rules that already ran. Known legacy state must not drown the real signal.
    From the effective line on, the signed object is the chain body hash; files are projections.
    """
    conn = get_conn(); init_schema(conn)
    rows = conn.execute(
        "SELECT event_id, sequence, ts, doc_key, patch_json, event_type FROM events "
        "WHERE event_type IN ('DECISION','SIGNATURE') ORDER BY sequence").fetchall()
    canon = {r[0]: r[1] for r in conn.execute("SELECT doc_key, value_json FROM canonical_state")}
    dissents = {r[0] for r in conn.execute(
        "SELECT doc_key FROM events WHERE event_type IN ('CORRECTION','REJECTED_CHANGE')")}
    superseded_by = _superseded_map(conn)
    conn.close()

    signed_shas = load_signature_shas()
    now = datetime.datetime.now(datetime.timezone.utc)
    # Default: no effective line, so every decision needs a signature. A deployment that
    # adopts the ledger on top of existing decisions sets the line to the first sequence
    # written under the new rule; older rows are then LEGACY instead of PENDING.
    if regime_start:
        try:
            _regime = datetime.datetime.fromisoformat(regime_start)
        except Exception:
            _regime = None
    else:
        _regime = datetime.datetime(1970, 1, 1, tzinfo=datetime.timezone.utc)
    signed, pending, legacy, superseded, signature_records = [], [], [], [], []
    for eid, seq, ts, doc, patch, etype in rows:
        # The signed object is the event patch_json sha256 (the source), never the canonical
        # value: appends change it, so signing it would expire for no visible reason.
        digest = hashlib.sha256(str(patch).encode('utf-8')).hexdigest()
        rec = {'event_id': eid, 'sequence': seq, 'doc_key': doc, 'body_sha256': digest}
        if eid in superseded_by:
            # Fragments superseded by a full version: not signed, not alerting, not pending.
            rec['state'] = 'SUPERSEDED'
            rec['superseded_by'] = superseded_by[eid]
            superseded.append(rec); continue
        if digest in signed_shas:
            rec['state'] = 'SIGNED'; rec['basis'] = 'sha256_in_signatures'
            signed.append(rec); continue
        if etype == 'SIGNATURE' or str(doc).startswith('SIGNATURE'):
            # A signing record is its own event type and never counts as a decision state.
            # Self-certification is not a signature.
            rec['state'] = 'SIGNATURE_RECORD'
            signature_records.append(rec); continue
        try:
            _t = datetime.datetime.fromisoformat(ts)
            age_h = (now - _t).total_seconds() / 3600.0
        except Exception:
            _t, age_h = None, None
        rec['age_hours'] = round(age_h, 1) if age_h is not None else None
        # The weakening-hypothesis test uses the current body (cumulative view);
        # the signature uses patch_json (source). Different purposes, do not mix them.
        _body = canon.get(doc, patch)
        if not isinstance(_body, str):
            _body = json.dumps(_body, ensure_ascii=False)
        is_weakening = 'WEAKENING HYPOTHESIS' in _body
        has_dissent = doc in dissents
        if is_weakening and age_h is not None and age_h >= 72.0 and not has_dissent:
            rec['state'] = 'SIGNED'; rec['basis'] = 'weakening_72h_no_dissent'
            signed.append(rec); continue
        if _regime is not None and _t is not None and _t < _regime:
            rec['state'] = 'LEGACY'          # before the effective line: valid, no alert
            legacy.append(rec)
        else:
            rec['state'] = 'PENDING_SIGNATURE'
            rec['weakening_class'] = is_weakening
            rec['dissent_seen'] = has_dissent
            pending.append(rec)
    return {'regime_start': regime_start,
            'signed_count': len(signed), 'pending_count': len(pending),
            'legacy_count': len(legacy), 'superseded_count': len(superseded),
            'signature_record_count': len(signature_records),
            'signed': signed, 'pending': pending, 'legacy': legacy,
            'superseded': superseded, 'signature_records': signature_records}


def verify_chain():
    """Verify the hash chain backwards from the latest event; report hand-edited rows."""
    conn = get_conn(); init_schema(conn)
    rows = conn.execute('SELECT sequence, hash, prev_hash, writer_id, doc_key, ts, patch_json FROM events ORDER BY sequence').fetchall()
    # Read the TAINTED registry to split known tampering from newly found breaks.
    # It lives in canonical_state.tainted_sequences.
    _tainted_reg = {}
    try:
        _trow = conn.execute("SELECT value_json FROM canonical_state WHERE doc_key='tainted_sequences'").fetchone()
        if _trow and _trow[0]:
            _tv = _trow[0]
            for _ in range(2):              # the value may be double JSON-encoded
                if isinstance(_tv, str):
                    try: _tv = json.loads(_tv)
                    except Exception: break
            if isinstance(_tv, dict):
                for _t in (_tv.get('tainted') or []):
                    if isinstance(_t, dict) and _t.get('seq') is not None:
                        _tainted_reg[int(_t['seq'])] = _t
    except Exception:
        _tainted_reg = {}
    conn.close()
    broken = []
    verified = 0
    legacy = 0
    genesis = 0
    for i, r in enumerate(rows):
        seq, h, prev_h, writer, doc, ts, patch = r
        if prev_h is None:
            # Old segment (no prev_hash before bootstrap): cannot be recomputed, mark legacy
            if seq == 1 or rows[i-1][0] != seq - 1:
                legacy += 1
            else:
                # Genesis segment: contiguous sequence but no prev_hash (bulk migration).
                # The content hash cannot be recomputed, so it must be counted explicitly.
                # Skipping these silently is how events end up in no bucket at all, which
                # makes every total add up while the ledger itself is wrong.
                genesis += 1
            continue
        if i > 0 and rows[i-1][0] == seq - 1 and prev_h is not None:
            expected_prev = rows[i-1][1]
            if prev_h != expected_prev:
                broken.append({'sequence': seq, 'reason': 'PREV_HASH_MISMATCH', 'expected': expected_prev, 'found': prev_h})
                continue
        if prev_h is not None:
            recomputed = hash_event(writer, doc, ts, seq, patch, prev_h)
            if recomputed != h:
                broken.append({'sequence': seq, 'reason': 'HASH_MISMATCH', 'expected': recomputed, 'found': h})
                continue
            verified += 1
    # Conservation assertion: every event either verifies or lands in a known bucket.
    # An event in neither makes "the totals add up" a lie.
    accounted = verified + legacy + genesis + len(broken)
    if accounted != len(rows):
        raise RuntimeError(
            f'CHAIN_ACCOUNTING_VIOLATION: verified={verified} legacy={legacy} '
            f'genesis={genesis} broken={len(broken)} accounted={accounted} total={len(rows)} '
            f' - an event is neither verified nor classified, so "it reconciles" is not a conclusion')
    # Split (approved): "known TAINTED" and "unregistered break" are reported separately.
    # Motivation: one historical row was already recorded as tampered after an UPDATE, so its
    # original content is unrecoverable and it sits in tainted_sequences. verify() did not read
    # that registry and reported it as broken on every run - known noise drowning the signal.
    # After the split it appears only in tainted_known; unregistered breaks are counted alone.
    tainted_known, broken_unregistered = [], []
    for _b in broken:
        try:
            _seq = int(_b.get('sequence'))
        except (TypeError, ValueError):
            _seq = None
        if _seq is not None and _seq in _tainted_reg:
            _b2 = dict(_b); _b2['status'] = 'already_registered_tainted'
            tainted_known.append(_b2)
        else:
            broken_unregistered.append(_b)
    latest = rows[-1] if rows else None
    _empty = len(rows) == 0
    result = {
        'chain_intact': len(broken_unregistered) == 0,
        # An empty chain must not report chain_intact=true: with zero events "no breaks" is
        # trivially true, and it gets read as "healthy". Emptiness is its own state, not a
        # pass. This is the failure mode that a naive verifier hides: silence looks like
        # success until something else notices the chain is not moving.
        'chain_empty': _empty,
        'chain_status': 'EMPTY' if _empty else ('BROKEN' if broken_unregistered else 'INTACT'),
        'chain_intact_definition': ('chain_intact only means "no unregistered new break"; '
                                    '**when chain_empty=true this value is not evidence of health, read chain_status**; '
                                    'it does not mean the chain was never altered - see tainted_known'),
        'events_total': len(rows),
        'chain_verified': verified,
        'legacy_unverifiable': legacy,
        'genesis_unverifiable': genesis,
        'tainted_known_count': len(tainted_known),
        'tainted_known': tainted_known,
        'broken_unregistered_count': len(broken_unregistered),
        'broken_unregistered': broken_unregistered,
        'broken': broken,          # kept for existing readers (= tainted_known + broken_unregistered)
        'latest_sequence': latest[0] if latest else None,
        'latest_hash': latest[1] if latest else None,
    }
    # Signature state counts: LEGACY / SIGNED / PENDING.
    # "How many decisions are pending, and for how long" - alerts look at PENDING only.
    # Derived by decision_signature_status() from the chain, never from a claim in the body.
    try:
        _sig = decision_signature_status()
        result['decision_signatures'] = {
            'regime_start': _sig['regime_start'],
            'signed_count': _sig['signed_count'],
            'pending_count': _sig['pending_count'],
            'legacy_count': _sig['legacy_count'],
            'superseded_count': _sig['superseded_count'],
            'signature_record_count': _sig['signature_record_count'],
            'pending_detail': [{'event_id': p['event_id'], 'doc_key': p['doc_key'],
                                'age_hours': p['age_hours']} for p in _sig['pending']],
        }
    except Exception as _sig_err:
        result['decision_signatures'] = {'error': str(_sig_err)}
    # Audit anchor: every verify appends latest_sequence + latest_hash to an audit file
    anchor_path = DB_PATH.parent / 'audit_anchors.jsonl'
    anchor_path.parent.mkdir(parents=True, exist_ok=True)
    with open(anchor_path, 'a', encoding='utf-8') as f:
        f.write(json.dumps({'ts': now_iso(), 'latest_sequence': result['latest_sequence'],
                            'latest_hash': result['latest_hash'], 'chain_intact': result['chain_intact'],
                            'chain_status': result['chain_status'], 'chain_empty': result['chain_empty']},
                           ensure_ascii=False) + '\n')
    return result

def lock_all():
    """Apply the OS read-only lock to every source document."""
    locked = []
    for doc_key, path in DOC_TO_PATH.items():
        p = Path(path)
        if p.exists():
            _lock(p)
            locked.append(doc_key)
    return {'locked': locked}

def audit():
    conn = get_conn(); init_schema(conn)
    events = conn.execute('SELECT COUNT(*) FROM events').fetchone()[0]
    accepted = conn.execute("SELECT COUNT(*) FROM events WHERE status='accepted'").fetchone()[0]
    rejected = conn.execute("SELECT COUNT(*) FROM events WHERE status='rejected'").fetchone()[0]
    docs = conn.execute('SELECT doc_key, revision FROM canonical_state ORDER BY doc_key').fetchall()
    writers = conn.execute('SELECT writer_id, surface_id, role, tier, status FROM writer_registry').fetchall()
    conflicts = conn.execute("SELECT conflict_id, event_id, doc_key, reason, status FROM conflict_queue WHERE status='pending'").fetchall()
    conn.close()
    return {'events_total': events, 'accepted': accepted, 'rejected': rejected,
            'docs': docs, 'writers': writers, 'pending_conflicts': conflicts}

# ==================== Effectiveness (is_effective) ===================================
# Rule: an event is effective iff a signing record names it AND the sha256 it cites matches
#   - the events table is never modified (append-only),
#   - EFFECTIVE_LINE_SEQ: decisions before it are treated as legacy (unless superseded);
#     at and after it, a signature is required for anything to take effect.
#   - every code path that acts on a decision must call this first and stop on False.
# Background: writing "in the chain != in force" as a semantic rule left no machine-readable
# anchor, so the same failure repeated: the chain and the effective state disagreed.
EFFECTIVE_LINE_SEQ = int(os.environ.get('CHAIN_EFFECTIVE_LINE_SEQ') or 0)   # 0 = no legacy band

_SHA64_RE = re.compile(r'[0-9a-f]{64}')
# Signature shape: an event id followed (within 40 chars, no hex) by a 64-char sha256.
_PAIR_RE = re.compile(r'ev(\d{6})[^0-9a-f]{0,40}([0-9a-f]{64})')
_SUPERSEDE_RE = re.compile(r'supersedes\s+ev(\d{6})')


def _ro_conn():
    conn = sqlite3.connect('file:%s?mode=ro' % str(DB_PATH).replace('\\', '/'), uri=True)
    return conn


def _iter_events(conn):
    """Yield (event_id, sequence, event_type, patch_json, content_text)."""
    for eid, seq, etype, pj in conn.execute(
            'SELECT event_id, sequence, event_type, patch_json FROM events ORDER BY sequence'):
        try:
            p = json.loads(pj) if pj else {}
        except Exception:
            p = {}
        text = (p.get('content') or '') if isinstance(p, dict) else ''
        yield eid, seq, etype, (pj or ''), text


def signature_declarations(conn):
    """Scan the chain; return {signing event id: {signed ev: declared sha256}}.

    Rule: an "evXXXXXX + 64-char sha256" pair inside the body counts as a signing statement.
    Both signing shapes fall under it -
      A. COUNTERSIGN (patch.op=='countersign', target=evXXXXXX)
      B. a signing DECISION that lists each event id with its patch_json sha256
    """
    decl = {}
    for eid, seq, etype, pj, text in _iter_events(conn):
        pairs = {}
        for m in _PAIR_RE.finditer(text):
            pairs['ev' + m.group(1)] = m.group(2)
        # A COUNTERSIGN target is also a signing statement (for amendments)
        try:
            p = json.loads(pj) if pj else {}
        except Exception:
            p = {}
        if isinstance(p, dict) and p.get('op') == 'countersign' and p.get('target'):
            pairs.setdefault(str(p['target']), None)
        if pairs:
            decl[eid] = pairs
    return decl


# Legacy supersede relations are parsed from prose (adjacent only, seq < EFFECTIVE_LINE_SEQ);
# at and after the line, only the structured "supersedes": ["evXXXXXX", ...] field counts.
# Reason: regex-parsing prose produced both a missed and a false supersede. A machine
# constraint expressed in prose is fragile by construction.
_LEGACY_SUP_RE = re.compile(
    r'supersedes\s+((?:ev\d{6})(?:\s*(?:and|,|;)\s*ev\d{6})*)', re.I)
_EV_RE = re.compile(r'ev\d{6}')


def declared_supersedes(conn):
    """Return {declaring event id: [superseded ev, ...]}.

    - seq >= EFFECTIVE_LINE_SEQ: only patch_json['supersedes'] (structured, one contract)
    - seq <  EFFECTIVE_LINE_SEQ: prose parsing (legacy; existing events never rewritten)
    """
    out = {}
    for eid, seq, etype, pj, text in _iter_events(conn):
        targets = []
        if seq >= EFFECTIVE_LINE_SEQ:
            try:
                p = json.loads(pj) if pj else {}
            except Exception:
                p = {}
            v = p.get('supersedes') if isinstance(p, dict) else None
            if isinstance(v, str):
                targets = [v]
            elif isinstance(v, list):
                for x in v:
                    # Two shapes exist on the chain: the string "evXXXXXX", or an object
                    # {"event_id": ..., "hash": ...}. Accepting only the string silently drops
                    # whole batches, which is indistinguishable from "no relation".
                    if isinstance(x, dict):
                        t = x.get('event_id') or x.get('id') or x.get('ev')
                        if t:
                            targets.append(str(t))
                    elif x is not None:
                        targets.append(str(x))
            targets = [t for t in targets if _EV_RE.fullmatch(t or '')]
        else:
            for m in _LEGACY_SUP_RE.finditer(text or ''):
                targets += _EV_RE.findall(m.group(1))
        if targets:
            out[eid] = sorted(set(targets))
    return out


def _declaration_targets(seq, pj, text):
    """Superseded targets declared by one event (structured at/after the line, prose before)."""
    targets = []
    if seq >= EFFECTIVE_LINE_SEQ:
        try:
            p = json.loads(pj) if pj else {}
        except Exception:
            p = {}
        v = p.get('supersedes') if isinstance(p, dict) else None
        if isinstance(v, str):
            targets = [v]
        elif isinstance(v, list):
            for x in v:
                # Two shapes exist on the chain: a string, or an object with event_id and hash.
                # Accepting only the string silently drops whole batches, which looks exactly
                # like "no relation exists".
                if isinstance(x, dict):
                    t = x.get('event_id') or x.get('id') or x.get('ev')
                    if t:
                        targets.append(str(t))
                elif x is not None:
                    targets.append(str(x))
        targets = [t for t in targets if _EV_RE.fullmatch(t or '')]
    else:
        for m in _LEGACY_SUP_RE.finditer(text or ''):
            targets += _EV_RE.findall(m.group(1))
    return sorted(set(targets))


def is_qualified(conn, event_id, seq, pj, decl):
    """Eligible to supersede = the declarer is itself in force (signed, or legacy).

    Deliberately does not consult supersede: eligibility and being-superseded are mutually
    dependent, and requiring "not superseded" here closes a cycle that explodes
    combinatorially (measured: 300s timeout, kernel killed). So eligibility depends on
    signatures only, and a supersede declared while in force stays historically valid.
    """
    if event_id in decl:
        return True
    if seq < EFFECTIVE_LINE_SEQ:
        return True
    actual = hashlib.sha256((pj or '').encode('utf-8')).hexdigest()
    for sig_ev, pairs in decl.items():
        if event_id in pairs and pairs[event_id] == actual:
            return True
    return False


def _superseded_ids(conn):
    """Set of events replaced by an *eligible* declarer. Two phases, no recursion.

    Eligibility: only an event that is in force may supersede another one. Otherwise any
    unsigned event (say, from a parallel session) could write "supersedes evXXXXXX" and
    kill a signed decision - an unsigned writer must not overturn a signed one.
    """
    decl = signature_declarations(conn)
    out = set()
    for eid, seq, etype, pj, text in _iter_events(conn):
        targets = _declaration_targets(seq, pj, text)
        if targets and is_qualified(conn, eid, seq, pj, decl):
            out.update(targets)
    return out


def is_effective(event_id, conn=None):
    """Return dict(ok=bool, reason=str, ...). Call before acting on a decision; ok=False stops."""
    own = conn is None
    conn = conn or _ro_conn()
    try:
        row = conn.execute(
            'SELECT sequence, event_type, patch_json FROM events WHERE event_id=?',
            (event_id,)).fetchone()
        if not row:
            return {'ok': False, 'reason': 'NOT_FOUND', 'event_id': event_id}
        seq, etype, pj = row

        # Non-decision events do not pass this gate (they have the ticket and countersign rules)
        if etype != 'DECISION':
            return {'ok': True, 'reason': 'NOT_A_DECISION', 'event_type': etype}

        decl = signature_declarations(conn)

        # A signing event is itself signed: its existence is the signature
        if event_id in decl:
            return {'ok': True, 'reason': 'IS_SIGNATURE_EVENT'}

        actual = hashlib.sha256((pj or '').encode('utf-8')).hexdigest()

        # Superseded by an eligible declarer -> never effective (legacy included)
        if event_id in _superseded_ids(conn):
            return {'ok': False,
                    'reason': 'SUPERSEDED' if seq >= EFFECTIVE_LINE_SEQ else 'SUPERSEDED_LEGACY',
                    'event_id': event_id}

        # At/after the line: a signing record must name it, with a matching sha256
        if seq >= EFFECTIVE_LINE_SEQ:
            for sig_ev, pairs in decl.items():
                if event_id in pairs and pairs[event_id] == actual:
                    return {'ok': True, 'reason': 'SIGNED', 'signed_by': sig_ev,
                            'sha256': actual}
            return {'ok': False, 'reason': 'PENDING_SIGNATURE', 'event_id': event_id,
                    'sha256': actual,
                    'detail': 'decisions at or after the effective line (seq %s) need a signing '
                              'record that names them with a matching sha256.' % EFFECTIVE_LINE_SEQ}

        # Before the line: legacy counts as effective unless superseded
        return {'ok': True, 'reason': 'LEGACY_BEFORE_LINE', 'event_id': event_id}
    finally:
        if own:
            conn.close()

# ==================== Effectiveness  end =============================================


def _manual_tty_attestation():
    """Channel gate for the manual-terminal path.

    All three must hold before an attestation is issued:
      1) all agent runtime env vars empty
      2) stdin and stdout are real TTYs
      3) --manual-tty was passed

    Returns 'manual_tty:<host>:<pid>:<time>'. Anything else exits (fail-closed).
    This function grants channel eligibility only, never authorization: submit_event
    still requires a valid one-time code on every call, with no exempt branch.
    """
    hit = [k for k in AGENT_ENV_VARS if (os.environ.get(k) or '').strip()]
    if hit:
        raise SystemExit(f'MANUAL_TTY_REFUSED_AGENT_ENV: detected {hit} - '
                         'the manual channel is for a real terminal without an agent runtime.')
    if not (sys.stdin.isatty() and sys.stdout.isatty()):
        raise SystemExit('MANUAL_TTY_REFUSED_NO_TTY: stdin/stdout is not a TTY - '
                         'the manual channel must be run in a real terminal window.')
    return 'manual_tty:%s:%d:%s' % ((os.environ.get('COMPUTERNAME') or 'host'), os.getpid(),
                                    datetime.datetime.now().isoformat(timespec='seconds'))


def _prompt_approval_token():
    """Read a one-time approval code from the TTY (no echo).

    The code must never arrive as a command-line argument or an env var: the command line
    is written to the agent log, which would leak approval power to the approved party.
    A non-interactive terminal is fail-closed: better to write nothing than approve blindly.
    """
    if not (sys.stdin.isatty() and sys.stdout.isatty()):
        raise SystemExit(
            'APPROVAL_NO_TTY: this operation needs a one-time code, and stdin/stdout is not a TTY.\n'
            'Run the command in a real terminal window; the code is never passed as an argument.')
    t = getpass.getpass('one-time approval code (no echo): ')
    if not t.strip():
        raise SystemExit('APPROVAL_EMPTY: no code entered; aborted, nothing was written.')
    return t


def main():
    ap = argparse.ArgumentParser(prog='continuity_core')
    sub = ap.add_subparsers(dest='cmd')
    sub.add_parser('bootstrap')
    r = sub.add_parser('register'); r.add_argument('writer_id'); r.add_argument('surface'); r.add_argument('role'); r.add_argument('tier')
    s = sub.add_parser('submit'); s.add_argument('writer_id'); s.add_argument('doc'); s.add_argument('patch')
    s.add_argument('--base', type=int, default=None); s.add_argument('--evidence', default=''); s.add_argument('--caused', default='')
    s.add_argument('--type', default='PATCH'); s.add_argument('--surface', default=None); s.add_argument('--session', default=None)
    s.add_argument('--force', action='store_true')
    s.add_argument('--force-reason', dest='force_reason', default='',
                   help='force requires a reason (ledger row + review ticket). Automation may not call it.')
    # --approval-token was removed: a code passed in argv ends up in the agent log in clear
    # text (the log records command lines verbatim), which made the gate decorative.
    # The old form is rejected as an unknown argument; the code is prompted for instead.
    # Manual channel (no agent env + real TTY); a one-time code is required every time.
    s.add_argument('--manual-tty', dest='manual_tty', action='store_true',
                   help='manual-terminal channel: no agent env + real TTY + a one-time code per call.')
    g = sub.add_parser('get'); g.add_argument('doc')
    d = sub.add_parser('delta'); d.add_argument('surface')
    a = sub.add_parser('advance'); a.add_argument('surface'); a.add_argument('--to', type=int, default=None)
    sub.add_parser('materialize')
    sub.add_parser('verify')
    sub.add_parser('lock')
    sub.add_parser('audit')
    args = ap.parse_args()
    if args.cmd == 'bootstrap':
        print(json.dumps(bootstrap(), ensure_ascii=False))
    elif args.cmd == 'register':
        print(json.dumps(register_writer(args.writer_id, args.surface, args.role, args.tier), ensure_ascii=False))
    elif args.cmd == 'submit':
        try: patch = json.loads(args.patch)
        except: patch = {'op': 'append', 'content': args.patch}
        _mt = _manual_tty_attestation() if getattr(args, 'manual_tty', False) else None
        print(json.dumps(submit_event(args.writer_id, args.doc, patch, base_revision=args.base,
                                      event_type=args.type, evidence=args.evidence, caused_by=args.caused,
                                      surface_id=args.surface, session_id=args.session, force=args.force,
                                      force_reason=getattr(args, 'force_reason', ''),
                                      manual_tty=_mt, approval_prompt=_prompt_approval_token),
                         ensure_ascii=False))
    elif args.cmd == 'get':
        print(json.dumps(get_canonical(args.doc), ensure_ascii=False))
    elif args.cmd == 'delta':
        print(json.dumps(get_surface_delta(args.surface), ensure_ascii=False, indent=1))
    elif args.cmd == 'advance':
        print(json.dumps(advance_cursor(args.surface, args.to), ensure_ascii=False))
    elif args.cmd == 'materialize':
        print(json.dumps(materialize(), ensure_ascii=False))
    elif args.cmd == 'verify':
        print(json.dumps(verify_chain(), ensure_ascii=False))
    elif args.cmd == 'lock':
        print(json.dumps(lock_all(), ensure_ascii=False))
    elif args.cmd == 'audit':
        print(json.dumps(audit(), ensure_ascii=False, indent=1))
    else:
        ap.print_help()

if __name__ == '__main__':
    main()
