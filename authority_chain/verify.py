"""Chain verification, the accounting assertion, the tainted registry, signature state
and effectiveness."""
import datetime
import hashlib
import json
import os
import re
import sqlite3

from .config import RESEARCH_ROOT
from .schema import DB_PATH, get_conn, init_schema, now_iso
from .hashing import hash_event


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
