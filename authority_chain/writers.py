"""Writer registry, runtime session identity, approval tokens and the policy module."""
import datetime
import getpass
import hashlib
import json
import os
import re
import sqlite3
import sys
from pathlib import Path

from .config import (RESEARCH_ROOT, AGENT_ENV_VARS, SIGNER_DB,
                     load_policy_module, load_post_write_hook)
from .schema import get_conn, init_schema, now_iso


try:
    policy_rules = load_policy_module()   # optional: a missing module degrades to observe-only
except Exception:  # noqa: BLE001  never crash at import because a policy module is absent
    policy_rules = None

try:
    post_write_hook = load_post_write_hook()   # optional; None means "do nothing after a write"
except Exception:  # noqa: BLE001
    post_write_hook = None


# Concurrent-write rejection log (events.sequence UNIQUE collision).
# Same JSONL shape as length_gate.log; used to prove "one accepted, one rejected, both logged".
SUBMIT_REJECT_LOG = RESEARCH_ROOT / 'authority-chain' / 'submit_reject.log'


# -- Gate switch: the switch is a state file, not an environment variable. --------------
# An env var only affects the process that set it, and independent writers each start
# their own process - an env-only switch would silently be a no-op.
# File first (the only cross-process form); env only for local debugging.
GATE_STATE_DIR = Path(os.environ.get('CHAIN_GATE_DIR') or (RESEARCH_ROOT / 'authority-chain'))
try:
    if not GATE_STATE_DIR.exists():
        GATE_STATE_DIR = RESEARCH_ROOT / 'authority-chain'
except Exception:
    GATE_STATE_DIR = RESEARCH_ROOT / 'authority-chain'
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


def _log_submit_reject(rec):
    """Rejection log (append-only JSONL). A logging failure must not break the caller."""
    try:
        SUBMIT_REJECT_LOG.parent.mkdir(parents=True, exist_ok=True)
        with SUBMIT_REJECT_LOG.open('a', encoding='utf-8') as fh:
            fh.write(json.dumps(rec, ensure_ascii=False) + '\n')
    except Exception:
        pass


def register_writer(writer_id, surface_id, role, tier, status='active'):
    conn = get_conn(); init_schema(conn)
    conn.execute('INSERT OR REPLACE INTO writer_registry VALUES (?,?,?,?,?,?,?)',
                 (writer_id, surface_id, role, tier, status, now_iso(), now_iso()))
    conn.commit(); conn.close()
    return {'ok': True, 'writer': writer_id, 'surface': surface_id, 'role': role, 'tier': tier}


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
