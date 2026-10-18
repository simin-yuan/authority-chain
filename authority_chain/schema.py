"""Connection, schema creation and migrations."""
import datetime
import sqlite3

from .config import RESEARCH_ROOT


DB_PATH = RESEARCH_ROOT / 'continuity' / 'continuity.db'


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
