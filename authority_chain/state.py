"""Reads of current state: revisions, canonical values, surface cursors, the audit view."""
import json

from .schema import get_conn, init_schema, now_iso


def get_current_revision(conn, doc_key):
    row = conn.execute('SELECT revision FROM canonical_state WHERE doc_key=?', (doc_key,)).fetchone()
    return row[0] if row else 0


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
