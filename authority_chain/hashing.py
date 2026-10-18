"""Event hashing and sequence assignment."""
import hashlib


def hash_event(writer_id, doc_key, ts, seq, patch_json, prev_hash=''):
    return hashlib.sha256(f'{prev_hash}|{writer_id}|{doc_key}|{ts}|{seq}|{patch_json}'.encode()).hexdigest()[:16]


def next_sequence(conn):
    row = conn.execute('SELECT COALESCE(MAX(sequence),0) FROM events').fetchone()
    return row[0] + 1


def chain_head(conn):
    """Current chain head hash (None on an empty chain). Writers read it and hand it back."""
    row = conn.execute('SELECT hash FROM events ORDER BY sequence DESC LIMIT 1').fetchone()
    return row[0] if row else None
