"""Tests for chaincore. Run with: python -m pytest -q

Isolation: every test gets its own data root, so nothing here can read or write a real
deployment's state. The environment is set before chaincore is imported because the
module resolves its paths at import time.
"""
import json
import os
import shutil
import sys
import tempfile
from pathlib import Path

_ROOT = Path(tempfile.mkdtemp(prefix='chaincore-test-'))
os.environ['CHAIN_DATA_ROOT'] = str(_ROOT / 'data')
os.environ['CHAIN_HOME'] = str(_ROOT / 'docs')
os.environ.pop('CHAIN_CONFIG', None)
# The runtime, not the caller, owns identity: the writer must run under a session id
# that the environment supplies. A missing one is a hard refusal (see MISSING_RUNTIME_SESSION_ID).
for _v in ('AGENT_CRON_SESSION', 'AGENT_PARENT_START_MARKER'):
    os.environ.pop(_v, None)
os.environ['AGENT_SESSION_ID'] = 'test-session'

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import chaincore as cc          # noqa: E402  (must follow the environment setup)
import pytest                   # noqa: E402


@pytest.fixture(autouse=True)
def fresh_root():
    _clean()
    yield
    _clean()


def _clean():
    if cc.DB_PATH.exists():
        try:
            cc.DB_PATH.unlink()
        except PermissionError:        # a handle may still be closing on Windows
            pass
    if cc.PROJECTION_DIR.exists():
        shutil.rmtree(cc.PROJECTION_DIR, ignore_errors=True)


def _writer():
    cc.register_writer('w_test', 'surface-test', 'writer', '1')


def test_write_without_ticket_is_refused():
    _writer()
    r = cc.submit_event('w_test', 'doc_a', {'v': 1}, event_type='INIT')
    assert r['error'] == 'MISSING_TICKET'


def test_accepted_write_advances_revision_and_verifies():
    _writer()
    r1 = cc.submit_event('w_test', 'doc_a', {'v': 1}, base_revision=0, event_type='INIT')
    assert r1.get('ok'), r1
    r2 = cc.submit_event('w_test', 'doc_a', {'v': 2}, base_revision=1)
    assert r2.get('ok'), r2
    v = cc.verify_chain()
    assert v['chain_intact'] is True
    assert v['chain_empty'] is False
    assert v['latest_sequence'] == 2


def test_stale_write_is_refused_and_queued():
    _writer()
    cc.submit_event('w_test', 'doc_a', {'v': 1}, base_revision=0, event_type='INIT')
    r = cc.submit_event('w_test', 'doc_a', {'v': 2}, base_revision=0)
    assert r['error'] == 'REJECT_STALE_WRITE'
    conn = cc.get_conn()
    rows = conn.execute('SELECT doc_key, status FROM conflict_queue').fetchall()
    conn.close()
    assert rows and rows[0][0] == 'doc_a' and rows[0][1] == 'pending'
    # The refused write did not move the state.
    conn = cc.get_conn()
    assert cc.get_current_revision(conn, 'doc_a') == 1
    conn.close()


def test_edited_content_is_detected_by_the_chain():
    """Rows are not write-protected at the storage level; the hash chain is the guard.

    This is deliberate: one field (status) is legitimately updated when a write is
    countersigned. Content instead becomes unforgeable, because `hash` covers every
    field that carries meaning and `verify` recomputes it.
    """
    _writer()
    cc.submit_event('w_test', 'doc_a', {'v': 1}, base_revision=0, event_type='INIT')
    cc.submit_event('w_test', 'doc_a', {'v': 2}, base_revision=1)
    conn = cc.get_conn()
    try:
        conn.execute("UPDATE events SET patch_json='{\"v\": 999}' WHERE sequence=2")
        conn.commit()
    finally:
        conn.close()
    v = cc.verify_chain()
    assert [b['reason'] for b in v['broken_unregistered']] == ['HASH_MISMATCH'], v
    assert v['chain_status'] != 'INTACT'


def test_genesis_event_content_is_not_recomputable():
    """Known limitation, asserted so it cannot regress silently.

    The first event carries no previous hash, so its own hash cannot be recomputed from
    the chain; `verify` classifies it as `genesis_unverifiable` instead of claiming it
    verified. Editing that single row's content is therefore undetectable by this check
    alone - the count makes the gap visible rather than hidden.
    """
    _writer()
    cc.submit_event('w_test', 'doc_a', {'v': 1}, base_revision=0, event_type='INIT')
    conn = cc.get_conn()
    try:
        conn.execute("UPDATE events SET patch_json='{\"v\": 999}' WHERE sequence=1")
        conn.commit()
    finally:
        conn.close()
    v = cc.verify_chain()
    assert v['broken_unregistered'] == []
    assert v['chain_status'] == 'INTACT'
    assert v.get('genesis_unverifiable', 0) + v.get('legacy_unverifiable', 0) >= 1, v



def test_broken_link_is_reported_not_hidden():
    _writer()
    cc.submit_event('w_test', 'doc_a', {'v': 1}, base_revision=0, event_type='INIT')
    conn = cc.get_conn()
    # Insert a row that bypasses the writer, with a previous hash that does not match.
    try:
        conn.execute(
            "INSERT INTO events (sequence, event_id, event_type, doc_key, status, hash, prev_hash, "
            "writer_id, surface_id, patch_json, ts) VALUES (?,?,?,?,?,?,?,?,?,?,?)",
            (2, 'ev_forged', 'PATCH', 'doc_a', 'accepted', 'deadbeef', 'not-the-previous-hash',
             'w_test', 'surface-test', '{"v": 9}', cc.now_iso()))
        conn.commit()
    finally:
        conn.close()
    v = cc.verify_chain()
    assert v['broken_unregistered'], v
    assert v['chain_status'] != 'INTACT'


def test_same_input_produces_the_same_hash():
    """Determinism: identical inputs -> identical hash, on every run and every build."""
    args = ('w_test', 'doc_a', '2026-01-01T00:00:00+00:00', 7, json.dumps({'v': 1}), 'abc')
    assert cc.hash_event(*args) == cc.hash_event(*args)
    # And the stored hash equals the recomputed one for the same fields.
    _writer()
    r = cc.submit_event('w_test', 'doc_a', {'v': 1}, base_revision=0, event_type='INIT')
    assert r.get('ok'), r
    conn = cc.get_conn()
    seq, ts, pj, h, prev = conn.execute(
        'SELECT sequence, ts, patch_json, hash, prev_hash FROM events WHERE sequence=1'
    ).fetchone()
    conn.close()
    assert cc.hash_event('w_test', 'doc_a', ts, seq, pj, prev or '') == h
