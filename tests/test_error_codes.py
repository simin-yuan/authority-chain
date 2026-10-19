"""Every refusal code in docs/errors.md, triggered through the public API.

One test per code (a few codes share a test where the trigger is the same write). Nothing
here starts a thread, a process or a real terminal: the manual-terminal channel is driven
with a stream that reports itself as a TTY, and the two failure paths that the renderer
cannot produce on its own say so at the point where they stub it.

tests/test_error_coverage.py parses the document and fails if a documented code is neither
exercised here nor listed as unreachable with a reason.
"""
import hashlib
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

import chaincore as cc
import authority_chain.projection as projection_mod
import authority_chain.submit as submit_mod
import authority_chain.verify as verify_mod
import authority_chain.writers as writers_mod

DOC = 'doc_a'


# -- helpers -------------------------------------------------------------------------

def _writer(writer_id='w_test', tier='1'):
    cc.register_writer(writer_id, 'surface-test', 'writer', tier)
    return writer_id


def _init(doc_key=DOC, content='# A\n\n## One\nx\n'):
    _writer()
    r = cc.submit_event('w_test', doc_key, {'op': 'full', 'content': content},
                        base_revision=0, event_type='INIT')
    assert r.get('ok'), r
    return r


def _event(event_id='ev000001'):
    conn = cc.get_conn()
    try:
        return conn.execute('SELECT event_id, hash, patch_json, status FROM events WHERE event_id=?',
                            (event_id,)).fetchone()
    finally:
        conn.close()


def _sha(event_id='ev000001'):
    return hashlib.sha256(_event(event_id)[2].encode('utf-8')).hexdigest()


def _count_events():
    conn = cc.get_conn()
    try:
        return conn.execute('SELECT COUNT(*) FROM events').fetchone()[0]
    finally:
        conn.close()


def _register_token(token, consumed=False):
    conn = cc.get_conn()
    try:
        conn.execute('INSERT INTO approval_tokens (token_sha256, created_at, created_by, label, '
                     'consumed_at) VALUES (?,?,?,?,?)',
                     (hashlib.sha256(token.encode('utf-8')).hexdigest(), cc.now_iso(), 'test',
                      'test', cc.now_iso() if consumed else None))
        conn.commit()
    finally:
        conn.close()


def _submit_error(**kwargs):
    kw = {'writer_id': 'w_test', 'doc_key': DOC, 'patch': {'op': 'append', 'content': 'y'},
          'base_revision': 1}
    kw.update(kwargs)
    r = cc.submit_event(**kw)
    assert r.get('ok') is not True, r
    return r


class _TTY:
    """A stream that reports itself as a terminal, with no terminal behind it."""

    def __init__(self, inner=None):
        self._inner = inner

    def isatty(self):
        return True

    def __getattr__(self, name):
        return getattr(self._inner, name)


class _NotTTY(_TTY):
    def isatty(self):
        return False


def _manual_env(monkeypatch):
    """The manual channel requires a runtime without any agent identity variables."""
    for name in cc.AGENT_ENV_VARS:
        monkeypatch.delenv(name, raising=False)


def _manual(monkeypatch, token=None, tty=True):
    stream = _TTY() if tty else _NotTTY()
    monkeypatch.setattr(submit_mod, 'sys', SimpleNamespace(stdin=stream, stdout=stream))
    return cc.submit_event('w_test', DOC, {'op': 'append', 'content': 'y'}, base_revision=0,
                           manual_tty='manual_tty:test:1:2026-01-01T00:00:00', approval_token=token)


# -- tier 0: the writer gate ---------------------------------------------------------

def test_force_without_a_reason_is_refused():
    _init()
    r = cc.submit_event('w_test', DOC, {'op': 'append', 'content': 'y'}, base_revision=1,
                        force=True)
    assert r['error'] == 'FORCE_REQUIRES_REASON', r


def test_a_taken_sequence_is_refused_instead_of_raising(monkeypatch):
    """Two writers that computed the same sequence: SQLite refuses the second insert."""
    _init()
    monkeypatch.setattr(submit_mod, 'next_sequence', lambda conn: 1)   # a slot already taken
    before = _count_events()
    r = cc.submit_event('w_test', DOC, {'op': 'append', 'content': 'y'}, base_revision=1)
    assert r['error'] == 'CONFLICT_SEQUENCE', r
    assert _count_events() == before


def test_a_write_against_a_moved_chain_head_is_refused():
    _init()
    r = cc.submit_event('w_test', DOC, {'op': 'append', 'content': 'y'}, base_revision=1,
                        expected_prev_hash='0000000000000000')
    assert r['error'] == 'CONFLICT_CHAIN_HEAD', r


def test_a_verdict_without_a_chain_head_is_refused():
    _init()
    # A patch that quotes a decision is a verdict, and a verdict must name the head it read.
    r = cc.submit_event('w_test', DOC,
                        {'op': 'append', 'content': 'y', 'decision_quote': 'ship it'},
                        base_revision=1)
    assert r['error'] == 'VERDICT_NEEDS_EXPECTED_PREV_HASH', r


# -- approval codes on a single-hash document ----------------------------------------

@pytest.fixture
def single_hash_doc(monkeypatch):
    """A document configured with single-hash headings, where the guarded ops are refused."""
    monkeypatch.setattr(submit_mod, 'SINGLE_HASH_DOCS', {'doc_sh'})
    _init('doc_sh', content='# Only\n\ntext here\n')
    return 'doc_sh'


def test_whole_file_overwrite_of_a_single_hash_document_is_forbidden(single_hash_doc):
    r = cc.submit_event('w_test', single_hash_doc, {'op': 'full', 'content': '# Other\n'},
                        base_revision=1)
    assert r['error'].startswith('FORBIDDEN_OP'), r


def test_replace_text_needs_a_code_and_says_so(single_hash_doc):
    r = cc.submit_event('w_test', single_hash_doc,
                        {'op': 'replace_text', 'find': 'text', 'replace': 'TEXT'},
                        base_revision=1)
    assert r['error'].startswith('FORBIDDEN_OP'), r


def test_a_code_that_was_never_issued_is_unknown(single_hash_doc):
    r = cc.submit_event('w_test', single_hash_doc,
                        {'op': 'replace_section', 'marker': '# Only', 'content': 'new\n'},
                        base_revision=1, approval_token='never-issued')
    assert r['error'].startswith('APPROVAL_TOKEN_UNKNOWN'), r


def test_a_code_that_was_already_used_is_refused(single_hash_doc):
    _register_token('spent', consumed=True)
    r = cc.submit_event('w_test', single_hash_doc,
                        {'op': 'replace_section', 'marker': '# Only', 'content': 'new\n'},
                        base_revision=1, approval_token='spent')
    assert r['error'].startswith('APPROVAL_TOKEN_USED'), r


def test_replace_text_without_a_find_text_is_refused(single_hash_doc):
    _register_token('fresh-1')
    r = cc.submit_event('w_test', single_hash_doc,
                        {'op': 'replace_text', 'find': '', 'replace': 'x'},
                        base_revision=1, approval_token='fresh-1')
    assert r['error'].startswith('REPLACE_TEXT_MISSING_FIND'), r


def test_replace_text_that_does_not_match_exactly_once_is_refused(single_hash_doc):
    _register_token('fresh-2')
    r = cc.submit_event('w_test', single_hash_doc,
                        {'op': 'replace_text', 'find': 'no such text', 'replace': 'x'},
                        base_revision=1, approval_token='fresh-2')
    assert r['error'].startswith('REPLACE_TEXT_BAD_MATCH'), r


def test_a_code_consumed_between_check_and_write_leaves_nothing_behind(single_hash_doc,
                                                                      monkeypatch):
    """The rowcount of the burn is the last line of defence: 0 means another writer won."""
    _register_token('racing')
    monkeypatch.setattr(submit_mod, '_consume_approval_token', lambda *a, **k: 0)
    before = _count_events()
    r = cc.submit_event('w_test', single_hash_doc,
                        {'op': 'replace_text', 'find': 'text', 'replace': 'TEXT'},
                        base_revision=1, approval_token='racing')
    assert r['error'].startswith('APPROVAL_TOKEN_RACE'), r
    assert _count_events() == before


# -- the manual-terminal channel -----------------------------------------------------

def test_the_manual_channel_is_refused_while_an_agent_environment_is_present(monkeypatch):
    _init()
    r = _manual(monkeypatch, token='whatever')      # the suite sets AGENT_SESSION_ID
    assert r['error'] == 'MANUAL_TTY_REFUSED_AGENT_ENV', r


def test_the_manual_channel_is_refused_without_a_terminal(monkeypatch):
    _init()
    _manual_env(monkeypatch)
    r = _manual(monkeypatch, token='whatever', tty=False)
    assert r['error'] == 'MANUAL_TTY_REFUSED_NO_TTY', r


def test_the_manual_channel_always_asks_for_a_code(monkeypatch):
    _init()
    _manual_env(monkeypatch)
    r = _manual(monkeypatch, token=None)
    assert r['error'] == 'MANUAL_TTY_NEEDS_TOKEN', r


def test_the_manual_channel_refuses_an_unknown_code(monkeypatch):
    _init()
    _manual_env(monkeypatch)
    r = _manual(monkeypatch, token='never-issued')
    assert r['error'] == 'MANUAL_TTY_APPROVAL_TOKEN_UNKNOWN', r


def test_the_manual_channel_refuses_a_used_code(monkeypatch):
    _init()
    _manual_env(monkeypatch)
    _register_token('spent', consumed=True)
    r = _manual(monkeypatch, token='spent')
    assert r['error'] == 'MANUAL_TTY_APPROVAL_TOKEN_USED', r


# -- countersignature ----------------------------------------------------------------

def test_countersigning_without_a_target_is_refused():
    _writer('w_t0', tier='tier0')
    r = cc.submit_event('w_t0', 'POLICY', {'op': 'countersign'}, event_type='COUNTERSIGN')
    assert r['error'].startswith('COUNTERSIGN_MISSING_TARGET'), r


def test_countersigning_an_unknown_event_is_refused():
    _writer('w_t0', tier='tier0')
    r = cc.submit_event('w_t0', 'POLICY', {'op': 'countersign', 'target': 'ev000099'},
                        event_type='COUNTERSIGN')
    assert r['error'].startswith('COUNTERSIGN_TARGET_NOT_FOUND'), r


def test_countersigning_a_row_whose_document_is_no_longer_protected_is_refused():
    """A row can outlive the protection it was written under: the tier list changed after
    the amendment was queued. The countersign must refuse, not silently apply it."""
    _init()
    conn = cc.get_conn()
    try:
        conn.execute("UPDATE events SET status='pending_countersign' WHERE event_id='ev000001'")
        conn.commit()
    finally:
        conn.close()
    r = cc.submit_event('w_test', DOC, {'op': 'countersign', 'target': 'ev000001'},
                        base_revision=1, event_type='COUNTERSIGN')
    assert r['error'].startswith('COUNTERSIGN_TARGET_NOT_NEVER_DOC'), r


# -- signatures ----------------------------------------------------------------------

def test_a_signature_without_targets_is_refused():
    _init()
    r = cc.submit_event('w_test', 'sig_doc', {'signer_message_id': 'm1'},
                        event_type='SIGNATURE')
    assert r['error'] == 'SIGNATURE_MISSING_TARGETS', r


def test_a_signature_target_without_a_sha_is_malformed():
    _init()
    r = cc.submit_event('w_test', 'sig_doc',
                        {'signer_message_id': 'm1', 'signs': [{'event_id': 'ev000001'}]},
                        event_type='SIGNATURE')
    assert r['error'] == 'SIGNATURE_MALFORMED', r


def test_a_signature_naming_an_unknown_event_is_refused():
    _init()
    r = cc.submit_event('w_test', 'sig_doc',
                        {'signer_message_id': 'm1',
                         'signs': [{'event_id': 'ev000099', 'sha256': '0' * 64}]},
                        event_type='SIGNATURE')
    assert r['error'] == 'SIGNATURE_TARGET_NOT_FOUND', r


def test_a_signature_with_the_wrong_sha_is_refused():
    _init()
    r = cc.submit_event('w_test', 'sig_doc',
                        {'signer_message_id': 'm1',
                         'signs': [{'event_id': 'ev000001', 'sha256': '0' * 64}]},
                        event_type='SIGNATURE')
    assert r['error'] == 'SIGNATURE_SHA_MISMATCH', r


def test_a_signature_is_refused_when_it_cannot_be_traced_to_a_message():
    _init()
    r = cc.submit_event('w_test', 'sig_doc',
                        {'signer_message_id': 'm1',
                         'signs': [{'event_id': 'ev000001', 'sha256': _sha()}]},
                        event_type='SIGNATURE')
    assert r['error'].startswith('SIGNATURE_NOT_TRACEABLE'), r


# -- references ----------------------------------------------------------------------

def test_supersedes_that_is_not_a_list_is_malformed():
    _init()
    r = _submit_error(patch={'op': 'append', 'content': 'y', 'supersedes': 'ev000001'})
    assert r['error'] == 'SUPERSEDES_MALFORMED', r


def test_amends_that_is_not_a_list_is_malformed():
    _init()
    r = _submit_error(patch={'op': 'append', 'content': 'y', 'amends': 'ev000001'})
    assert r['error'] == 'AMENDS_MALFORMED', r


def test_a_reference_to_an_event_that_does_not_exist_is_refused():
    _init()
    r = _submit_error(patch={'op': 'append', 'content': 'y',
                             'supersedes': [{'event_id': 'ev000099', 'hash': 'aaaaaaaaaaaaaaaa'}]})
    assert r['error'] == 'UNKNOWN_REFERENCE', r


def test_a_reference_to_a_version_not_on_the_chain_is_stale():
    _init()
    r = _submit_error(patch={'op': 'append', 'content': 'y',
                             'supersedes': [{'event_id': 'ev000001', 'hash': '0' * 16}]})
    assert r['error'] == 'STALE_REFERENCE', r


def _superseding_observation(target_id, target_hash, doc_key=DOC):
    """An observation that supersedes one event, and is itself eligible to do so.

    Eligibility (is_qualified) comes from the event naming the target together with a
    64-character sha256: that is the signature-declaration shape, and it is also the prose
    form the legacy branch parses, so the same row works before and after the line.
    """
    content = 'This record supersedes %s (%s)' % (target_id, 'a' * 64)
    return cc.submit_event('w_test', doc_key,
                           {'op': 'observation', 'content': content,
                            'supersedes': [{'event_id': target_id, 'hash': target_hash}]},
                           event_type='OBSERVATION')


def test_an_event_cannot_be_superseded_twice():
    _init()
    target_id, target_hash = _event()[:2]
    first = _superseding_observation(target_id, target_hash)
    assert first.get('ok'), first
    r = _superseding_observation(target_id, target_hash)
    assert r['error'] == 'ALREADY_SUPERSEDED', r


# -- the policy gate -----------------------------------------------------------------

class _Policy:
    """A minimal policy module: one keyword tripwire, one message store, one quote check."""

    answer = True
    content = 'I approve this, here is the text'

    def is_decision_claim(self, body):
        hit = 'we decided' in body
        return hit, 'we decided'

    def user_message(self, smi, state_db=''):
        if self.answer:
            return True, {'content': self.content, 'session_id': 'test-session', 'role': 'user'}
        return False, 'message not found'

    def validate_quote(self, quote, content, doc_key):
        return quote in content, 'quote does not occur in the message'

    def evidence_payload(self, smi, verdict, ok):
        return None


@pytest.fixture
def policy(monkeypatch):
    """The gate only blocks when it is switched on; advisory mode lets everything through."""
    monkeypatch.setenv('CHAIN_GATE_ENFORCE', '1')
    rules = _Policy()
    monkeypatch.setattr(submit_mod, 'policy_rules', rules)
    _init()
    return rules


def test_a_writer_may_not_countersign_its_own_write(policy):
    r = _submit_error(patch={'op': 'append', 'content': 'y', 'countersigned_by': 'w_test'})
    assert r['error'] == 'COUNTERSIGN_BY_WRITER_REJECTED', r


def test_a_decision_worded_claim_needs_evidence(policy):
    r = _submit_error(patch={'op': 'append', 'content': 'we decided to ship v2'})
    assert r['error'] == 'DECIDE_CLAIM_WITHOUT_EVIDENCE', r


def test_a_quoted_decision_needs_the_message_it_came_from(policy):
    r = _submit_error(patch={'op': 'append', 'content': 'y', 'decision_quote': 'I approve'},
                      expected_prev_hash=_event()[1])
    assert r['error'] == 'VERDICT_NEEDS_SOURCE_MSG_ID', r


def test_a_quoted_decision_whose_message_cannot_be_found_is_refused(policy):
    policy.answer = False
    r = _submit_error(patch={'op': 'append', 'content': 'y',
                             'decision_quote': 'I approve', 'source_msg_id': 'm1'},
                      expected_prev_hash=_event()[1])
    assert r['error'] == 'VERDICT_SOURCE_UNVERIFIED', r


def test_a_quote_that_is_not_in_the_message_is_refused(policy):
    r = _submit_error(patch={'op': 'append', 'content': 'y',
                             'decision_quote': 'not in the message', 'source_msg_id': 'm1'},
                      expected_prev_hash=_event()[1])
    assert r['error'] == 'VERDICT_QUOTE_INVALID', r


def test_a_cause_that_does_not_exist_is_refused(policy):
    r = _submit_error(patch={'op': 'append', 'content': 'y', 'caused_by': 'ev000099'})
    assert r['error'] == 'CAUSED_BY_NOT_FOUND', r


def test_a_cause_that_is_not_verified_is_refused(policy):
    r = _submit_error(patch={'op': 'append', 'content': 'y', 'caused_by': 'ev000001'})
    assert r['error'] == 'PARENT_NOT_VERIFIED', r


# -- verification and materialize ----------------------------------------------------

def test_a_rewritten_prev_hash_is_named_as_such():
    _init()
    conn = cc.get_conn()
    try:
        conn.execute(
            "INSERT INTO events (sequence, event_id, event_type, doc_key, status, hash, prev_hash, "
            "writer_id, surface_id, patch_json, ts) VALUES (?,?,?,?,?,?,?,?,?,?,?)",
            (2, 'ev000002', 'PATCH', DOC, 'accepted', 'deadbeef', 'ffffffffffffffff',
             'w_test', 'surface-test', '{"v": 9}', cc.now_iso()))
        conn.commit()
    finally:
        conn.close()
    v = cc.verify_chain()
    assert [b['reason'] for b in v['broken_unregistered']] == ['PREV_HASH_MISMATCH'], v


def test_a_projection_that_fails_its_own_check_is_not_written(monkeypatch):
    """The renderer cannot produce a bad header, so the check is made to fail here: what is
    under test is that a failure is reported instead of killing the run."""
    _init()
    monkeypatch.setattr(projection_mod, '_verify_projection', lambda *a, **k: (False, 'bad header'))
    out = cc.materialize()
    assert [f['reason'] for f in out['__failures__']] == ['VERIFY_FAILED'], out


def test_a_projection_that_cannot_be_written_is_reported():
    _init()
    p = cc.projection_path(DOC)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.mkdir()                                   # a directory where the file should go
    out = cc.materialize()
    assert 'PROJECTION_WRITE_FAILED' in [f['reason'] for f in out['__failures__']], out


def test_a_source_document_that_cannot_be_written_is_reported():
    _writer('w_t1', tier='tier1')
    r = cc.submit_event('w_t1', 'AGENTS', {'op': 'full', 'content': 'x\n'},
                        base_revision=0, event_type='INIT')
    assert r.get('ok'), r
    src = Path(cc.DOC_TO_PATH['AGENTS'])
    src.parent.mkdir(parents=True, exist_ok=True)
    if src.exists():
        src.unlink()
    src.mkdir()                                 # a directory where the document should go
    try:
        out = cc.materialize()
        assert 'SOURCE_WRITE_FAILED' in [f['reason'] for f in out['__failures__']], out
    finally:
        src.rmdir()


def test_a_missing_source_document_is_reported():
    _writer('w_t1', tier='tier1')
    r = cc.submit_event('w_t1', 'RULES', {'op': 'full', 'content': 'x\n'},
                        base_revision=0, event_type='INIT')
    assert r.get('ok'), r
    v = cc.verify_projections()
    assert [m['reason'] for m in v['mismatches']] == ['MISSING'], v


def test_a_source_document_that_disagrees_with_canonical_is_reported():
    _writer('w_t1', tier='tier1')
    r = cc.submit_event('w_t1', 'AGENTS', {'op': 'full', 'content': 'x\n'},
                        base_revision=0, event_type='INIT')
    assert r.get('ok'), r
    src = Path(cc.DOC_TO_PATH['AGENTS'])
    src.parent.mkdir(parents=True, exist_ok=True)
    # Path.write_text(newline=) is 3.10+; CI still runs 3.9.
    with open(src, 'w', encoding='utf-8', newline='') as fh:
        fh.write('something else\n')
    try:
        v = cc.verify_projections()
        assert [m['reason'] for m in v['mismatches']] == ['CONTENT_MISMATCH'], v
    finally:
        src.unlink()


# -- effectiveness -------------------------------------------------------------------

def _decision(content='we decided to ship v2'):
    _writer()
    r = cc.submit_event('w_test', 'doc_dec', {'op': 'append', 'content': content},
                        base_revision=0, event_type='DECISION')
    assert r.get('ok'), r
    return r['event_id'], r['hash']


def test_effectiveness_of_an_unknown_event_is_not_found():
    _writer()
    assert cc.is_effective('ev000099')['reason'] == 'NOT_FOUND'


def test_an_unsigned_decision_is_pending():
    event_id, _ = _decision()
    assert cc.is_effective(event_id)['reason'] == 'PENDING_SIGNATURE'


def test_a_superseded_decision_is_not_effective():
    event_id, event_hash = _decision()
    r = _superseding_observation(event_id, event_hash, doc_key='doc_dec')
    assert r.get('ok'), r
    assert cc.is_effective(event_id)['reason'] == 'SUPERSEDED'


def test_a_superseded_decision_before_the_line_is_reported_as_legacy(monkeypatch):
    """The same relation, read with the effective line moved past both events."""
    event_id, event_hash = _decision()
    r = _superseding_observation(event_id, event_hash, doc_key='doc_dec')
    assert r.get('ok'), r
    monkeypatch.setattr(verify_mod, 'EFFECTIVE_LINE_SEQ', 10 ** 6)
    assert cc.is_effective(event_id)['reason'] == 'SUPERSEDED_LEGACY'


# -- post-write hook -----------------------------------------------------------------

def test_a_failing_post_write_hook_does_not_fail_the_write(monkeypatch):
    _init()

    def boom(*args, **kwargs):
        raise RuntimeError('hook exploded')

    monkeypatch.setattr(writers_mod, 'post_write_hook', boom)
    r = cc.submit_event('w_test', DOC, {'op': 'append', 'content': 'y'}, base_revision=1)
    assert r.get('ok'), r
    lines = cc.SUBMIT_REJECT_LOG.read_text(encoding='utf-8').splitlines()
    assert any('POST_WRITE_SKIPPED' in line for line in lines), lines[-3:]
