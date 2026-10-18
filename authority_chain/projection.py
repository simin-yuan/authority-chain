"""Rendering, path mapping, atomic verified writes and the drift check."""
import json
import os
import re
import sys
from pathlib import Path

from .config import RESEARCH_ROOT, DOC_TO_PATH
from .schema import DB_PATH, get_conn, init_schema, now_iso


PROJECTION_DIR = RESEARCH_ROOT / 'continuity' / 'projections'


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


def lock_all():
    """Apply the OS read-only lock to every source document."""
    locked = []
    for doc_key, path in DOC_TO_PATH.items():
        p = Path(path)
        if p.exists():
            _lock(p)
            locked.append(doc_key)
    return {'locked': locked}
