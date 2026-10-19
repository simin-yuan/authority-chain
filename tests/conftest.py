"""One throwaway environment for the whole suite, set up before the package is imported.

Paths are resolved when the package is imported, so this has to be a plugin module and not
a block at the top of a test file: whichever test file imported the package first would
freeze its data root, and the next file would silently reuse it. It also means test order
and ``-k`` selections cannot change where a test writes.
"""
import os
import shutil
import sys
import tempfile
from pathlib import Path

_ROOT = Path(tempfile.mkdtemp(prefix='authority-chain-test-'))
os.environ['CHAIN_DATA_ROOT'] = str(_ROOT / 'data')
os.environ['CHAIN_HOME'] = str(_ROOT / 'docs')
os.environ.pop('CHAIN_CONFIG', None)
# The runtime, not the caller, owns identity: the writer must run under a session id
# that the environment supplies. A missing one is a hard refusal.
for _v in ('AGENT_CRON_SESSION', 'AGENT_PARENT_START_MARKER'):
    os.environ.pop(_v, None)
os.environ['AGENT_SESSION_ID'] = 'test-session'

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import pytest                                     # noqa: E402
import chaincore as cc                            # noqa: E402  (must follow the setup above)


def clean():
    """Empty the ledger between tests: the database, its log, and every projection.

    Removing only the database file is not enough. A surviving -wal is replayed into the
    next connection, so the next test opens a ledger it never wrote and sees revisions from
    the previous one.
    """
    for suffix in ('', '-wal', '-shm'):
        try:
            Path(str(cc.DB_PATH) + suffix).unlink()
        except OSError:               # a handle may still be closing on Windows
            pass
    if cc.DB_PATH.exists():
        # The unlink lost that race, so empty the tables instead of trusting the delete.
        try:
            conn = cc.get_conn()
            for (table,) in conn.execute("SELECT name FROM sqlite_master WHERE type='table'"):
                conn.execute('DELETE FROM "%s"' % table)
            conn.commit()
            conn.close()
        except Exception:
            pass
    if cc.PROJECTION_DIR.exists():
        shutil.rmtree(cc.PROJECTION_DIR, ignore_errors=True)


@pytest.fixture(autouse=True)
def fresh_root():
    clean()
    yield
    clean()
