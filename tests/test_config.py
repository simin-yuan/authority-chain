"""Where the data directory comes from.

Two layers are tested: the pure functions with an injected environment and platform
(so the Windows and the XDG branches are both exercised on any host), and the module's
actual resolution order, which happens at import time and therefore has to be checked in
a subprocess with a controlled environment.
"""
import os
import subprocess
import sys
from pathlib import Path

import pytest

from authority_chain import config as cfg

_REPO = Path(__file__).resolve().parents[1]


# -- the per-user directory, both platforms, no real platform switch ------------------

def test_windows_uses_localappdata():
    got = cfg.user_data_dir({'LOCALAPPDATA': r'C:\Users\someone\AppData\Local'}, 'win32')
    assert got == Path(r'C:\Users\someone\AppData\Local') / 'authority-chain'


def test_windows_without_localappdata_falls_back_to_the_home_directory():
    home = Path.home()
    got = cfg.user_data_dir({}, 'win32')
    assert got == home / 'AppData' / 'Local' / 'authority-chain'


def test_xdg_data_home_is_honoured():
    got = cfg.user_data_dir({'XDG_DATA_HOME': '/tmp/xdg'}, 'linux')
    assert got == Path('/tmp/xdg') / 'authority-chain'


@pytest.mark.parametrize('platform', ['linux', 'darwin'])
def test_without_xdg_the_local_share_directory_is_used(platform):
    got = cfg.user_data_dir({}, platform)
    assert got == Path.home() / '.local' / 'share' / 'authority-chain'


# -- checkout vs installed -----------------------------------------------------------

def test_a_checkout_keeps_the_ledger_in_the_tree(tmp_path):
    (tmp_path / 'pyproject.toml').write_text('[project]\nname = "x"\n', encoding='utf-8')
    got = cfg.default_data_root(base_dir=tmp_path, environ={}, platform='linux')
    assert got == tmp_path / 'data'


def test_an_installed_copy_uses_the_user_directory(tmp_path):
    got = cfg.default_data_root(base_dir=tmp_path, environ={'XDG_DATA_HOME': '/tmp/xdg'},
                                platform='linux')
    assert got == Path('/tmp/xdg') / 'authority-chain'
    # the important part: it is not inside the directory the package was imported from
    assert tmp_path not in got.parents


# -- the real resolution order (module import time, so: subprocess) -------------------

_PRINT_DATA_ROOT = 'import authority_chain.config as c; print(c.DATA_ROOT)'


def _resolve(extra_env, tmp_path):
    env = {k: v for k, v in os.environ.items() if not k.startswith('CHAIN_')}
    env.pop('PYTHONPATH', None)
    env.update(extra_env)
    out = subprocess.run([sys.executable, '-c', _PRINT_DATA_ROOT], env=env, cwd=str(tmp_path),
                         capture_output=True, text=True)
    assert out.returncode == 0, out.stderr
    return Path(out.stdout.strip())


def _config(tmp_path, data_root):
    path = tmp_path / 'chaincore.json'
    path.write_text('{"data_root": "%s"}' % data_root.replace('\\', '\\\\'), encoding='utf-8')
    return path


def test_the_checkout_default_is_the_data_directory_of_the_checkout(tmp_path):
    assert _resolve({}, tmp_path) == (_REPO / 'data').resolve()


def test_chain_data_root_overrides_the_checkout_default(tmp_path):
    target = tmp_path / 'somewhere'
    assert _resolve({'CHAIN_DATA_ROOT': str(target)}, tmp_path) == target.resolve()


def test_chain_config_data_root_overrides_the_environment(tmp_path):
    """CHAIN_CONFIG is the deployment's own file, so it outranks a process variable."""
    target = tmp_path / 'from-file'
    env_target = tmp_path / 'from-env'
    conf = _config(tmp_path, str(target))
    got = _resolve({'CHAIN_CONFIG': str(conf), 'CHAIN_DATA_ROOT': str(env_target)}, tmp_path)
    assert got == target.resolve()


def test_chain_config_data_root_works_on_its_own(tmp_path):
    target = tmp_path / 'only-file'
    got = _resolve({'CHAIN_CONFIG': str(_config(tmp_path, str(target)))}, tmp_path)
    assert got == target.resolve()
