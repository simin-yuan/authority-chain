"""Host configuration for authority-chain.

Everything machine-specific lives here instead of inside the core modules: the data
directory, the document registry with its tiers, length caps, and the two optional
integration points (a policy module and a post-write hook).

Why a module and a JSON file rather than environment variables alone: a package that
reads its paths from the environment cannot be inspected, cannot be diffed, and cannot
run two configurations in parallel (both runs share one process environment). A JSON
file is a single object that can be copied, reviewed, and shipped as an example.

Resolution order for the data directory
---------------------------------------
1. ``data_root`` in the config file: ``CHAIN_CONFIG`` if set, otherwise
   ``chaincore.json`` next to the package                     - the deployment's answer
2. ``CHAIN_DATA_ROOT``                                        - process-level override
3. a checkout (the directory holding the package also holds ``pyproject.toml``):
   ``<checkout>/data``, which is git-ignored
4. everywhere else (a wheel, ``pip install git+...``): the per-user directory -
   ``%LOCALAPPDATA%\\authority-chain`` on Windows,
   ``$XDG_DATA_HOME/authority-chain`` or ``~/.local/share/authority-chain`` otherwise

Step 4 exists because an installed copy used to write its ledger inside site-packages,
which is deleted on uninstall and replaced on upgrade: the record of who changed what
would disappear with the package that produced it.

Other environment overrides (tests and CI only):
  ``CHAIN_HOME``        root of the document tree

Safety: a missing or unparsable file never raises at import time. A ledger that
refuses to start because one config file is malformed is worse than one that starts
with defaults and says so on stderr.
"""

from __future__ import annotations

import importlib
import json
import os
import sys
from pathlib import Path

# The directory that holds the package: in a checkout, the repository root.
PACKAGE_DIR = Path(__file__).resolve().parent
BASE_DIR = PACKAGE_DIR.parent

APP_DIR_NAME = 'authority-chain'

# Three neutral documents, one per tier. Nothing here is specific to a deployment;
# replace them in chaincore.json with the documents you actually govern.
DEFAULT_DOCUMENTS = {
    'AGENTS': 'AGENTS.md',   # tier 1: operational instructions the agent follows
    'RULES': 'RULES.md',     # tier 1: behavioural rules
    'POLICY': 'POLICY.md',   # tier 0: changes need a countersignature
}
DEFAULT_TIER0 = ['POLICY']
DEFAULT_TIER1 = ['AGENTS', 'RULES']
DEFAULT_TIER2 = []

# Names of the environment variables your runtime uses to identify a session.
# The model never supplies these; the runtime does. See runtime_session_id().
DEFAULT_AGENT_ENV_VARS = (
    'AGENT_SESSION_ID',
    'AGENT_CRON_SESSION',
    'AGENT_PARENT_START_MARKER',
)


def _read_raw():
    """Load the JSON config if one exists. Never raises."""
    explicit = os.environ.get('CHAIN_CONFIG')
    path = Path(explicit) if explicit else (BASE_DIR / 'chaincore.json')
    if not path.exists():
        return {}, path
    try:
        return json.loads(path.read_text(encoding='utf-8')), path
    except Exception as exc:                      # noqa: BLE001
        sys.stderr.write(f'[config] ignoring unreadable {path}: {exc}\n')
        return {}, path


_RAW, CONFIG_FILE = _read_raw()
_CFG = _RAW if isinstance(_RAW, dict) else {}


def _path(value, default):
    return Path(value).expanduser().resolve() if value else default


def is_checkout(base_dir=None):
    """True when the package was imported from a source checkout (editable install).

    The test is the build file next to the package: an editable install points at the
    repository, a wheel points at site-packages, and site-packages has no pyproject.toml.
    """
    return (Path(BASE_DIR if base_dir is None else base_dir) / 'pyproject.toml').is_file()


def user_data_dir(environ=None, platform=None):
    """Per-user data directory, standard library only, no per-platform dependency."""
    env = os.environ if environ is None else environ
    plat = sys.platform if platform is None else platform
    if plat.startswith('win'):
        base = env.get('LOCALAPPDATA') or str(Path.home() / 'AppData' / 'Local')
    else:
        base = env.get('XDG_DATA_HOME') or str(Path.home() / '.local' / 'share')
    return Path(base).expanduser() / APP_DIR_NAME


def default_data_root(base_dir=None, environ=None, platform=None):
    """The data directory when nobody configured one.

    A checkout keeps its ledger inside the tree (git-ignored, one per checkout, easy to
    delete). Anything installed keeps it in the user's data directory, because
    site-packages is replaced on upgrade.
    """
    if is_checkout(base_dir):
        return Path(BASE_DIR if base_dir is None else base_dir) / 'data'
    return user_data_dir(environ, platform)


# The configured file wins over the environment: pointing CHAIN_CONFIG at a file is the
# deployment's own, reviewable answer, and a stray CHAIN_DATA_ROOT in a shell (CI, a
# test that forgot to clean up) must not silently move the ledger somewhere else.
DATA_ROOT = _path(_CFG.get('data_root') or os.environ.get('CHAIN_DATA_ROOT'),
                  default_data_root().resolve())
# The database, the logs and the projections live under one research root; keeping the
# name explicit means a deployment can mount that directory read-write and nothing else.
RESEARCH_ROOT = DATA_ROOT / 'ledger'
HOME = _path(os.environ.get('CHAIN_HOME') or _CFG.get('home'), RESEARCH_ROOT / 'docs')

DOCUMENTS = dict(_CFG.get('documents') or DEFAULT_DOCUMENTS)
DOC_TO_PATH = {}
for _key, _rel in DOCUMENTS.items():
    _p = Path(_rel)
    DOC_TO_PATH[_key] = str(_p if _p.is_absolute() else (HOME / _p))

TIER0 = set(_CFG.get('tier0') or DEFAULT_TIER0)
TIER1 = set(_CFG.get('tier1') or DEFAULT_TIER1)
TIER2 = set(_CFG.get('tier2') or DEFAULT_TIER2)

# Documents whose changes must be countersigned before they are rendered to anyone.
# Defaults to tier 0: "constitutional" and "requires a countersign" are the same set
# unless a deployment deliberately separates them.
_P = _CFG.get('protected_docs')
NEVER_DOCS = set(_P) if _P is not None else set(TIER0)

# Documents that use a single-hash heading style; section operations are refused on them
# because those operations look for "## " and would swallow everything after the marker.
SINGLE_HASH_DOCS = set(_CFG.get('single_hash_docs') or [])

AGENT_ENV_VARS = tuple(_CFG.get('agent_env_vars') or DEFAULT_AGENT_ENV_VARS)

# Path to a read-only SQLite database holding the human's messages (the evidence a
# signature points at). None = signature verification reports SIGNER_DB_NOT_CONFIGURED.
SIGNER_DB = _CFG.get('signer_db')

# Optional integration points. Both are None by default so the ledger has no imports it
# does not need: a policy module decides what to refuse, a post-write hook decides what
# to do after a write lands. Values look like "package.module" and "package.module:function".
POLICY_MODULE = _CFG.get('policy_module')
POST_WRITE_HOOK = _CFG.get('post_write_hook')

LENGTH_CAPS = dict(_CFG.get('length_caps') or {})


def load_policy_module():
    """Import the configured policy module, or return None.

    Kept as a function so the import failure is visible at call time and can be caught
    by the caller instead of turning an import-time error into a dead process.
    """
    if not POLICY_MODULE:
        return None
    return importlib.import_module(POLICY_MODULE)


def load_post_write_hook():
    """Resolve "module:function" into a callable, or return None."""
    if not POST_WRITE_HOOK:
        return None
    target = POST_WRITE_HOOK
    if ':' not in target:
        raise ValueError('post_write_hook must look like "package.module:function"')
    module_name, func_name = target.split(':', 1)
    return getattr(importlib.import_module(module_name), func_name)
