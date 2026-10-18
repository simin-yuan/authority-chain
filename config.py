"""Compatibility name for `authority_chain.config`, kept so `import config` works from a
checkout. The configuration itself lives in authority_chain/config.py."""
from authority_chain.config import *   # noqa: F401,F403
