#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Single-file entry point, kept so `python chaincore.py <command>` works from a checkout.

The implementation lives in the `authority_chain` package; this module re-exports its
public API so `import chaincore` keeps working.
"""
import sys

from authority_chain import *          # noqa: F401,F403  (re-export the public API)
from authority_chain import __all__    # noqa: F401
from authority_chain.cli import main

if __name__ == '__main__':
    sys.exit(main())
