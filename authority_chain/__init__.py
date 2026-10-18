"""AUTHORITY_CHAIN V1 - one authoritative event sequence per document.

Design:
  - One owner, many entry points: every caller is a surface, never a separate self.
  - events: append-only history of factual changes, never overwritten.
  - canonical_state: the single current value per document (doc_key -> revision -> value).
  - surface_cursors: how far each surface has read the history.
  - writer_registry: who may write which document, with tiers.
  - conflict_queue: conflicts that need a human decision (no silent auto-resolution).
  - Revision check + patch/event writes; whole-file rewrites are forbidden except INIT.

Modules:
  config      paths and the document registry (the only place that knows about either)
  schema      connection, schema creation, migrations
  hashing     hash_event, sequence assignment, chain head
  writers     writer registry, runtime session identity, approval tokens, policy module
  submit      submit_event, patch semantics, bootstrap
  state       revisions, canonical values, surface cursors, the audit view
  verify      verify_chain, accounting assertion, tainted registry, signature state
  projection  render, path mapping, atomic verified write, drift check
  cli         argument parsing and dispatch only

Usage:
  authority-chain bootstrap      # import the configured documents as revision 1
  authority-chain register <wid> <surface> <role> <tier>
  authority-chain submit <wid> <doc> '<patch-json>' [--base <rev>] [--evidence "..."] [--manual-tty]
  authority-chain get <doc>
  authority-chain delta <surface>
  authority-chain materialize    # render projections and re-verify them
  authority-chain audit          # audit view
(`python chaincore.py <command>` is the same command line, from a checkout.)
"""
from .config import (RESEARCH_ROOT, TIER0, TIER1, TIER2, DOC_TO_PATH, NEVER_DOCS,
                     SINGLE_HASH_DOCS, AGENT_ENV_VARS, SIGNER_DB,
                     load_policy_module, load_post_write_hook)
from .schema import DB_PATH, now_iso, get_conn, init_schema
from .hashing import hash_event, next_sequence, chain_head
from .writers import (register_writer, runtime_session_id, verify_approval_token,
                      verify_signer_message, gate_enforced, SUBMIT_REJECT_LOG,
                      GATE_STATE_DIR, GATE_ENFORCE_FLAG, GATE_OBSERVE_MARKER,
                      policy_rules, post_write_hook)
from .state import get_current_revision, get_canonical, get_surface_delta, advance_cursor, audit
from .projection import (PROJECTION_DIR, render_projection, projection_path, atomic_write_verified,
                         materialize_doc, materialize, verify_projections, lock_all)
from .verify import (SIGNATURES_FILE, EFFECTIVE_LINE_SEQ, load_signature_shas,
                     decision_signature_status, verify_chain, signature_declarations,
                     declared_supersedes, is_qualified, is_effective)
from .submit import (LENGTH_CAPS_FILE, LENGTH_GATE_LOG, length_caps, length_gate, classify_entry,
                     submit_event, apply_patch, bootstrap)
from .cli import main

__version__ = '0.1.0'

__all__ = [
    'RESEARCH_ROOT', 'TIER0', 'TIER1', 'TIER2', 'DOC_TO_PATH', 'NEVER_DOCS', 'SINGLE_HASH_DOCS',
    'AGENT_ENV_VARS', 'SIGNER_DB', 'load_policy_module', 'load_post_write_hook',
    'DB_PATH', 'now_iso', 'get_conn', 'init_schema',
    'hash_event', 'next_sequence', 'chain_head',
    'register_writer', 'runtime_session_id', 'verify_approval_token', 'verify_signer_message',
    'gate_enforced', 'SUBMIT_REJECT_LOG', 'GATE_STATE_DIR', 'GATE_ENFORCE_FLAG', 'GATE_OBSERVE_MARKER',
    'policy_rules', 'post_write_hook',
    'get_current_revision', 'get_canonical', 'get_surface_delta', 'advance_cursor', 'audit',
    'PROJECTION_DIR', 'render_projection', 'projection_path', 'atomic_write_verified',
    'materialize_doc', 'materialize', 'verify_projections', 'lock_all',
    'SIGNATURES_FILE', 'EFFECTIVE_LINE_SEQ', 'load_signature_shas', 'decision_signature_status',
    'verify_chain', 'signature_declarations', 'declared_supersedes', 'is_qualified', 'is_effective',
    'LENGTH_CAPS_FILE', 'LENGTH_GATE_LOG', 'length_caps', 'length_gate', 'classify_entry',
    'submit_event', 'apply_patch', 'bootstrap',
    'main',
]
