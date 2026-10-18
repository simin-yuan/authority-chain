"""Command line: argument parsing and dispatch only."""
import argparse
import json
import sys

from .writers import register_writer, _manual_tty_attestation, _prompt_approval_token
from .submit import submit_event, bootstrap
from .state import get_canonical, get_surface_delta, advance_cursor, audit
from .projection import materialize, lock_all
from .verify import verify_chain


def main():
    ap = argparse.ArgumentParser(prog='continuity_core')
    sub = ap.add_subparsers(dest='cmd')
    sub.add_parser('bootstrap')
    r = sub.add_parser('register'); r.add_argument('writer_id'); r.add_argument('surface'); r.add_argument('role'); r.add_argument('tier')
    s = sub.add_parser('submit'); s.add_argument('writer_id'); s.add_argument('doc'); s.add_argument('patch')
    s.add_argument('--base', type=int, default=None); s.add_argument('--evidence', default=''); s.add_argument('--caused', default='')
    s.add_argument('--type', default='PATCH'); s.add_argument('--surface', default=None); s.add_argument('--session', default=None)
    s.add_argument('--force', action='store_true')
    s.add_argument('--force-reason', dest='force_reason', default='',
                   help='force requires a reason (ledger row + review ticket). Automation may not call it.')
    # --approval-token was removed: a code passed in argv ends up in the agent log in clear
    # text (the log records command lines verbatim), which made the gate decorative.
    # The old form is rejected as an unknown argument; the code is prompted for instead.
    # Manual channel (no agent env + real TTY); a one-time code is required every time.
    s.add_argument('--manual-tty', dest='manual_tty', action='store_true',
                   help='manual-terminal channel: no agent env + real TTY + a one-time code per call.')
    g = sub.add_parser('get'); g.add_argument('doc')
    d = sub.add_parser('delta'); d.add_argument('surface')
    a = sub.add_parser('advance'); a.add_argument('surface'); a.add_argument('--to', type=int, default=None)
    sub.add_parser('materialize')
    sub.add_parser('verify')
    sub.add_parser('lock')
    sub.add_parser('audit')
    args = ap.parse_args()
    indent = None
    if args.cmd == 'bootstrap':
        out = bootstrap()
    elif args.cmd == 'register':
        out = register_writer(args.writer_id, args.surface, args.role, args.tier)
    elif args.cmd == 'submit':
        try: patch = json.loads(args.patch)
        except: patch = {'op': 'append', 'content': args.patch}
        _mt = _manual_tty_attestation() if getattr(args, 'manual_tty', False) else None
        out = submit_event(args.writer_id, args.doc, patch, base_revision=args.base,
                           event_type=args.type, evidence=args.evidence, caused_by=args.caused,
                           surface_id=args.surface, session_id=args.session, force=args.force,
                           force_reason=getattr(args, 'force_reason', ''),
                           manual_tty=_mt, approval_prompt=_prompt_approval_token)
    elif args.cmd == 'get':
        out = get_canonical(args.doc)
    elif args.cmd == 'delta':
        out = get_surface_delta(args.surface); indent = 1
    elif args.cmd == 'advance':
        out = advance_cursor(args.surface, args.to)
    elif args.cmd == 'materialize':
        out = materialize()
    elif args.cmd == 'verify':
        out = verify_chain()
    elif args.cmd == 'lock':
        out = lock_all()
    elif args.cmd == 'audit':
        out = audit(); indent = 1
    else:
        ap.print_help()
        return 0
    print(json.dumps(out, ensure_ascii=False, indent=indent))
    # Every refusal is {"ok": false, ...}; a caller that only checks the exit status
    # (a shell, a scheduler) must see it as a failure too.
    return 1 if isinstance(out, dict) and out.get('ok') is False else 0

if __name__ == '__main__':
    sys.exit(main())
