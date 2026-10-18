# authority-chain

**Self-improving agents rewrite their own skills and memory. This makes every rewrite auditable.**

An append-only event log with a hash chain, a ticket protocol for writes, and countersignatures
for the documents that define what the agent is allowed to do. Small on purpose: one module,
SQLite, no service to run.

The problem it solves is not "keep a history". Git already keeps a history. The problem is that
an agent that edits its own rules does not stop to commit, does not open a pull request against
itself, and has no reviewer standing between the edit and the next turn.

## What it gives you

| Guarantee | Mechanism |
|---|---|
| A write cannot silently land on top of someone else's write | the writer must send the revision it read; a mismatch is refused and queued |
| Two writers that disagree leave a record instead of a coin toss | `conflict_queue` keeps both revisions and the refused patch |
| Content edits cannot pass as history | each event hashes its own fields plus the previous hash; `verify` recomputes from genesis |
| A constitutional document is not live until a human approves that exact content | countersignature bound to both the message and the content `sha256` |
| A rendering can be told apart from the source | projections carry a header naming the event they came from; drift is detectable byte for byte |
| An empty or partly-migrated chain cannot be reported as healthy | `chain_status` distinguishes `EMPTY`, `LEGACY`, `TAINTED` and `INTACT` |

`chain_intact` alone answers a narrower question than "is this ledger healthy", so it is never
the only field you read.

## Quick start

```bash
pip install -r requirements.txt       # stdlib only; pytest for the tests
python chaincore.py bootstrap         # import the documents named in config
python chaincore.py register w1 host1 writer 1
python chaincore.py get doc_a         # prints the current revision
python chaincore.py submit w1 doc_a '{"v": 1}' --type INIT --base 0
python chaincore.py submit w1 doc_a '{"v": 2}' --base 1
python chaincore.py verify            # chain_status=INTACT, latest_hash=...
```

Submission without `--base` is refused (`MISSING_TICKET`). Submitting a stale `--base` is
refused and queued (`REJECT_STALE_WRITE`). Both refusals are the feature.

The document registry, tiers, length caps and integration points live in `chaincore.json`;
see `chaincore.json.example`. Nothing machine-specific is compiled into the module.

## Why not just git?

Because the agent is running while it edits, and the edit takes effect on the next turn.

- **No review step, no merge gate.** Git assumes a human or CI stands between a change and its
  effect. Here the consumer of the file is the same process that wrote it: the file is read again
  seconds later, not at merge time. Authority has to be checked at the write, not at the review.
- **Concurrent writes are refused on the spot.** Two sessions of the same agent can write the
  same document within the same second. Git resolves that later, with a conflict marker and a
  human. Here the second write is rejected at the moment it happens and turned into a ticket.
- **A hand-edited rendering is detected byte for byte.** The projection is generated output; a
  direct edit is drift, and the next materialize run can find it instead of silently adopting it.
- **Approval is bound to content, not to a commit.** A commit message says "approved". A
  countersignature says "approved these bytes, for this message id".

Git is still the right tool for the source of the tool. It is the wrong tool for the state an
agent is reading from while it runs.

## How this differs from hash-chained memory projects

Projects such as [Lians](https://github.com/Lians-ai/Lians) chain an agent's *memory records* for
regulatory evidence, and gate writes through an admission mode (`monitor` / `enforce`). This
project gates *authority*: who may change a rule, against which revision, and what a human
signature covers. The two are complementary — a memory chain records what the agent knew, an
authority chain records what the agent was allowed to change.

## Hermes agent integration

Hermes exposes a plugin hook API. Resolve paths through the runtime rather than hardcoding them:

```python
from hermes_cli.paths import get_hermes_home     # authoritative home for the running install
home = get_hermes_home()
```

The optional integration points in `chaincore.json` are a policy module (decides what to refuse)
and a post-write hook (called after a write lands). Both default to `None`, so the core module
imports nothing from the host.

## Tests

```bash
python -m pytest -q
```

Seven scenarios: missing ticket, accepted write advancing the revision, stale write refused and
queued, content edit detected by the chain, broken link reported rather than hidden, the genesis
event's known-unverifiable gap, and determinism (identical input → identical hash).

## Status

Used in daily operation. Behavior is frozen for the flows covered by the tests; see
`docs/why.md` for the reasoning behind each guard, including the two places where the design
accepts a limitation instead of hiding it.

## License

Apache-2.0. See `LICENSE` and `NOTICE`.
