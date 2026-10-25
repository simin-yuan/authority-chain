# authority-chain

**Self-improving agents rewrite their own skills and memory. This makes every rewrite auditable.**

The problem is not "keep a history". Git already keeps a history. The problem is that an agent
that edits its own rules does not stop to commit, does not open a pull request against itself,
and has no reviewer standing between the edit and the next turn.

## Why not just git?

Because the agent is running while it edits, and the edit takes effect on the next turn.

1. **No review step, no merge gate.** A running agent's edit takes effect on the next turn. Git
   assumes a human or CI stands between a change and its effect; here the consumer of the file is
   the same process that wrote it, and it reads the file again seconds later, not at merge time.
   Authority has to be checked at the write, not at the review.
2. **Concurrent writes are refused on the spot.** Two sessions of the same agent can write the
   same document within the same second. Git resolves that later, with a conflict marker and a
   human. Here the second write is refused at the moment it happens and turned into a ticket.
3. **A hand-edited rendering is detectable byte for byte.** The file an agent reads is generated
   output, not the source. A direct edit is drift, and the next check finds it instead of
   silently adopting it.

Git is still the right tool for the source of the tool. It is the wrong tool for the state an
agent is reading from while it runs.

Hash-chained memory projects such as [Lians](https://github.com/Lians-ai/Lians) chain an agent's
*memory records* for regulatory evidence; this project gates *authority*: who may change a rule,
against which revision, and what a human signature covers.

## What it gives you

| Guarantee | Mechanism |
|---|---|
| A write cannot silently land on top of someone else's write | the writer must send the revision it read; a mismatch is refused and queued |
| Two writers that disagree leave a record instead of a coin toss | `conflict_queue` keeps both revisions and the refused patch |
| A write that would change nothing does not pass as an edit | an unknown patch op (`UNKNOWN_PATCH_OP`) or a no-op patch (`NO_CHANGE`) is refused; the revision does not move |
| Content edits cannot pass as history | each event hashes its own fields plus the previous hash; `verify` recomputes from genesis |
| A constitutional document is not live until a human approves that exact content | the change lands as `pending_countersign`; a countersignature applies it, and a one-time approval code is burned on use |
| A rendering can be told apart from the source | projections carry a header naming the revision they came from; drift is detectable byte for byte |
| An empty or partly-migrated chain cannot be reported as healthy | `chain_status` is `EMPTY`, `BROKEN` or `INTACT`; legacy, genesis and known-tainted rows are counted separately |

`chain_intact` alone answers a narrower question than "is this ledger healthy", so it is never
the only field you read.

Small on purpose: one package, the Python standard library and SQLite, no service to run.

## Quick start

Get the code:

```bash
git clone https://github.com/simin-yuan/authority-chain
cd authority-chain
```

### Run it

In real use the agent runtime sets `AGENT_SESSION_ID`; the model never chooses it. For a
first run, set it by hand:

```bash
pip install -e .                      # no runtime dependencies; pip install -e ".[test]" for pytest
export AGENT_SESSION_ID=demo          # PowerShell: $env:AGENT_SESSION_ID = "demo"
authority-chain bootstrap             # import the documents named in config
authority-chain register w1 host1 writer 1
authority-chain get doc_a             # prints the current revision (null before the first write)
authority-chain submit w1 doc_a '{"v": 1}' --type INIT --base 0
authority-chain submit w1 doc_a '{"op": "append", "content": "more"}' --base 1
authority-chain verify                # chain_status=INTACT, latest_hash=...
```

From a checkout without installing, `python chaincore.py <command>` is the same command line.

Submission without `--base` is refused (`MISSING_TICKET`). Submitting a stale `--base` is
refused and queued (`REJECT_STALE_WRITE`). Both refusals are the feature. Every refusal prints
`{"ok": false, ...}` and exits with a non-zero status, so a shell or a scheduler sees it too.
Every refusal code is listed in [`docs/errors.md`](docs/errors.md).

Ticketed writes need a session id that the runtime injects through the environment
(`AGENT_SESSION_ID`, `AGENT_CRON_SESSION` or `AGENT_PARENT_START_MARKER` by default; the names
are configurable). The caller cannot supply one.

The document registry, tiers and integration points live in `chaincore.json`; see
`chaincore.json.example`. In a checkout it is read from the repository root; an installed copy
should point `CHAIN_CONFIG` at it (or set `CHAIN_DATA_ROOT`). Length caps are read from
`length_caps.json` in the ledger's data directory. Nothing machine-specific is compiled into the
code.

The data directory follows the install. From a checkout — the directory holding the package also
holds `pyproject.toml`, which is what an editable install points at — the ledger stays in `data/`
inside that checkout, git-ignored and easy to delete. Any other install writes to your own data
directory, because site-packages is lost on uninstall and replaced on upgrade:
`%LOCALAPPDATA%\authority-chain` on Windows, `$XDG_DATA_HOME/authority-chain` or
`~/.local/share/authority-chain` elsewhere. Both are defaults only: a `data_root` in the config
file outranks `CHAIN_DATA_ROOT`, which outranks both.

## Layout

| Module | Contents |
|---|---|
| `authority_chain/config.py` | paths and the document registry: the only place that knows about either |
| `authority_chain/schema.py` | connection, schema creation, migrations |
| `authority_chain/hashing.py` | `hash_event`, sequence assignment, chain head |
| `authority_chain/writers.py` | writer registry, runtime session identity, approval tokens, policy module |
| `authority_chain/submit.py` | `submit_event`: ticket check, tier check, length gate, conflict queue; patch semantics; `bootstrap` |
| `authority_chain/state.py` | revisions, canonical values, surface cursors, the audit view |
| `authority_chain/verify.py` | `verify_chain`, accounting assertion, tainted registry, signature state |
| `authority_chain/projection.py` | render, path mapping, atomic verified write, drift check |
| `authority_chain/cli.py` | argument parsing and dispatch only |

`chaincore.py` and `config.py` at the top level re-export the package for single-file use.

## Integration points

Two optional hooks in `chaincore.json`: a policy module (decides what to refuse) and a
post-write hook (called after a write lands). Both default to `None`, so the core package
imports nothing from the host.

## Tests

```bash
pip install -e ".[test]"
pytest -q
```

Seven scenarios: missing ticket, accepted write advancing the revision, stale write refused and
queued, content edit detected by the chain, broken link reported rather than hidden, the genesis
event's known-unverifiable gap, and determinism (identical input → identical hash). Every refusal
code in `docs/errors.md` — all 57 of them — is exercised by a test, as is the `pending_countersign`
state. `tests/test_error_coverage.py` parses that document and fails if a code is neither exercised
by a test nor listed with a reason.

## Status

Used in daily operation. Behavior is frozen for the flows covered by the tests; see
`docs/why.md` for the reasoning behind each guard, including the two places where the design
accepts a limitation instead of hiding it.

## Related reading

*History Is Not Memory* — why a persistent agent's state is not the same thing as its history:
[10.6084/m9.figshare.34155195](https://doi.org/10.6084/m9.figshare.34155195).

## License

Apache-2.0. See `LICENSE` and `NOTICE`.

© 2026 Simin Yuan — ORCID [0009-0002-6843-3390](https://orcid.org/0009-0002-6843-3390) · [github.com/simin-yuan](https://github.com/simin-yuan).
