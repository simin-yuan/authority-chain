# Why the ledger is built this way

Every non-obvious decision in `chaincore.py`, with the failure it prevents. This is the
document to read before changing anything: most of these guards look redundant until you
know what they replace.

## Append-only events, one hash chain

**Why the row is not write-protected, and why that is not a weakness.** Rows stay
writable on purpose: exactly one field (`status`) is legitimately updated when a write is
countersigned, and a storage-level `RAISE(ABORT)` on every UPDATE would forbid that. The
hash is computed over the immutable fields only — `prev_hash|writer|doc|ts|seq|patch` — and
deliberately excludes `status`, so the one legal mutation does not break verification. What
is protected instead is *meaning*: `verify` recomputes every hash from genesis, so an edited
`patch` or a rewritten `prev_hash` cannot pass. Two limits, stated plainly: the chain does
not prevent tampering, it makes tampering impossible to hide (which is the property that
matters when the tamperer may be the process holding the database file); and the stored hash
is truncated to 16 hex characters, which is enough to detect an accidental or casual edit but
is not a full 256-bit commitment — a determined adversary with write access and compute can
search for a colliding prefix. If you need the stronger property, store the full digest.

**Why one global chain rather than one per document.** A per-document chain lets you
reorder across documents: document A rewritten before document B, and no hash notices.
A global chain fixes a total order, which is what "what did the state look like at that
moment" requires.

**Why `last_sequence` is read inside the write transaction.** Reading the head and then
starting the insert leaves a window where two writers both think they are next. The
sequence is assigned by the database (`AUTOINCREMENT`) and the insert is rejected by a
uniqueness constraint if the chain head moved in between.

## Tickets: read the revision, then write against it

**Why a write without `base_revision` is refused (`MISSING_TICKET`).** An agent that
writes "the new version" without having read the current one is guessing. Requiring the
revision it read turns a guess into a claim that can be checked, and the check is cheap.

**Why `base_revision` is compared against the current revision instead of being accepted
as given.** If the comparison is skipped — or the code re-reads the current revision just
before comparing — the two numbers are equal by construction and the gate never closes.
The comparison must use the caller's value against a revision read at the same moment as
the insert, inside the same transaction.

**Why a stale write is queued rather than dropped.** A rejected write that leaves no
trace teaches nobody anything: the writer retries, the same conflict happens, nobody can
see that two writers disagreed. The refusal is written to `conflict_queue` with both
revisions, so the disagreement becomes a decision someone can resolve.

**Why `force` exists and what it may not do.** `force` is a concurrency escape hatch: it
lets a writer take the revision it did not read when a human has decided that is
acceptable. It is recorded in its own ledger and it never bypasses length caps, tier
checks, or signature requirements. An escape hatch that also disables content checks is
not an escape hatch, it is a hole.

## Tiers and countersignatures

**Why tier 0 changes need a countersignature.** Documents that define what the system is
allowed to do cannot be edited by the thing being governed, in the same breath as the
edit. The write lands, but it is not rendered to anyone until a signature records that a
human read that exact content (`sha256` bound, not merely "approved the change").

**Why the signature binds to the message and the content hash.** A signature over "the
revision" can be replayed onto different content. Binding to both the message the human
actually saw and the hash of the bytes to be written means an approval covers one
artifact and nothing else.

**Why one-time codes.** A reusable authorization turns a single approval into a standing
permission. Each signature consumes a code, and a code that has been used is refused.

## Projections

**Why source and projection are separate.** The canonical value is authoritative; the
file on disk is a rendering. Tools, humans and other agents edit renderings. When the
renderer is the only way to produce the file, "the file changed" and "the state changed"
stop being the same event, and drift becomes detectable instead of plausible.

**Why the temp file is read back and compared byte for byte before replacing.** A replace
that fails halfway leaves a truncated file whose existence looks like success. Writing a
temp copy, reading it, comparing to the bytes that were meant to be written, and only then
calling `os.replace` makes a partial write impossible to mistake for a complete one.

**Why projection writes are best-effort but their failures are recorded.** A projection
failure must not fail the authoritative write — the event is already committed and cannot
be taken back. It must still be visible: silently missing renderings are indistinguishable
from renderings nobody looked at.

**Why generated files start with a header naming their source.** A reader who opens the
file cannot tell a rendering from an original. The header states that direct edits will be
overwritten and how to make the change properly.

## Verification

**Why `chain_intact` cannot be the health answer on its own.** "No new break found" is
also true of an empty chain, and of a chain whose first event was replaced. `chain_empty`
and `chain_status` exist because the boolean alone answers a narrower question than the
one being asked.

**Why `tainted_known` is counted separately from `broken_unregistered`.** A chain that
contains a documented, already-accounted-for break is in a different state from one that
just broke. Reporting them as one number either hides a new break inside a known one, or
makes the known one look new forever.

**Why a materialize run that finds zero events is reported, not asserted.** An empty
result is a legitimate outcome of "nothing changed" and also the shape of a run that never
executed. The status file records the counts so the two cases can be told apart later.

## Small decisions that are easy to undo by accident

- Sections operations (`--section`) are refused on documents that use a single `#`
  heading level: the splitter looks for `## ` and would swallow the rest of the file.
- Filenames derived from document keys replace characters that are illegal on Windows
  instead of failing: renderings are generated output, so lossy-but-complete beats
  fatal.
- Length caps live in configuration, not in code: the cap is a property of the deployment,
  and a cap compiled into the module is a rewrite every time it changes.
- The post-write hook is resolved lazily and defaults to `None`, so the core module has no
  import-time dependency on the system that consumes its events. An import cycle here made
  the module unimportable whenever the consumer was also being imported.
- Runtime session identity comes from environment variables set by the runtime, never from
  arguments the model passes: an identity the writer can choose is not an identity.
