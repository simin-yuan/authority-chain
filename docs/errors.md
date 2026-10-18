# Refusal codes

Every refusal is returned as `{"ok": false, "error": "<CODE>...", ...}`, and the command line
exits with status 1 when it prints one. Some codes carry a suffix after a colon (for example
`UNREGISTERED_WRITER:w1`); match on the prefix. Unless a row says otherwise, a refusal stores
no event and leaves the revision where it was.

## Writer and permission

| Code | When it happens | What to do |
|---|---|---|
| `UNREGISTERED_WRITER` | the writer id is not in the writer registry | register the writer (`register <writer> <surface> <role> <tier>`) |
| `WRITER_INACTIVE` | the writer is registered but its status is not `active` | reactivate the writer, or write as an active one |
| `PERMISSION_DENIED` | a tier 0 document written by a writer that is not `tier0`, or a tier 1 document written by a `tier2` writer | use a writer whose tier covers the document, or change the tiers in `chaincore.json` |

## Session and ticket

| Code | When it happens | What to do |
|---|---|---|
| `MISSING_RUNTIME_SESSION_ID` | a ticketed write (or a `SIGNATURE`) with every configured session variable (`AGENT_SESSION_ID`, `AGENT_CRON_SESSION`, `AGENT_PARENT_START_MARKER` by default) empty | have the runtime set one of them; a human at a terminal uses `--manual-tty` with a one-time code |
| `MISSING_TICKET` | a state-changing write (or a `COUNTERSIGN`) sent without `--base` | `get <doc>` and send its revision back as `--base` |
| `REJECT_STALE_WRITE` | `--base` does not match the current revision | the write is queued in `conflict_queue`; re-read the document and decide on the queued patch |
| `FORCE_REQUIRES_REASON` | `--force` without a reason | pass `--force-reason "..."`; the reason is recorded and opens a review ticket |
| `CONFLICT_SEQUENCE` | another writer took the same sequence number at the same moment | re-read the latest entry and retry |
| `CONFLICT_CHAIN_HEAD` | `expected_prev_hash` does not match the current chain head | re-read the chain head and retry |
| `VERDICT_NEEDS_EXPECTED_PREV_HASH` | a verdict entry (one with `decision_quote`) without `expected_prev_hash` | call `chain_head()` and pass its value |

## Patch content

| Code | When it happens | What to do |
|---|---|---|
| `UNKNOWN_PATCH_OP` | a non-`INIT` canonical write whose patch has a missing or unrecognized `op` | use one of `full`, `append`, `insert_after`, `replace_section`, `delete_section`, `replace_text` |
| `NO_CHANGE` | the patch would leave the stored value exactly as it is (for example an absent marker, or a `find` text that does not occur exactly once) | check the marker or `find` text against the current content |
| `DOC_LENGTH_GATE` | the rendered document would grow past its cap in `length_caps.json` | shrink the document first, then add; a write that does not grow always passes |
| `FORBIDDEN_OP` | on a single-hash document: a whole-file overwrite after `INIT`, or `replace_section`, `delete_section` or `replace_text`, without a one-time approval code | use `append` or `insert_after`, or supply a one-time code issued out of band |
| `REPLACE_TEXT_MISSING_FIND` | an approved `replace_text` with an empty `find` | give the text to replace |
| `REPLACE_TEXT_BAD_MATCH` | an approved `replace_text` whose `find` does not occur exactly once | make `find` unique; the code is not consumed |

## One-time approval codes

| Code | When it happens | What to do |
|---|---|---|
| `APPROVAL_TOKEN_UNKNOWN` | the code is not registered | use a code issued out of band |
| `APPROVAL_TOKEN_USED` | the code was already consumed (a `COUNTERSIGN` consumes one too) | request a new code |
| `APPROVAL_TOKEN_RACE` | the code was consumed by another write while this one was in progress | nothing was stored; request a new code |
| `MANUAL_TTY_REFUSED_AGENT_ENV` | `--manual-tty` while an agent session variable is set | the manual channel is for a terminal without an agent runtime |
| `MANUAL_TTY_REFUSED_NO_TTY` | `--manual-tty` without a real terminal on stdin and stdout | run it in a terminal window |
| `MANUAL_TTY_NEEDS_TOKEN` | `--manual-tty` without a code | enter the one-time code at the prompt |
| `MANUAL_TTY_APPROVAL_TOKEN_UNKNOWN`, `MANUAL_TTY_APPROVAL_TOKEN_USED` | the code given on the manual channel is unknown or already used | as for the codes above |

## Countersignature

A change to a protected document (tier 0 by default) is not refused: it lands as
`pending_countersign` and is applied when countersigned.

| Code | When it happens | What to do |
|---|---|---|
| `COUNTERSIGN_MISSING_TARGET` | a `COUNTERSIGN` patch without `target` | send `{"op": "countersign", "target": "evXXXXXX"}` |
| `COUNTERSIGN_TARGET_NOT_FOUND` | the target event does not exist | check the event id |
| `COUNTERSIGN_TARGET_NOT_PENDING` | the target is not in `pending_countersign` | only pending amendments can be countersigned |
| `COUNTERSIGN_TARGET_NOT_NEVER_DOC` | the target belongs to a document that is not protected | ordinary documents need no countersignature |

## Signatures and references

| Code | When it happens | What to do |
|---|---|---|
| `SIGNATURE_MISSING_TARGETS` | a `SIGNATURE` without a `signs` list | list each signed event as `{"event_id": ..., "sha256": ...}` |
| `SIGNATURE_MALFORMED` | a `signs` entry without `event_id` or `sha256` | complete the entry |
| `SIGNATURE_TARGET_NOT_FOUND` | a signed event does not exist | check the event id |
| `SIGNATURE_SHA_MISMATCH` | the declared sha256 is not the sha256 of the event's patch on the chain | sign the version that is on the chain |
| `SIGNATURE_NOT_TRACEABLE` | the signer message cannot be verified; the suffix names why: `MISSING_SIGNER_MESSAGE_ID`, `SIGNER_DB_NOT_CONFIGURED`, `STATE_DB_NOT_FOUND`, `STATE_DB_ERROR`, `SIGNER_MESSAGE_NOT_FOUND`, `SIGNER_MESSAGE_NOT_USER`, `SIGNER_MESSAGE_SESSION_MISMATCH`, `SIGNER_MESSAGE_NO_SIGNAL`, `SIGNER_MESSAGE_DOES_NOT_NAME` | pass `signer_message_id`, configure `signer_db`, and point at a message from the human, in the same session, that expresses consent and names every signed event id |
| `SUPERSEDES_MALFORMED`, `AMENDS_MALFORMED` | `supersedes` or `amends` is not a list of `{"event_id": ..., "hash": ...}` | send structured references with the chain hash |
| `UNKNOWN_REFERENCE` | a referenced event does not exist | check the event id |
| `STALE_REFERENCE` | the referenced hash is not the one on the chain | re-read the event and use its current hash |
| `ALREADY_SUPERSEDED` | the event was already superseded | supersede the superseding event instead |

## Policy gate

Returned only when a policy module is configured and the gate is enforced (a
`GATE_ENFORCE.on` file in the gate directory, or `CHAIN_GATE_ENFORCE=1`). Otherwise the same
findings are logged to `submit_reject.log` and the write goes through.

| Code | When it happens | What to do |
|---|---|---|
| `COUNTERSIGN_BY_WRITER_REJECTED` | the patch sets `countersigned_by` itself | leave it to the countersign path |
| `DECIDE_CLAIM_WITHOUT_EVIDENCE` | decision wording with neither `decision_quote` nor `caused_by` | add the quote or the parent event |
| `VERDICT_NEEDS_SOURCE_MSG_ID` | a `decision_quote` without `source_msg_id` | name the source message |
| `VERDICT_SOURCE_UNVERIFIED` | the source message cannot be verified | point at an existing message from the human |
| `VERDICT_QUOTE_INVALID` | the quote does not occur in the source message | quote the message verbatim |
| `CAUSED_BY_NOT_FOUND` | the `caused_by` event does not exist | check the event id |
| `PARENT_NOT_VERIFIED` | the `caused_by` event is not `verified` or `countersigned` | verify the parent first |

## Reasons in reports

These are not refusals of a write; they appear inside the results of `verify`, `materialize`,
`verify_projections` (the drift check) and `is_effective`.

| Reason | Where | Meaning |
|---|---|---|
| `HASH_MISMATCH` | `verify` | an event's stored hash does not match its recomputed fields |
| `PREV_HASH_MISMATCH` | `verify` | an event's `prev_hash` is not the previous event's hash |
| `VERIFY_FAILED`, `PROJECTION_WRITE_FAILED`, `SOURCE_WRITE_FAILED` | `materialize` | a rendering failed its own check, or could not be written |
| `MISSING`, `CONTENT_MISMATCH` | `verify_projections` | a rendering is absent, or differs from what the chain produces |
| `NOT_FOUND`, `SUPERSEDED`, `SUPERSEDED_LEGACY`, `PENDING_SIGNATURE` | `is_effective` | the decision must not be acted on |
| `POST_WRITE_SKIPPED` | `submit_reject.log` | the post-write hook raised; the write itself landed |
