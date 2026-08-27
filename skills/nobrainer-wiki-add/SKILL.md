---
name: nobrainer-wiki-add
description: "Use when the owner says nb-wiki-add, save this to the wiki, ingest this source, or promote inbox items into an existing NoBrainer Wiki with provenance, classification, deduplication, links, and a scoped change log."
---

# NoBrainer Wiki Add

Turn a source or inbox candidate into durable, cited knowledge. Follow the
target `WIKI.md` and index. Reuse existing pages before creating new ones.

## Preflight and classification

Resolve the wiki root from project instructions or the owner; never guess a
destination. Read rules, index, relevant pages, source policy and git/dirty
state. Confirm one writer owns the target files.

Classify both source and destination:

- `PUBLIC`: safe for intentional public disclosure;
- `INTERNAL`: non-public operating knowledge without sensitive personal data;
- `CONFIDENTIAL`: explicitly restricted target and minimal need-to-know content;
- `SECRET`: credentials, keys, tokens, cookies, seed phrases or equivalent.

Never write `SECRET` material to sources, pages, inbox, logs, prompts or commit
history. Customer/personal data never enters a public target. A mixed sensitive
source requires a proposed sanitization list and explicit owner approval for the
exact payload and destination; "save it" does not authorize declassification.

Respect copyright and source-access restrictions. Store only material the owner
is allowed to preserve; prefer a concise synthesis and provenance reference over
copying an entire external work.

## Add or promote

1. Read the complete allowed input and record source, date, classification and
   capture method. Separate verbatim source from agent synthesis.
2. Extract only durable facts, decisions, definitions, evidence and reusable
   procedures. Exclude transient task status and unsupported conclusions.
3. Search index and pages by exact terms, aliases and relevant languages. Do not
   create a near-duplicate merely because wording differs.
4. Prepare a scoped write set: source capture if allowed, pages to create/update,
   index entry, log line and exact inbox items to mark processed.
5. Preserve contradictions and stale-risk markers. Distinguish observed fact,
   inference, recommendation and forecast.
6. Apply minimal edits. One concept per page, absolute dates, relative internal
   links and citations to source evidence.
7. Run close checks before marking inbox lines processed: target content exists,
   citations resolve, index reaches the page, no secret/PII leakage, and diff
   matches the approved scope.
8. Append one meaningful log entry. Mark only successfully promoted inbox items.

Do not pull/rebase a dirty vault, mass-rewrite pages, resolve owner decisions,
commit, push or publish unless those actions were separately authorized and
verified. On conflict preserve both versions and stop.

## Report

Return classification, source references, pages created/updated, inbox items
promoted, index/log changes, validation, excluded sensitive material,
contradictions, uncertainty, rollback and one next action.
