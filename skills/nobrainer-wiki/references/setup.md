# NoBrainer Wiki setup reference

Adapt this reference to the target. Existing conventions win when they preserve
the same safety and information boundaries.

## Minimal layout

```text
WIKI_ROOT/
  WIKI.md             durable rules and confidentiality boundaries
  index.md            small map to curated knowledge
  log.md              append-only meaningful changes
  sources/            raw captures with provenance and classification
  pages/              curated, linked, cited knowledge
  _inbox/WRITER.md    append-only candidates owned by one writer
```

Do not create empty layers that have no present use. A project-local wiki may
live under its existing docs structure.

## Curated page contract

```markdown
# Human title

One durable statement a future reader can act on.

CLASSIFICATION: PUBLIC | INTERNAL | CONFIDENTIAL
LAST_VERIFIED: YYYY-MM-DD | UNKNOWN

## Facts

- <observed or source-backed claim> (source: <relative source or URL>)

## Decisions and implications

- <decision, owner, date and scope>

## Contradictions / stale risk

- <conflict or freshness warning, or NONE>

## Related

- [[another-page]]
```

Use absolute dates. Mark observed fact, inference, recommendation and forecast
separately. Do not resolve conflicting sources by silently deleting one.

## Managed instruction block

Insert a project-specific block with a complete marker pair. Keep it concise so
instructions do not become a copy of the wiki protocol.

```markdown
<!-- NB-WIKI:START -->
## NoBrainer Wiki

Knowledge root: `WIKI_ROOT`. Rules: `WIKI_ROOT/WIKI.md`.
- At session start, read `WIKI_ROOT/index.md`, then search only relevant pages.
- Capture only durable facts in the current writer's inbox; never secrets.
- Use `nobrainer-wiki` mode `GET` for queries, `ADD` for explicit persistence,
  and `TIDY_AUDIT` before any maintenance write.
- Runtime state, leases and transient blockers stay in their canonical ledgers.
<!-- NB-WIKI:END -->
```

Before replacement, require exactly one START and one END in the correct order.
Zero markers means append at the repository's conventional location. Any other
count/order is a stop for manual repair. Verify a byte-level before/after diff
outside the managed block.

## Setup report

```text
WIKI_DECISION: REUSE | CREATE | REPAIR | NOT_JUSTIFIED | BLOCKED
ROOT: <resolved path/reference>
CLASSIFICATION: <level>
FILES_REUSED: <list>
FILES_CREATED: <list>
INSTRUCTIONS_UPDATED: <list>
AUTOMATION: NOT_CONFIGURED | PROPOSED | VERIFIED
CHECKS: <commands/readbacks>
UNCERTAINTY: <items or NONE>
ROLLBACK: <exact procedure and readback>
NEXT_ACTION: <one action>
```
