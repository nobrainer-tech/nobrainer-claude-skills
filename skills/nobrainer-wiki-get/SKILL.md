---
name: nobrainer-wiki-get
description: "Use when the owner says nb-wiki-get, ask the wiki, what do I know about, or requests a read-only answer from an existing NoBrainer Wiki with page-level provenance, freshness, contradictions, and explicit gaps."
---

# NoBrainer Wiki Get

Answer from the wiki without changing it. Resolve the wiki root from project
instructions or the owner, read its rules and index, then search only relevant
knowledge.

## Query flow

1. Rewrite the question into concepts, aliases, abbreviations, languages and an
   optional date/freshness constraint.
2. Use the index as a map, then perform lexical search with `rg`. Follow only
   relevant wikilinks and source references; do not load the whole vault unless
   the query genuinely spans it.
3. Prefer curated pages, but inspect cited raw sources when a claim, conflict or
   exact wording needs verification.
4. Enforce the requester's access boundary. Do not reveal confidential content,
   credentials, personal data or private source paths into an unsafe response.
5. Separate `WIKI_FACT`, `INFERENCE`, `RECOMMENDATION` and `UNKNOWN`. Check
   last-verified dates for time-sensitive claims and say when live verification
   is required.
6. Cite the exact wiki page and its underlying source near each material claim.
   If sources disagree, present the conflict; do not choose silently.

An absent lexical hit is not proof of absent knowledge. Search synonyms and
related map entries before declaring the wiki silent. If evidence remains
insufficient, say exactly what was searched and what source would close the gap.

Ordinary query mode is read-only: do not update freshness, repair links, save the
answer, commit or push. If the owner asks to preserve a reusable result, route a
separate write through `nobrainer-wiki-add`.

## Output

Lead with the answer. Then give concise evidence/citations, freshness and
contradictions, confidence, gaps and one optional capture/verification action.
