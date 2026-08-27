---
name: nobrainer-wiki-tidy
description: "Use when the owner says nb-wiki-tidy, tidy or audit the wiki, or asks to find and safely repair dead links, index drift, stale claims, duplicate candidates, orphan pages, contradictions, or processed inbox backlog."
---

# NoBrainer Wiki Tidy

Maintain trust with the smallest evidence-backed changes. Default to `AUDIT`:
scan and report before editing. Use `APPLY` only when the owner explicitly asks
for fixes and the exact candidates pass the gates below.

## Preflight

Resolve the wiki and read its rules, index, classification boundaries and git
state. Record pre-existing dirty files and active writers. Do not pull/rebase,
edit or delete in an overlapping dirty scope. Large vaults may be scanned in
parallel by independent defect class, but one coordinator owns the report and
any later writes.

## Audit classes

- index entry without a target and curated page missing from the index;
- exact dangling wikilinks and pages with no inbound links;
- stale-risk markers and time-sensitive claims past their verification date;
- uncited material claims or source references that no longer resolve;
- explicit contradictions and incompatible decisions;
- duplicate candidates based on evidence, not title similarity alone;
- unchecked inbox backlog and old processed items with provable promotion;
- classification leaks, credentials, personal data and unsafe public paths.

Every finding needs exact file/line, evidence, confidence and recommended action.
An orphan can be a valid entry page. A dangling link can be an intentional TODO.
A fuzzy title match is not permission to merge.

## Apply gates

Apply automatically only deterministic, reversible changes within the approved
scope: exact broken-link correction with a proven target, missing index link,
format normalization, or removal of a processed inbox line whose payload is
proven present in a cited page and meets the retention rule.

Require an owner decision for semantic merges, deleting pages/sources, choosing
between contradictions, changing classifications, broad rewrites or uncertain
link targets. Preserve both claims and add a contradiction marker until decided.

Before each write verify current content has not changed since the audit. After
edits rerun link/index checks, secret/classification scan and scoped diff. Add one
log entry only for actual changes. Do not commit, push or publish unless
separately authorized and read back.

## Report

Return mode, files scanned, findings by severity/confidence, exact fixes applied,
items intentionally left unchanged, owner decisions, validation, dirty-state
constraints, rollback and one next action. Never report a clean wiki when parts
were inaccessible or scans were partial.
