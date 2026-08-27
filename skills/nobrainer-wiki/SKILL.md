---
name: nobrainer-wiki
description: "Use when the owner says nb-wiki or asks to create, connect, or govern a durable Markdown knowledge base that agents and humans can query across projects or sessions; do not use for transient task state."
---

# NoBrainer Wiki

Create a small, trustworthy knowledge system only when information should
compound across tasks. This skill is explicitly inspired by Andrej Karpathy's
[LLM wiki concept](https://gist.github.com/karpathy/442a6bf555914893e9891c11519de94f)
and adapts it into a portable, multi-client workflow. It is not an official
Karpathy project.

Use `nobrainer-wiki-add` to ingest/promote, `nobrainer-wiki-get` to query and
`nobrainer-wiki-tidy` to audit or maintain. Read
[references/setup.md](references/setup.md) before changing a project or vault.

## Decide whether a wiki is justified

Prefer normal repository documentation when knowledge is local to one codebase
and already discoverable. A wiki is justified when durable decisions, sources,
research or operational knowledge must be queried across tasks, sessions or
tools and would otherwise be repeatedly reconstructed.

Do not store live execution state, leases, current hashes, transient blockers,
credentials or secrets in the wiki. A spec defines a contract; a plan orders
work; a wiki preserves reusable knowledge. Do not merge those roles.

## Durable personalization without hidden memory

The wiki may preserve an owner's explicit, reusable preferences, corrections,
decisions and verified working patterns when the repository's confidentiality
rules allow it. Each entry needs source, date, scope and certainty. Label an
inference as an inference; do not turn one interaction into a permanent trait.

At task start, retrieve only pages relevant to the current project and outcome.
At close, capture only information likely to matter again. Keep transient task
details out, let the owner correct or remove learned preferences, and never
promote private personalization into a public repository. This makes knowledge
compound without creating an opaque behavioral profile or an ever-growing
context dump.

## Model

Keep four concerns distinct while adapting their actual folder names to the
existing vault:

1. raw sources: preserved provenance, not silently edited or treated as truth;
2. curated pages: one concept or entity, concise, linked, cited and dated;
3. map and rules: `index.md` plus a rules file such as `WIKI.md`;
4. capture and history: per-writer inbox plus an append-only change log.

The confidentiality boundary outranks topic taxonomy. Public, internal and
confidential knowledge must not share an accidental promotion path.

## Safe setup

Run a read-only preflight first:

- resolve the actual project/vault and owner; do not assume a default path;
- read existing instructions, map, wiki rules, folder conventions and git state;
- inspect managed marker pairs in every proposed instruction file;
- detect existing sources/pages/inbox/log, sync model, writers and automation;
- classify the target as public, internal or confidential;
- compare existing structure with the minimal model above.

Do not initialize a repository, pull/rebase, truncate, relocate or overwrite an
existing file just because the template differs. A dirty overlapping scope,
unpaired managed marker, unknown target classification or conflicting writer is
`BLOCKED`; report the exact evidence and safe repair.

When setup is authorized, preserve existing conventions and create only missing
pieces. Use one source of truth and one inbox per independent writer/machine.
Merge a concise `NB-WIKI` managed block into the project's established agent
instructions. Replace only a complete paired block; never rewrite content around
malformed markers.

## Optional automation

Manual capture and promotion are the default. Propose scheduled promotion only
after volume justifies it. Automation needs a bounded trigger/input/output,
single state owner, clean-tree policy, idempotence, retry budget, conflict stop,
secret filtering, dry run, logs and rollback.

Creating a scheduler, committing/pushing, publishing, or granting credentials is
an owner gate at action time. A failed pull, conflict, partial synthesis or
transport error must stop; it must not continue and publish stale state.

## Close gate

Verify by readback:

- all created files exist and no existing content was lost;
- instruction markers are exactly one matched pair and surrounding content is
  byte-preserved;
- index links resolve, inbox ownership is unambiguous and classification rules
  are explicit;
- no secrets, customer data or machine-specific values entered public templates;
- ordinary query remains read-only and write operations route to the correct
  companion skill;
- diff is scoped and rollback restores the exact previous state.

Report what was reused, added, deliberately omitted, verified, blocked and how
to roll back. Do not claim cross-client installation without reading each
client's actual instruction file or capability after setup.
