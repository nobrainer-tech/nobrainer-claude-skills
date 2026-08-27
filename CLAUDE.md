# AGENTS.md — working in this repo

Guidance for any AI agent (or human) adding to or editing skills in
`nobrainer-claude-skills`. This is a **public** repo of Claude Code skills.
`CLAUDE.md` is a verbatim copy of this file — edit both together, or edit this
one and copy it over.

## What a skill is here

- One skill = one directory containing a `SKILL.md`.
- `SKILL.md` starts with YAML frontmatter:
  ```yaml
  ---
  name: my-skill                     # MUST equal the directory name (kebab-case)
  description: >-
    One or two sentences on what it does, then the trigger phrases the user
    would say — "do X", "/my-skill", "zrób Y". The router matches on this text.
  ---
  ```
- The body is the instructions the model follows when the skill loads. Write for
  an agent executing it, not for a human reading docs: concrete steps, exact
  commands, stop conditions, and what to verify before declaring done.
- A skill may ship companion files (scripts, templates, a reference `.md`).
  Keep it **self-contained** — reference files by a skill-relative path, never
  an absolute machine path.

## Naming & structure

- Directory name = `name` in frontmatter = `kebab-case`. They must match, or the
  skill won't index reliably.
- The file is `SKILL.md` (uppercase). Not `skill.md`.
- Keep one concept per skill. If a skill does two unrelated things, split it.

## Public-clean rules (non-negotiable — this repo is public)

- **No secrets.** No API keys, tokens, passwords, AWS account IDs, cert bodies.
  If a skill needs them, externalize to a gitignored `.env` and ship a
  `.env.example` with placeholders.
- **No machine-specific absolute paths.** Never `~/.claude/skills/<user>/...`,
  `/Users/<name>/...`, or a hardcoded home dir. Use a skill-relative path,
  `$VAR`, or a generic placeholder like `/path/to/thing`.
- **Shell-safe placeholders.** In a bash snippet, never write `<placeholder>` —
  a leading `<` is input redirection and breaks copy-paste. Use `/path/to/x`
  or `$VAR`.
- **No private client or company names**, internal hostnames, or personal data.
- **No emoji** in code, commands, or commit messages.

## Adding or changing a skill

1. Create `my-skill/SKILL.md` with matching frontmatter.
2. Keep it self-contained and public-clean (rules above).
3. Verify it: read your own instructions as if executing them cold — can an
   agent follow every step without guessing? Run any shipped script (`bash -n`
   at minimum). Don't claim it works without checking.
4. Update `README.md` — add a row to the right table (name, one-line, trigger).
5. Branch + PR (see below). GitHub Copilot review is enabled on this repo;
   address its comments before/after merge.

## Git workflow

- Never commit straight to `main`. Branch, push, open a PR, merge after review.
- Small, focused commits and PRs — one concern per PR (a new skill, a fix, a
  docs pass), not a grab-bag.
- Don't include unrelated untracked files (e.g. another branch's leftovers) in
  your commit — add files explicitly rather than `git add -A` when the working
  tree has stray files.
- The token used here may lack `workflow` scope; don't add/modify
  `.github/workflows/*` in an unrelated PR.

## Verification before done

Would a senior engineer merge this as-is? Frontmatter valid, name matches dir,
no secrets/private paths, snippets copy-paste-safe, README updated, scripts at
least syntax-checked. If any is "no" or "maybe", fix it before opening the PR.

<!-- ENG-RULES:START -->
## Engineering rules

The waste in AI-written code is not wrong code — it is too much code. Left alone,
an agent pulls in three dependencies and five layers of abstraction for something
the standard library does in ten lines; asked to fix it, it writes two hundred
more. These rules exist to stop that before the first line is written: don't
write what needn't be written, reuse what can be reused, don't complicate what
can stay simple.

1. **Do not preserve backward compatibility.** Delete what is obsolete. No
   compatibility layers, no migrations, no leftover fallbacks.
2. **Choose the simplest implementation that meets the current requirement.**
   No pre-emptive abstraction, no configuration layer nobody asked for.
3. **Grow the system in layers.** Get a minimal end-to-end version working
   first, then add on top of it. Never tear down something that works for the
   sake of unfinished complexity.
4. **Keep components modular and concerns separated.**
5. **Prefer mature, maintained libraries.** Do not rewrite one yourself without
   a clear reason.
6. **Check what the project's existing dependencies already do** before adding a
   package or writing your own. Do not assume a library lacks a capability —
   read its docs and types first.
7. **Make architectural decisions for the long term.** Do not accept a "this way
   for now, we'll swap it later" stopgap.
8. **Look at how mature products solve the same problem.** Use proven patterns
   instead of inventing from zero.

**Exception to rule 1 — anything holding state or money.** A service on a cron
touching a live account, a repo mid-migration, an API with external consumers:
there, deleting an "obsolete" path is an incident, not a cleanup. Rule 1 applies
only behind a test that covers the path being removed.

**Delegating to subagents.** Delegate when the work would otherwise flood this
context — reading across many files for one answer, independent tasks that can
run in parallel. Keep the conclusion, not the file dumps. Do it yourself when you
already know the file and symbol; a subagent that must rediscover your context
costs more than the lookup saves. Give each one a scoped task and say what to
return. Never let a subagent's unverified conclusion drive a destructive step.
<!-- ENG-RULES:END -->

## Design principles

**YAGNI outranks the rest.** Build for the requirement in front of you, not the
one you expect next quarter — you will guess wrong, and an abstraction built for
the wrong guess is harder to remove than the duplication it replaced.

**KISS.** The simplest thing that fully works wins. Complexity must be argued
for, never assumed. If explaining a solution needs a diagram, look for the one
that doesn't.

**DRY — for knowledge, not for text.** Deduplicate a *rule* that lives in two
places and must change together. Do not deduplicate two things that merely look
alike today: three call sites with a similar shape and different reasons to
change want three implementations, not one helper with a `mode` flag. Premature
DRY violates rule 2 while feeling virtuous. Wait for the third repetition *and* a
shared reason to change before extracting.

**SOLID, in the order it pays off:**
- **S** — one reason to change per unit. This one carries the others.
- **D** — depend on interfaces at real seams (I/O, network, clock, storage) so
  the thing stays testable. Not everywhere; an interface per class is noise.
- **O/L/I** — apply once a real second implementation exists. Designing for
  extension that never arrives is YAGNI wearing a suit.

## Comments

Comments explain **why**, never **what**. The code already states what it does;
if it doesn't, fix the code instead of narrating it.

Write one only where a reader would otherwise ask "why on earth is it like
this": a non-obvious constraint, a bug being worked around, a trade-off taken on
purpose, an ordering that looks arbitrary and isn't. Everything else is debt that
goes stale and starts lying.

Delete on sight: commented-out code, `// step 1`, restatements of the line below,
docstrings echoing the signature, and TODOs with no owner or date.

Match the density of the surrounding file. A file with no comments is telling you
something.

## Configuration and constants

**Nothing is hardcoded that could differ between environments, runs, or
accounts.** Paths, hostnames, ports, URLs, credentials, timeouts, retry counts,
limits, model names, feature flags — configuration, not literals.

- Read from env or a config file, and fail loudly at startup when a required
  value is missing rather than defaulting silently into wrong behaviour.
- A default is fine when it is safe everywhere: `TIMEOUT_MS = 30_000` at module
  scope with an env override, yes; the same number buried in three call sites,
  no.
- **Secrets never appear in source, logs, or commit messages** — env or the
  system keychain only.
- Magic numbers and repeated string literals get a named constant. The name is
  the documentation.
- One source of truth per value. The same limit defined twice will diverge, and
  the resulting bug is expensive to find.
