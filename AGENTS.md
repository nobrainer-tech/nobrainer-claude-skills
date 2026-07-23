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
