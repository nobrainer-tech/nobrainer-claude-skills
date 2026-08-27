# NoBrainer Tech Skills repository instructions for Copilot

The nine canonical Agent Skills are under `skills/`; retired predecessors exist
only in Git history. Read the relevant `skills/<name>/SKILL.md` before changing
a skill.

For a non-trivial delivery workflow start with `nobrainer-ultra`. Use
`nobrainer-sessions` only when visible handoff, isolation, resume, or real
parallel benefit justifies coordination. Worker reports require independent
receive-audit before state advances.

Keep `SKILL.md` portable: line-1 YAML frontmatter with only `name` and
`description`, directory/name match, relative companion links, no secrets,
private paths, private client data, hardcoded model vendors, or unsafe shell
placeholders. Run `python3 scripts/validate_skills.py --suite` and the relevant
tests before reporting success.

Superpowers is an external dependency for implementation methods. Do not copy or
fork its skills into this repository.
