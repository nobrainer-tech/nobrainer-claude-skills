# NoBrainer Tech Skills repository instructions for Copilot

The fourteen canonical Agent Skills are under `skills/`; retired predecessors exist
only in Git history. Read the relevant `skills/<name>/SKILL.md` before changing
a skill.

For a non-trivial delivery workflow start with `nobrainer-ultra`. Use
`nobrainer-team` for roles, `nobrainer-dispatcher` for an approved queue with
multiple delegated units, and `nobrainer-sessions` for exact transport. Worker
reports require independent receive-audit before state advances.

Keep `SKILL.md` portable: line-1 YAML frontmatter with only `name` and
`description`, directory/name match, relative companion links, no secrets,
private paths, private client data, hardcoded model vendors, or unsafe shell
placeholders. Run `python3 scripts/validate_skills.py --suite` and the relevant
tests before reporting success.

Use `nobrainer-build` for implementation, `nobrainer-security` for material
trust boundaries and `nobrainer-review` for the final evidence gate.
