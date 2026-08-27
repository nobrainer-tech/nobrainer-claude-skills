# Contributing

NoBrainer skills shape agent behavior. Treat them like executable control code,
not ordinary prose.

## Before changing anything

1. Read `AGENTS.md` and the target skill completely.
2. Search open and closed issues and pull requests for the same problem.
3. Describe a real failure, missing workflow, or observed friction. Generic
   cleanup is not enough reason to rewrite a tuned skill.
4. Confirm the change belongs in this portable core rather than a project- or
   client-specific plugin.

## Skill changes

- Change one behavioral concern at a time.
- Start with a scenario that demonstrates the current gap.
- Preserve the baseline, then make the smallest reversible change.
- Re-run the same scenario and adversarial/non-trigger controls.
- Use independent forward testing for complex routing or safety changes.
- Keep detailed templates in `references/` and deterministic helpers in
  `scripts/`; do not add a README inside a skill folder.
- Keep `SKILL.md` concise, imperative and free of client-specific tool names
  unless that tool is the skill's explicit domain.

## Public repository rules

- Never commit secrets, tokens, cookies, personal data, private paths, internal
  hosts or private client names.
- Use one canonical skill name. Put `nb-*` aliases in `description`; do not
  create duplicate alias directories.
- Official Superpowers is an external dependency. Do not vendor, rename or copy
  its skills here.
- Generated visuals require exact-text review, descriptive alt text and sensible
  compression before use.

## Required checks

```bash
python3 scripts/validate_skills.py
python3 scripts/validate_skills.py --suite
python3 -m unittest discover -s tests -v
```

Run every changed helper with its actual interpreter. Scan for secrets and
review the complete diff before pushing.

## Pull requests

Use the pull-request template. State the problem, scope, authoring environment,
tests, behavior evidence, compatibility proof level, uncertainty and rollback.
One PR should tell one coherent story. A human owner approves merge and release.
