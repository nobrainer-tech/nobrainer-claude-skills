# Installing NoBrainer Tech Skills for OpenCode

Add the git-backed package to the `plugin` array in the global or project
`opencode.json`:

Use an immutable reviewed commit, not the moving default branch. Replace the
example ref only after the new commit passes the repository suite and its
public-clean/readback checks. For pre-merge review, use a local checkout and
explicit skills path instead.

```json
{
  "plugin": [
    "nobrainer-tech-skills@git+https://github.com/nobrainer-tech/nobrainer-tech-skills.git#881bcafad8d1a7c2708b80186ef33400ac67f343"
  ]
}
```

The example is intentionally pinned to a full commit. After a reviewed
release, update the ref and record the new SHA in the release notes; do not
silently follow `main`.

Restart OpenCode, list native skills, and confirm `nobrainer-ultra` is present.
The adapter only registers the canonical `skills/` directory; it does not inject
an always-on prompt or copy archived skills into discovery.

Install official Superpowers separately when you want its implementation
methods. NoBrainer Tech Skills routes to it but does not vendor it.

For a local checkout, either use `scripts/install_skills.py --client opencode`
or configure the checkout's `skills/` directory as an OpenCode skills path.
See [the full installation guide](../docs/INSTALL.md).
