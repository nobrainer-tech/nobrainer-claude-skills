# Installing NoBrainer Tech Skills for OpenCode

Add the git-backed package to the `plugin` array in the global or project
`opencode.json`:

Use this package reference only after the release is present on the repository's
default branch. For pre-merge review, use a local checkout and explicit skills
path instead.

```json
{
  "plugin": [
    "nobrainer-tech-skills@git+https://github.com/nobrainer-tech/nobrainer-tech-skills.git"
  ]
}
```

Restart OpenCode, list native skills, and confirm `nobrainer-ultra` is present.
The adapter only registers the canonical `skills/` directory; it does not inject
an always-on prompt or copy archived skills into discovery.

Install official Superpowers separately when you want its implementation
methods. NoBrainer Tech Skills routes to it but does not vendor it.

For a local checkout, either use `scripts/install_skills.py --client opencode`
or configure the checkout's `skills/` directory as an OpenCode skills path.
See [the full installation guide](../docs/INSTALL.md).
