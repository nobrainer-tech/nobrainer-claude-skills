# Installation

NoBrainer Tech Skills keeps one canonical `skills/` directory. Install that
same source for each client; do not maintain client-specific forks.

## Before installing

1. Clone the repository.
2. Run `python3 scripts/validate_skills.py --suite`.
3. Dry-run the installer for the target client.
4. Install official Superpowers separately if you want the implementation
   methods used by `nobrainer-ultra`.

The local installer never overwrites an existing target. It defaults to a
dry-run and requires `--apply` before writing:

```bash
python3 scripts/install_skills.py --client codex
python3 scripts/install_skills.py --client codex --apply
```

Use `--mode copy` if symlinks are unsuitable. Repeat `--skill NAME` to install a
subset. On error, entries created by that run are rolled back.

## Claude Code

For a local checkout:

```bash
python3 scripts/install_skills.py --client claude --apply
```

The repository also includes `.claude-plugin/plugin.json` and a development
marketplace manifest for plugin packaging. Restart the client and confirm
`nobrainer-ultra` is discoverable.

## Codex

Use the Codex plugin manifest when installing through a compatible marketplace,
or install the local checkout:

```bash
python3 scripts/install_skills.py --client codex --apply
```

The `.codex-plugin/plugin.json` manifest points to `./skills/`. Restart Codex and
verify the loaded skill list rather than trusting the installer exit code.

## Cursor

Cursor supports the repository's `.cursor-plugin/plugin.json` and discovers the
canonical `skills/` directory. For local testing, link the entire repository
into Cursor's local plugin directory, reload the window, and inspect Customize:

```bash
ln -s /path/to/nobrainer-tech-skills ~/.cursor/plugins/local/nobrainer-tech-skills
```

Do not replace an existing target; remove or reconcile it explicitly first.

## OpenCode

Follow [the OpenCode adapter guide](../.opencode/INSTALL.md), or use the local
skills installer:

```bash
python3 scripts/install_skills.py --client opencode --apply
```

The git package adapter registers `skills/` through OpenCode's config hook and
does not inject a permanent prompt.

## GitHub Copilot

Copilot supports Agent Skills in personal skill directories. Install the same
canonical folders:

```bash
python3 scripts/install_skills.py --client copilot --apply
```

For work inside this repository, `.github/copilot-instructions.md` tells Copilot
where the canonical skills and validators live. Confirm skill discovery in the
actual Copilot surface you use.

## Superpowers dependency

NoBrainer Tech Skills owns lifecycle, visible sessions, specifications,
decision/RCA protocols, evaluation loops and durable knowledge. Official
Superpowers owns implementation methods such as brainstorming, planning, TDD,
systematic debugging, worktrees, review and verification.

Install the current official release separately for every harness. Do not copy
its skills into this repository and do not keep an older local wrapper with the
same names. See the official project:
https://github.com/obra/superpowers

## Verification and rollback

Run:

```bash
python3 scripts/validate_skills.py
python3 scripts/validate_skills.py --suite
python3 -m unittest discover -s tests -v
```

These checks prove the portable source and local adapters only. Follow
[`COMPATIBILITY.md`](COMPATIBILITY.md) for clean-session runtime proof; do not
infer client discovery from files on disk or an installer exit code.

For symlink installs, rollback is removing only the symlinks created in the
client's skills directory. For copy installs, remove only the copied NoBrainer
skill directories after confirming their names and contents. Never recursively
delete a broad skills root.

If a previous install left a symlink pointing at this checkout's deleted
root-level skill path or a known renamed predecessor, the installer reports
`LEGACY`/`LEGACY_ALIAS` and refuses to change it. Inspect every printed target,
then dry-run and apply the explicit migration:

```bash
python3 scripts/install_skills.py --client codex --migrate-legacy
python3 scripts/install_skills.py --client codex --migrate-legacy --apply
```

Only exact symlinks whose names and targets match the previous layout in this
same checkout are removed. Unknown symlinks, copied directories and foreign
targets remain conflicts. If installation fails, removed legacy links are
restored; an incomplete rollback is reported loudly. A dry run never removes or
replaces a target.
