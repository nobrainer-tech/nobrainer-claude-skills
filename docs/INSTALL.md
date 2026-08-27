# Installation

NoBrainer Tech Skills keeps one canonical `skills/` directory. Install that
same source for each client; do not maintain client-specific forks.

This repository currently proves portable source and local repository contracts,
not client loading, public marketplace distribution or clean-client runtime.
Prefer an immutable reviewed commit. After installation, perform the readback in
[`COMPATIBILITY.md`](COMPATIBILITY.md) before saying a harness is supported in
your environment.

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

The default installs the complete nine-skill curated set. Use `--mode copy` if
symlinks are unsuitable. Repeat `--skill NAME` only for a deliberate exact
subset. On error, entries created by that run are rolled back.

Before any write, the installer verifies that the checkout contains exactly the
nine reviewed skill entrypoints. A missing or additional `SKILL.md` is inventory
drift and blocks both default and subset installation until it is reviewed.

## Claude Code

For a local checkout:

```bash
python3 scripts/install_skills.py --client claude --apply
```

The repository also includes `.claude-plugin/plugin.json`, a development
marketplace manifest and `hooks/hooks.json`. A plugin install can add the small
shared bootstrap at session start; a skills-only install cannot. Restart the
client and confirm both `nobrainer-ultra` discovery and the first routing action.

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
The manifest also binds `hooks/hooks-cursor.json`, which injects the same small
bootstrap using Cursor's own `additional_context` shape.

## OpenCode

Follow [the OpenCode adapter guide](../.opencode/INSTALL.md), or use the local
skills installer:

```bash
python3 scripts/install_skills.py --client opencode --apply
```

The git package adapter registers `skills/` through OpenCode's config hook and
prepends the small shared bootstrap to the first user message once. It detects
its marker on repeated transforms and never copies all skill bodies into the
prompt.

## GitHub Copilot

Copilot supports Agent Skills in personal skill directories. Install the same
canonical folders:

```bash
python3 scripts/install_skills.py --client copilot --apply
```

For work inside this repository, `.github/copilot-instructions.md` tells Copilot
where the canonical skills and validators live. Confirm skill discovery in the
actual Copilot surface you use.

This repository does not claim an automatic Copilot startup hook. A personal
skills install relies on native discovery and the instructions available in the
active repository. Prove the exact Copilot surface before promoting support.

## Gemini CLI

The extension manifest points at the extension-owned `GEMINI.md`, which includes
only `adapters/bootstrap.md`. A candidate Git install is:

```bash
gemini extensions install https://github.com/nobrainer-tech/nobrainer-tech-skills
```

Do not claim success from installation output alone. Start a clean session,
confirm the extension context is loaded, and verify native discovery of
`nobrainer-ultra` from the same checkout.

## Kimi Code

The Kimi manifest exposes `./skills/`, selects `nobrainer-ultra` at session start
and maps only real Kimi tools. Install from the repository in the plugin manager
or with its Git URL, then start a fresh session:

```text
/plugins install https://github.com/nobrainer-tech/nobrainer-tech-skills
```

Kimi `Agent` workers do not become visible NoBrainer sessions merely because
they run in parallel. If exact session identity and report transport are absent,
the workflow must remain in the current MAIN session.

## Devin CLI

There is deliberately no dedicated Devin manifest in this repository: the
current plugin and startup contract has not been proved against an installed
client. If the Devin version in use supports portable Agent Skills, point it at
the canonical `skills/` folders using that version's official instructions, then
run the clean-session acceptance. Until then, compatibility is source-only.

## Pi

The root package declares the canonical skills and a zero-dependency extension
that injects the shared bootstrap at session start and once again after
compaction when needed:

```bash
pi install git:github.com/nobrainer-tech/nobrainer-tech-skills
```

For a local checkout, use Pi's temporary package flag. Confirm resource
discovery and the first action in a clean session; optional subagent packages do
not substitute for NoBrainer's visible-session contract.

## Hermes Agent

The root `plugin.json` follows Agent Plugins v1, which current Hermes releases
can install as a portable plugin:

```bash
hermes plugins install nobrainer-tech/nobrainer-tech-skills --enable
```

Hermes imports portable plugin skills under its own namespace and requires
explicit skill selection. This repository does not add a native Hermes hook or
automatic bootstrap. Restart after installation, inspect the imported skill
names and run the clean-session acceptance before claiming runtime support.

## Other Agent Skills or plugin hosts

Antigravity, Factory Droid, Grok Build CLI and future hosts may be able to
consume the canonical folders or root Agent Plugin manifest. Use the current
client's official install path and record exact discovery, hook consumption and
clean-session behavior. A shared file layout is not evidence that a host loads
the Claude or Cursor bootstrap.

## Superpowers dependency

NoBrainer Tech Skills owns lifecycle, visible sessions, specifications,
decision/RCA protocols, evaluation loops and durable knowledge. Official
Superpowers owns implementation methods such as brainstorming, planning, TDD,
systematic debugging, worktrees, review and verification.

Install the current official release separately for every harness. Do not copy
its skills into this repository and do not keep an older local wrapper with the
same names. See the official project:
https://github.com/obra/superpowers

## Dynamic specialist discovery

Do not permanently install a broad community pack pre-emptively. When a task has
a real capability gap:

1. Check the installed NoBrainer set.
2. Prefer the task's maintained first-party CLI, API or existing project tool.
3. Search the open skills ecosystem only if a reusable instruction set would
   materially help:

   ```bash
   npx skills find "$SKILL_QUERY"
   npx skills use "$SKILL_SOURCE@$SKILL_NAME"
   ```

The official `skills` CLI supports discovery and one-off `use` without a
permanent install. It also collects anonymous usage telemetry by default, so do
not invoke it where network or telemetry policy forbids that behavior.

Treat every external skill as untrusted input. Before use, inspect the exact
repository/ref, `SKILL.md`, companion scripts, license, requested permissions,
network/credential behavior and overlaps with installed triggers. Prefer an
immutable source ref. For a persistent install, use a reviewed project-local
source and require owner approval; do not silently add it globally or execute
its scripts. Record source/ref, reason, checks and rollback.

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
