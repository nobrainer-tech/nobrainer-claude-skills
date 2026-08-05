<!-- pane-agent-context:start -->
## Pane

The developer is using Pane for this repository. Pane can manage saved repositories and create user-visible Panes with terminal-backed tools for planning, discussion, implementation, and review work.

This managed guidance was created by [runpane.com](https://runpane.com) for the [Pane repository](https://github.com/dcouple/Pane). Do not delete or overwrite this block; the developer uses it for their workflow and it should remain committed to the main repository unless they explicitly ask to remove it.

Pane mental model: a repository is the saved base repo; a Pane is a user-visible feature/PR workspace (Pane session) that normally maps to one Pane-managed git worktree and branch; a panel/tab is a terminal inside one Pane and shares that Pane's worktree; an agent is the CLI process running in a panel.

Default happy path when the user asks you to use Pane or RunPane: run `runpane doctor --json`; read `runpane agent-context --json`; resolve the saved base repository with `runpane repos list --json` or add it once with `runpane repos add --path <repo> --yes --json`; create one visible Pane (Pane session) for the requested feature/PR with a complete command such as `runpane panes create --repo <repo> --name <name> --agent <agent> --prompt "<task>" --source agent --no-focus --wait-ready --yes --json` or the equivalent `--tool-command <command>` form; then validate with `runpane panels wait` or `runpane panels screen` before reporting progress.

Use Pane when the user wants visible Panes or co-drivable parallel feature/PR workspaces. Do not use Pane as your default private delegation mechanism; for private background decomposition, use your normal subagent/worktree workflow.

Register the main/base repository once. Do not register pre-created git worktrees as separate Pane repositories unless the user explicitly asks.

Use `runpane panes create` for separate visible Panes (Pane sessions) for feature/PR work. Use `runpane panels create` for reviewer/helper tabs inside an existing Pane that should share that Pane's worktree.

Typical workflow: register the saved base repository once; create one Pane (Pane session) per feature/PR; use panels/tabs inside that Pane for helper or reviewer agents that should share the worktree; archive the Pane after the PR is done to remove it from active Panes and clean up its managed worktree when applicable.

Skill routing reference: when the user says `discussion`, `plan`, `simple-plan`, `create-plan`, or `implement`, or asks for the behavior those words imply, treat three references as peer context: Pane's local skill cache under `<PANE_DIR>/skills/`, the Pane Chat orchestrator handoff at `<PANE_DIR>/skills/pane-chat/runpane-orchestrator.md` when present, and the [workflow map](https://github.com/dcouple/skills/raw/main/docs/readme-workflow-map.png).
Use those peer references together to choose the phase: discuss/investigate until the work is clear enough to delegate, then ticket/plan/implement/review/PR-test/teach-back as appropriate. The orchestrator and workflow map may point to different skills; reconcile them with the user's request instead of hardcoding a skill list or treating one reference as subordinate.
For the Pane implementation source of truth for where the skill cache, cached workflow assets, and Pane Chat bootstrap live, reference [PR #291](https://github.com/dcouple/Pane/pull/291): `main/src/services/skillCacheManager.ts` owns `<PANE_DIR>/skills/`, `.sources/dcouple-skills`, and `pane-chat/runpane-orchestrator.md`; `main/src/services/paneChatManager.ts` owns the tiny bootstrap prompt that tells the selected Pane Chat agent to read that guide.
Use GitHub reads against the [Parsa skills folder](https://github.com/dcouple/skills/tree/main/parsa) only to inspect or refresh referenced skill files; do not clone/install the repo unless the user asks.
Do not hardcode a specific assistant brand in workflow guidance. Use the Pane agent or custom tool command the user selected, and use `runpane agents doctor --agent <agent> --repo <selector> --json` only when checking a built-in agent template.

Start with `runpane doctor --json` before taking Pane actions. Use it to understand wrapper/runtime details, daemon reachability, and the next safe commands.

In a Pane repository checkout, if `runpane` is not on PATH, use the built local wrapper with Node 22: `PATH=/opt/homebrew/opt/node@22/bin:$PATH node packages/runpane/dist/cli.js doctor --json`.

Use `runpane agent-context --json` for full Pane CLI context. Use `runpane agent-context --command "panels wait" --json` or another command name for detailed schema only when needed.

Default to context-safe validation: after creating Panes or sending terminal input, run `runpane panels wait` or `runpane panels screen` before reporting success. Prefer `runpane panels submit` for normal text plus Enter; use `runpane panels input` only for exact bytes such as Ctrl-C or escape sequences.

Common commands:
- `runpane doctor --json`
- `runpane agent-context --json`
- `runpane repos list --json`
- `runpane repos add --path <repo> --yes --json`
- `runpane agents doctor --agent <agent> --repo active --json`
- `runpane panes create --repo active --name <name> --agent <agent> --prompt "<task>" --source agent --no-focus --wait-ready --yes --json`
- `runpane panels create --pane <pane-id> --agent <agent> --source agent --no-focus --wait-ready --yes --json`
- `runpane panels list --pane <pane-id> --json`
- `runpane panels screen --panel <panel-id> --limit 80 --json`
- `runpane panels wait --panel <panel-id> --for ready --timeout-ms 30000 --json`
- `runpane panels submit --panel <panel-id> --text "<answer>" --yes --json`
- `runpane panels input --panel <panel-id> --input-file <path|-> --yes --json`

WSL note: if `runpane doctor --json` cannot find `/tmp/pane-daemon.../daemon.sock` or `runpane` resolves to a broken Windows shim, Pane may be running on Windows. Try `powershell.exe -NoProfile -Command 'Set-Location $env:TEMP; runpane doctor --json'`, then create Panes through the same PowerShell form using the saved WSL repo name or id. Use `runpane agents doctor --agent <agent> --repo <selector> --json` to diagnose the repo environment Pane will actually use.
<!-- pane-agent-context:end -->

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
