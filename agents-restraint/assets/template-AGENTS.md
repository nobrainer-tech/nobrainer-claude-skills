# AGENTS.md

<!-- Universal starting template. Copy to the repo root as both AGENTS.md and
     CLAUDE.md. Delete any section that does not apply to this project —
     see "Keep this file short" at the bottom for why that matters. -->

## Engineering rules

The waste in AI-written code is not wrong code — it is too much code. Left alone,
an agent pulls in three dependencies and five layers of abstraction for something
the standard library does in ten lines; asked to fix it, it writes two hundred
more.

1. **Do not preserve backward compatibility.** Delete what is obsolete. No
   compatibility layers, no migrations, no leftover fallbacks.
2. **Choose the simplest implementation that meets the current requirement.**
   No pre-emptive abstraction, no configuration layer nobody asked for.
3. **Grow the system in layers.** Get a minimal end-to-end version working
   first, then add on top of it. Never trade a working product for unfinished
   complexity.
4. **Keep components modular and concerns separated.**
5. **Prefer mature, maintained libraries.** Do not rewrite one without a clear
   reason.
6. **Check what the project's dependencies already do** before adding a package
   or writing your own. Read the docs and types before assuming a gap.
7. **Make architectural decisions for the long term.** No "this way for now,
   we'll swap it later".
8. **Look at how mature products solve the same problem.** Use proven patterns
   instead of inventing from zero.

**Exception to rule 1 — anything holding state or money.** A service on a cron
touching a live account, a repo mid-migration, an API with external consumers:
there, deleting an "obsolete" path is an incident, not a cleanup. Rule 1 applies
only behind a test covering the path being removed.

## Design principles

**YAGNI outranks the rest.** Build for the requirement in front of you. An
abstraction built for a guess is harder to remove than the duplication it
replaced.

**KISS.** Complexity must be argued for, never assumed.

**DRY — for knowledge, not for text.** Deduplicate a *rule* that lives in two
places and must change together. Three call sites that merely look alike and
change for different reasons want three implementations, not one helper with a
`mode` flag. Wait for the third repetition *and* a shared reason to change.

**SOLID, in the order it pays off.** **S** — one reason to change per unit;
this one carries the others. **D** — depend on interfaces at real seams (I/O,
network, clock, storage) so the thing stays testable; an interface per class is
noise. **O/L/I** — once a real second implementation exists.

## Comments

Comments explain **why**, never **what**. If the code doesn't say what it does,
fix the code instead of narrating it.

Write one only where a reader would otherwise ask "why on earth is it like
this": a non-obvious constraint, a bug being worked around, a deliberate
trade-off. Delete on sight: commented-out code, `// step 1`, restatements of the
line below, docstrings echoing the signature, TODOs with no owner or date.

## Configuration

**Nothing is hardcoded that could differ between environments, runs, or
accounts** — paths, hosts, ports, URLs, credentials, timeouts, limits, model
names. Read from env or config; fail loudly at startup on a missing required
value rather than defaulting silently into wrong behaviour. Secrets never appear
in source, logs, or commit messages. Magic numbers get a named constant; the
name is the documentation.

## Delegating to subagents

Delegate when the work would otherwise flood this context: reading across many
files to answer one question, independent tasks that can run in parallel, a
broad search whose intermediate output you don't need. Keep the conclusion, not
the file dumps.

Do it yourself when you already know the file and symbol — a subagent that has
to rediscover your context costs more than the lookup saves.

Give each subagent one scoped task and tell it what to return. A subagent that
reports "I looked at the auth module" wasted its run; one that reports "auth
refresh drops the retry header at client.ts:88" did the job.

Never let a subagent's conclusion through unverified when it drives a
destructive or irreversible step. Check the claim against the real code first.

## Verification before done

A task is finished when it is *proven* finished: tests run, output shown, the
command actually executed. "Should work" is not done.

Report failures with the failing output, say plainly when a step was skipped,
and never describe unrun code as working.

## Keep this file short

Every line here is loaded into **every** prompt in this repo, whether or not it
is relevant. A long AGENTS.md makes the agent weigh git conventions while fixing
a CSS bug — the instructions stop being guidance and become noise.

Karpathy's widely-copied `CLAUDE.md` is 65 lines. Treat that as the budget.

**This template is deliberately over budget** — it is a menu, not a finished
file. Cut it to the sections this repo actually needs, then delete this one.
Anything task-specific belongs in a skill that loads on demand, not here where
it is paid for on every turn.
