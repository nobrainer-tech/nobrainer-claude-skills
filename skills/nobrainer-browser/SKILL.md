---
name: nobrainer-browser
description: "Use when the owner says nb-browser or nobrainer-browser, asks to inspect or operate a rendered website, attach to an existing approved Chrome/Edge session, reproduce a browser flow, run Playwright tests, or record and analyze a Playwright trace. Prefer the latest Playwright CLI; do not set up MCP or extra browser plugins by default."
---

# NoBrainer Browser

Use one Playwright-first browser path. The agent-focused `@playwright/cli`
drives and inspects pages; the repository's Playwright test CLI records and
opens traces. Do not add a second browser framework merely because one exists.

## Route the task

| Need | Default |
|---|---|
| Inspect a rendered page, follow navigation, read dynamic content | `playwright-cli` |
| Reuse an approved logged-in Chrome/Edge session | `playwright-cli attach` over CDP |
| Run or debug repository tests | the repository's `npx playwright test` |
| Record or inspect failure evidence | Playwright trace + `show-trace` |
| Plain static content already available without a browser | use the cheaper read path |

Do not install MCP when the CLI covers the task. Do not install a browser
plugin as the default path. Reuse an already configured MCP only when the
current harness cannot run the CLI and the MCP has fresh capability readback.

## Capability and install gate

First inspect the repository and machine:

```bash
command -v playwright-cli && playwright-cli --version
test -f package.json && npm exec playwright -- --version
npm view @playwright/cli dist-tags.latest --json
```

For interactive agent work, prefer the current npm `latest` channel and record
the exact version after installation:

```bash
npm install -g @playwright/cli@latest
playwright-cli --version
playwright-cli --help
playwright-cli --help attach
```

Package installation is a machine write. Perform it only when setup is within
scope, and do not claim success until the binary readback passes. For a test
repository, prefer its lockfile and package scripts over changing dependencies.

The CLI also offers `playwright-cli install --skills`. Do not run it by default
while `nobrainer-browser` owns browser routing: that would add another skill
owner with overlapping triggers. Read the live CLI help instead. If the owner
chooses the upstream Playwright skills, reconcile to one browser-skill owner
rather than keeping both active.

## Existing-session attach

Use attach when the owner needs the actual approved session, login or open tab:

```bash
playwright-cli attach --cdp=chrome
playwright-cli attach --cdp=http://127.0.0.1:9222
# Example for a separately configured Edge debugging endpoint:
playwright-cli attach --cdp=http://127.0.0.1:9333
```

The current CLI accepts a supported channel such as `chrome` or an actual CDP
endpoint URL; verify the live `attach` help because this interface can change.
CDP attach is Chromium-only. Confirm the exact browser, profile, endpoint and
write scope before acting. The CLI also exposes extension attach, but that is
not the default because it requires a browser extension. If attach is
unavailable, say so; do not bypass a saved browser permission block, copy or
mirror a profile, extract cookies, reuse credentials, or silently launch a
look-alike authenticated session. A request to inspect does not authorize form
submission, purchase, publication, message sending, deletion or account
changes.

If no existing login is required, a disposable session is simpler:

```bash
playwright-cli open https://example.com
```

## Inspect and operate

Take a fresh snapshot before using element references, and refresh it after a
navigation or substantial DOM change:

```bash
playwright-cli snapshot
playwright-cli find "Settings"
playwright-cli click e4
playwright-cli fill e7 "value"
playwright-cli eval "el => el.textContent" e4
```

Prefer semantic refs and visible state over brittle coordinates. For each
material action, verify the resulting URL, visible state or downloaded artifact
instead of trusting command exit alone.

## Tests and traces

Use the repository's existing script/config first. Narrow the test target and
record a trace when reproduction or evidence matters:

```bash
npx playwright test path/to/spec --trace on
npx playwright show-report --port 0
npx playwright show-trace trace.zip
```

For a live CLI flow:

```bash
playwright-cli tracing-start
playwright-cli snapshot
# perform the bounded steps
playwright-cli tracing-stop
```

Locate the actual trace artifact, preserve its path and open it. Review Actions,
DOM snapshots, Network, Console and Source; a green status without the expected
side effect is not proof. Use `--port 0` for a remote/headless viewer. Do not
edit project trace policy merely to inspect one failure when a CLI flag is
sufficient.

## Failure and closeout

- If the CLI, target session or required permission is unavailable, stop with
  the exact failed probe and one remediation.
- If a trace cannot reproduce the issue, report `NOT_REPRODUCED`; do not invent
  a cause.
- For an attached external session use `playwright-cli detach`; never close it.
  Close only a disposable session owned by this CLI run.
- Report the exact CLI version, browser/session mode, pages or tests inspected,
  trace/report paths, observed result, side effects, uncertainty and cleanup.

Sources: [Playwright test CLI](https://playwright.dev/docs/test-cli),
[Trace Viewer](https://playwright.dev/docs/trace-viewer), and
[`@playwright/cli` on npm](https://www.npmjs.com/package/@playwright/cli).
