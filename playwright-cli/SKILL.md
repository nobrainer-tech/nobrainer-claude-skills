---
name: playwright-cli
description: >-
  Drive the latest Playwright from the command line — the agent-focused
  @playwright/cli (attach to an existing browser over CDP, snapshot/click/eval,
  built-in tracing) AND the classic test CLI (test, codegen, show-report, and the
  trace viewer show-trace). Covers reading traces, binding to an already-running
  logged-in Chrome/Edge session, and the newest Playwright features. Cross-platform:
  macOS, Windows, and Windows/WSL. Use when the user says "playwright cli",
  "read a trace", "show trace", "attach to my browser", "connect to existing
  chrome", "codegen", "playwright latest", or wants CLI browser automation.
---

# playwright-cli

Two complementary command-line surfaces for the latest Playwright. Pick by task:

| You want to… | Use |
|--------------|-----|
| Let an agent drive a browser step-by-step, attach to a live session, snapshot/click/eval | **`@playwright/cli`** (`playwright-cli`) |
| Run tests, generate code, open the **trace viewer**, show the HTML report, UI mode | **classic test CLI** (`npx playwright …`) |

Both install the newest Playwright. `connectOverCDP` / `--cdp` attaching is **Chromium-only** (Chrome/Edge).

## Install (latest, cross-platform)

```bash
# agent CLI — step-by-step browser control for coding agents
npm install -g @playwright/cli@latest
playwright-cli --help
playwright-cli install --skills          # register skills for Claude Code / Copilot

# classic test/runner CLI
npm install -g playwright@latest          # or: npm i -D @playwright/test@latest
npx playwright install                    # download Chromium/Firefox/WebKit
```

- **Windows/WSL (running Playwright inside WSL):** browsers need Linux deps —
  `npx playwright install --with-deps` (installs the OS packages too). Use a
  WSL2 distro; on headless WSL, view UIs with `--port 0` (opens in your default
  browser, i.e. the Windows browser via `wslview`/`xdg-open`).
- For `connectOverCDP`/`--cdp` you do **not** need `playwright install` — you're
  attaching to a browser that already exists.

## Bind to an existing (logged-in) browser session

The big one: don't launch a throwaway browser — attach to a real, already-logged-in
session (cookies, storage, even e2ee content that no API exposes).

**Agent CLI — `attach`:**
```bash
playwright-cli attach --cdp=chrome                 # auto-find a local Chrome
playwright-cli attach --cdp=msedge                 # Edge
playwright-cli attach --cdp=http://localhost:9222  # explicit CDP endpoint
playwright-cli attach --extension=chrome           # via the Playwright browser extension
playwright-cli snapshot                            # then read the page, get element refs
playwright-cli find "Inbox"
```

**Library — `connectOverCDP`:**
```js
import { chromium } from 'playwright';
const b = await chromium.connectOverCDP('http://127.0.0.1:9222');
const page = b.contexts()[0].pages()[0];   // the existing logged-in tab
// ... read / act ...
await b.close();  // detaches CDP only — does NOT close the user's browser
```

The target Chrome/Edge must have been started with `--remote-debugging-port`:
```bash
# macOS
"/Applications/Google Chrome.app/Contents/MacOS/Google Chrome" \
  --remote-debugging-port=9222 --user-data-dir="/path/to/a/profile-dir"
# Windows (PowerShell)
& "C:\Program Files\Google\Chrome\Application\chrome.exe" `
  --remote-debugging-port=9222 --user-data-dir="C:\path\to\a\profile-dir"
```

> [!warning] Chrome 136+ blocks debugging on the DEFAULT profile
> Since Chrome 136, `--remote-debugging-port` is ignored on the **default**
> `user-data-dir`, so you can't attach to the everyday browser directly. Run a
> dedicated Chrome on a **copy (mirror)** of that profile in its own
> `--user-data-dir`: it carries the real logins, and — being a non-default dir —
> allows debugging AND runs alongside the everyday browser. Cookies keep
> decrypting because the cookie key lives in the OS keychain/credential store,
> not the profile. (Refresh the mirror after logging into new accounts.)

**WSL → attach to Windows Chrome:** run Chrome on Windows with the debug port,
then from WSL point the endpoint at the Windows host. On recent WSL2 with mirrored
networking `http://localhost:9222` works; otherwise use the host IP:
```bash
WIN_HOST=$(ip route show default | awk '{print $3}')   # or: grep nameserver /etc/resolv.conf | awk '{print $2}'
playwright-cli attach --cdp="http://$WIN_HOST:9222"
```
(Start Chrome on Windows with `--remote-debugging-address=0.0.0.0` so WSL can reach it.)

## Read / show traces

```bash
# open a recorded trace in the Trace Viewer GUI
npx playwright show-trace trace.zip
# open it in a browser tab on a random port — best for headless/WSL/remote
npx playwright show-trace --port 0
```
Record traces from the test runner via config, then view the failures:
```js
// playwright.config.ts
export default { use: { trace: 'on-first-retry' } };  // or 'on', 'retain-on-failure'
```
Agent CLI has built-in tracing for a live session:
```bash
playwright-cli open https://example.com
playwright-cli tracing-start
playwright-cli click e4
playwright-cli fill e7 "test"
playwright-cli tracing-stop      # writes a trace you can show-trace
playwright-cli close
```
Reading a trace tells you exactly what happened: the **Actions** timeline, DOM
**Snapshots** (before/after each step), **Network**, **Console**, and **Source** —
never trust a bare "passed"; open the trace to confirm side effects.

## Newest features worth knowing

- **UI mode** — `npx playwright test --ui` (watch/run/debug interactively);
  `--ui-port 0` opens it in a browser tab on a random port (headless/remote/WSL).
- **Agent CLI** (`@playwright/cli`) — token-efficient, ref-based control designed
  for coding agents; `snapshot` returns element refs, `find`/`--regex` searches
  the snapshot, `eval` runs JS on a ref. `install --skills` wires it into agents.
- **ARIA snapshots** — accessibility-tree snapshots for stable, human-readable
  assertions (`expect(locator).toMatchAriaSnapshot(...)`).
- **Selective runs** — `--only-changed` (only tests touching changed files),
  `--last-failed`, `-g <regex>`, `--project <name>`.
- **Codegen targets** — `npx playwright codegen --target=python|java|csharp <url>`
  records a session and emits code in your language.
- **Clock API** — control time in tests (`page.clock`) for timers/date-dependent UI.

## Quick reference

```bash
npx playwright test [--ui|--headed|--debug|-g re|--project p|--only-changed|--last-failed]
npx playwright codegen [--target=lang] [url]
npx playwright show-report [--port N]
npx playwright show-trace [--port 0] [trace.zip]
npx playwright install [--with-deps] [chromium|firefox|webkit]

playwright-cli open|goto|click|fill|type|snapshot|find|eval|hover|select|upload|resize
playwright-cli attach --cdp=chrome|msedge|http://host:9222 | --extension=chrome
playwright-cli tracing-start | tracing-stop | close
```

## Notes

- `connectOverCDP` / `--cdp` is Chromium-only (Chrome, Edge). Firefox/WebKit
  can't be attached this way.
- Prefer `--port 0` / `--ui-port 0` on headless or WSL boxes so the viewer opens
  in whatever browser is available instead of failing to find a display.
- Pin an exact version instead of `@latest` if you need reproducible CI, but for
  interactive/agent use `@latest` keeps you on current features and fixes.
