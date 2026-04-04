---
name: agent-browser
description: >
  Vercel agent-browser — Rust CLI for AI-driven browser automation via CDP.
  Use when: "agent-browser", "browse website", "automate browser", "scrape with browser",
  "fill form", "click button", "take screenshot", "browser automation", "headless chrome",
  "web interaction", "accessibility snapshot", "browser refs". Deterministic ref-based selectors,
  JSON output, daemon architecture. Replaces Playwright/Puppeteer for agent workflows.
---

# agent-browser — AI Browser Automation CLI

Rust-native CLI by Vercel Labs. Persistent daemon per session, CDP-based, deterministic ref selectors (`@e1`, `@e2`), JSON output. Built for AI agents.

**Repo:** github.com/vercel-labs/agent-browser | **License:** Apache 2.0

## Install

```bash
# npm (recommended)
npm install -g agent-browser
agent-browser install   # downloads Chrome for Testing

# homebrew
brew install agent-browser && agent-browser install

# cargo
cargo install agent-browser && agent-browser install

# Linux — also install system deps
agent-browser install --with-deps
```

Upgrade: `agent-browser upgrade`

## Core Concept: Refs

Every `snapshot` assigns deterministic refs (`@e1`, `@e2`, ...) to DOM elements. Use refs instead of CSS selectors — they're stable within a snapshot, semantic, and LLM-friendly.

```bash
agent-browser open https://example.com
agent-browser snapshot -i          # interactive elements only
# Output:
#   - heading "Example" [ref=e1]
#   - link "More info" [ref=e2]
#   - button "Submit" [ref=e3]

agent-browser click @e3            # click Submit
```

**After any DOM change (navigation, AJAX, form submit) — re-snapshot to get fresh refs.**

## Essential Commands

### Navigation
```bash
agent-browser open <url>
agent-browser back | forward | reload
```

### Snapshot (primary way to "see" the page)
```bash
agent-browser snapshot              # full accessibility tree
agent-browser snapshot -i           # interactive elements only (buttons, inputs, links)
agent-browser snapshot -c           # compact (remove empty nodes)
agent-browser snapshot -d 3         # limit depth
agent-browser snapshot -s "#main"   # scope to selector
agent-browser snapshot --json       # machine-readable
```

### Interaction
```bash
agent-browser click <ref|selector>
agent-browser fill <ref> "text"         # clear + type (for inputs)
agent-browser type <ref> "text"         # type without clearing
agent-browser select <ref> "option"     # dropdown
agent-browser check|uncheck <ref>       # checkbox
agent-browser hover <ref>
agent-browser press Enter|Tab|Escape    # keyboard
agent-browser press Control+a           # key combo
agent-browser scroll down 500           # scroll page
agent-browser upload <ref> file.pdf     # file upload
```

### Data Extraction
```bash
agent-browser get text <ref>        # element text
agent-browser get html <ref>        # innerHTML
agent-browser get value <ref>       # input value
agent-browser get attr <ref> href   # attribute
agent-browser get title             # page title
agent-browser get url               # current URL
```

### Screenshot & PDF
```bash
agent-browser screenshot [path]         # to file or temp
agent-browser screenshot --full         # full page scroll capture
agent-browser screenshot --annotate     # numbered labels matching refs
agent-browser pdf output.pdf
```

### Wait
```bash
agent-browser wait <ref>                    # wait for element visible
agent-browser wait 2000                     # wait ms
agent-browser wait --load networkidle       # wait for network idle
agent-browser wait --url "**/dashboard"     # wait for URL pattern
agent-browser wait --text "Success"         # wait for text
agent-browser wait <ref> --state hidden     # wait for element to disappear
```

### Semantic Locators (alternative to refs)
```bash
agent-browser find role button click --name "Submit"
agent-browser find text "Sign In" click
agent-browser find label "Email" fill "test@test.com"
agent-browser find placeholder "Search" fill "query"
agent-browser find testid "login-btn" click
```

### Session Management
```bash
agent-browser session list              # active sessions
agent-browser --session myapp <cmd>     # named session
agent-browser close                     # close current
agent-browser close --all               # close all
```

### Tabs
```bash
agent-browser tab                   # list tabs
agent-browser tab new [url]         # new tab
agent-browser tab 2                 # switch to tab 2
agent-browser tab close
```

## AI Agent Workflow Pattern

Standard loop for any AI agent:

```bash
# 1. Navigate
agent-browser open https://target.com

# 2. Observe (snapshot → LLM reads → decides action)
agent-browser snapshot -i --json

# 3. Act (LLM picks ref from snapshot)
agent-browser fill @e2 "search query"
agent-browser click @e3

# 4. Wait for result
agent-browser wait --load networkidle

# 5. Re-observe (new snapshot after DOM changed)
agent-browser snapshot -i --json

# 6. Extract or continue
agent-browser get text @e5
```

Repeat 2-5 until task complete. Always `close` when done.

## Batch Execution

When exact sequence is known upfront:

```bash
cat << 'EOF' | agent-browser batch --json
[
  ["open", "https://example.com/login"],
  ["fill", "@e1", "user@example.com"],
  ["fill", "@e2", "password123"],
  ["click", "@e3"],
  ["wait", "--load", "networkidle"],
  ["screenshot", "result.png"]
]
EOF
```

`--bail` stops on first error.

## Authentication & State Persistence

```bash
# Save credentials (encrypted vault — LLM never sees password)
echo "pass" | agent-browser auth save myapp \
  --url https://app.example.com/login \
  --username user@example.com --password-stdin

# Login with saved creds
agent-browser auth login myapp

# Auto-persist session (cookies, localStorage, IndexedDB)
agent-browser --session-name myapp open https://app.example.com
# ... interact ...
agent-browser close   # state auto-saved to ~/.agent-browser/sessions/

# Next run — auto-restored, already logged in
agent-browser --session-name myapp open https://app.example.com/dashboard
```

Manual state save/load:
```bash
agent-browser state save auth.json
agent-browser state load auth.json
```

## Network Control

```bash
agent-browser network requests                  # list tracked requests
agent-browser network requests --type xhr,fetch # filter
agent-browser network route "**/analytics" --abort    # block tracking
agent-browser network route "**/api/*" --body '{"mock":true}'  # mock response
agent-browser network har start && agent-browser network har stop output.har
```

## Device Emulation

```bash
agent-browser set device "iPhone 14"
agent-browser set viewport 1920 1080        # desktop
agent-browser set viewport 1920 1080 2      # retina
agent-browser set media dark                # dark mode
agent-browser set geo 52.2297 21.0122       # Warsaw
```

## Configuration

Priority: CLI flags > env vars > `./agent-browser.json` > `~/.agent-browser/config.json`

Key env vars:
```bash
AGENT_BROWSER_SESSION=myapp           # default session
AGENT_BROWSER_HEADED=1                # show browser window
AGENT_BROWSER_EXECUTABLE_PATH=/path   # custom Chrome
AGENT_BROWSER_PROXY=http://host:port  # proxy
AGENT_BROWSER_DEFAULT_TIMEOUT=25000   # operation timeout (max 30000)
AGENT_BROWSER_IDLE_TIMEOUT_MS=60000   # daemon auto-shutdown
AGENT_BROWSER_ENCRYPTION_KEY=<64hex>  # encrypt state files
AGENT_BROWSER_ALLOWED_DOMAINS=a.com,b.com  # restrict navigation
AGENT_BROWSER_MAX_OUTPUT=50000        # truncate output (prevent context flooding)
```

Config file (`agent-browser.json`):
```json
{
  "headed": false,
  "proxy": "http://localhost:8080",
  "profile": "./browser-data",
  "userAgent": "my-agent/1.0",
  "screenshotDir": "./shots",
  "colorScheme": "dark"
}
```

Key CLI flags: `--json`, `--session <name>`, `--profile <name|path>`, `--headed`, `--proxy <url>`, `--ignore-https-errors`, `--annotate`, `--engine lightpanda`, `--provider <cloud>`, `--content-boundaries`, `--no-auto-dialog`, `--debug`

## Safety Features for AI

```bash
--content-boundaries          # wrap untrusted page content in markers
--max-output 50000            # prevent context window flooding
--allowed-domains a.com,b.com # restrict navigation to trusted domains
--action-policy policy.json   # gate destructive actions
--confirm-actions eval,download  # require approval for sensitive ops
```

## Cloud Providers

For scalable/CI deployments: `--provider <name>`

Supported: AgentCore, Browserbase, Browserless, BrowserUse, Kernel

## Gotchas

1. **Refs invalidate on DOM change** — always re-snapshot after navigation/AJAX/form submit
2. **Daemon persists** — run `agent-browser close` explicitly to avoid orphaned processes
3. **networkidle unreliable on SPAs** — prefer `wait --text "X"` or `wait --url "pattern"`
4. **Timeout max 30s** — keep `DEFAULT_TIMEOUT` under 30000ms
5. **State files contain tokens** — use `ENCRYPTION_KEY` or add to `.gitignore`
6. **Shadow DOM not in snapshots** — only light DOM visible
7. **Large pages** — use `snapshot -i -c -d 3` to limit output size
8. **Chrome profile lock** — close Chrome before using `--profile` with same profile
