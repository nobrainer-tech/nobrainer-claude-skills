# Restart an approved profile for CDP attach

Use this reference only when the owner explicitly approves closing the target
browser and the target is an existing, dedicated Chromium user-data directory.
The shell examples are POSIX; use the platform equivalent for process readback
and graceful exact-PID stopping on another operating system.

## Resolve and preflight

Resolve these values without printing secrets or persisting the profile path:

```text
BROWSER_EXECUTABLE: <approved Chrome, Chromium or Edge binary>
BROWSER_PID: <exact numeric PID read back from that executable and profile>
BROWSER_USER_DATA_DIR: <existing, approved non-default user-data directory>
BROWSER_PROFILE: <profile directory inside that user-data directory>
CDP_PORT: <unused local port>
PLAYWRIGHT_CLI_SESSION: <named CLI session>
```

Read the exact process identity and arguments, confirm the executable and data
directory match, and check for unsaved work. Continue only when the readback is
`PROCESS_MATCH=PASS`, `PROFILE_MATCH=PASS` and `UNSAVED_WORK=NONE`. Run the
preflight and stop as separate invocations:

```bash
test -n "$BROWSER_PID"
case "$BROWSER_PID" in
  ''|*[!0-9]*) printf '%s\n' 'BROWSER_STOP_BLOCKED'; exit 1 ;;
esac
ps -p "$BROWSER_PID" -o pid=,comm=,args=
```

If any preflight match is missing, return `BROWSER_STOP_BLOCKED` and stop. Do
not use a broad process matcher. A force stop requires a fresh identity readback
and a second explicit owner approval for that exact PID.

## Stop and relaunch

After the pass readback, stop the exact process in a separate invocation:

```bash
kill -TERM "$BROWSER_PID"
```

After a bounded grace period, re-read the process list and profile lock. Require
`BROWSER_PID=GONE` and `PROFILE_LOCK=GONE` before continuing. If the process
remains or the profile is locked, return `BROWSER_STOP_BLOCKED` and stop; never
continue against a locked profile.

Start the same approved profile with CDP bound to loopback only:

```bash
"$BROWSER_EXECUTABLE" \
  --remote-debugging-address=127.0.0.1 \
  --remote-debugging-port="$CDP_PORT" \
  --user-data-dir="$BROWSER_USER_DATA_DIR" \
  --profile-directory="$BROWSER_PROFILE" \
  about:blank &
BROWSER_LAUNCH_PID=$!
```

Chrome 136 and newer requires `--user-data-dir` to point to a non-default data
directory when remote debugging is enabled. Do not point this flow at the
daily/default directory, copy or mirror a profile, extract cookies, add a
permissive remote-origin wildcard, or bind CDP to a non-loopback address. If the
only available session is the daily/default profile, use the approved extension
attach path or a disposable/Chrome-for-Testing profile instead.

## Verify and attach

Read back the endpoint before attaching. If it does not respond, return
`BROWSER_ATTACH_BLOCKED` and stop; do not silently switch to another profile or
endpoint:

```bash
curl --fail --silent --show-error "http://127.0.0.1:${CDP_PORT}/json/version"
playwright-cli attach --cdp="http://127.0.0.1:${CDP_PORT}" --session="$PLAYWRIGHT_CLI_SESSION"
playwright-cli --session="$PLAYWRIGHT_CLI_SESSION" list
playwright-cli --session="$PLAYWRIGHT_CLI_SESSION" snapshot
```

The endpoint, page list and snapshot prove connectivity only; they do not
authorize form submission, publication or other external side effects. Confirm
the expected browser, profile and tab before operating. Record the exact CLI
version, browser/session mode and observed pages, but redact the profile path,
cookies, headers and private page data.

If the CLI created the browser itself, `playwright-cli close-all` or
`playwright-cli kill-all` may be used only for those CLI-owned sessions after a
fresh `playwright-cli list`. Do not use either command to close an externally
attached profile. After an external attach, use `playwright-cli detach`; never
close the attached browser from the CLI.
