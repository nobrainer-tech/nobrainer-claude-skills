from __future__ import annotations

import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SKILL = ROOT / "skills" / "nobrainer-browser" / "SKILL.md"
CDP_REFERENCE = SKILL.parent / "references" / "cdp-profile-restart.md"


class NoBrainerBrowserTests(unittest.TestCase):
    def test_one_canonical_browser_skill(self) -> None:
        self.assertTrue(SKILL.is_file())
        self.assertFalse((ROOT / "skills" / "agent-browser" / "SKILL.md").exists())
        self.assertFalse((ROOT / "skills" / "playwright-cli" / "SKILL.md").exists())

    def test_pinned_cli_attach_and_trace_contract(self) -> None:
        text = SKILL.read_text(encoding="utf-8")
        for required in (
            "nb-browser",
            "npm view @playwright/cli version",
            'PLAYWRIGHT_CLI_VERSION="$(npm view @playwright/cli version)"',
            'test -n "$PLAYWRIGHT_CLI_VERSION"',
            'npm install -g "@playwright/cli@$PLAYWRIGHT_CLI_VERSION"',
            "playwright-cli attach --cdp=chrome",
            "playwright-cli attach --cdp=http://127.0.0.1:9222",
            "playwright-cli --help attach",
            "playwright-cli detach",
            "playwright show-trace",
            "trace.zip",
            "existing",
            "sensitive artifacts",
            "explicit report port",
        ):
            self.assertIn(required, text)
        self.assertNotIn("npm install -g @playwright/cli@latest", text)

    def test_no_default_plugin_or_mcp_install(self) -> None:
        text = " ".join(SKILL.read_text(encoding="utf-8").lower().split())
        self.assertIn("do not install mcp", text)
        self.assertIn("do not install a browser plugin", text)
        self.assertIn("playwright-cli install --skills", text)
        self.assertIn("another skill owner", text)
        self.assertIn("do not bypass", text)

    def test_approved_profile_restart_is_loopback_and_exact_pid_only(self) -> None:
        self.assertTrue(CDP_REFERENCE.is_file())
        text = SKILL.read_text(encoding="utf-8") + CDP_REFERENCE.read_text(encoding="utf-8")
        normalized = " ".join(text.split())
        for required in (
            "Restart an approved profile for CDP attach",
            "BROWSER_EXECUTABLE",
            "BROWSER_PID",
            "BROWSER_USER_DATA_DIR",
            "BROWSER_PROFILE",
            "CDP_PORT",
            "Run the preflight and stop as separate invocations",
            "case \"$BROWSER_PID\" in",
            "kill -TERM \"$BROWSER_PID\"",
            "PROCESS_MATCH=PASS",
            "PROFILE_MATCH=PASS",
            "UNSAVED_WORK=NONE",
            "BROWSER_PID=GONE",
            "PROFILE_LOCK=GONE",
            "BROWSER_STOP_BLOCKED",
            "BROWSER_ATTACH_BLOCKED",
            "--remote-debugging-address=127.0.0.1",
            "--remote-debugging-port=\"$CDP_PORT\"",
            "--user-data-dir=\"$BROWSER_USER_DATA_DIR\"",
            "--profile-directory=\"$BROWSER_PROFILE\"",
            "http://127.0.0.1:${CDP_PORT}/json/version",
            "playwright-cli close-all",
            "playwright-cli kill-all",
            "externally attached profile",
            "daily/default directory",
            "copy or mirror a profile",
        ):
            self.assertIn(required, normalized)
        for forbidden in (
            "killall",
            "pkill -f",
            "--remote-debugging-address=0.0.0.0",
            "--remote-allow-origins=*",
        ):
            self.assertNotIn(forbidden, normalized)


if __name__ == "__main__":
    unittest.main()
