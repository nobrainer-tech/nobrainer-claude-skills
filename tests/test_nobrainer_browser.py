from __future__ import annotations

import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SKILL = ROOT / "skills" / "nobrainer-browser" / "SKILL.md"


class NoBrainerBrowserTests(unittest.TestCase):
    def test_one_canonical_browser_skill(self) -> None:
        self.assertTrue(SKILL.is_file())
        self.assertFalse((ROOT / "skills" / "agent-browser" / "SKILL.md").exists())
        self.assertFalse((ROOT / "skills" / "playwright-cli" / "SKILL.md").exists())

    def test_latest_cli_attach_and_trace_contract(self) -> None:
        text = SKILL.read_text(encoding="utf-8")
        for required in (
            "nb-browser",
            "@playwright/cli@latest",
            "playwright-cli attach --cdp=http://127.0.0.1:9222",
            "playwright-cli --help attach",
            "playwright show-trace",
            "trace.zip",
            "existing",
        ):
            self.assertIn(required, text)

    def test_no_default_plugin_or_mcp_install(self) -> None:
        text = " ".join(SKILL.read_text(encoding="utf-8").lower().split())
        self.assertIn("do not install mcp", text)
        self.assertIn("do not install a browser plugin", text)
        self.assertIn("do not bypass", text)


if __name__ == "__main__":
    unittest.main()
