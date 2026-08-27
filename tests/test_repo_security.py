from __future__ import annotations

import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


class RepositorySecurityTests(unittest.TestCase):
    def test_gitleaks_policy_has_no_broad_allowlist(self) -> None:
        config = (ROOT / ".gitleaks.toml").read_text(encoding="utf-8")
        pre_commit = (ROOT / ".pre-commit-config.yaml").read_text(encoding="utf-8")
        self.assertIn("useDefault = true", config)
        self.assertNotIn("[allowlist]", config)
        self.assertNotIn("[[allowlists]]", config)
        self.assertNotIn(".*\\.md", config)
        self.assertIn("rev: v8.30.1", pre_commit)
        self.assertIn('args: ["--ignore-gitleaks-allow"]', pre_commit)

    @unittest.skipUnless(shutil.which("gitleaks"), "gitleaks CLI not installed")
    def test_current_cli_rejects_a_synthetic_staged_probe(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            repo = Path(temp)
            subprocess.run(["git", "init", "-q", str(repo)], check=True)
            shutil.copy2(ROOT / ".gitleaks.toml", repo / ".gitleaks.toml")
            probe = repo / ".gitleaks-verify.tmp"
            probe.write_text(
                "aws_access_key_id=" + "AKIA" + "ABCDEFGHIJKLMNOP" + "\n",
                encoding="utf-8",
            )
            subprocess.run(
                ["git", "-C", str(repo), "add", ".gitleaks-verify.tmp"],
                check=True,
            )
            result = subprocess.run(
                [
                    "gitleaks",
                    "git",
                    "--staged",
                    "--redact",
                    "--no-banner",
                    "--ignore-gitleaks-allow",
                ],
                cwd=repo,
                text=True,
                capture_output=True,
                check=False,
            )
        self.assertNotEqual(0, result.returncode, result.stdout + result.stderr)


if __name__ == "__main__":
    unittest.main()
