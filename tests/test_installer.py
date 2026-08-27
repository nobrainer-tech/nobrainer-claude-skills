from __future__ import annotations

import importlib.util
import io
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
INSTALLER = ROOT / "scripts" / "install_skills.py"


class InstallerTests(unittest.TestCase):
    def run_installer(self, *args: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            ["python3", str(INSTALLER), *args],
            cwd=ROOT,
            text=True,
            capture_output=True,
            check=False,
        )

    def test_dry_run_does_not_write(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            destination = Path(temp) / "skills"
            result = self.run_installer(
                "--client",
                "codex",
                "--dest",
                str(destination),
                "--skill",
                "nobrainer-ultra",
            )
            self.assertEqual(0, result.returncode, result.stderr)
            self.assertIn("SYMLINK: nobrainer-ultra", result.stdout)
            self.assertNotIn("LEGACY", result.stdout)
            self.assertIn("DRY_RUN", result.stdout)
            self.assertFalse(destination.exists())

    def test_apply_and_idempotent_readback(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            destination = Path(temp) / "skills"
            args = (
                "--client",
                "codex",
                "--dest",
                str(destination),
                "--skill",
                "nobrainer-ultra",
                "--apply",
            )
            first = self.run_installer(*args)
            second = self.run_installer(*args)
            target = destination / "nobrainer-ultra"
            self.assertEqual(0, first.returncode, first.stderr)
            self.assertEqual(0, second.returncode, second.stderr)
            self.assertTrue(target.is_symlink())
            self.assertTrue((target / "SKILL.md").is_file())
            self.assertIn("1 unchanged", second.stdout)

    def test_conflict_is_not_overwritten(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            target = Path(temp) / "skills" / "nobrainer-ultra"
            target.mkdir(parents=True)
            marker = target / "keep.txt"
            marker.write_text("owned by user\n", encoding="utf-8")
            result = self.run_installer(
                "--client",
                "codex",
                "--dest",
                str(target.parent),
                "--skill",
                "nobrainer-ultra",
                "--apply",
            )
            self.assertEqual(3, result.returncode)
            self.assertEqual("owned by user\n", marker.read_text(encoding="utf-8"))

    def test_relocated_legacy_symlink_requires_explicit_migration(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            destination = Path(temp) / "skills"
            destination.mkdir()
            target = destination / "deep-audit"
            old_source = ROOT / "deep-audit"
            target.symlink_to(old_source, target_is_directory=True)

            refused = self.run_installer(
                "--client",
                "codex",
                "--dest",
                str(destination),
                "--skill",
                "deep-audit",
                "--apply",
            )
            self.assertEqual(3, refused.returncode)
            self.assertIn("legacy symlink", refused.stderr)
            self.assertEqual(str(old_source), str(target.readlink()))

            migrated = self.run_installer(
                "--client",
                "codex",
                "--dest",
                str(destination),
                "--skill",
                "deep-audit",
                "--migrate-legacy",
                "--apply",
            )
            self.assertEqual(0, migrated.returncode, migrated.stderr)
            self.assertIn("MIGRATE", migrated.stdout)
            self.assertEqual((ROOT / "skills" / "deep-audit").resolve(), target.resolve())

    def test_unknown_symlink_remains_a_conflict(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            destination = Path(temp) / "skills"
            destination.mkdir()
            target = destination / "deep-audit"
            foreign = Path(temp) / "foreign-target"
            target.symlink_to(foreign, target_is_directory=True)
            result = self.run_installer(
                "--client",
                "codex",
                "--dest",
                str(destination),
                "--skill",
                "deep-audit",
                "--migrate-legacy",
                "--apply",
            )
            self.assertEqual(3, result.returncode)
            self.assertEqual(foreign, target.readlink())

    def test_renamed_legacy_alias_is_migrated_only_with_explicit_flag(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            destination = Path(temp) / "skills"
            destination.mkdir()
            legacy = destination / "karpathy-auto-improver"
            old_source = ROOT / "karpathy-auto-improver"
            legacy.symlink_to(old_source, target_is_directory=True)

            refused = self.run_installer(
                "--client",
                "codex",
                "--dest",
                str(destination),
                "--skill",
                "nobrainer-autoimprove",
                "--apply",
            )
            self.assertEqual(3, refused.returncode)
            self.assertIn("LEGACY_ALIAS", refused.stdout)
            self.assertTrue(legacy.is_symlink())
            self.assertFalse((destination / "nobrainer-autoimprove").exists())

            migrated = self.run_installer(
                "--client",
                "codex",
                "--dest",
                str(destination),
                "--skill",
                "nobrainer-autoimprove",
                "--migrate-legacy",
                "--apply",
            )
            canonical = destination / "nobrainer-autoimprove"
            self.assertEqual(0, migrated.returncode, migrated.stderr)
            self.assertIn("MIGRATE_ALIAS", migrated.stdout)
            self.assertFalse(legacy.exists())
            self.assertFalse(legacy.is_symlink())
            self.assertEqual(
                (ROOT / "skills" / "nobrainer-autoimprove").resolve(),
                canonical.resolve(),
            )

    def test_foreign_renamed_alias_blocks_migration(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            destination = Path(temp) / "skills"
            destination.mkdir()
            legacy = destination / "karpathy-auto-improver"
            foreign = Path(temp) / "foreign-target"
            legacy.symlink_to(foreign, target_is_directory=True)

            result = self.run_installer(
                "--client",
                "codex",
                "--dest",
                str(destination),
                "--skill",
                "nobrainer-autoimprove",
                "--migrate-legacy",
                "--apply",
            )
            self.assertEqual(3, result.returncode)
            self.assertIn("CONFLICT_ALIAS", result.stdout)
            self.assertEqual(foreign, legacy.readlink())
            self.assertFalse((destination / "nobrainer-autoimprove").exists())

    def test_failed_renamed_migration_restores_legacy_alias(self) -> None:
        spec = importlib.util.spec_from_file_location(
            "skill_installer_legacy_rollback_test", INSTALLER
        )
        self.assertIsNotNone(spec)
        self.assertIsNotNone(spec.loader)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)

        with tempfile.TemporaryDirectory() as temp:
            destination = Path(temp) / "skills"
            destination.mkdir()
            legacy = destination / "karpathy-auto-improver"
            old_source = ROOT / "karpathy-auto-improver"
            canonical = destination / "nobrainer-autoimprove"
            legacy.symlink_to(old_source, target_is_directory=True)
            real_symlink = os.symlink
            symlink_calls = 0

            def fail_canonical_link(
                source: Path | str,
                target: Path | str,
                target_is_directory: bool = False,
            ) -> None:
                nonlocal symlink_calls
                symlink_calls += 1
                if symlink_calls == 1:
                    raise OSError("simulated canonical install failure")
                real_symlink(
                    source,
                    target,
                    target_is_directory=target_is_directory,
                )

            argv = [
                str(INSTALLER),
                "--client",
                "codex",
                "--dest",
                str(destination),
                "--skill",
                "nobrainer-autoimprove",
                "--migrate-legacy",
                "--apply",
            ]
            stderr = io.StringIO()
            with (
                mock.patch.object(sys, "argv", argv),
                mock.patch.object(module.os, "symlink", side_effect=fail_canonical_link),
                redirect_stdout(io.StringIO()),
                redirect_stderr(stderr),
            ):
                result = module.main()

            self.assertEqual(4, result)
            self.assertTrue(legacy.is_symlink())
            self.assertEqual(old_source, legacy.readlink())
            self.assertFalse(canonical.exists())
            self.assertFalse(canonical.is_symlink())
            self.assertIn("installation rolled back", stderr.getvalue())

    def test_interrupted_copy_removes_partial_target(self) -> None:
        spec = importlib.util.spec_from_file_location("skill_installer_under_test", INSTALLER)
        self.assertIsNotNone(spec)
        self.assertIsNotNone(spec.loader)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)

        with tempfile.TemporaryDirectory() as temp:
            destination = Path(temp) / "skills"
            target = destination / "nobrainer-ultra"

            def interrupted_copy(
                source: Path,
                partial: Path,
                *,
                dirs_exist_ok: bool = False,
            ) -> None:
                self.assertTrue(dirs_exist_ok)
                self.assertTrue(partial.is_dir())
                (partial / "partial.txt").write_text("incomplete\n", encoding="utf-8")
                raise OSError("simulated interrupted copy")

            argv = [
                str(INSTALLER),
                "--client",
                "codex",
                "--dest",
                str(destination),
                "--skill",
                "nobrainer-ultra",
                "--mode",
                "copy",
                "--apply",
            ]
            with (
                mock.patch.object(sys, "argv", argv),
                mock.patch.object(shutil, "copytree", side_effect=interrupted_copy),
                redirect_stdout(io.StringIO()),
                redirect_stderr(io.StringIO()),
            ):
                result = module.main()

            self.assertEqual(4, result)
            self.assertFalse(target.exists(), "partial copy must be rolled back")

    def test_copy_ownership_race_preserves_foreign_target(self) -> None:
        spec = importlib.util.spec_from_file_location("skill_installer_race_test", INSTALLER)
        self.assertIsNotNone(spec)
        self.assertIsNotNone(spec.loader)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)

        with tempfile.TemporaryDirectory() as temp:
            destination = Path(temp) / "skills"
            target = destination / "nobrainer-ultra"
            target.mkdir(parents=True)
            marker = target / "foreign.txt"
            marker.write_text("owned by another process\n", encoding="utf-8")

            argv = [
                str(INSTALLER),
                "--client",
                "codex",
                "--dest",
                str(destination),
                "--skill",
                "nobrainer-ultra",
                "--mode",
                "copy",
                "--apply",
            ]
            with (
                mock.patch.object(sys, "argv", argv),
                mock.patch.object(module, "existing_state", return_value="missing"),
                redirect_stdout(io.StringIO()),
                redirect_stderr(io.StringIO()),
            ):
                result = module.main()

            self.assertEqual(4, result)
            self.assertTrue(target.is_dir())
            self.assertEqual(
                "owned by another process\n",
                marker.read_text(encoding="utf-8"),
            )

    def test_full_copy_install_has_exact_active_inventory(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            destination = Path(temp) / "skills"
            result = self.run_installer(
                "--client",
                "agents",
                "--dest",
                str(destination),
                "--mode",
                "copy",
                "--apply",
            )
            installed = {
                path.parent.name for path in destination.glob("*/SKILL.md")
            }
            source = {
                path.parent.name for path in (ROOT / "skills").glob("*/SKILL.md")
            }
            self.assertEqual(0, result.returncode, result.stdout + result.stderr)
            self.assertEqual(source, installed)
            self.assertEqual(19, len(installed))


if __name__ == "__main__":
    unittest.main()
