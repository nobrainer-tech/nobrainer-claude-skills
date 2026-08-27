from __future__ import annotations

import json
import re
import subprocess
import tempfile
import unittest
from pathlib import Path

from scripts import install_skills, validate_skills


ROOT = Path(__file__).resolve().parents[1]
SKILLS = ROOT / "skills"

CANONICAL = {
    "nobrainer-ultra": "nb-ultra",
    "nobrainer-sessions": "nb-sessions",
    "nobrainer-spec-driven-development": "nb-sdd",
    "nobrainer-wiki": "nb-wiki",
    "nobrainer-browser": "nb-browser",
    "nobrainer-autoimprove": "nb-autoimprove",
    "nobrainer-decide": "nb-decide",
    "nobrainer-rca": "nb-rca",
    "nobrainer-review": "nb-review",
}

LEGACY = {
    "add-gitleaks",
    "agent-browser",
    "agents-restraint",
    "codex-in-claude-code",
    "deep-audit",
    "deep-autoreview",
    "deep-bugs-finder",
    "deep-decide",
    "deep-rca",
    "karpathy-auto-improver",
    "karpathy-llm-wiki",
    "llm-wiki",
    "nb-add",
    "nb-get",
    "nb-tidy",
    "nobrainer-autopilot",
    "nobrainer-continuous-improvement",
    "nobrainer-memory",
    "nobrainer-memory-memsearch",
    "nobrainer-fast-audit",
    "nobrainer-npm-secure",
    "nobrainer-reddit",
    "nobrainer-starter",
    "nobrainer-team-builder",
    "nobrainer-ultracode-workflow",
    "nobrainer-wiki-add",
    "nobrainer-wiki-get",
    "nobrainer-wiki-tidy",
    "playwright-cli",
    "wiki-add",
    "wiki-get",
    "wiki-tidy",
}

ACTIVE = set(CANONICAL)

VERSION_MANIFESTS = (
    "package.json",
    "plugin.json",
    ".claude-plugin/plugin.json",
    ".codex-plugin/plugin.json",
    ".cursor-plugin/plugin.json",
)


def parse_frontmatter(path: Path) -> dict[str, str]:
    text = path.read_text(encoding="utf-8")
    lines = text.splitlines()
    if not lines or lines[0] != "---":
        raise AssertionError(f"{path}: frontmatter must start on line 1")
    try:
        end = lines.index("---", 1)
    except ValueError as exc:
        raise AssertionError(f"{path}: frontmatter is not closed") from exc

    values: dict[str, str] = {}
    key: str | None = None
    chunks: list[str] = []
    for line in lines[1:end]:
        match = re.match(r"^([a-zA-Z0-9_-]+):(?:\s*(.*))?$", line)
        if match:
            if key is not None:
                values[key] = " ".join(chunks).strip().strip('"')
            key = match.group(1)
            raw = (match.group(2) or "").strip()
            chunks = [] if raw in {"", ">", ">-", "|", "|-"} else [raw]
        elif key is not None and line.startswith("  "):
            chunks.append(line.strip())
        elif line.strip():
            raise AssertionError(f"{path}: unsupported frontmatter line: {line}")
    if key is not None:
        values[key] = " ".join(chunks).strip().strip('"')
    return values


class SuiteTests(unittest.TestCase):
    def test_curated_active_inventory(self) -> None:
        actual = {path.parent.name for path in SKILLS.glob("*/SKILL.md")}
        self.assertEqual(ACTIVE, actual)

    def test_repository_contains_only_the_curated_skill_tree(self) -> None:
        actual = {
            path.relative_to(ROOT)
            for path in ROOT.rglob("SKILL.md")
            if ".git" not in path.parts
        }
        expected = {Path("skills") / name / "SKILL.md" for name in ACTIVE}
        self.assertEqual(expected, actual)

    def test_all_active_frontmatter_is_portable(self) -> None:
        for skill in sorted(SKILLS.glob("*/SKILL.md")):
            with self.subTest(skill=skill.parent.name):
                self.assertEqual(
                    {"name", "description"},
                    set(parse_frontmatter(skill)),
                    f"{skill}: active skills use only portable frontmatter",
                )

    def test_canonical_skills_and_aliases(self) -> None:
        for name, alias in CANONICAL.items():
            with self.subTest(name=name):
                skill = SKILLS / name / "SKILL.md"
                self.assertTrue(skill.is_file(), f"missing {skill}")
                frontmatter = parse_frontmatter(skill)
                self.assertEqual({"name", "description"}, set(frontmatter))
                self.assertEqual(name, frontmatter["name"])
                self.assertTrue(frontmatter["description"].startswith("Use when"))
                self.assertIn(alias, frontmatter["description"])
                self.assertLessEqual(len(frontmatter["description"]), 1024)

    def test_ultra_contract(self) -> None:
        text = (SKILLS / "nobrainer-ultra" / "SKILL.md").read_text(encoding="utf-8")
        for term in (
            "DRIFT_CHECK",
            "BUDDY",
            "READY_GATE",
            "AUTOPILOT",
            "RECEIVE_AUDIT",
            "nobrainer-sessions",
            "nobrainer-spec-driven-development",
            "Superpowers",
        ):
            self.assertIn(term, text)
        self.assertNotIn("continue until done", text.lower())
        routing = (
            SKILLS / "nobrainer-ultra" / "references" / "routing.md"
        ).read_text(encoding="utf-8")
        self.assertIn("nobrainer-browser", routing)

    def test_ultra_setup_upgrade_contract(self) -> None:
        skill = (SKILLS / "nobrainer-ultra" / "SKILL.md").read_text(encoding="utf-8")
        setup = (SKILLS / "nobrainer-ultra" / "references" / "setup.md").read_text(
            encoding="utf-8"
        )
        for term in ("set up", "upgrade", "references/setup.md"):
            self.assertIn(term, skill)
        for term in (
            "CURRENT",
            "DRIFTED",
            "OWNER_GATE",
            "official Superpowers",
            "RUNTIME_CHECKS",
            "ROLLBACK",
        ):
            self.assertIn(term, setup)

    def test_sessions_fail_closed_contract(self) -> None:
        text = (SKILLS / "nobrainer-sessions" / "SKILL.md").read_text(encoding="utf-8")
        for term in (
            "<repo> | MAIN",
            "THREAD_ID",
            "HOST_ID",
            "CHECKOUT",
            "LEASE",
            "FENCING_EPOCH",
            "RECEIVE_AUDIT",
            "2091905058933792771",
        ):
            self.assertIn(term, text)

    def test_sdd_is_spec_driven_not_subagent_driven(self) -> None:
        text = (SKILLS / "nobrainer-spec-driven-development" / "SKILL.md").read_text(
            encoding="utf-8"
        )
        self.assertIn("spec-driven development", text.lower())
        self.assertIn("not subagent-driven development", text.lower())
        self.assertIn("ACCEPTANCE", text)
        self.assertIn("ROLLBACK", text)

    def test_karpathy_attribution(self) -> None:
        for name in ("nobrainer-autoimprove", "nobrainer-wiki"):
            with self.subTest(name=name):
                text = (SKILLS / name / "SKILL.md").read_text(encoding="utf-8")
                self.assertIn("Andrej Karpathy", text)
                self.assertRegex(text, r"https://(gist\.)?github\.com/karpathy/")

    def test_lightweight_learning_contract(self) -> None:
        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        agents = (ROOT / "AGENTS.md").read_text(encoding="utf-8")
        ultra = (SKILLS / "nobrainer-ultra" / "SKILL.md").read_text(
            encoding="utf-8"
        )
        autoimprove = (SKILLS / "nobrainer-autoimprove" / "SKILL.md").read_text(
            encoding="utf-8"
        )
        wiki = (SKILLS / "nobrainer-wiki" / "SKILL.md").read_text(encoding="utf-8")

        self.assertIn("Continuous improvement beats delayed perfection", readme)
        self.assertIn("A small task stays small", readme)
        self.assertIn("Lightweight learning loop", agents)
        self.assertIn("Learning close", ultra)
        self.assertIn("One correction", ultra)
        self.assertIn("regression scenario", autoimprove)
        self.assertIn("Durable personalization without hidden memory", wiki)
        self.assertIn("source, date, scope", wiki)

    def test_legacy_skills_are_not_discoverable(self) -> None:
        for name in LEGACY:
            with self.subTest(name=name):
                self.assertFalse((SKILLS / name / "SKILL.md").exists())

    def test_installer_migrates_every_retired_name(self) -> None:
        self.assertEqual(ACTIVE, set(install_skills.CURATED_SKILLS))
        self.assertLessEqual(
            validate_skills.LEGACY,
            set(install_skills.LEGACY_TO_CANONICAL),
        )
        self.assertLessEqual(
            set(install_skills.LEGACY_TO_CANONICAL.values()),
            ACTIVE,
        )

    def test_public_clean_suite(self) -> None:
        forbidden = (
            "/Users/",
            "nobrainer-tech@",
            "--dangerously-skip-permissions",
            "CLAUDE-CODE-FABLE",
        )
        for name in CANONICAL:
            for path in (SKILLS / name).rglob("*"):
                if not path.is_file() or path.suffix not in {".md", ".yaml", ".yml", ".json"}:
                    continue
                text = path.read_text(encoding="utf-8")
                for value in forbidden:
                    self.assertNotIn(value, text, f"{path}: forbidden public value")

    def test_multi_harness_adapters(self) -> None:
        required = (
            ".claude-plugin/plugin.json",
            ".codex-plugin/plugin.json",
            ".cursor-plugin/plugin.json",
            ".opencode/INSTALL.md",
            ".github/copilot-instructions.md",
            "docs/INSTALL.md",
        )
        for relative in required:
            with self.subTest(path=relative):
                self.assertTrue((ROOT / relative).is_file(), f"missing {relative}")

        manifests = (
            "plugin.json",
            ".claude-plugin/plugin.json",
            ".claude-plugin/marketplace.json",
            ".codex-plugin/plugin.json",
            ".agents/plugins/marketplace.json",
            ".cursor-plugin/plugin.json",
            "package.json",
        )
        for relative in manifests:
            with self.subTest(manifest=relative):
                json.loads((ROOT / relative).read_text(encoding="utf-8"))

        result = subprocess.run(
            [
                "node",
                "--input-type=module",
                "-e",
                (
                    "import('./.opencode/plugins/nobrainer-tech-skills.js')"
                    ".then(async m => { const p = await m.default(); const c = {}; "
                    "await p.config(c); if (!c.skills?.paths?.some(x => "
                    "x.endsWith('/skills'))) process.exit(2); })"
                ),
            ],
            cwd=ROOT,
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(0, result.returncode, result.stdout + result.stderr)

    def test_readme_branding_and_links(self) -> None:
        text = (ROOT / "README.md").read_text(encoding="utf-8")
        self.assertIn("nobrainer-tech-skills", text)
        self.assertIn("assets/nobrainer-tech-logo.svg", text)
        self.assertIn("https://nobrainer.tech", text)
        self.assertIn("https://nobrainertech.gumroad.com", text)
        self.assertIn("agentic workflows", text.lower())
        self.assertIn("assets/nobrainer-skills-coverage.webp", text)
        self.assertIn("docs/COMPATIBILITY.md", text)
        self.assertIn("docs/TESTING.md", text)

    def test_coverage_graphic_is_readme_ready(self) -> None:
        path = ROOT / "assets" / "nobrainer-skills-coverage.webp"
        data = path.read_bytes()
        self.assertEqual(b"RIFF", data[:4])
        self.assertEqual(b"WEBP", data[8:12])
        frame = data.find(b"\x9d\x01\x2a")
        self.assertGreaterEqual(frame, 0, "lossy WebP frame header is missing")
        width = int.from_bytes(data[frame + 3 : frame + 5], "little") & 0x3FFF
        height = int.from_bytes(data[frame + 5 : frame + 7], "little") & 0x3FFF
        self.assertGreaterEqual(width, 1200)
        self.assertGreaterEqual(height, 600)
        self.assertLessEqual(len(data), 300_000)
        self.assertGreater(width / height, 1.6)
        self.assertLess(width / height, 2.0)

    def test_product_repository_surface(self) -> None:
        required = (
            "CONTRIBUTING.md",
            "SECURITY.md",
            "docs/COMPATIBILITY.md",
            "docs/TESTING.md",
            "docs/SKILL_CURATION.md",
            ".github/PULL_REQUEST_TEMPLATE.md",
            ".github/ISSUE_TEMPLATE/bug_report.md",
            ".github/ISSUE_TEMPLATE/feature_request.md",
            ".github/ISSUE_TEMPLATE/config.yml",
            ".github/dependabot.yml",
            ".github/workflows/validate.yml",
        )
        for relative in required:
            with self.subTest(path=relative):
                self.assertTrue((ROOT / relative).is_file())

        workflow = (ROOT / ".github" / "workflows" / "validate.yml").read_text(
            encoding="utf-8"
        )
        for term in (
            "scripts/validate_skills.py --suite",
            "unittest discover",
            "py_compile",
            "GITLEAKS_VERSION: 8.30.1",
            "GITLEAKS_SHA256:",
            "--config .gitleaks.toml --redact --no-banner --ignore-gitleaks-allow",
            "timeout-minutes:",
            "persist-credentials: false",
        ):
            self.assertIn(term, workflow)
        self.assertNotRegex(workflow, r"uses:\s+[^\s]+@v[0-9]+(?:\s|$)")

    def test_manifest_versions_are_consistent(self) -> None:
        versions = {
            relative: json.loads(
                (ROOT / relative).read_text(encoding="utf-8")
            )["version"]
            for relative in VERSION_MANIFESTS
        }
        marketplace = json.loads(
            (ROOT / ".claude-plugin" / "marketplace.json").read_text(encoding="utf-8")
        )
        versions[".claude-plugin/marketplace.json"] = marketplace["plugins"][0][
            "version"
        ]
        unique = set(versions.values())
        self.assertEqual(1, len(unique), versions)
        self.assertRegex(
            next(iter(unique)),
            r"^[0-9]+\.[0-9]+\.[0-9]+(?:[-+][0-9A-Za-z.-]+)?$",
        )

        codex = json.loads(
            (ROOT / ".codex-plugin" / "plugin.json").read_text(encoding="utf-8")
        )
        self.assertNotIn("hooks", codex)
        self.assertEqual("./skills/", codex["skills"])
        interface = codex["interface"]
        self.assertEqual("./assets/nobrainer-tech-logo.svg", interface["composerIcon"])
        self.assertEqual(
            "https://nobrainer.tech/privacy", interface["privacyPolicyURL"]
        )
        self.assertEqual(
            "https://nobrainer.tech/terms", interface["termsOfServiceURL"]
        )

    def test_review_has_one_evidence_gated_owner(self) -> None:
        directory = SKILLS / "nobrainer-review"
        text = (directory / "SKILL.md").read_text(encoding="utf-8")
        self.assertEqual({"SKILL.md"}, {path.name for path in directory.iterdir()})
        for term in (
            "CLOSEOUT",
            "BUG_HUNT",
            "RELEASE_GATE",
            "Finding gate",
            "reachable input/state/sequence",
            "PARTIAL",
        ):
            self.assertIn(term, text)
        self.assertIn("filter out speculative AI noise", text)
        self.assertIn("Ordinary implementation-time", text)
        self.assertIn("official Superpowers", text)
        self.assertNotIn("asks for a code or change review", text)
        self.assertNotIn("continue until dry", text.lower())

    def test_opencode_guide_has_no_stale_package_pin(self) -> None:
        text = (ROOT / ".opencode" / "INSTALL.md").read_text(encoding="utf-8")
        self.assertIn("NB_REVIEWED_COMMIT_SHA", text)
        self.assertNotIn(
            "881bcafad8d1a7c2708b80186ef33400ac67f343",
            text,
        )

    def test_wiki_modes_have_one_owner(self) -> None:
        text = (SKILLS / "nobrainer-wiki" / "SKILL.md").read_text(encoding="utf-8")
        setup = (
            SKILLS / "nobrainer-wiki" / "references" / "setup.md"
        ).read_text(encoding="utf-8")
        for mode in ("SETUP", "GET", "ADD", "TIDY_AUDIT", "TIDY_APPLY"):
            self.assertIn(mode, text)
        self.assertIn("One skill owns all wiki behavior", text)
        self.assertIn("TIDY_AUDIT", setup)
        for retired in (
            "nobrainer-wiki-add",
            "nobrainer-wiki-get",
            "nobrainer-wiki-tidy",
        ):
            self.assertFalse((SKILLS / retired / "SKILL.md").exists())

    def test_repository_validator(self) -> None:
        result = subprocess.run(
            ["python3", "scripts/validate_skills.py", "--suite"],
            cwd=ROOT,
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(0, result.returncode, result.stdout + result.stderr)

    def test_public_text_scan_ignores_unknown_extensionless_binary(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            binary = Path(directory) / ".DS_Store"
            binary.write_bytes(b"\x00\xff\x00\xff")
            self.assertFalse(validate_skills.is_public_text_file(binary))

        for helper in validate_skills.PUBLIC_EXTENSIONLESS_FILES:
            with self.subTest(helper=helper):
                self.assertTrue(validate_skills.is_public_text_file(helper))


if __name__ == "__main__":
    unittest.main()
