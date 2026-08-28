from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import subprocess
import tempfile
import unittest
from pathlib import Path

from scripts import install_skills, validate_skills


ROOT = Path(__file__).resolve().parents[1]
SKILLS = ROOT / "skills"

CANONICAL_ITEMS = (
    ("nobrainer-ultra", "nb-ultra"),
    ("nobrainer-team", "nb-team"),
    ("nobrainer-dispatcher", "nb-dispatcher"),
    ("nobrainer-research", "nb-research"),
    ("nobrainer-writing", "nb-write"),
    ("nobrainer-build", "nb-build"),
    ("nobrainer-security", "nb-security"),
    ("nobrainer-sessions", "nb-sessions"),
    ("nobrainer-spec-driven-development", "nb-sdd"),
    ("nobrainer-wiki", "nb-wiki"),
    ("nobrainer-browser", "nb-browser"),
    ("nobrainer-autoimprove", "nb-autoimprove"),
    ("nobrainer-decide", "nb-decide"),
    ("nobrainer-rca", "nb-rca"),
    ("nobrainer-review", "nb-review"),
)
CANONICAL = dict(CANONICAL_ITEMS)
CANONICAL_ORDER = tuple(name for name, _ in CANONICAL_ITEMS)

LEGACY = {
    "add-gitleaks",
    "agent-browser",
    "agents-restraint",
    "codex-in-claude-code",
    "code-autoresearch",
    "deep-audit",
    "deep-autoreview",
    "deep-autoresearch",
    "deep-bugs-finder",
    "deep-code-review",
    "deep-decide",
    "dispatching-parallel-agents",
    "deep-rca",
    "engineering-standards",
    "karpathy-auto-improver",
    "karpathy-llm-wiki",
    "llm-wiki",
    "nb-add",
    "nb-flow",
    "nb-dispatcher",
    "nb-get",
    "nb-multi",
    "nb-tidy",
    "nb-workflow",
    "nb-write",
    "nobrainer-autopilot",
    "nobrainer-capture-lesson",
    "nobrainer-continuous-improvement",
    "nobrainer-memory",
    "nobrainer-memory-memsearch",
    "nobrainer-npm-secure",
    "nobrainer-reddit",
    "nobrainer-starter",
    "nobrainer-skill-browser",
    "nobrainer-simplifier",
    "nobrainer-style",
    "nobrainer-human-like",
    "security-review",
    "session-handoff",
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
    ".kimi-plugin/plugin.json",
    "gemini-extension.json",
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
            "EXECUTION_MAP",
            "READY_GATE",
            "AUTOPILOT",
            "RECEIVE_AUDIT",
            "nobrainer-sessions",
            "nobrainer-dispatcher",
            "nobrainer-spec-driven-development",
            "nobrainer-team",
            "nobrainer-research",
            "nobrainer-writing",
            "nobrainer-build",
        ):
            self.assertIn(term, text)
        self.assertNotIn("continue until done", text.lower())
        self.assertIn("one focused requirements round", text.lower())
        self.assertIn("without routine check-ins", text.lower())
        self.assertIn("Use these enum values literally", text)
        self.assertIn("Any map that assigns a worker", text)
        self.assertIn("Do not replace `EXECUTION_MAP` with a generic numbered", text)
        self.assertIn("Every executable row must display its literal `METHOD`", text)
        self.assertIn("target 5-12 rows", text)
        self.assertIn("stable locally testable fact", text)
        self.assertIn("affected not-started `READY` rows to `STOPPED`", text)
        routing = (
            SKILLS / "nobrainer-ultra" / "references" / "routing.md"
        ).read_text(encoding="utf-8")
        for name in CANONICAL:
            self.assertIn(name, routing)

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
            "nobrainer-team",
            "`ASK` prepares an exact diff",
            "`OFF` persists",
            "RUNTIME_CHECKS",
            "ROLLBACK",
        ):
            self.assertIn(term, setup)
        self.assertNotIn("fix the result and record one reusable prevention rule", setup)

    def test_build_contract_is_anti_slop_and_calibrated(self) -> None:
        text = (SKILLS / "nobrainer-build" / "SKILL.md").read_text(encoding="utf-8")
        for term in (
            "KISS",
            "DRY",
            "SOLID",
            "YAGNI",
            "Anti-slop gate",
            "failing proof",
            "acceptance trace",
            "nobrainer-review",
        ):
            self.assertIn(term, text)
        self.assertIn("incidental similarity", text)
        self.assertIn("not a mandate for object-oriented ceremony", text)

    def test_research_contract_is_bounded_and_current(self) -> None:
        text = (SKILLS / "nobrainer-research" / "SKILL.md").read_text(
            encoding="utf-8"
        )
        for term in (
            "MICRO",
            "STANDARD",
            "DEEP",
            "primary sources",
            "RESEARCH_BLOCKED",
            "FACT",
            "INFERENCE",
            "nobrainer-wiki",
        ):
            self.assertIn(term, text)
        self.assertIn("Stop when the decision-relevant uncertainty is resolved", text)

    def test_problem_gate_checks_targeted_wiki_then_current_research(self) -> None:
        research = (SKILLS / "nobrainer-research" / "SKILL.md").read_text(
            encoding="utf-8"
        )
        ultra = (SKILLS / "nobrainer-ultra" / "SKILL.md").read_text(
            encoding="utf-8"
        )
        setup = (
            SKILLS / "nobrainer-ultra" / "references" / "setup.md"
        ).read_text(encoding="utf-8")
        for text in (research, ultra, setup):
            self.assertIn("PROBLEM_GATE", text)
            self.assertIn("wiki", text.lower())
            self.assertIn("internet", text.lower())
        self.assertIn("Wiki is context, not current-state proof", research)

    def test_writing_contract_is_high_signal_without_detector_gaming(self) -> None:
        text = (SKILLS / "nobrainer-writing" / "SKILL.md").read_text(
            encoding="utf-8"
        )
        research = (
            SKILLS / "nobrainer-writing" / "references" / "research.md"
        ).read_text(encoding="utf-8")
        for term in (
            "DRAFT",
            "COMPRESS",
            "REWRITE",
            "REVIEW",
            "meaning ledger",
            "VALUE_DENSITY",
            "CAVEATS_AND_CONDITIONS_PRESERVED",
            "nobrainer-research",
        ):
            self.assertIn(term, text)
        self.assertIn("Do not optimize for an AI detector", text)
        self.assertIn("Ten approaches reviewed", research)
        self.assertEqual(10, len(re.findall(r"^\| \d+ \|", research, re.M)))

    def test_security_contract_is_evidence_gated_and_read_only(self) -> None:
        text = (SKILLS / "nobrainer-security" / "SKILL.md").read_text(
            encoding="utf-8"
        )
        for term in (
            "THREAT_MODEL",
            "SECURITY_REVIEW",
            "SUPPLY_CHAIN",
            "READ_ONLY",
            "trust boundary",
            "false-positive",
            "nobrainer-build",
            "nobrainer-research",
            "RESEARCH_BLOCKED",
        ):
            self.assertIn(term, text)
        self.assertIn("Do not test a live target", text)

    def test_team_contract_builds_minimum_capability_roster(self) -> None:
        text = (SKILLS / "nobrainer-team" / "SKILL.md").read_text(encoding="utf-8")
        reference = (
            SKILLS / "nobrainer-team" / "references" / "team-plan.md"
        ).read_text(encoding="utf-8")
        for term in (
            "CAPABILITY_GAP",
            "npx skills find",
            "npx skills use",
            "nobrainer-dispatcher",
            "nobrainer-sessions",
            "MAIN",
            "2-4",
            "untrusted",
        ):
            self.assertIn(term, text)
        self.assertIn("METHOD", reference)
        self.assertIn("WRITE_SCOPE", reference)
        self.assertIn("ACCEPTANCE", reference)

    def test_dispatcher_contract_schedules_without_stealing_other_owners(self) -> None:
        text = (SKILLS / "nobrainer-dispatcher" / "SKILL.md").read_text(
            encoding="utf-8"
        )
        normalized = " ".join(text.split())
        for term in (
            "SCHEDULE",
            "DISPATCH",
            "RECONCILE",
            "RECOVER",
            "READY",
            "PENDING",
            "SENT",
            "PLAN_REF_AND_FINGERPRINT",
            "ATTENTION_BUDGET",
            "BLOCKER_FINGERPRINT",
            "PARALLEL_SAFETY",
            "nobrainer-team",
            "nobrainer-sessions",
            "RECEIVE_AUDIT",
            "NEXT_ACTION",
        ):
            self.assertIn(term, text)
        self.assertIn("A single coherent work unit stays in MAIN", text)
        self.assertIn("must not repair a vague plan", text)
        self.assertIn("worker cannot choose, dispatch or start a successor", text)
        self.assertIn("Unknown dependency state is `BLOCKED`", text)
        self.assertIn("one eligible `BLOCKED` task", text)
        self.assertIn("record `BLOCKED -> READY`", text)
        self.assertIn("plan fingerprint and task contract are still current", normalized)
        self.assertIn("transport identity may still be", text)
        self.assertIn("unknown transport state keeps the task `READY`", normalized)
        self.assertIn("Sessions alone performs the send", text)
        self.assertIn(
            "rerun affected tests and any required failed review, then run a "
            "fresh `RECEIVE_AUDIT`",
            normalized,
        )
        self.assertIn("none substitutes for another", normalized)
        self.assertIn(
            "affected not-started `READY` rows to `STOPPED`", normalized
        )
        self.assertIn("new fingerprint", normalized)
        self.assertIn("RESULT: NOT_NEEDED", text)

    def test_team_dispatcher_sessions_transition_has_one_transport_owner(self) -> None:
        dispatcher = (SKILLS / "nobrainer-dispatcher" / "SKILL.md").read_text(
            encoding="utf-8"
        )
        sessions = (SKILLS / "nobrainer-sessions" / "SKILL.md").read_text(
            encoding="utf-8"
        )
        ultra = (SKILLS / "nobrainer-ultra" / "SKILL.md").read_text(
            encoding="utf-8"
        )
        routing = (
            SKILLS / "nobrainer-ultra" / "references" / "routing.md"
        ).read_text(encoding="utf-8")
        normalized_dispatcher = " ".join(dispatcher.split())
        normalized_sessions = " ".join(sessions.split())
        normalized_ultra = " ".join(ultra.split())
        normalized_routing = " ".join(routing.split())
        sequence = (
            "Team -> Dispatcher SCHEDULE -> Sessions setup/delegate -> Dispatcher "
            "DISPATCH"
        )
        self.assertIn(sequence, dispatcher)
        self.assertIn(sequence, ultra)
        self.assertIn("Sessions alone performs identity preflight and transport", normalized_ultra)
        self.assertIn("Sessions alone performs identity preflight and transport", normalized_routing)
        self.assertIn("it never invokes a second transport pass", normalized_dispatcher)
        self.assertIn("return `CORRECTION_REQUIRED`", sessions)
        self.assertIn(
            "do not choose, dispatch or execute the correction", normalized_sessions
        )
        self.assertIn(
            "after the repair and any required repeated review, run a fresh "
            "`receive_audit`",
            normalized_sessions.lower(),
        )
        self.assertIn(
            "repeat the review with fresh proof, then run a fresh `RECEIVE_AUDIT`",
            normalized_ultra,
        )
        hooks = (
            SKILLS
            / "nobrainer-ultra"
            / "references"
            / "correction-hooks.md"
        ).read_text(encoding="utf-8")
        normalized_hooks = " ".join(hooks.split())
        self.assertIn("mark it `STOPPED`", normalized_hooks)
        self.assertIn("keep its dependants `PENDING` or `BLOCKED`", normalized_hooks)
        self.assertIn("new plan fingerprint", normalized_hooks)
        self.assertIn("never infer that cancellation succeeded", normalized_hooks)
        self.assertIn(
            "after the repeated review, run a fresh `receive_audit`",
            normalized_hooks.lower(),
        )

    def test_dispatcher_eval_preserves_failed_history_and_current_holdout(self) -> None:
        record = (
            ROOT / "docs" / "evals" / "dispatcher-routing-v1.2.0-2026-08-28.md"
        ).read_text(encoding="utf-8")
        historical_run = (
            ROOT
            / "docs"
            / "evals"
            / "artifacts"
            / "v1.2.0-routing-release-holdout-run.md"
        ).read_text(encoding="utf-8")
        historical_final_run = (
            ROOT
            / "docs"
            / "evals"
            / "artifacts"
            / "v1.2.0-routing-final-verified-holdout-run.md"
        ).read_text(encoding="utf-8")
        current_probe_run = (
            ROOT
            / "docs"
            / "evals"
            / "artifacts"
            / "v1.2.0-routing-current-release-holdout-run.md"
        ).read_text(encoding="utf-8")
        exact_run = (
            ROOT
            / "docs"
            / "evals"
            / "artifacts"
            / "v1.2.0-routing-exact-release-holdout-run.md"
        ).read_text(encoding="utf-8")
        development_judge = (
            ROOT
            / "docs"
            / "evals"
            / "artifacts"
            / "v1.2.0-dispatcher-development-probe-judge.md"
        ).read_text(encoding="utf-8")
        post_review_judge = (
            ROOT
            / "docs"
            / "evals"
            / "artifacts"
            / "v1.2.0-dispatcher-post-review-holdout-judge.md"
        ).read_text(encoding="utf-8")
        post_review_prompt = (
            ROOT
            / "docs"
            / "evals"
            / "artifacts"
            / "v1.2.0-dispatcher-post-review-holdout-prompt.md"
        ).read_text(encoding="utf-8")
        release_judge = (
            ROOT
            / "docs"
            / "evals"
            / "artifacts"
            / "v1.2.0-routing-release-holdout-judge.md"
        ).read_text(encoding="utf-8")
        historical_final_judge = (
            ROOT
            / "docs"
            / "evals"
            / "artifacts"
            / "v1.2.0-routing-final-verified-holdout-judge.md"
        ).read_text(encoding="utf-8")
        current_probe_judge = (
            ROOT
            / "docs"
            / "evals"
            / "artifacts"
            / "v1.2.0-routing-current-release-holdout-judge.md"
        ).read_text(encoding="utf-8")
        exact_judge = (
            ROOT
            / "docs"
            / "evals"
            / "artifacts"
            / "v1.2.0-routing-exact-release-holdout-judge.md"
        ).read_text(encoding="utf-8")
        self.assertIn("DEVELOPMENT_PROBE: FAIL 3/4", record)
        self.assertIn("PRE_REVIEW_HOLDOUT: PASS 5/5", record)
        self.assertIn("INDEPENDENT_DIFF_REVIEW: NO_GO", record)
        self.assertIn("POST_REVIEW_HOLDOUT: INVALIDATED", record)
        self.assertIn("undefined lease value `UNCLAIMED`", record)
        self.assertIn("FULL_PACKAGE_REVIEW: NO_GO", record)
        self.assertIn(
            "HISTORICAL_RELEASE_HOLDOUT: PASS 5/5; "
            "INVALIDATED_BY_LATER_CONTRACT_EDITS",
            record,
        )
        self.assertIn("FINAL_VERIFIED_HOLDOUT: FAIL 4/5", record)
        self.assertIn("FINAL_HOLDOUT_JUDGE_ERROR", record)
        self.assertIn(
            "FINAL_HOLDOUT_BINDING: historical after "
            "semantics-preserving bootstrap compression",
            record,
        )
        self.assertIn("CURRENT_RELEASE_HARNESS_PROBE: FAIL 4/5", record)
        self.assertIn(
            "CURRENT_RELEASE_HARNESS_FINDING: candidate excerpt omitted "
            "the explicit no-blind-retry rule",
            record,
        )
        self.assertIn("EXACT_RELEASE_HOLDOUT: PASS 5/5", record)
        self.assertIn(
            "EXACT_RELEASE_BINDING: current source and 190-word bootstrap "
            "hashes verified",
            record,
        )
        self.assertIn(
            "INDEPENDENT_FINAL_DIFF_REVIEW: CLEAN_BY_BOUND_REVIEW_CHAIN",
            record,
        )
        self.assertIn(
            "FULL_REVIEW_DIFF_SHA256: "
            "d2c989148341a379cf6a9eee3a81898dcc024f0a5ea474f4d746eb7eac64d45c",
            record,
        )
        self.assertIn(
            "FOCUSED_REREVIEW_PACKET_SHA256: "
            "845cbe47e7cce845a7a96b26989ac20ee6c815f5a7d918217a0111c039717fc4",
            record,
        )
        self.assertIn("FOCUSED_REREVIEW_RESULT: CLEAN", record)
        self.assertIn("VERDICT: FAIL", development_judge)
        self.assertIn("VERDICT: PASS", post_review_judge)
        self.assertIn("`UNCLAIMED`", post_review_prompt)
        self.assertIn("VERDICT: PASS — 5/5 cases", release_judge)
        historical_final_case_lines = [
            line
            for line in historical_final_judge.splitlines()
            if re.match(r"^[A-E]: (PASS|FAIL)\b", line)
        ]
        self.assertEqual(
            sum(": PASS" in line for line in historical_final_case_lines), 4
        )
        self.assertEqual(
            sum(": FAIL" in line for line in historical_final_case_lines), 1
        )
        self.assertIn("HARD_FAILURES: NONE", historical_final_judge)
        self.assertIn("VERDICT: FAIL — 1/5 cases", historical_final_judge)
        self.assertIn("RESULT: FAIL 4/5", historical_final_run)
        self.assertIn("RELEASE_EVIDENCE: NO", historical_final_run)

        current_probe_case_lines = [
            line
            for line in current_probe_judge.splitlines()
            if re.match(r"^[A-E]: (PASS|FAIL)\b", line)
        ]
        self.assertEqual(
            sum(": PASS" in line for line in current_probe_case_lines), 4
        )
        self.assertEqual(
            sum(": FAIL" in line for line in current_probe_case_lines), 1
        )
        self.assertIn("VERDICT: FAIL — 4/5 cases", current_probe_judge)
        self.assertIn("RESULT: FAIL 4/5", current_probe_run)
        self.assertIn("RELEASE_EVIDENCE: NO", current_probe_run)

        exact_case_lines = [
            line
            for line in exact_judge.splitlines()
            if re.match(r"^[A-E]: (PASS|FAIL)\b", line)
        ]
        self.assertEqual(sum(": PASS" in line for line in exact_case_lines), 5)
        self.assertEqual(sum(": FAIL" in line for line in exact_case_lines), 0)
        self.assertIn("HARD_FAILURES: NONE", exact_judge)
        self.assertIn("MATERIAL_FINDINGS: NONE", exact_judge)
        self.assertIn("VERDICT: PASS — 5/5 cases", exact_judge)
        self.assertIn("RESULT: PASS 5/5", exact_run)
        self.assertIn("RELEASE_EVIDENCE: YES", exact_run)
        self.assertIn("CLIENT_RUNTIME: NOT_VERIFIED", record)
        self.assertIn(
            "BASELINE_COMMIT: d6931a1006bf0180955d8437fd93174b6a512428",
            historical_run,
        )
        self.assertIn("COMPARATIVE_SCORE_CLAIM: NONE", exact_run)
        self.assertRegex(exact_run, r"CANDIDATE_SESSION: [0-9a-f-]{36}")
        self.assertRegex(exact_run, r"JUDGE_SESSION: [0-9a-f-]{36}")

        def sha256(relative: str) -> str:
            return hashlib.sha256((ROOT / relative).read_bytes()).hexdigest()

        declared_skill = re.search(r"^SKILL_SHA256: ([0-9a-f]{64})$", record, re.M)
        self.assertIsNotNone(declared_skill)
        self.assertEqual(
            sha256("skills/nobrainer-dispatcher/SKILL.md"), declared_skill.group(1)
        )
        current_bootstrap = re.search(
            r"^CURRENT_BOOTSTRAP_SHA256: ([0-9a-f]{64})$", record, re.M
        )
        self.assertIsNotNone(current_bootstrap)
        self.assertEqual(
            sha256("adapters/bootstrap.md"), current_bootstrap.group(1)
        )
        for label in (
            "ULTRA_SHA256",
            "CORRECTION_HOOKS_SHA256",
            "DISPATCHER_SHA256",
            "SESSIONS_SHA256",
            "BOOTSTRAP_SHA256",
        ):
            self.assertRegex(
                historical_final_run, rf"(?m)^{label}: [0-9a-f]{{64}}$"
            )
        frozen_bootstrap = re.search(
            r"^BOOTSTRAP_SHA256: ([0-9a-f]{64})$", historical_final_run, re.M
        )
        self.assertIsNotNone(frozen_bootstrap)
        self.assertNotEqual(current_bootstrap.group(1), frozen_bootstrap.group(1))

        for run in (current_probe_run, exact_run):
            for label, relative in (
                ("ULTRA_SHA256", "skills/nobrainer-ultra/SKILL.md"),
                (
                    "CORRECTION_HOOKS_SHA256",
                    "skills/nobrainer-ultra/references/correction-hooks.md",
                ),
                ("DISPATCHER_SHA256", "skills/nobrainer-dispatcher/SKILL.md"),
                ("SESSIONS_SHA256", "skills/nobrainer-sessions/SKILL.md"),
                ("BOOTSTRAP_SHA256", "adapters/bootstrap.md"),
            ):
                declared = re.search(rf"^{label}: ([0-9a-f]{{64}})$", run, re.M)
                self.assertIsNotNone(declared)
                self.assertEqual(sha256(relative), declared.group(1))

        def assert_packet_integrity(run: str, stem: str) -> None:
            base = f"docs/evals/artifacts/{stem}"
            for label, suffix in (
                ("PROMPT_SHA256", "-prompt.md"),
                ("OUTPUT_SHA256", "-output.md"),
                ("JUDGE_RUBRIC_SHA256", "-judge-rubric.md"),
                ("JUDGE_PROMPT_SHA256", "-judge-prompt.md"),
                ("JUDGE_OUTPUT_SHA256", "-judge.md"),
            ):
                declared = re.search(rf"^{label}: ([0-9a-f]{{64}})$", run, re.M)
                self.assertIsNotNone(declared)
                self.assertEqual(sha256(base + suffix), declared.group(1))

            for label, raw_suffix, normalized_suffix in (
                ("RAW_OUTPUT_SHA256", "-output.raw.b64", "-output.md"),
                (
                    "RAW_JUDGE_OUTPUT_SHA256",
                    "-judge.raw.b64",
                    "-judge.md",
                ),
            ):
                raw = base64.b64decode(
                    (ROOT / (base + raw_suffix))
                    .read_text(encoding="ascii")
                    .strip(),
                    validate=True,
                )
                declared = re.search(rf"^{label}: ([0-9a-f]{{64}})$", run, re.M)
                self.assertIsNotNone(declared)
                self.assertEqual(hashlib.sha256(raw).hexdigest(), declared.group(1))
                self.assertEqual(
                    (ROOT / (base + normalized_suffix)).read_bytes(), raw + b"\n"
                )

        assert_packet_integrity(
            historical_final_run, "v1.2.0-routing-final-verified-holdout"
        )
        assert_packet_integrity(
            current_probe_run, "v1.2.0-routing-current-release-holdout"
        )
        assert_packet_integrity(
            exact_run, "v1.2.0-routing-exact-release-holdout"
        )

        exact_base = "docs/evals/artifacts/v1.2.0-routing-exact-release-holdout"
        exact_prompt = (ROOT / f"{exact_base}-prompt.md").read_text(
            encoding="utf-8"
        )
        exact_output = (ROOT / f"{exact_base}-output.md").read_text(
            encoding="utf-8"
        )
        exact_rubric = (ROOT / f"{exact_base}-judge-rubric.md").read_text(
            encoding="utf-8"
        )
        exact_judge_prompt = (ROOT / f"{exact_base}-judge-prompt.md").read_text(
            encoding="utf-8"
        )
        embedded_output = exact_judge_prompt.split(
            "## Candidate output\n\n", 1
        )[1]
        self.assertEqual(exact_output, embedded_output)
        rubric_payload = "Hard failures are:" + exact_rubric.split(
            "Hard failures are:", 1
        )[1]
        embedded_rubric = (
            exact_judge_prompt.split("## Frozen rubric\n\n", 1)[1]
            .split("\n\n## Candidate output", 1)[0]
            + "\n"
        )
        self.assertEqual(rubric_payload, embedded_rubric)

        routing_sources = (
            ("ULTRA_SHA256", "skills/nobrainer-ultra/SKILL.md"),
            (
                "CORRECTION_HOOKS_SHA256",
                "skills/nobrainer-ultra/references/correction-hooks.md",
            ),
            ("DISPATCHER_SHA256", "skills/nobrainer-dispatcher/SKILL.md"),
            ("SESSIONS_SHA256", "skills/nobrainer-sessions/SKILL.md"),
            ("BOOTSTRAP_SHA256", "adapters/bootstrap.md"),
        )
        for label, relative in routing_sources:
            prompt_declared = re.search(
                rf"^{label}: ([0-9a-f]{{64}})$", exact_prompt, re.M
            )
            run_declared = re.search(
                rf"^{label}: ([0-9a-f]{{64}})$", exact_run, re.M
            )
            self.assertIsNotNone(prompt_declared)
            self.assertIsNotNone(run_declared)
            self.assertEqual(sha256(relative), prompt_declared.group(1))
            self.assertEqual(prompt_declared.group(1), run_declared.group(1))

        routing_binding_paths = tuple(relative for _, relative in routing_sources) + (
            f"{exact_base}-prompt.md",
            f"{exact_base}-output.md",
            f"{exact_base}-output.raw.b64",
            f"{exact_base}-judge-rubric.md",
            f"{exact_base}-judge-prompt.md",
            f"{exact_base}-judge.md",
            f"{exact_base}-judge.raw.b64",
        )
        binding = hashlib.sha256()
        for relative in routing_binding_paths:
            binding.update(relative.encode("utf-8"))
            binding.update(b"\0")
            binding.update(hashlib.sha256((ROOT / relative).read_bytes()).digest())
        declared_binding = re.search(
            r"^SOURCE_AND_ARTIFACT_SET_SHA256: ([0-9a-f]{64})$", exact_run, re.M
        )
        self.assertIsNotNone(declared_binding)
        self.assertEqual(binding.hexdigest(), declared_binding.group(1))

    def test_writing_eval_freezes_research_behavior_and_release_evidence(self) -> None:
        record = (
            ROOT / "docs" / "evals" / "writing-density-v1.2.0-2026-08-28.md"
        ).read_text(encoding="utf-8")
        run = (
            ROOT
            / "docs"
            / "evals"
            / "artifacts"
            / "v1.2.0-writing-release-holdout-run.md"
        ).read_text(encoding="utf-8")
        release_judge = (
            ROOT
            / "docs"
            / "evals"
            / "artifacts"
            / "v1.2.0-writing-release-holdout-judge.md"
        ).read_text(encoding="utf-8")
        for status in (
            "BASELINE_CAPABILITY: ABSENT",
            "COMPARATIVE_SCORE_CLAIM: NONE",
            "DEVELOPMENT_PROBE: PASS 5/5",
            "FIRST_FINAL_HOLDOUT: PASS 5/5",
            "INDEPENDENT_DIFF_REVIEW: NO_GO",
            "RELEASE_HOLDOUT: PASS 5/5",
            "CLIENT_RUNTIME: NOT_VERIFIED",
        ):
            self.assertIn(status, record)
        self.assertIn("VERDICT: PASS — 5/5 cases", release_judge)
        self.assertIn("BASELINE_COMMIT: d6931a1006bf0180955d8437fd93174b6a512428", run)
        self.assertRegex(run, r"CANDIDATE_SESSION: [0-9a-f-]{36}")
        self.assertRegex(run, r"JUDGE_SESSION: [0-9a-f-]{36}")

        def sha256(relative: str) -> str:
            return hashlib.sha256((ROOT / relative).read_bytes()).hexdigest()

        for label, relative in (
            ("SKILL_SHA256", "skills/nobrainer-writing/SKILL.md"),
            (
                "PROMPT_SHA256",
                "docs/evals/artifacts/v1.2.0-writing-release-holdout-prompt.md",
            ),
            (
                "OUTPUT_SHA256",
                "docs/evals/artifacts/v1.2.0-writing-release-holdout-output.md",
            ),
            (
                "JUDGE_PROMPT_SHA256",
                "docs/evals/artifacts/v1.2.0-writing-release-holdout-judge-prompt.md",
            ),
            (
                "JUDGE_OUTPUT_SHA256",
                "docs/evals/artifacts/v1.2.0-writing-release-holdout-judge.md",
            ),
        ):
            declared = re.search(rf"^{label}: ([0-9a-f]{{64}})$", run, re.M)
            self.assertIsNotNone(declared)
            self.assertEqual(sha256(relative), declared.group(1))

        for label, raw_relative, normalized_relative in (
            (
                "RAW_OUTPUT_SHA256",
                "docs/evals/artifacts/v1.2.0-writing-release-holdout-output.raw.b64",
                "docs/evals/artifacts/v1.2.0-writing-release-holdout-output.md",
            ),
            (
                "RAW_JUDGE_OUTPUT_SHA256",
                "docs/evals/artifacts/v1.2.0-writing-release-holdout-judge.raw.b64",
                "docs/evals/artifacts/v1.2.0-writing-release-holdout-judge.md",
            ),
        ):
            raw = base64.b64decode(
                (ROOT / raw_relative).read_text(encoding="ascii").strip(),
                validate=True,
            )
            declared = re.search(rf"^{label}: ([0-9a-f]{{64}})$", run, re.M)
            self.assertIsNotNone(declared)
            self.assertEqual(hashlib.sha256(raw).hexdigest(), declared.group(1))
            self.assertEqual((ROOT / normalized_relative).read_bytes(), raw + b"\n")

        writing_binding_paths = (
            "skills/nobrainer-writing/SKILL.md",
            "docs/evals/artifacts/v1.2.0-writing-release-holdout-prompt.md",
            "docs/evals/artifacts/v1.2.0-writing-release-holdout-output.md",
            "docs/evals/artifacts/v1.2.0-writing-release-holdout-output.raw.b64",
            "docs/evals/artifacts/v1.2.0-writing-release-holdout-judge-prompt.md",
            "docs/evals/artifacts/v1.2.0-writing-release-holdout-judge.md",
            "docs/evals/artifacts/v1.2.0-writing-release-holdout-judge.raw.b64",
        )
        binding = hashlib.sha256()
        for relative in writing_binding_paths:
            binding.update(relative.encode("utf-8"))
            binding.update(b"\0")
            binding.update(hashlib.sha256((ROOT / relative).read_bytes()).digest())
        declared_binding = re.search(
            r"^SOURCE_AND_ARTIFACT_SET_SHA256: ([0-9a-f]{64})$", run, re.M
        )
        self.assertIsNotNone(declared_binding)
        self.assertEqual(binding.hexdigest(), declared_binding.group(1))

        judge_prompt = (
            ROOT
            / "docs/evals/artifacts/v1.2.0-writing-release-holdout-judge-prompt.md"
        ).read_text(encoding="utf-8")
        for relative in writing_binding_paths[:3]:
            self.assertIn(f"`{relative}`", judge_prompt)

        historical = (
            (
                "DEVELOPMENT_RAW_OUTPUT_SHA256",
                "docs/evals/artifacts/v1.2.0-writing-development-probe-output.raw.b64",
            ),
            (
                "DEVELOPMENT_RAW_JUDGE_OUTPUT_SHA256",
                "docs/evals/artifacts/v1.2.0-writing-development-probe-judge.raw.b64",
            ),
            (
                "FIRST_FINAL_RAW_OUTPUT_SHA256",
                "docs/evals/artifacts/v1.2.0-writing-final-holdout-output.raw.b64",
            ),
            (
                "FIRST_FINAL_RAW_JUDGE_OUTPUT_SHA256",
                "docs/evals/artifacts/v1.2.0-writing-final-holdout-judge.raw.b64",
            ),
        )
        for label, relative in historical:
            raw = base64.b64decode(
                (ROOT / relative).read_text(encoding="ascii").strip(), validate=True
            )
            declared = re.search(rf"^{label}: ([0-9a-f]{{64}})$", record, re.M)
            self.assertIsNotNone(declared)
            self.assertEqual(hashlib.sha256(raw).hexdigest(), declared.group(1))

    def test_active_product_has_no_external_workflow_branding(self) -> None:
        checked = [
            ROOT / "README.md",
            ROOT / "AGENTS.md",
            ROOT / "CLAUDE.md",
            ROOT / "CONTRIBUTING.md",
            ROOT / "RELEASE-NOTES.md",
            ROOT / "docs" / "INSTALL.md",
            ROOT / "docs" / "SKILL_CURATION.md",
            *[path for name in CANONICAL for path in (SKILLS / name).rglob("*.md")],
        ]
        for path in checked:
            with self.subTest(path=path):
                text = path.read_text(encoding="utf-8").lower()
                for brand in validate_skills.EXTERNAL_WORKFLOW_BRANDS:
                    self.assertNotIn(brand, text)

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
        self.assertIn("Correction hooks", ultra)
        self.assertIn("OWNER_DECISION_CHANGED", ultra)
        self.assertIn("AGENT_ERROR_CORRECTED", ultra)
        self.assertIn("REVIEW_FAILED", ultra)
        self.assertIn("invalidate", ultra.lower())
        self.assertIn("regression scenario", autoimprove)
        self.assertIn("`AUTO_SCOPED`", autoimprove)
        self.assertIn("`ASK`", autoimprove)
        self.assertIn("`OFF`", autoimprove)
        self.assertIn("do not create a durable diff", autoimprove)
        self.assertIn("Durable personalization without hidden memory", wiki)
        self.assertIn("source, date, scope", wiki)

        hooks = (
            SKILLS / "nobrainer-ultra" / "references" / "correction-hooks.md"
        ).read_text(encoding="utf-8")
        for term in (
            "SUPERSEDE",
            "tasks/lessons.md",
            "AGENTS.md",
            "nobrainer-wiki",
            "secret",
            "REPLAN_REQUIRED",
            "LEARNING_WRITE_POLICY",
            "AUTO_SCOPED",
        ):
            self.assertIn(term, hooks)
        self.assertIn("one canonical owner", hooks)
        self.assertIn("under `ASK`, prepare the exact single-store diff", hooks)
        self.assertIn("under `OFF`, keep the prevention candidate", hooks)
        self.assertIn("do not\n     create or modify `tasks/lessons.md`", hooks)

        self.assertIn("`AUTO_SCOPED` may persist", readme)
        self.assertIn("`ASK` prepares one exact diff", readme)
        self.assertIn("`OFF` keeps it\n  task-local without a durable diff", readme)

    def test_legacy_skills_are_not_discoverable(self) -> None:
        for name in LEGACY:
            with self.subTest(name=name):
                self.assertFalse((SKILLS / name / "SKILL.md").exists())

    def test_retiable_private_invocations_route_without_alias_directories(self) -> None:
        expected = {
            "nobrainer-ultra": ("nb-flow", "nb-workflow"),
            "nobrainer-team": ("nobrainer-skill-browser",),
            "nobrainer-dispatcher": ("nb-dispatcher",),
            "nobrainer-build": ("engineering-standards", "nobrainer-simplifier"),
            "nobrainer-writing": (
                "nobrainer-style",
                "nobrainer-human-like",
            ),
            "nobrainer-security": ("security-review",),
            "nobrainer-sessions": ("nb-multi", "session-handoff"),
            "nobrainer-wiki": ("nb-add", "nb-get", "nb-tidy"),
            "nobrainer-autoimprove": (
                "deep-autoresearch",
                "code-autoresearch",
                "nobrainer-capture-lesson",
            ),
            "nobrainer-decide": ("deep-decide",),
            "nobrainer-rca": ("deep-rca",),
            "nobrainer-review": ("deep-audit", "deep-code-review"),
        }
        for name, triggers in expected.items():
            description = parse_frontmatter(SKILLS / name / "SKILL.md")[
                "description"
            ]
            for trigger in triggers:
                self.assertIn(trigger, description, f"{name}: missing {trigger}")

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

    def test_unknown_private_audit_skill_has_no_unsafe_migration(self) -> None:
        name = "nobrainer-fast-audit"
        curation = (ROOT / "docs" / "SKILL_CURATION.md").read_text(
            encoding="utf-8"
        )
        self.assertNotIn(name, install_skills.LEGACY_TO_CANONICAL)
        self.assertIn(name, install_skills.UNMAPPED_LEGACY)
        self.assertIn(f"`{name}` is currently `UNKNOWN`", curation)
        self.assertIn("clean-session parity check", curation)

    def test_public_clean_suite(self) -> None:
        forbidden = (
            "/Users/",
            "/opt/homebrew/",
            "/private/tmp/",
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
            "adapters/bootstrap.md",
            ".claude-plugin/plugin.json",
            ".codex-plugin/plugin.json",
            ".cursor-plugin/plugin.json",
            ".kimi-plugin/plugin.json",
            ".pi/extensions/nobrainer-tech-skills.js",
            "GEMINI.md",
            "gemini-extension.json",
            "hooks/hooks.json",
            "hooks/hooks-cursor.json",
            "hooks/run-hook.cmd",
            "hooks/session-start",
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
            ".kimi-plugin/plugin.json",
            "gemini-extension.json",
            "package.json",
        )
        for relative in manifests:
            with self.subTest(manifest=relative):
                json.loads((ROOT / relative).read_text(encoding="utf-8"))

        self.assertFalse((ROOT / ".devin-plugin" / "plugin.json").exists())
        self.assertFalse((ROOT / ".hermes-plugin" / "plugin.yaml").exists())

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

    def test_compatibility_separates_repository_client_and_runtime_proof(self) -> None:
        text = (ROOT / "docs" / "COMPATIBILITY.md").read_text(encoding="utf-8")
        pull_request_template = (
            ROOT / ".github" / "PULL_REQUEST_TEMPLATE.md"
        ).read_text(encoding="utf-8")
        for level in (
            "SOURCE_VALIDATED",
            "REPOSITORY_CHECKED",
            "CLIENT_LOADED",
            "RUNTIME_VERIFIED",
            "DISTRIBUTED",
        ):
            self.assertIn(level, text)
            self.assertIn(level, pull_request_template)
        for surface in (text, pull_request_template):
            self.assertNotIn("ADAPTER_VALIDATED", surface)

    def test_v1_0_release_readback_remains_explicit(self) -> None:
        release_notes = (ROOT / "RELEASE-NOTES.md").read_text(encoding="utf-8")
        normalized_notes = " ".join(release_notes.split())
        compatibility = (ROOT / "docs" / "COMPATIBILITY.md").read_text(
            encoding="utf-8"
        )
        release_evidence = (
            ROOT / "docs" / "releases" / "v1.0.0.md"
        ).read_text(encoding="utf-8")
        version = "1.0.0"
        release_sha = "bf60c4c3a57440c6b87cd1b326cd41237b7225da"
        self.assertIn(release_sha, release_notes)
        self.assertIn(f"## v{version}", release_notes)
        self.assertIn(
            "This version is published as a tagged GitHub source release",
            normalized_notes,
        )
        self.assertIn("docs/releases/v1.0.0.md", release_notes)
        self.assertIn("GitHub source channel is `DISTRIBUTED`", compatibility)
        self.assertIn("isolated installer readback", compatibility)
        self.assertNotIn("does not claim publication", release_notes)
        self.assertIn(
            "This is not a claim of publication in npm or any client marketplace",
            normalized_notes,
        )
        evidence_pairs = re.findall(
            r"^([A-Z][A-Z0-9_]+): (.+)$", release_evidence, re.MULTILINE
        )
        evidence = dict(evidence_pairs)
        self.assertEqual(len(evidence_pairs), len(evidence))
        self.assertEqual(f"v{version}", evidence["TAG"])
        self.assertEqual(version, evidence["VERSION"])
        self.assertEqual(release_sha, evidence["COMMIT_SHA"])
        self.assertRegex(evidence["COMMIT_SHA"], r"^[0-9a-f]{40}$")
        self.assertRegex(evidence["TREE_SHA"], r"^[0-9a-f]{40}$")
        self.assertRegex(evidence["TARBALL_SHA256"], r"^[0-9a-f]{64}$")
        self.assertTrue(evidence["RELEASE_URL"].endswith(f"/tag/{evidence['TAG']}"))
        self.assertTrue(evidence["TARBALL_URL"].endswith(f"/{evidence['TAG']}"))
        self.assertEqual(f"{evidence['TAG']}.tar.gz", evidence["TARBALL_FILENAME"])
        self.assertEqual("false", evidence["GITHUB_RELEASE_IMMUTABLE"])
        self.assertEqual("PASS", evidence["ARCHIVE_FILE_MATCH"])
        self.assertEqual("9", evidence["ARCHIVE_SKILL_COUNT"])
        self.assertEqual("57/57 PASS", evidence["ARCHIVE_TESTS"])
        self.assertEqual("codex", evidence["INSTALL_CLIENT"])
        self.assertEqual("PASS", evidence["INSTALL_READBACK"])

    def test_v1_1_release_readback_remains_explicit(self) -> None:
        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        release_notes = (ROOT / "RELEASE-NOTES.md").read_text(encoding="utf-8")
        normalized_notes = " ".join(release_notes.split())
        release_evidence = (
            ROOT / "docs" / "releases" / "v1.1.0.md"
        ).read_text(encoding="utf-8")
        section = release_notes.split("## v1.1.0", 1)[1].split("## v1.0.0", 1)[0]
        released_skills = re.findall(
            r"^- `(nobrainer-[a-z0-9-]+)`$", section, re.MULTILINE
        )
        release_sha = "d6931a1006bf0180955d8437fd93174b6a512428"
        expected_skills = [
            name
            for name in CANONICAL_ORDER
            if name not in {"nobrainer-dispatcher", "nobrainer-writing"}
        ]
        self.assertIn("## v1.1.0", release_notes)
        self.assertEqual(expected_skills, released_skills)
        self.assertNotIn("release candidate", section.lower())
        self.assertIn(
            "This version is published as a tagged GitHub source release",
            normalized_notes,
        )
        self.assertIn(release_sha, readme)
        self.assertIn(release_sha, release_notes)
        self.assertIn("docs/releases/v1.1.0.md", readme)

        evidence_pairs = re.findall(
            r"^([A-Z][A-Z0-9_]+): (.+)$", release_evidence, re.MULTILINE
        )
        evidence = dict(evidence_pairs)
        self.assertEqual(len(evidence_pairs), len(evidence))
        self.assertEqual("1.1.0", evidence["VERSION"])
        self.assertEqual("v1.1.0", evidence["TAG"])
        self.assertEqual(release_sha, evidence["COMMIT_SHA"])
        self.assertEqual("false", evidence["GITHUB_RELEASE_IMMUTABLE"])
        self.assertEqual("PASS", evidence["ARCHIVE_FILE_MATCH"])
        self.assertEqual("13", evidence["ARCHIVE_SKILL_COUNT"])
        self.assertEqual("70/70 PASS", evidence["ARCHIVE_TESTS"])
        self.assertEqual("13/13 PASS", evidence["ARCHIVE_QUICK_VALIDATE"])
        self.assertEqual("PASS", evidence["ARCHIVE_SECRET_SCAN"])
        self.assertEqual("agents", evidence["INSTALL_CLIENT"])
        self.assertEqual("copy", evidence["INSTALL_MODE"])
        self.assertEqual("PASS", evidence["INSTALL_READBACK"])

    def test_current_release_candidate_surface(self) -> None:
        release_notes = (ROOT / "RELEASE-NOTES.md").read_text(encoding="utf-8")
        current = json.loads((ROOT / "package.json").read_text(encoding="utf-8"))[
            "version"
        ]
        section = release_notes.split("## v1.1.0", 1)[0]
        candidate_skills = re.findall(
            r"^- `(nobrainer-[a-z0-9-]+)`$", section, re.MULTILINE
        )
        self.assertEqual("1.2.0", current)
        self.assertIn(f"## v{current}", release_notes)
        self.assertEqual(list(CANONICAL_ORDER), candidate_skills)
        self.assertEqual(ACTIVE, set(candidate_skills))
        self.assertIn("release candidate", section.lower())
        self.assertIn("not a publication claim", section.lower())

    def test_readme_branding_and_links(self) -> None:
        text = (ROOT / "README.md").read_text(encoding="utf-8")
        self.assertIn("nobrainer-tech-skills", text)
        self.assertIn("assets/nobrainer-tech-logo.svg", text)
        self.assertIn("https://nobrainer.tech", text)
        self.assertIn("https://nobrainertech.gumroad.com", text)
        self.assertIn("agentic workflows", text.lower())
        self.assertIn("assets/nobrainer-workflow.svg", text)
        self.assertNotIn("nobrainer-skills-coverage-v2.png", text)
        self.assertIn("docs/COMPATIBILITY.md", text)
        self.assertIn("docs/TESTING.md", text)

    def test_install_snippets_require_one_literal_reviewed_commit(self) -> None:
        documents = (
            (ROOT / "README.md", "## Install safely"),
            (ROOT / "docs" / "INSTALL.md", "## Safe default"),
        )
        for path, heading in documents:
            with self.subTest(path=path.relative_to(ROOT)):
                section = path.read_text(encoding="utf-8").split(heading, 1)[1]
                match = re.search(r"```bash\n(.*?)```", section, re.DOTALL)
                self.assertIsNotNone(match)
                snippet = match.group(1)
                self.assertIn("NB_REVIEWED_COMMIT", snippet)
                self.assertNotIn("NB_REVIEWED_REF", snippet)
                self.assertIn('${#NB_REVIEWED_COMMIT}', snippet)
                self.assertIn('*[!0-9a-f]*', snippet)
                self.assertIn(
                    'test "$(git rev-parse HEAD)" = "$NB_REVIEWED_COMMIT"',
                    snippet,
                )
                self.assertIn("git clone --no-checkout", snippet)
                self.assertGreaterEqual(snippet.count("|| exit"), 8)

                for value in (None, "v1.2.0", "g" * 40, "a" * 39):
                    with self.subTest(value=value):
                        environment = dict(os.environ)
                        if value is None:
                            environment.pop("NB_REVIEWED_COMMIT", None)
                        else:
                            environment["NB_REVIEWED_COMMIT"] = value
                        with tempfile.TemporaryDirectory() as temp:
                            result = subprocess.run(
                                ["bash", "-c", snippet],
                                cwd=temp,
                                env=environment,
                                text=True,
                                capture_output=True,
                                check=False,
                            )
                            self.assertNotEqual(0, result.returncode)
                            self.assertFalse(
                                (Path(temp) / "nobrainer-tech-skills").exists()
                            )

    def test_coverage_graphic_is_readme_ready(self) -> None:
        path = ROOT / "assets" / "nobrainer-workflow.svg"
        text = path.read_text(encoding="utf-8")
        self.assertTrue(text.startswith("<svg"))
        self.assertIn('viewBox="0 0 1600 900"', text)
        self.assertIn("BUDDY", text)
        self.assertIn("EXECUTION MAP", text)
        self.assertIn("BUILD", text)
        self.assertIn("REVIEW", text)
        self.assertIn("LEARN", text)
        self.assertIn("review-fix-loop", text)
        self.assertLessEqual(len(text.encode("utf-8")), 200_000)
        self.assertFalse((ROOT / "assets" / "nobrainer-skills-coverage-v2.png").exists())
        self.assertFalse((ROOT / "assets" / "nobrainer-skills-coverage.webp").exists())

    def test_product_repository_surface(self) -> None:
        required = (
            ".gitattributes",
            "CONTRIBUTING.md",
            "RELEASE-NOTES.md",
            "SECURITY.md",
            "docs/COMPATIBILITY.md",
            "docs/releases/v1.0.0.md",
            "docs/releases/v1.1.0.md",
            "docs/TESTING.md",
            "docs/SKILL_CURATION.md",
            "docs/evals/core-routing-v1.1.0-2026-08-28.md",
            "docs/evals/dispatcher-routing-v1.2.0-2026-08-28.md",
            "docs/evals/writing-density-v1.2.0-2026-08-28.md",
            "assets/nobrainer-workflow.svg",
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
        self.assertEqual({}, codex["hooks"])
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
        self.assertIn("nobrainer-build", text)
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

    def test_frozen_eval_payloads_do_not_impersonate_repository_links(self) -> None:
        artifact_dir = ROOT / "docs" / "evals" / "artifacts"
        prompt = artifact_dir / "v1.2.0-routing-final-verified-holdout-prompt.md"
        run = artifact_dir / "v1.2.0-routing-final-verified-holdout-run.md"
        record = ROOT / "docs" / "evals" / "dispatcher-routing-v1.2.0-2026-08-28.md"
        self.assertFalse(validate_skills.should_validate_relative_links(prompt))
        self.assertTrue(validate_skills.should_validate_relative_links(run))
        self.assertTrue(validate_skills.should_validate_relative_links(record))
        self.assertTrue(
            validate_skills.relative_link_errors(prompt, "[literal](missing.md)")
        )

        attributes = (ROOT / ".gitattributes").read_text(encoding="utf-8")
        self.assertNotIn("docs/evals/artifacts/** -whitespace", attributes)
        for line in attributes.splitlines():
            if line.startswith("docs/evals/artifacts/"):
                self.assertTrue(line.endswith("-text -whitespace"), line)
        checked = subprocess.run(
            [
                "git",
                "check-attr",
                "text",
                "whitespace",
                "--",
                str(prompt),
                str(run),
            ],
            cwd=ROOT,
            text=True,
            capture_output=True,
            check=True,
        ).stdout
        self.assertIn(f"{prompt}: text: unset", checked)
        self.assertIn(f"{prompt}: whitespace: unset", checked)
        self.assertIn(f"{run}: text: unspecified", checked)
        self.assertIn(f"{run}: whitespace: unspecified", checked)

    def test_frozen_eval_payloads_are_byte_stable_under_autocrlf(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            repo = Path(directory)
            payloads = {
                "docs/evals/artifacts/example-prompt.md": (
                    b"prompt CRLF with spaces  \r\nprompt LF\nprompt CRLF\r\n"
                ),
                "docs/evals/artifacts/example-output.md": (
                    b"output LF with spaces  \noutput CRLF\r\noutput LF\n"
                ),
                "docs/evals/artifacts/example-judge.md": (
                    b"judge CRLF\r\njudge LF with spaces  \njudge CRLF\r\n"
                ),
                "docs/evals/artifacts/example-judge-rubric.md": (
                    b"rubric LF\nrubric CRLF with spaces  \r\nrubric LF\n"
                ),
                "docs/evals/artifacts/example.raw.b64": (
                    b"cHJvbXB0DQo=\r\nb3V0cHV0Cg==\n"
                ),
            }
            for relative, original in payloads.items():
                payload = repo / relative
                payload.parent.mkdir(parents=True, exist_ok=True)
                payload.write_bytes(original)
            (repo / ".gitattributes").write_bytes(
                (ROOT / ".gitattributes").read_bytes()
            )
            subprocess.run(["git", "init", "-q"], cwd=repo, check=True)
            subprocess.run(
                [
                    "git",
                    "-c",
                    "core.autocrlf=true",
                    "add",
                    ".gitattributes",
                    *payloads,
                ],
                cwd=repo,
                check=True,
            )
            for relative, original in payloads.items():
                with self.subTest(relative=relative, phase="index"):
                    stored = subprocess.run(
                        ["git", "show", f":{relative}"],
                        cwd=repo,
                        capture_output=True,
                        check=True,
                    ).stdout
                    self.assertEqual(original, stored)
                    (repo / relative).unlink()
            subprocess.run(
                [
                    "git",
                    "-c",
                    "core.autocrlf=true",
                    "-c",
                    "core.eol=crlf",
                    "checkout",
                    "--",
                    *payloads,
                ],
                cwd=repo,
                check=True,
            )
            for relative, original in payloads.items():
                with self.subTest(relative=relative, phase="checkout"):
                    self.assertEqual(original, (repo / relative).read_bytes())

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
