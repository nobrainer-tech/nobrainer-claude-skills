from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import re
import subprocess
import sys
import unittest


ROOT = Path(__file__).resolve().parents[1]
EVENTS = (
    "START",
    "AFTER_COMPACTION",
    "MATERIAL_TRANSITION",
    "BEFORE_CLOSEOUT",
)
SIGNALS = ("turn_age", "history_size", "compactions", "cost_or_tokens")


@dataclass(frozen=True)
class HealthSnapshot:
    policy: dict[str, int]
    signals: dict[str, int]
    unsupported: bool = False


def session_health_gate(snapshot: HealthSnapshot) -> str:
    """Small test-only reference for the portable gate, not a host adapter."""
    if snapshot.unsupported:
        return "UNSUPPORTED"
    if any(name not in snapshot.signals for name in snapshot.policy):
        return "UNKNOWN"
    if any(
        snapshot.signals[name] > limit
        for name, limit in snapshot.policy.items()
    ):
        return "ROTATE_REQUIRED"
    return "HEALTHY"


def rotation_action(health: str, *, owner_approved: bool) -> tuple[str, bool]:
    if health != "ROTATE_REQUIRED":
        return "CONTINUE", False
    if not owner_approved:
        return "CHECKPOINT_AND_END_TURN", False
    return "ROTATE_WITH_OWNER_APPROVAL", True


def runtime_release(owned_workers: int | None, *, supported: bool = True) -> str:
    if not supported:
        return "UNSUPPORTED"
    if owned_workers is None:
        return "UNKNOWN"
    return "VERIFIED" if owned_workers == 0 else "NOT_RELEASED"


def live_worker_count(workers: list[subprocess.Popen[bytes]]) -> int:
    return sum(worker.poll() is None for worker in workers)


def clean_closeout(health: str, task_complete: bool, release: str) -> bool:
    return health == "HEALTHY" and task_complete and release == "VERIFIED"


def no_ready_action(ready_rows: list[str], owner_gated: bool) -> str:
    if not ready_rows and owner_gated:
        return "OWNER_DECISION_REQUIRED"
    return "CONTINUE"


class SessionLifecycleTests(unittest.TestCase):
    def setUp(self) -> None:
        self.policy = {
            "turn_age": 100,
            "history_size": 1000,
            "compactions": 3,
            "cost_or_tokens": 10_000,
        }
        self.signals = {
            "turn_age": 20,
            "history_size": 400,
            "compactions": 1,
            "cost_or_tokens": 2_000,
        }

    def test_clean_session_trace_is_healthy_and_released(self) -> None:
        snapshot = HealthSnapshot(self.policy, self.signals)
        for event in EVENTS:
            with self.subTest(event=event):
                self.assertEqual(session_health_gate(snapshot), "HEALTHY")
        self.assertEqual(runtime_release(0), "VERIFIED")
        self.assertTrue(clean_closeout("HEALTHY", True, "VERIFIED"))

    def test_limit_checkpoints_and_ends_turn_without_rotation(self) -> None:
        signals = dict(self.signals, history_size=1_001)
        health = session_health_gate(HealthSnapshot(self.policy, signals))
        self.assertEqual(health, "ROTATE_REQUIRED")
        action, created_session = rotation_action(health, owner_approved=False)
        self.assertEqual(action, "CHECKPOINT_AND_END_TURN")
        self.assertFalse(created_session)

    def test_unknown_and_unsupported_signals_never_look_healthy(self) -> None:
        incomplete = dict(self.signals)
        incomplete.pop("history_size")
        self.assertEqual(
            session_health_gate(HealthSnapshot(self.policy, incomplete)), "UNKNOWN"
        )
        self.assertEqual(
            session_health_gate(HealthSnapshot(self.policy, self.signals, True)),
            "UNSUPPORTED",
        )
        self.assertFalse(clean_closeout("UNKNOWN", True, "VERIFIED"))
        self.assertFalse(clean_closeout("HEALTHY", True, "UNSUPPORTED"))

    def test_task_complete_does_not_release_live_workers(self) -> None:
        self.assertEqual(runtime_release(1), "NOT_RELEASED")
        self.assertFalse(clean_closeout("HEALTHY", True, "NOT_RELEASED"))

    def test_clean_session_releases_a_controlled_live_worker(self) -> None:
        worker = subprocess.Popen(
            [sys.executable, "-c", "import time; time.sleep(30)"]
        )
        try:
            self.assertEqual(runtime_release(live_worker_count([worker])), "NOT_RELEASED")
            self.assertFalse(clean_closeout("HEALTHY", True, "NOT_RELEASED"))
        finally:
            worker.terminate()
            worker.wait(timeout=5)
        self.assertEqual(runtime_release(live_worker_count([worker])), "VERIFIED")

    def test_no_ready_work_returns_owner_decision_required(self) -> None:
        action = no_ready_action([], owner_gated=True)
        self.assertEqual(action, "OWNER_DECISION_REQUIRED")

    def test_portable_contract_names_health_and_release_boundaries(self) -> None:
        paths = (
            ROOT / "skills" / "nobrainer-ultra" / "SKILL.md",
            ROOT / "skills" / "nobrainer-ultra" / "references" / "long-run-state.md",
            ROOT / "skills" / "nobrainer-sessions" / "SKILL.md",
            ROOT / "skills" / "nobrainer-sessions" / "references" / "protocol.md",
            ROOT / "docs" / "TESTING.md",
            ROOT / "docs" / "COMPATIBILITY.md",
            ROOT / "README.md",
            ROOT / "assets" / "nobrainer-workflow.svg",
        )
        combined = "\n".join(path.read_text(encoding="utf-8") for path in paths)
        for term in (
            "SESSION_HEALTH_GATE",
            "RUNTIME_RELEASE",
            "AFTER_COMPACTION",
            "MATERIAL_TRANSITION",
            "BEFORE_CLOSEOUT",
            "ROTATE_REQUIRED",
            "CHECKPOINT_AND_END_TURN",
            "OWNER_DECISION_REQUIRED",
            "task_complete",
            "UNKNOWN",
            "UNSUPPORTED",
            "RUNTIME_RELEASE readback",
        ):
            self.assertIn(term, combined)
        self.assertNotRegex(combined, re.compile(r"\bPID\b"))
        self.assertNotIn("JSONL", combined)
        self.assertNotIn("/" + "Users" + "/", combined)
        self.assertNotIn("/" + "Volumes" + "/", combined)


if __name__ == "__main__":
    unittest.main()
