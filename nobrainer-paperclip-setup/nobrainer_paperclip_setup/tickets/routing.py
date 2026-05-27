"""Pick which agent to assign a new ticket to.

Strategies:
- ``round-robin`` (default): rotate via a persisted cursor stored in state so
  consecutive ticks distribute load evenly. Falls back to index 0 for the
  very first pick.
- ``least-loaded``: agent without an active ``current_task_id`` wins.
- ``by-type``: match agent ``specialty`` to issue type, fallback round-robin.

In all strategies, agents without a ``paperclip_agent_id`` or with a stale
heartbeat are filtered out before selection.
"""

from __future__ import annotations

import datetime as _dt
from typing import Any, Optional

from .. import preferences


def _stale_threshold_minutes() -> int:
    prefs = preferences.load()
    routing = prefs.get("routing", {}) or {}
    try:
        return int(routing.get("stale_heartbeat_minutes", 60))
    except (TypeError, ValueError):
        return 60


def _heartbeat_fresh(agent: dict[str, Any], threshold_min: int) -> bool:
    hb = agent.get("last_heartbeat")
    if not hb:
        # No heartbeat recorded yet: treat as fresh so freshly-provisioned
        # agents are dispatchable.
        return True
    try:
        ts = _dt.datetime.strptime(hb, "%Y-%m-%dT%H:%M:%SZ").replace(
            tzinfo=_dt.timezone.utc,
        )
    except (TypeError, ValueError):
        return True
    age_min = (
        _dt.datetime.now(tz=_dt.timezone.utc) - ts
    ).total_seconds() / 60.0
    return age_min <= threshold_min


def _healthy_agents(state: dict[str, Any]) -> list[dict[str, Any]]:
    threshold = _stale_threshold_minutes()
    return [
        a for a in state.get("agents", [])
        if a.get("paperclip_agent_id") and _heartbeat_fresh(a, threshold)
    ]


def pick_agent(
    company: str,
    repo: str,
    ticket: dict,
    state: dict[str, Any],
) -> Optional[int]:
    """Return the chosen agent id, or ``None`` if none are healthy.

    Mutates ``state["_routing_cursor"]`` for round-robin — caller is
    responsible for persisting state after the pick so the cursor survives
    across ticks. Concurrency must be guarded by an external lock.
    """
    agents = _healthy_agents(state)
    if not agents:
        return None

    strategy = preferences.get("routing_strategy", "round-robin")

    if strategy == "least-loaded":
        agents.sort(key=lambda a: 1 if a.get("current_task_id") else 0)
        return int(agents[0]["id"])

    if strategy == "by-type":
        ttype = (
            (ticket.get("fields") or {}).get("issuetype", {}).get("name", "Task")
        ).lower()
        for a in agents:
            if (a.get("specialty") or "").lower() == ttype:
                return int(a["id"])
        # Fall through to round-robin

    cursor = int(state.get("_routing_cursor", 0) or 0)
    idx = cursor % len(agents)
    state["_routing_cursor"] = cursor + 1
    return int(agents[idx]["id"])
