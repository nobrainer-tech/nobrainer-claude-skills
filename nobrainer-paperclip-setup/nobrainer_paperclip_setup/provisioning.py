"""Per-agent provisioning logic shared by ``add_repo`` and ``scale``.

The two actions used to duplicate ~40 lines each for the same end-to-end
provisioning sequence: pick agent_id, create worktree, allocate browser
profile + CDP port, build prompt, optionally upsert with Paperclip, append
the agent dict to state. This module owns that flow.

Callers handle the broader transaction (state.save cadence, rollback,
scheduler entry installation, browser launch).
"""

from __future__ import annotations

import shutil
import sys
from pathlib import Path
from typing import Any, Optional

from . import backend, browser_pool, paperclip_api, paths, state as state_mod, worktree


def provision_agent(
    *,
    state: dict[str, Any],
    company: dict[str, Any],
    repo_name: str,
    repo_path: Path,
    cdp_port: int,
    browser_choice: str,
    backend_choice: str,
    api: Optional[paperclip_api.PaperclipAPI],
) -> dict[str, Any]:
    """Provision one agent end-to-end and return the agent dict to append to
    ``state["agents"]``. The caller is responsible for ``state_mod.save``.

    Idempotency: if Paperclip already has an agent with the conventional name
    AND the local state already references the same ``paperclip_agent_id``,
    raises :class:`AgentAlreadyProvisioned` so the caller can skip without
    treating it as an error.

    On failure raises, after best-effort rollback of any side effects created
    in this call (Paperclip agent, worktree, browser profile dir).
    """
    agent_id = state_mod.next_agent_id(state)
    agent_name = f"{company['slug']}-{repo_name}-agent-{agent_id}"

    worktree_path: Optional[Path] = None
    profile_dir: Optional[Path] = None
    paperclip_agent_id: Optional[str] = None

    paperclip_ok = bool(
        api is not None
        and company.get("paperclip_company_id")
        and api.health()
    )

    try:
        # Idempotency: reuse an existing Paperclip agent if one already has
        # the conventional name. If local state already references it, raise
        # AlreadyProvisioned so the caller can skip cleanly.
        if paperclip_ok:
            existing = api.find_agent_by_name(
                company["paperclip_company_id"], agent_name,
            )
            if existing is not None:
                paperclip_agent_id = (
                    existing.get("id") or existing.get("agent_id")
                )
                already_present = any(
                    a.get("paperclip_agent_id") == paperclip_agent_id
                    for a in state.get("agents", [])
                )
                if already_present:
                    raise AgentAlreadyProvisioned(agent_name)

        worktree_path = worktree.create(repo_path, company["slug"], agent_id)
        _, profile_dir = browser_pool.allocate(
            company["slug"], repo_name, agent_id,
        )

        be_cfg = backend.agent_config(backend_choice)
        prompt = backend.system_prompt(
            company=company["slug"],
            repo=repo_name,
            agent_id=agent_id,
            ticket_path=paths.ticket_cache_dir(company["slug"]) / "PLACEHOLDER.json",
            worktree_path=worktree_path,
            report_path=(
                paths.tickets_dir(company["slug"], repo_name)
                / "PLACEHOLDER" / "report.html"
            ),
        )

        if paperclip_ok and paperclip_agent_id is None:
            # Strict variant: PaperclipAPIError on failure propagates to the
            # outer except below, which tears down the worktree + profile and
            # re-raises. Persisting a half-created agent with
            # ``paperclip_agent_id=None`` would silently swallow every task
            # assigned to it later on.
            created = api.create_agent(
                company_id=company["paperclip_company_id"],
                name=agent_name,
                backend_config=be_cfg,
                system_prompt=prompt,
            )
            paperclip_agent_id = (
                created.get("id") or created.get("agent_id")
            )
            if not paperclip_agent_id:
                raise paperclip_api.PaperclipAPIError(
                    "create_agent returned an object without id/agent_id",
                    kind="json", method="POST",
                    path=f"/api/companies/{company['paperclip_company_id']}/agents",
                )

        return {
            "id": agent_id,
            "paperclip_agent_id": paperclip_agent_id,
            "worktree_path": str(worktree_path),
            "cdp_port": int(cdp_port),
            "browser": browser_choice,
            "browser_profile_path": str(profile_dir),
            "backend": backend_choice,
            "model": be_cfg.get("model"),
            "current_task_id": None,
            "last_heartbeat": paths.now_utc_iso(),
        }

    except AgentAlreadyProvisioned:
        raise
    except Exception as exc:  # noqa: BLE001 — rethrown after rollback
        print(
            f"error provisioning agent {agent_id}: {exc}; rolling back",
            file=sys.stderr,
        )
        if paperclip_agent_id and api is not None and company.get("paperclip_company_id"):
            try:
                api.delete_agent(
                    company["paperclip_company_id"], paperclip_agent_id,
                )
            except Exception as cleanup_exc:  # noqa: BLE001
                print(
                    f"  rollback: delete_agent failed: {cleanup_exc}",
                    file=sys.stderr,
                )
        if worktree_path is not None:
            try:
                worktree.remove(worktree_path)
            except Exception as cleanup_exc:  # noqa: BLE001
                print(
                    f"  rollback: worktree.remove failed: {cleanup_exc}",
                    file=sys.stderr,
                )
        if profile_dir is not None:
            shutil.rmtree(profile_dir, ignore_errors=True)
        raise


class AgentAlreadyProvisioned(Exception):
    """Raised when Paperclip + local state already have this agent registered."""

    def __init__(self, agent_name: str) -> None:
        super().__init__(f"agent {agent_name!r} already provisioned")
        self.agent_name = agent_name
