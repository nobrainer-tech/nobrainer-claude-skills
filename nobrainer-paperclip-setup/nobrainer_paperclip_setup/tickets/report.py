"""Render the per-ticket HTML report from a string.Template.

Embeds a minimal markdown-to-HTML converter so we never depend on a third-party
library. Output is a single self-contained file with inline CSS.
"""

from __future__ import annotations

import html
import re
from pathlib import Path
from string import Template
from typing import Any

from .. import paths


def _md_to_html(text: str) -> str:
    """Tiny markdown subset: headings, bullets, code fences, bold, italics, links."""
    if not text:
        return ""
    out_lines: list[str] = []
    in_code = False
    code_buf: list[str] = []
    bullet_open = False

    def _flush_bullet() -> None:
        nonlocal bullet_open
        if bullet_open:
            out_lines.append("</ul>")
            bullet_open = False

    for raw in text.splitlines():
        line = raw.rstrip()
        if line.startswith("```"):
            if in_code:
                out_lines.append("<pre><code>" + html.escape("\n".join(code_buf)) + "</code></pre>")
                code_buf = []
                in_code = False
            else:
                _flush_bullet()
                in_code = True
            continue
        if in_code:
            code_buf.append(line)
            continue
        if not line.strip():
            _flush_bullet()
            out_lines.append("")
            continue
        m = re.match(r"^(#{1,6})\s+(.*)$", line)
        if m:
            _flush_bullet()
            level = len(m.group(1))
            out_lines.append(f"<h{level}>{html.escape(m.group(2))}</h{level}>")
            continue
        if re.match(r"^\s*[-*]\s+", line):
            if not bullet_open:
                out_lines.append("<ul>")
                bullet_open = True
            item = re.sub(r"^\s*[-*]\s+", "", line)
            out_lines.append(f"  <li>{_inline(item)}</li>")
            continue
        _flush_bullet()
        out_lines.append(f"<p>{_inline(line)}</p>")
    if in_code and code_buf:
        out_lines.append("<pre><code>" + html.escape("\n".join(code_buf)) + "</code></pre>")
    _flush_bullet()
    return "\n".join(out_lines)


_ALLOWED_URL_SCHEMES = re.compile(r"^(?:https?:|mailto:|#|/)", re.IGNORECASE)


def _safe_url(u: str) -> str:
    """Reject ``javascript:``, ``data:``, and other unsafe schemes."""
    u = u.strip()
    if not u or not _ALLOWED_URL_SCHEMES.match(u):
        return "#"
    return u


def _inline(text: str) -> str:
    text = html.escape(text)
    text = re.sub(r"\*\*(.+?)\*\*", r"<strong>\1</strong>", text)
    text = re.sub(r"\*(.+?)\*", r"<em>\1</em>", text)
    text = re.sub(r"`([^`]+)`", r"<code>\1</code>", text)
    text = re.sub(
        r"\[([^\]]+)\]\(([^)]+)\)",
        lambda m: f'<a href="{html.escape(_safe_url(m.group(2)))}">{m.group(1)}</a>',
        text,
    )
    return text


def _coverage_rows(coverage: list[dict[str, Any]]) -> str:
    if not coverage:
        return '<tr><td colspan="3"><em>No acceptance criteria captured.</em></td></tr>'
    rows: list[str] = []
    for entry in coverage:
        ac = html.escape(str(entry.get("ac", "")))
        covered = "yes" if entry.get("covered") else "no"
        evidence_url = entry.get("evidence_url") or ""
        if evidence_url:
            # ``_safe_url`` strips ``javascript:`` / ``data:`` / etc. so an
            # attacker-controlled evidence URL cannot run JS when the report
            # is opened in a browser.
            evidence_html = (
                f'<a href="{html.escape(_safe_url(str(evidence_url)))}">link</a>'
            )
        else:
            evidence_html = "&mdash;"
        rows.append(f"<tr><td>{ac}</td><td>{covered}</td><td>{evidence_html}</td></tr>")
    return "\n".join(rows)


def _files_changed(files: list[str]) -> str:
    if not files:
        return "<em>No file changes recorded.</em>"
    items = "".join(f"<li><code>{html.escape(f)}</code></li>" for f in files)
    return f"<ul>{items}</ul>"


_IMG_EXTS: set[str] = {".png", ".jpg", ".jpeg", ".gif", ".webp"}


def _safe_evidence_files(evidence_dir: Path) -> list[Path]:
    """Return regular files inside ``evidence_dir`` that are safe to expose.

    Rejects:
    - names containing ``..`` or path separators (defence in depth, iterdir
      should never produce these but a malicious filesystem can).
    - symlinks pointing outside ``evidence_dir`` (post-resolve check).
    """
    safe: list[Path] = []
    try:
        base = evidence_dir.resolve()
    except OSError:
        return safe
    try:
        entries = list(evidence_dir.iterdir())
    except OSError:
        return safe
    for f in entries:
        if not f.is_file():
            continue
        if ".." in f.name or "/" in f.name or "\\" in f.name:
            continue
        try:
            resolved = f.resolve()
            resolved.relative_to(base)
        except (OSError, ValueError):
            continue
        safe.append(f)
    return safe


def _evidence_gallery(evidence_dir: Path) -> str:
    if not evidence_dir.exists():
        return "<em>No evidence captured.</em>"
    files = _safe_evidence_files(evidence_dir)
    images = sorted(f for f in files if f.suffix.lower() in _IMG_EXTS)
    if not images:
        return "<em>No screenshots captured.</em>"
    cards: list[str] = []
    for img in images:
        cards.append(
            f'<a class="thumb" href="{html.escape(img.name)}">'
            f'<img src="{html.escape(img.name)}" alt="{html.escape(img.name)}"></a>'
        )
    return f'<div class="gallery">{"".join(cards)}</div>'


def render(ticket: dict, agent_output: dict, evidence_dir: Path) -> Path:
    """Render a self-contained HTML report. Returns the report path."""
    fields = ticket.get("fields") or {}
    key = str(ticket.get("key") or ticket.get("id") or "UNKNOWN")
    company = str(agent_output.get("company") or ticket.get("_company") or "unknown")
    repo = str(agent_output.get("repo") or ticket.get("_repo") or "unknown")

    out_dir = paths.ticket_report_dir(company, repo, key)
    report_path = out_dir / "report.html"

    tmpl_path = paths.templates_dir() / "ticket_report.html"
    template = Template(tmpl_path.read_text(encoding="utf-8"))

    description = fields.get("description") or ""
    if isinstance(description, dict):
        description = _flatten_adf(description)

    ac = agent_output.get("acceptance_criteria") or fields.get("customfield_acceptance") or ""
    if isinstance(ac, list):
        ac = "\n".join(f"- {item}" for item in ac)

    body = template.substitute(
        title=html.escape(fields.get("summary", key)),
        ticket_key=html.escape(key),
        status=html.escape((fields.get("status") or {}).get("name", "unknown")),
        issue_type=html.escape((fields.get("issuetype") or {}).get("name", "unknown")),
        priority=html.escape((fields.get("priority") or {}).get("name", "unknown")),
        ticket_url=html.escape(_safe_url(ticket.get("self") or ticket.get("url") or "")),
        company=html.escape(company),
        repo=html.escape(repo),
        description_html=_md_to_html(str(description)),
        acceptance_html=_md_to_html(str(ac)),
        coverage_rows=_coverage_rows(agent_output.get("coverage", []) or []),
        files_changed=_files_changed(agent_output.get("files_changed", []) or []),
        tests_summary=html.escape(str(agent_output.get("tests_summary", "no tests reported"))),
        tests_link=html.escape(_safe_url(agent_output.get("tests_link", "") or "")),
        evidence_gallery=_evidence_gallery(evidence_dir),
        reasoning_html=_md_to_html(str(agent_output.get("reasoning", ""))),
        proposed_action=html.escape(agent_output.get("proposed_action", "no action proposed")),
        backend_name=html.escape(str(agent_output.get("backend", "unknown"))),
        time_spent=html.escape(str(agent_output.get("time_spent", "n/a"))),
        retry_count=html.escape(str(agent_output.get("retry_count", 0))),
        queued_at=html.escape(str(agent_output.get("queued_at", ""))),
        rendered_at=html.escape(paths.now_utc_iso()),
        agent_status=html.escape(str(agent_output.get("status", "unknown"))),
    )

    paths.atomic_write_text(report_path, body)
    return report_path


def _flatten_adf(adf: dict) -> str:
    """Best-effort flatten of Atlassian Document Format to plain text."""
    out: list[str] = []
    def _walk(node: Any) -> None:
        if isinstance(node, dict):
            if node.get("type") == "text" and isinstance(node.get("text"), str):
                out.append(node["text"])
            for child in node.get("content", []) or []:
                _walk(child)
            if node.get("type") in ("paragraph", "heading", "bulletList", "listItem"):
                out.append("\n")
        elif isinstance(node, list):
            for child in node:
                _walk(child)
    _walk(adf)
    return "".join(out).strip()
