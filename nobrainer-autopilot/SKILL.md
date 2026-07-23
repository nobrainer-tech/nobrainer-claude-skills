---
name: nobrainer-autopilot
description: >-
  Autonomous CI/CD workflow for any project — collects work items, spawns expert
  teams, implements on branches, opens PRs, drives them through a mandatory
  fail-closed Copilot review gate, and (only when explicitly armed for merge)
  merges and optionally deploys. Language-agnostic; fails closed at every gate.
  Use when the user says "autopilot", "autopilot mode", "autonomous mode", "work
  autonomously", "uruchom autopilota", "tryb autopilota". Never fires on vague
  filler like "go"/"go go"/"cisnij".
---

# NoBrainer Autopilot

Autonomous CI/CD workflow for any project. Collects work items, spawns expert
teams, implements on branches, opens PRs, drives them through a mandatory
Copilot review gate, and — only when explicitly armed for merge — merges and
optionally deploys. Language-agnostic; fails closed at every gate.

**Trigger** (exact, explicit only — never fire on conversational filler):
"autopilot", "autopilot mode", "autonomous mode", "work autonomously",
"uruchom autopilota", "tryb autopilota".

Do NOT auto-trigger on vague phrases like "go", "go go", "cisnij", "lec sam".
If the user says one of those, ask: "Uruchomić autopilota (autonomiczny loop
z merge gate)?" and wait for a yes.

## Arming Handshake (required before any destructive phase)

Autopilot has two authority levels. Confirm which one applies for THIS run:

- **PR-only (default)**: implement, open PRs, drive the review gate — but STOP
  before merge and hand each green PR back to the user. Safe default; honors the
  standing rule "never merge to main without explicit approval."
- **Full-merge**: same, plus auto-merge and (if configured) deploy. Only enter
  this mode when the user explicitly says "autopilot with merge" / "merguj sam"
  in this run. Never assume it.

State the chosen mode back to the user before Phase 2.

## Prerequisites Check

Resolve repo identity once and reuse it everywhere:
```bash
OWNER=$(gh repo view --json owner --jq '.owner.login')
REPO=$(gh repo view --json name --jq '.name')
DEFAULT_BRANCH=$(gh repo view --json defaultBranchRef --jq '.defaultBranchRef.name')
