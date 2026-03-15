# NoBrainer Autopilot

Autonomous CI/CD workflow for any project. Converts TODOs to issues, spawns expert teams, implements, creates PRs with Copilot review gate, merges — all hands-free.

**Trigger**: "autopilot", "go go", "dzialaj sam", "lec sam", "cisnij", "autopilot mode", "autonomous mode", "work autonomously"

## Prerequisites Check

Before starting, verify:

1. **nobrainer-team-builder installed**:
   ```bash
   ls ~/.claude/skills/nobrainer-team-builder/skill.md
   ```
   If missing: `git clone https://github.com/nobrainer-tech/nobrainer-claude-skills.git /tmp/nbs && cp -r /tmp/nbs/nobrainer-team-builder ~/.claude/skills/`

2. **GitHub Copilot review configured** on the repo:
   ```bash
   # Check if Copilot reviews exist on recent PRs
   gh api repos/{owner}/{repo}/pulls?state=closed\&per_page=5 --jq '.[].number' | while read pr; do
     has=$(gh api repos/{owner}/{repo}/pulls/$pr/reviews --jq '[.[] | select(.user.login == "copilot-pull-request-reviewer[bot]")] | length')
     if [ "$has" -gt 0 ]; then echo "Copilot active on PR #$pr"; break; fi
   done
   ```
   If not configured: warn user to enable Copilot code review in repo settings → Code review → Copilot.

3. **CLAUDE.md exists** in project root with coding standards.

## Phase 1: Discovery & Planning

### Step 1: Codebase Review
Spawn 3 agents in parallel:
- **code-explorer**: Map architecture, key files, dependencies
- **code-reviewer**: Find bugs, code quality issues, missing tests
- **test-engineer**: Assess test coverage gaps

### Step 2: Collect TODOs
Gather work items from ALL sources:
```bash
# Existing GitHub issues
gh issue list --state open --json number,title,labels

# TODO/FIXME/HACK in code
grep -rn "TODO\|FIXME\|HACK\|XXX" --include="*.py" --include="*.ts" --include="*.js" .

# tasks/todo.md if exists
cat tasks/todo.md 2>/dev/null
```

### Step 3: Present Plan to User
Show a prioritized list:

```
## Autopilot Plan

| # | Priority | Source | Description |
|---|----------|--------|-------------|
| 1 | HIGH | Issue #42 | Fix auth bypass vulnerability |
| 2 | HIGH | Code review | 3 files over 300-line limit |
| 3 | MED | TODO | Add input validation to API |
| 4 | LOW | Issue #38 | Refactor logging module |

Proceed on autopilot? (adjust priorities or say "go")
```

### Step 4: Convert to Issues
After user approves, ensure each item has a GitHub issue:
```bash
# Create issues for TODOs not yet tracked
gh issue create --title "..." --body "..." --label "autopilot"
```

## Phase 2: Autonomous Execution Loop

For each issue (highest priority first):

### Step 1: Spawn Expert Team (min 5 agents)

Use `nobrainer-team-builder` skill with **minimum 5 agents**. Team composition based on task:

| Task Type | Agents |
|-----------|--------|
| Bug fix | python-pro, debugger, test-engineer, code-reviewer, security-auditor |
| Feature | python-pro, architect-reviewer, test-engineer, code-reviewer, debugger |
| Refactor | refactoring-specialist, code-reviewer, test-engineer, python-pro, architect-reviewer |
| Security | security-auditor, python-pro, test-engineer, code-reviewer, debugger |

### Step 2: Implement
- Create feature branch from main
- Implement the fix/feature
- Run tests: `python -m pytest tests/ -x`
- Verify coding standards:
  - **DRY** — no duplicated logic
  - **KISS** — simplest solution that works
  - **SOLID** — single responsibility, open/closed
  - **YAGNI** — no speculative features
  - **Max 300 lines per file** (up to 350 acceptable)
  - **Max 80 lines per function**

### Step 3: Create PR
```bash
git push -u origin {branch}
gh pr create --title "..." --body "Fixes #{N}\n\n## Summary\n...\n\n## Test plan\n..."
```

### Step 4: Copilot Review Gate

**CRITICAL — the most important step. NEVER skip.**

```bash
# Poll until Copilot review EXISTS (3-5 min typical)
for i in $(seq 1 10); do
  reviews=$(gh api repos/{owner}/{repo}/pulls/{N}/reviews \
    --jq '[.[] | select(.user.login == "copilot-pull-request-reviewer[bot]")] | length')
  if [ "$reviews" -gt 0 ]; then echo "Copilot reviewed"; break; fi
  echo "Waiting for Copilot... ($i/10)"
  sleep 60
done
```

**After review exists:**
1. Read inline comments: `gh api repos/{owner}/{repo}/pulls/{N}/comments`
2. Reply to EACH comment (1-2 sentences)
3. Resolve EACH thread via GraphQL
4. If fixes needed → commit, push, wait for re-review (repeat from poll)
5. Verify 0 unresolved threads:
   ```bash
   gh api graphql -f query='{ repository(owner:"{owner}", name:"{repo}") {
     pullRequest(number:{N}) { reviewThreads(first:50) {
       nodes { isResolved } } } } }' \
     --jq '[.data.repository.pullRequest.reviewThreads.nodes[] | select(.isResolved==false)] | length'
   ```
   Must return `0`.

### Step 5: Merge
```bash
gh pr merge {N} --squash --delete-branch
```

### Step 6: Deploy (if configured)
If project has deploy instructions in CLAUDE.md → deploy after merge.

### Step 7: Next Issue
Go back to Step 1 with next priority issue.

## Quality Gates (enforced on every PR)

| Gate | Check |
|------|-------|
| Tests pass | `pytest -x` exit 0 |
| No file > 350 lines | `find . -name "*.py" -exec wc -l {} \; \| awk '$1>350'` |
| No function > 80 lines | Code review agent |
| DRY/KISS/SOLID/YAGNI | Code review agent |
| Copilot reviewed | Review exists + 0 unresolved threads |
| CI passes | `gh pr checks {N}` all pass |

## Rules

- **Min 5 agents per task** — diminishing returns below that for quality
- **Always create issue first** — never implement without tracked issue
- **Copilot gate is NON-NEGOTIABLE** — even for "trivial" changes
- **Reply before resolve** — never silently resolve threads
- **300-line limit** — up to 350 acceptable, over 350 must split
- **Deploy after merge** — if deploy instructions exist in CLAUDE.md
- **Ask user only when blocked** — autopilot means autonomous
