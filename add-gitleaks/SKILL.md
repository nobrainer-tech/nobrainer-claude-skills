---
name: add-gitleaks
description: Add gitleaks secret-scanning to any git repo — config, pre-commit hook, CI job (GitHub Actions or Buildkite), and a baseline so existing findings don't block. Use when the user says "dodaj gitleaks", "add gitleaks", "secret scanning do repo", "wykrywanie sekretów w repo", "gitleaks hook/CI", or wants to stop committing secrets.
---

# Add gitleaks to a repo

Wires [gitleaks](https://github.com/gitleaks/gitleaks) into a repository at three layers: local pre-commit (fast feedback), CI (enforcement), and a baseline (so legacy secrets already in history don't block the pipeline on day one).

## When to use

- User asks to add secret scanning / gitleaks to a project.
- A repo has no guard against committing API keys, tokens, `.env` values, private keys.
- Standardizing a new `sm-*` or NoBrainer repo.

## Procedure

Work from the repo root. Do NOT invent secrets or paste real ones into any file.

### 1. Recon — decide what to wire

Run these to learn the repo's shape:

```bash
git rev-parse --show-toplevel                    # confirm we're in a git repo
gitleaks version 2>/dev/null || echo "no-gitleaks"
ls .github/workflows 2>/dev/null && echo "HAS_GHA"
ls .buildkite 2>/dev/null && echo "HAS_BUILDKITE"
test -f .pre-commit-config.yaml && echo "HAS_PRECOMMIT"
test -f lefthook.yml -o -f lefthook.yaml && echo "HAS_LEFTHOOK"
test -f .gitleaks.toml && echo "HAS_GITLEAKS_CFG"
```

Decisions:
- **CI target**: `.github/workflows/` present → GitHub Actions. `.buildkite/` present → Buildkite. If both, do both. If neither, add GitHub Actions only if the repo has a GitHub remote (`git remote -v`); otherwise skip CI and tell the user.
- **Hook mechanism**: prefer whatever the repo already uses — `pre-commit` framework, then `lefthook`, else a committed helper script + install note. Never rely only on `.git/hooks/` (not shared across clones).

### 2. Install gitleaks locally if missing

```bash
brew install gitleaks   # macOS
# or: go install github.com/gitleaks/gitleaks/v8@latest
```

### 3. Config — `.gitleaks.toml`

If `HAS_GITLEAKS_CFG` is absent, copy `assets/gitleaks.toml` to the repo root. It extends the built-in ruleset (`useDefault = true`) and holds project allowlist entries (test fixtures, example files). Only add allowlist paths you can justify — never allowlist a real secret.

### 4. Baseline existing findings

Scan history and freeze current findings so CI fails only on NEW secrets:

```bash
gitleaks git . --report-path gitleaks-baseline.json --exit-code 0
```

- If the report is `[]` (empty), delete `gitleaks-baseline.json` — no baseline needed, clean repo.
- If it has findings, KEEP the file, commit it, and **surface the count to the user** — these are real secrets already in history. Recommend rotation; baselining silences the alert, it does not make the secret safe. State this explicitly.

### 5. Pre-commit hook

- **pre-commit framework** (`HAS_PRECOMMIT` or user prefers it): merge the `gitleaks` block from `assets/pre-commit-config.yaml` into `.pre-commit-config.yaml`, then `pre-commit install`.
- **lefthook**: add the `gitleaks` command from `assets/lefthook-snippet.yml` under `pre-commit.commands`, then `lefthook install`.
- **neither**: copy `assets/pre-commit.sh` to `scripts/gitleaks-precommit.sh`, `chmod +x` it, and give the user the one-liner to symlink it: `ln -sf ../../scripts/gitleaks-precommit.sh .git/hooks/pre-commit`. Explain this is per-clone (not shared), so recommend adopting the pre-commit framework for team-wide coverage.

The hook scans STAGED changes only (`gitleaks git --staged`) — fast, blocks the commit on a hit.

### 6. CI job

- **GitHub Actions**: copy `assets/github-actions-gitleaks.yml` to `.github/workflows/gitleaks.yml`. Uses `gitleaks/gitleaks-action@v2` with `fetch-depth: 0` (full history). Note: the Action requires `GITLEAKS_LICENSE` only for org accounts — personal/OSS repos run free. Tell the user if the repo is under an org.
- **Buildkite**: add the step from `assets/buildkite-gitleaks.yml` to the repo's pipeline (usually `.buildkite/pipeline.yml`). It runs gitleaks in a container with the baseline path wired in.

Wire the baseline into CI: if `gitleaks-baseline.json` exists, both templates already pass `--baseline-path gitleaks-baseline.json`. If you deleted the baseline in step 4, remove that flag from the template you copied.

### 7. Verify — prove it works

Do not declare done without this.

```bash
# Full scan must pass (respecting baseline)
gitleaks git . $( [ -f gitleaks-baseline.json ] && echo "--baseline-path gitleaks-baseline.json" ) -v

# Prove the hook actually catches a secret: stage a fake key, scan staged, expect exit 1
printf 'aws_secret=AKIAIOSFODNN7EXAMPLE\n' > /tmp/gl_probe && git add -f -N /tmp/gl_probe 2>/dev/null
gitleaks git --staged -v; echo "exit=$?"   # expect a finding / non-zero
git reset -q 2>/dev/null; rm -f /tmp/gl_probe
```

Report to the user: files added, CI target chosen, hook mechanism, and — if a baseline was created — the count of pre-existing findings with a rotation recommendation.

## Guardrails

- Never commit real secrets, never allowlist a real finding to make CI green.
- A baseline hides history findings from CI; it does not remediate them. Always say so.
- Do not commit any of this unless the user asks (per their global rule: no commits without explicit permission).
