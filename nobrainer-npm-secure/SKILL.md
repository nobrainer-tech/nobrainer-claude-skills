---
name: nobrainer-npm-secure
description: "Use when hardening a machine or project against npm supply-chain attacks (compromised packages, malicious postinstall scripts, typosquats) — e.g. after incidents like the TanStack, axios, chalk/debug, or Shai-Hulud worm compromises. Sets up minimum-release-age cooldown across npm/pnpm/bun, blocks lifecycle scripts, and pins dependency trees. Trigger on: npm supply chain, cooldown, minimum-release-age, ignore-scripts, pin dependencies, secure npm, lockfile."
---

# nobrainer-npm-secure — npm Supply-Chain Hardening

Set up defense-in-depth against npm supply-chain attacks: a **release-age cooldown** so package managers refuse versions published in the last N days, **lifecycle-script blocking** so malicious `postinstall` code can't run, and **pinned + committed lockfiles** so the resolved tree is reproducible.

**Core principle:** Malicious package versions are typically detected and unpublished within hours to a few days. A cooldown window means you never install a version during its dangerous, freshly-published phase. Blocking install scripts removes the most common malware execution path.

This skill defaults to a **14-day** cooldown. 7 days catches nearly all real incidents; 14 adds margin at the cost of lagging legitimate updates (including security patches) by 14 days.

## When to Use

- Hardening a dev machine or CI runner against npm supply-chain attacks
- After a publicized npm/pnpm compromise, wanting to make sure you're protected
- Setting up a new project and wanting safe-by-default dependency installs
- User says "secure npm", "set up cooldown", "minimum release age", "protect against supply chain"

**When NOT to use:** projects that *must* consume bleeding-edge releases within hours (rare); air-gapped/offline installs (cooldown needs registry publish timestamps).

## Critical Facts (verified)

| Tool | Config key | File | **Unit** | 14-day value | Min version |
|------|-----------|------|----------|--------------|-------------|
| npm  | `min-release-age` | `~/.npmrc` (global) or project `.npmrc` | **days** | `14` | **npm 11.10.0** (Feb 2026) |
| pnpm | `minimumReleaseAge` | `pnpm-workspace.yaml` (per project) | **minutes** | `20160` | pnpm 10.16; **on by default in pnpm 11** (1-day) |
| bun  | `minimumReleaseAge` | `bunfig.toml` `[install]` | **seconds** | `1209600` | bun 1.2.x |
| Yarn | `npmMinimalAgeGate` | `.yarnrc.yml` | **minutes** | `20160` | Yarn 4.10.0 |

Each tool uses a **different unit** — using the wrong unit silently disables protection. The cooldown is enforced at *install* time, not at update-suggestion time, so Renovate/Dependabot need their own `minimumReleaseAge` config.

## Procedure

### Step 0 — Detect tools and versions (do this first)

```bash
npm -v 2>/dev/null; pnpm -v 2>/dev/null; bun -v 2>/dev/null
```

**`min-release-age` does nothing on npm < 11.10.0.** If `npm -v` reports below 11.10.0, the cooldown line is dead config — upgrade first:

```bash
npm install -g npm@latest
```

Only configure the tools that are actually installed. Report which were skipped.

### Step 1 — npm: edit `~/.npmrc`

Read the file first. **Keep every existing line** (auth tokens, registry, scopes). Append only keys that are not already present:

```ini
min-release-age=14
save-exact=true
ignore-scripts=true
```

- `min-release-age=14` — refuse versions published in the last 14 **days** (npm ≥ 11.10.0).
- `save-exact=true` — `npm install <pkg>` writes an exact version, no `^`/`~`.
- `ignore-scripts=true` — blocks lifecycle scripts (`preinstall`/`install`/`postinstall`) of dependencies. **This is the highest-value line** — most npm malware runs here. See the caveat below before adding it.

Do **not** add `minimum-release-age=...` — that is not an npm key (npm only honours `min-release-age`, in days). It is silently ignored.

### Step 2 — pnpm: per-project `pnpm-workspace.yaml`

In pnpm 11+, `.npmrc` is restricted to auth/registry; pnpm settings live in `pnpm-workspace.yaml`. Create or edit it at the project root:

```yaml
minimumReleaseAge: 20160          # 14 days, in minutes
minimumReleaseAgeExclude:         # optional: trusted internal scopes
  - '@myorg/*'
```

For a **global** pnpm default across all projects:

```bash
pnpm config set --global minimumReleaseAge 20160
pnpm config get minimumReleaseAge   # verify it stuck
```

pnpm 10+ already **blocks dependency lifecycle scripts by default** (allowlist via `pnpm approve-builds` / `onlyBuiltDependencies`) — so pnpm users get the `ignore-scripts` benefit for free. Upgrading to pnpm 11 also enables a 1-day cooldown by default.

### Step 3 — bun: edit `~/.bunfig.toml` (only if bun is installed)

Create if missing, keep existing content, append:

```toml
[install]
minimumReleaseAge = 1209600       # 14 days, in seconds
```

### Step 4 — pin the project's dependencies

Open `package.json`. Strip `^` and `~` from **`dependencies` and `devDependencies` only** — exact versions.

**Do NOT exact-pin `peerDependencies`.** Peer deps are intentionally ranges; pinning them to one exact version makes a library nearly impossible to install for downstream consumers. Leave them as ranges.

Pinning direct deps does **not** pin transitive deps — only the lockfile does. So:

### Step 5 — commit the lockfile

Commit `package-lock.json` / `pnpm-lock.yaml` / `bun.lock` so the fully-resolved tree (including transitive deps) is locked in git. In CI, install with the frozen variant so the lockfile is honoured exactly, never silently re-resolved:

```bash
npm ci                              # not: npm install
pnpm install --frozen-lockfile
bun install --frozen-lockfile
```

### Step 6 — verify and report

```bash
npm config get min-release-age      # → 14
npm config get ignore-scripts       # → true
pnpm config get minimumReleaseAge   # → 20160 (if set globally)
```

Report: files changed, deps pinned (count), tools skipped (and why — not installed / version too old), and anything unexpected.

## The `ignore-scripts` caveat

`ignore-scripts=true` blocks malicious install hooks — but it also blocks **legitimate** native builds. Packages like `esbuild`, `sharp`, `better-sqlite3`, `bcrypt`, `puppeteer`, and `node-sap` compile native addons in `postinstall`. With scripts globally off they will install broken.

Handling it:
- After a normal install, rebuild trusted native packages explicitly: `npm rebuild <pkg>` (this runs *their* scripts only, on demand).
- Or override per-install when you trust the set: `npm install --ignore-scripts=false`.
- If a project depends heavily on native modules and `npm rebuild` is friction, you may omit `ignore-scripts=true` globally and rely on the cooldown alone — but say so explicitly in the report; it's a real reduction in protection.

## What this does NOT protect against

- **Already-installed compromised versions** — cooldown only gates *new* resolutions. Audit existing trees separately (`npm audit signatures`, Socket, etc.).
- **Slow-burn attacks** that stay undetected past the cooldown window (rare, but the Shai-Hulud worm re-propagated). Cooldown is one layer, not the only one.
- **Renovate/Dependabot PRs** — they suggest updates regardless; configure their own `minimumReleaseAge`.
- **Registry-level or account compromise** — pair with 2FA, scoped tokens, and OIDC publishing.

Trade-off to state up front: a 14-day cooldown also delays legitimate security patches by 14 days. If a CVE fix is urgent, add the package to the tool's `*Exclude` list temporarily.

## Common Mistakes

| Mistake | Reality |
|---------|---------|
| Putting `minimum-release-age=10080` in `~/.npmrc` | Not an npm key. npm uses `min-release-age` in **days**. Silently ignored. |
| Assuming npm is protected after editing `.npmrc` | `min-release-age` needs **npm ≥ 11.10.0**. On older npm the line is inert. Check `npm -v` first. |
| Using minutes for bun or seconds for pnpm | Each tool's unit differs (npm=days, pnpm=minutes, bun=seconds). Wrong unit = wrong (often disabled) protection. |
| Exact-pinning `peerDependencies` | Breaks installability for library consumers. Pin `dependencies`/`devDependencies` only. |
| Treating pinned `package.json` as "tree locked" | Only the committed lockfile pins transitive deps. |
| Dropping `ignore-scripts` | Most npm malware runs via `postinstall`. Cooldown without script-blocking leaves the main execution path open. |
| `npm install` in CI | Can re-resolve. Use `npm ci` / `--frozen-lockfile` to honour the lockfile exactly. |
