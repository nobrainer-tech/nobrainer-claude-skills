---
name: nobrainer-polymarket
description: "Browse Polymarket prediction markets, place orders, manage positions, and interact with onchain contracts via the official polymarket-cli. Use when a user asks to search markets, check prices, trade, manage wallets, view portfolios, redeem winnings, or translate a task into safe polymarket-cli commands with correct flags and output format."
---

# Polymarket CLI Skill

Interact with [Polymarket](https://polymarket.com) prediction markets via the official `polymarket-cli` (Rust, open source).
Read market data, manage positions, execute trades, redeem winnings — all from the terminal.

> **Warning:** Early, experimental software. Do not use with large amounts of funds. Always verify transactions before confirming.

---

## Installation

### Quick install (macOS/Linux, verifies SHA256 checksum)
```bash
curl -sSL https://raw.githubusercontent.com/Polymarket/polymarket-cli/main/install.sh | sh
```

### Manual install (macOS arm64 example)
```bash
# Download from official GitHub releases
curl -L https://github.com/Polymarket/polymarket-cli/releases/latest/download/polymarket-v<VERSION>-aarch64-apple-darwin.tar.gz -o polymarket.tar.gz

# Verify checksum (compare against checksums.txt from the same release)
curl -L https://github.com/Polymarket/polymarket-cli/releases/latest/download/checksums.txt | grep aarch64-apple-darwin
shasum -a 256 polymarket.tar.gz  # must match

# Extract and install
tar xzf polymarket.tar.gz
mv polymarket ~/bin/  # or /usr/local/bin/ with sudo
chmod +x ~/bin/polymarket
```

Available targets: `aarch64-apple-darwin`, `x86_64-apple-darwin`, `aarch64-unknown-linux-gnu`, `x86_64-unknown-linux-gnu`

### Build from source
```bash
git clone https://github.com/Polymarket/polymarket-cli
cd polymarket-cli && cargo install --path .
```

### Upgrade existing install
```bash
polymarket upgrade
# Always re-verify checksum after upgrade!
```

---

## Authentication & Key Precedence

Priority (highest to lowest):
1. `--private-key <key>` flag ← never use in production (visible in `ps`)
2. `POLYMARKET_PRIVATE_KEY` env var ← preferred for scripts
3. Config file: `~/.config/polymarket/config.json` ← preferred for interactive use

### Config file
```json
{
  "private_key": "0x...",
  "chain_id": 137,
  "signature_type": "proxy"
}
```

### Signature types
- `proxy` — default (Polymarket proxy/Safe wallet, recommended)
- `eoa` — EOA direct wallet
- `gnosis-safe` — Gnosis Safe

Override per-command: `--signature-type eoa`
Override via env: `POLYMARKET_SIGNATURE_TYPE=eoa`

### First-time setup
```bash
polymarket setup           # guided wizard: wallet + approvals
# Or manually:
polymarket wallet create   # generate new wallet
polymarket wallet import <key>  # or import existing
polymarket approve set     # approve contracts (needs MATIC for gas, 6 txns)
```

---

## Output Format

- Default: `table` (human-readable)
- Scripting: `-o json` — use when piping to `jq` or Python

```bash
polymarket -o json markets list --limit 10 | jq '.[].question'
```

---

## What Needs a Wallet

**No wallet needed** (public read-only):
- `markets`, `events`, `tags`, `series`, `profiles`, `sports`
- `clob price/book/spread/midpoint/price-history`
- `data positions/trades/activity/leaderboard/holders` (any address)
- `approve check <address>`, `ctf condition-id/collection-id/position-id`

**Wallet required** (authenticated / on-chain):
- `clob orders/trades/balance` (your own)
- `clob create-order/market-order/cancel-*`
- `approve set`, `ctf split/merge/redeem`

---

## Common Workflows

### Market research
```bash
polymarket markets list --limit 20 --active true
polymarket markets search "bitcoin"
polymarket markets get <slug-or-id>

polymarket clob price <TOKEN_ID> --side buy
polymarket clob book <TOKEN_ID>
polymarket clob price-history <TOKEN_ID> --interval 1h
polymarket clob spread <TOKEN_ID>
```

### Check portfolio
```bash
polymarket data positions <WALLET_ADDRESS>
polymarket data closed-positions <WALLET_ADDRESS>
polymarket data value <WALLET_ADDRESS>
polymarket data trades <WALLET_ADDRESS> --limit 50
polymarket clob balance --asset-type collateral    # USDC
```

### Trading

**Market order** (fills at current best price):
```bash
polymarket clob market-order --token <TOKEN_ID> --side buy --amount 10   # $10 USDC
polymarket clob market-order --token <TOKEN_ID> --side sell --amount 50  # 50 shares
```

**Limit order:**
```bash
polymarket clob create-order --token <TOKEN_ID> --side buy --price 0.95 --size 10
# Order types: GTC (default), FOK, GTD, FAK. Add --post-only for maker-only.
```

**Manage orders:**
```bash
polymarket clob orders                              # list open
polymarket clob cancel <ORDER_ID>
polymarket clob cancel-all
polymarket clob cancel-market --market <CONDITION_ID>
```

### Redeem winning positions

Most binary markets on Polymarket are NegRisk. Check which type first:
```bash
polymarket clob neg-risk --token <TOKEN_ID>   # true = NegRisk
```

```bash
# NegRisk (most binary markets)
polymarket ctf redeem-neg-risk --condition <CONDITION_ID> --amounts "<yes_amount>,<no_amount>"

# Standard CTF
polymarket ctf redeem --condition <CONDITION_ID>

# Merge YES+NO back to USDC anytime (no resolution needed)
polymarket ctf merge --condition <CONDITION_ID> --amount 10
```

### Leaderboard / research
```bash
polymarket data leaderboard --period all --order-by pnl --limit 20
polymarket data holders <CONDITION_ID> --limit 20
polymarket data open-interest <CONDITION_ID>
```

---

## Key Concepts

| Term | Meaning |
|------|---------|
| Token ID | ERC1155 token ID for YES or NO outcome (long numeric string) |
| Condition ID | Hex market identifier (`0xABC...`) — used for CTF ops |
| NegRisk | Most binary markets; use `ctf redeem-neg-risk` not `ctf redeem` |
| Amount (ctf) | In USDC units (`10` = $10) |
| Price (orders) | Between 0–1 (`0.95` = 95¢) |
| Gas | On-chain ops need MATIC on Polygon (chain ID 137) |

Get Token IDs and Condition IDs via:
```bash
polymarket markets get <slug>       # shows both
polymarket clob market <CONDITION_ID>
```

---

## Interactive Shell

```bash
polymarket shell
# > markets search "bitcoin"
# > clob balance --asset-type collateral
# Use all commands without the "polymarket" prefix
```

---

## Quick Reference

| Task | Command |
|------|---------|
| USDC balance | `polymarket clob balance --asset-type collateral` |
| Open positions | `polymarket data positions <ADDRESS>` |
| Trade history | `polymarket data trades <ADDRESS> --limit 20` |
| Search market | `polymarket markets search "query"` |
| Get price | `polymarket clob price <TOKEN_ID> --side buy` |
| Order book | `polymarket clob book <TOKEN_ID>` |
| Open orders | `polymarket clob orders` |
| Cancel all | `polymarket clob cancel-all` |
| Redeem (NegRisk) | `polymarket ctf redeem-neg-risk --condition <ID> --amounts "0,100"` |
| API health | `polymarket status` |
| Leaderboard | `polymarket data leaderboard --period all --order-by pnl` |

Full command reference: `references/commands.md` or run `polymarket <command> --help`
