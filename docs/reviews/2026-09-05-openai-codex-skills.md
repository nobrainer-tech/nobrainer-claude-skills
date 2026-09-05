# OpenAI Codex skills adoption map — 2026-09-05

Status: source-backed instruction changes only. This is not runtime, model-quality,
token, cost or compatibility evidence.

Source: official Apache-2.0 `openai/codex` repository at commit
`5d358057152d5e2950f20a25cb6cf050ed5b5d85`, under `.codex/skills/`.

| Official source | Adopted Flow change | Owner |
|---|---|---|
| [`code-review-context`](https://github.com/openai/codex/blob/5d358057152d5e2950f20a25cb6cf050ed5b5d85/.codex/skills/code-review-context/SKILL.md) | Bound every restart context fragment and keep reusable inputs stable when a host supports cache reuse. No universal numeric limit or saving claim. | Sessions |
| [`babysit-pr`](https://github.com/openai/codex/blob/5d358057152d5e2950f20a25cb6cf050ed5b5d85/.codex/skills/babysit-pr/SKILL.md) and its [review/CI heuristics](https://github.com/openai/codex/blob/5d358057152d5e2950f20a25cb6cf050ed5b5d85/.codex/skills/babysit-pr/references/heuristics.md) | Optional monitoring binds state to the exact head SHA, includes published feedback, excludes pending reviews, and retries only diagnosed transient failures within a finite budget. Monitoring grants no merge or communication authority. | Review; Build links delivery evidence to the current head |
| [`code-review`](https://github.com/openai/codex/blob/5d358057152d5e2950f20a25cb6cf050ed5b5d85/.codex/skills/code-review/SKILL.md) and focused [`code-review-*` perspectives](https://github.com/openai/codex/tree/5d358057152d5e2950f20a25cb6cf050ed5b5d85/.codex/skills) | Select only perspectives justified by the changed boundary and risk; do not mandate every perspective or maximum effort. | Review |
| [`codex-pr-body`](https://github.com/openai/codex/blob/5d358057152d5e2950f20a25cb6cf050ed5b5d85/.codex/skills/codex-pr-body/SKILL.md) | PR copy leads with why, describes the net base-to-head change, and keeps only useful verification and durable artifacts. | Writing |

The source repository provides host-specific implementations and defaults. Flow
adopts the portable decision boundaries above inside existing modules; it does not
add a watcher daemon, require GitHub, or claim the same runtime behavior.
