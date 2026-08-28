---
name: nobrainer-writing
description: "Use when the owner says nb-write, nobrainer-writing, nobrainer-style, or nobrainer-human-like, or asks to draft, rewrite, compress, humanize, edit, or review user-facing prose such as a message, comment, document, README, report, summary, email, post, or release note; maximize useful information per word without dropping facts, evidence, caveats, voice, or required action."
---

# NoBrainer Writing

Produce high-signal prose that helps a specific reader understand, decide or act.
Treat the Pareto idea as a direction: preserve nearly all decision-relevant value
while using far fewer words. It is not permission to remove evidence, conditions
or nuance merely to hit an arbitrary ratio.

This skill owns prose quality. `nobrainer-research` owns missing or current
external facts, `nobrainer-decide` owns consequential choices, and
`nobrainer-build` owns behavioral code changes and repository integration. A
small text-only edit can stay here. Do not invoke this skill for a one-sentence
answer that is already clear, specific and complete.

Read [references/research.md](references/research.md) only when changing this
protocol, auditing its rationale or comparing another writing method. Ordinary
writing runs should not spend context on the research record.

## Choose one mode

- `DRAFT`: create prose from an established brief and verified source material.
- `COMPRESS`: shorten existing prose while preserving its material meaning.
- `REWRITE`: improve clarity, structure, voice and naturalness without changing
  the factual contract.
- `REVIEW`: identify only material prose defects and propose the smallest useful
  correction; do not rewrite merely to express a preference.

If the user did not name a mode, infer the smallest one that satisfies the
request. A request to "humanize" means `REWRITE`, not detector evasion or the
injection of fake mistakes.

## Freeze the content contract

Before drafting, resolve internally:

```text
PURPOSE:
AUDIENCE:
USE_AFTER_READING:
ARTIFACT_AND_CHANNEL:
LANGUAGE_AND_TONE:
VOICE_SOURCE: supplied sample | project guide | inferred neutral | NONE
MUST_PRESERVE: facts | names | numbers | dates | links | quotations | terms |
               commands | conditions | uncertainty | caveats | requested action
SOURCE_STATUS: VERIFIED | PROVIDED | RESEARCH_REQUIRED | UNKNOWN
LENGTH_OR_FORMAT_CONSTRAINT:
```

Infer obvious fields from the request and current project. Ask one focused
question only when the answer changes factual meaning, audience fit, material
tone or safety. In a larger Ultra run, use the approved BUDDY brief and do not
re-open settled requirements.

For `COMPRESS` and `REWRITE`, make a private meaning ledger before changing the
text. Track every material claim, number, name, date, URL, quotation,
attribution, identifier, command, negation, condition, uncertainty marker,
caveat and call to action. Never add a source, experience, opinion, metric or
detail that the input does not support. Route a material knowledge gap to
`nobrainer-research`; do not cover it with fluent prose.

## Write in six passes

1. **Outcome:** state the answer, decision, result or requested action in the
   first useful sentence. Keep background only when the reader needs it to
   interpret that outcome.
2. **Structure:** group each idea once. Put decision-relevant information first.
   Use headings, bullets or a table only when they make a real relationship
   easier to scan than short prose.
3. **Compression:** remove throat-clearing, repeated points, self-reference,
   empty transitions, generic summaries and decorative detail. Merge sentences
   only while the result remains easier to understand.
4. **Precision:** prefer concrete nouns and precise verbs. Name the actor when it
   clarifies responsibility. Use one term per concept and define necessary
   jargon for the actual audience.
5. **Voice:** match an authentic supplied sample or project guide when one
   exists. Otherwise use a direct, calm and natural neutral voice. Adapt tone to
   the reader's situation; technical, legal, error and safety text should not be
   made casual for entertainment.
6. **Integrity:** compare the final text with the meaning ledger and the user's
   requested action. Restore anything materially lost, and remove anything that
   cannot be traced to the input or a cited source.

Compress structure before swapping vocabulary. A shorter synonym cannot repair
a paragraph with no clear purpose.

## Anti-slop gate

Remove these patterns when they add no information:

- praise, greetings, apologies or announcements before the actual point;
- inflated significance, sales language, vague attribution and unsupported
  certainty;
- headings that repeat the next sentence, repetitive transitions, forced groups
  of three and multiple labels that say the same thing;
- fake candor, invented objections, rejected options no reader proposed,
  dramatic fragments and generic optimistic endings;
- abstract metaphors, buzzwords or modifiers standing in for a concrete fact;
- formatting used as decoration, including excessive bold text, emoji and a
  list where one sentence is clearer;
- comments or documentation that restate visible code instead of explaining a
  non-obvious reason, constraint, risk or consequence.

These are contextual signals, not a forbidden-word list. Keep a transition,
technical term, passive construction, long sentence, repeated phrase or unusual
punctuation when it is accurate, natural for the writer and useful to the
reader. Professional grammar is not an AI tell.

Never simulate humanity with typos, missing punctuation, fabricated anecdotes,
random slang, artificial sentence fragments or opinions the author did not
express. Do not optimize for an AI detector or claim that prose is human-written.

## Match the artifact

- **Reply, comment or status:** outcome first, then only decisive evidence,
  blocker and next action.
- **Email or request:** purpose, essential context, one clear ask and timing when
  material.
- **README or instructions:** purpose, prerequisites, shortest successful path,
  verification and only likely failure recovery.
- **Report or decision note:** answer, verified facts, inference or trade-off,
  decision and next action. Keep fact and inference visibly distinct.
- **Long-form content:** thesis, evidence and implications in a coherent arc.
  Concision removes repetition; it does not flatten a real argument into notes.
- **Code comment:** explain why, invariant, risk or surprising consequence.
  Delete comments that merely translate the code into English.
- **Marketing or social copy:** audience problem, concrete value or proof and one
  honest action. Do not manufacture urgency, authority or transformation.

## Quality gate

Before returning the text, require:

```text
PURPOSE_CLEAR: PASS | FAIL
ANSWER_OR_ACTION_FRONT_LOADED: PASS | NOT_APPLICABLE | FAIL
MEANING_PRESERVED: PASS | NOT_APPLICABLE | FAIL
CLAIMS_TRACEABLE: PASS | NOT_APPLICABLE | FAIL
CAVEATS_AND_CONDITIONS_PRESERVED: PASS | NOT_APPLICABLE | FAIL
VOICE_AND_AUDIENCE_FIT: PASS | FAIL
VALUE_DENSITY: PASS | FAIL
SCAN_AND_ACCESSIBILITY: PASS | NOT_APPLICABLE | FAIL
```

`VALUE_DENSITY` passes when every sentence adds a distinct fact, implication,
instruction, decision, transition or intentional voice effect. Ask of each
sentence: if it disappears, does meaning, evidence, tone or action materially
change? If not, cut it.

A lower word count is diagnostic, not acceptance. Do not over-compress a short
source, remove a necessary example, collapse separate conditions or hide risk.
When accessibility matters, preserve descriptive headings, meaningful link text,
expanded acronyms and enough context to understand the text out of layout.

## Return the result

Return only the finished prose by default. Do not surround a two-line answer
with a process report. When the owner asks for an audit, comparison or measured
compression, add a compact block after the result:

```text
MODE:
WORDS: before -> after | NOT_MEASURED
MATERIAL_CHANGES:
PRESERVED_CONTRACT:
UNVERIFIED_OR_INPUT_REQUIRED:
```

Return `INPUT_REQUIRED` instead of drafting when a missing fact, source, voice
sample or constraint would force invention or materially change the result.
