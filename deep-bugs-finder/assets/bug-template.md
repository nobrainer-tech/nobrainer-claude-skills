# BUG-<NNN>: <one-line title>

- **Severity:** Critical | High | Medium
- **Status:** open
- **Location:** `<path>:<line-or-range>`
- **Component/area:** <module / subsystem>
- **Found:** <YYYY-MM-DD> via deep-bugs-finder (round <n>, <engine>)
- **Confidence:** <0-100> (verified against real code: yes)

## What's wrong
<Plain-language description of the defect.>

## Why it's a real bug (proof)
<Concrete failure scenario: the exact input / state / sequence that triggers wrong
behaviour, traced through the real code. Quote the offending lines. This must be a
real, reachable failure — not a hypothetical.>

```text
<the offending code, with file:line>
```

## Root cause
<The underlying mistake — the wrong assumption / missing check / bad operator.>

## Proposed fix
<Specific change. Show a diff or the corrected code. Keep it minimal and at the
right ownership boundary — no broad rewrite unless the bug class demands it.>

```diff
- <before>
+ <after>
```

## Verification / regression guard
<How to prove the fix works: the test to add (input → expected), or the manual
check. A real bug should get a test that fails before and passes after.>

## Notes
<Related bugs ([[BUG-XXX]]), blast radius, anything a reviewer must know. If this
was reconsidered and is actually NOT a bug, set Status: rejected and say why.>
