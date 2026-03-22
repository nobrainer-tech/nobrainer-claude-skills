# Domain 4: Prompt Engineering & Structured Output (20%)

Two words: **be explicit**. Vague instructions like "be conservative" never work.

## Explicit Criteria

### Wrong vs Right
- **Wrong**: "Be conservative." "Only report high-confidence findings."
- **Right**: "Flag comments only when claimed behaviour contradicts actual code. Report bugs and security vulnerabilities. Skip minor style preferences."

### False Positive Trust Problem
High false positive rates in one category destroy trust in ALL categories.
Fix: temporarily disable high-FP categories while improving prompts.

### Severity Calibration
Define severity with concrete CODE EXAMPLES for each level. Not prose - actual code.

## Few-Shot Prompting

Most effective technique for consistency. Not more instructions. Not confidence thresholds.

### When to Deploy
- Detailed instructions alone produce inconsistent formatting
- Model makes inconsistent judgment calls on ambiguous cases
- Extraction tasks produce empty/null fields for existing information

### How to Construct
- 2-4 targeted examples for ambiguous scenarios
- Each example shows REASONING for why one action was chosen over alternatives
- Teaches generalisation to novel patterns, not just pattern-matching
- Include edge cases, not just happy paths

## Structured Output with tool_use

### Reliability Hierarchy
- `tool_use` with JSON schemas = eliminates syntax errors entirely
- Prompt-based JSON = model can produce malformed JSON

### What tool_use Does NOT Prevent
- Semantic errors: line items don't sum to stated total
- Field placement errors: values in wrong fields
- Fabrication: model invents values for required fields when source lacks info

### Schema Design Best Practices
- Optional/nullable fields when source may not contain info (PREVENTS FABRICATION)
- `"unclear"` enum value for ambiguous cases
- `"other"` + freeform detail string for extensible categorisation
- Include format normalization rules in prompts alongside strict schemas to handle inconsistent source formatting (e.g., date formats, currency symbols)

## Validation-Retry Loops

### Retry-with-Error-Feedback
Send back: original document + failed extraction + specific validation error. Model uses error to self-correct.

### Retry Effectiveness
- EFFECTIVE for: format mismatches, structural errors, misplaced values
- INEFFECTIVE for: information genuinely absent from source

### Self-Correction Patterns
- Extract `calculated_total` alongside `stated_total` to flag discrepancies
- `conflict_detected` booleans for inconsistent source data
- `detected_pattern` field tracking which code constructs trigger findings (enables systematic FP analysis when developers dismiss findings)

### Pydantic Validation Integration
Use Pydantic for schema validation in retry loops. When Pydantic validation fails, send follow-up with: original document + failed extraction + specific Pydantic validation error. Distinguish resolvable errors (format mismatches) from unresolvable (information absent from source).

## Message Batches API

### Constraints
- 50% cost savings
- Up to 24-hour processing window
- No guaranteed latency SLA
- Does NOT support multi-turn tool calling
- Uses `custom_id` for request/response correlation

### Matching Rule
- **Synchronous API**: blocking workflows (pre-merge checks, things devs wait for)
- **Batch API**: latency-tolerant workflows (overnight reports, weekly audits, nightly test gen)

### SLA Calculation (exam-tested)
Calculate batch frequency from SLA constraints: e.g., 4-hour submission windows with 24-hour batch processing guarantees a 30-hour SLA. Chunk oversized documents that exceed context limits before resubmitting.

### Failure Handling
- Identify failed documents by `custom_id`
- Resubmit only failures with modifications
- Refine prompts on sample set BEFORE batch processing

## Multi-Instance Review

### Self-Review Limitation
Same session reviewing own output retains reasoning context -> less likely to question own decisions. Independent instance catches more.

### Multi-Pass Architecture
- Per-file local analysis passes: consistent depth per file
- Separate cross-file integration pass: catches data flow issues across files

### Confidence-Based Routing
- Model self-reports confidence per finding
- Route low-confidence to human review
- Calibrate thresholds with labelled validation sets

## Prompt Engineering Techniques (from Courses 05/10/11)

### Being Clear and Direct
- Specific instructions beat vague ones every time
- "Write a 300-word review with plot summary, two characters, rating" vs "write a good review"

### XML Tags for Structure
- Separate document from instructions: `<document>`, `<instructions>`
- Separate user input from prompt: `<review>user text</review>`
- Prevents user content from being confused with instructions

### Providing Examples (Few-Shot)
- Show the model the style/format you want with concrete examples
- Works for sarcasm detection, consistent formatting, ambiguous cases

### Temperature Settings
- Low (0.0-0.3): factual, consistent answers (data extraction, classification)
- Medium (0.5-0.7): balanced (general conversation)
- High (0.8-1.0): creative, varied (brainstorming, creative writing)

### Assistant Message Prefilling
- Start Claude's response to guide direction
- Prefill with `{` for JSON output
- Prefill with specific stance for controlled arguments

### Stop Sequences
- Immediately halt generation at specified strings
- Combine with prefill for clean structured output

## Prompt Evaluation (from Courses 05/10/11)

### Workflow
1. Write prompt
2. Generate test cases (use Claude to auto-generate)
3. Run prompt on test cases
4. Feed responses through grader
5. Analyse scores, iterate

### Grader Types
- **Code grader**: keywords, length, format checks (deterministic)
- **Model grader**: strengths, weaknesses, reasoning, score (nuanced)

### Key Principles
- Engineering writes prompts, evaluation measures how well they work
- Test once risk: users provide unexpected inputs
- Always test on diverse, representative data

## Quiz-Validated Facts
- Movie reviews style -> Give sample as example (few-shot)
- After first version -> Test it, see how it works, improve
- Customer review mixed with instructions -> XML tags
- Book summary opening -> "Write a three-paragraph summary of this book"
- Test data quickly -> Use Claude to generate test cases
- Engineering vs evaluation -> Engineering writes, evaluation measures
- What is a grader -> Objective scores measuring output quality
- Model grader output -> Strengths, weaknesses, reasoning, and a score
- Keywords/length check -> Code grader
