# Domain 5: Context Management & Reliability (15%)

Smallest weight but mistakes cascade everywhere.

## Context Preservation

### Progressive Summarisation Trap
Condensing history compresses critical values into vague summaries.
- "Customer wants refund of \$247.83 for order #8891 placed March 3rd"
- Becomes: "customer wants a refund for a recent order"
- Fix: extract transactional facts into persistent "case facts" block, never summarised

### "Lost in the Middle" Effect
Models process beginning and end of long inputs reliably. Middle gets missed.
Fix: place key findings summaries at the BEGINNING with explicit section headers.

### Tool Result Trimming
Order lookup returns 40+ fields, you need 5.
Trim verbose results to relevant fields BEFORE appending to context.

### Upstream Agent Optimisation
Modify agents to return structured data (key facts, citations, relevance scores) instead of verbose reasoning chains.

## Escalation and Ambiguity Resolution

### Three Valid Escalation Triggers
1. **Customer explicitly requests human**: honour immediately. Do NOT attempt to resolve first.
2. **Policy exceptions/gaps**: request falls outside documented policy.
3. **Inability to progress**: agent cannot make meaningful progress.

### Two Unreliable Triggers (exam traps)
1. **Sentiment-based**: frustration does not correlate with case complexity.
2. **Self-reported confidence**: model is often incorrectly confident on hard cases.

### Ambiguous Customer Matching
Multiple customers match search -> ask for additional identifiers. Do NOT select based on heuristics.

## Error Propagation

### Structured Error Context
Include: failure type, what was attempted, partial results, potential alternatives.

### Two Anti-Patterns
1. **Silent suppression**: returning empty results marked as success -> prevents any recovery
2. **Workflow termination**: killing entire pipeline on single failure -> throws away partial results

### Access Failure vs Valid Empty Result
- Access failure (could not reach source) -> consider retry
- Valid empty result (reached source, found nothing) -> this IS the answer, no retry

### Coverage Annotations
Note which findings are well-supported vs which areas have gaps.

## Codebase Exploration

### Context Degradation
Extended sessions -> model starts referencing "typical patterns" instead of specific classes it discovered earlier.

### Mitigation Strategies
- **Scratchpad files**: write key findings to a file, reference it
- **Subagent delegation**: spawn subagents for specific investigations
- **Summary injection**: summarise findings from one phase before next
- **`/compact`**: reduce context usage when filled with verbose discovery

### Crash Recovery
Each agent exports structured state to known file location (manifest). On resume, coordinator loads manifest.

## Human Review and Confidence Calibration

### Aggregate Metrics Trap
97% overall accuracy can hide 40% error rates on specific document type.
Always validate by document type AND field segment.

### Stratified Random Sampling
Sample high-confidence extractions for ongoing verification. Detects novel error patterns.

### Field-Level Confidence
- Model outputs confidence per field
- Calibrate thresholds with labelled validation sets
- Route low-confidence fields to human review

## Information Provenance

### Structured Claim-Source Mappings
Each finding: claim + source URL + document name + relevant excerpt + publication date.
Downstream agents preserve and merge these mappings.

### Conflict Handling
Two credible sources report different statistics -> do NOT arbitrarily select one.
Annotate with BOTH values and source attribution.

### Temporal Awareness
Require publication/data collection dates. Different dates explain different numbers.

### Content-Appropriate Rendering
- Financial data -> tables
- News -> prose
- Technical findings -> structured lists

## RAG - Retrieval Augmented Generation (from Courses 05/10/11)

### What RAG Does
Send only relevant sections to the AI for each question (not entire 800-page document).

### Full RAG Flow
1. **Chunking**: split documents into smaller pieces
2. **Embedding**: convert chunks to ~1024-dimensional vectors
3. **Storage**: store in vector database (specialised for embedding comparison)
4. **Query**: embed user query, find similar chunks
5. **Augment**: include relevant chunks in prompt
6. **Generate**: Claude answers using retrieved context

### Search Methods
- **Semantic search**: embeddings capture meaning (good for concepts)
- **BM25 lexical search**: exact keyword matching (good for IDs, specific terms)
- **Hybrid/multi-index**: combine both for best results
- **Reranking**: re-order results by relevance after initial retrieval

### Contextual Retrieval
Add context to document chunks BEFORE storing them. Improves search accuracy by preserving original document context that chunking removes.

### Key Features (from Courses 05/10/11)

#### Extended Thinking
Let Claude reason through complex problems. Two parts: reasoning process + final answer. Use when prompt optimisation isn't enough for accuracy.

#### Prompt Caching
- Saves computational work for repeated long content
- Minimum 1024 tokens to be eligible
- Same system prompt sent twice -> cached on second call

#### Citations
Clear trail from response back to source documents. Provenance for verification.

#### Files API
Upload files ahead of time, reference later. Efficient for repeated use.

#### Code Execution
Runs in isolated Docker container. No network access. Sandboxed.

## Quiz-Validated Facts
- Contextual retrieval -> Adds context to chunks before storing
- Vector database -> Specialised for storing/comparing embeddings
- Exact ID search fails with semantic -> BM25 lexical search
- Embedding output -> ~1024 numbers representing meaning
- 800-page report -> Send only relevant sections to AI
- Extended thinking -> Improve accuracy on complex tasks
- Prompt caching -> Saves computational work (min 1024 tokens)
- 500 token caching -> Won't be cached (too short)
- Citations -> Clear trail back to source documents
- Image effectiveness -> Prompt engineering techniques
