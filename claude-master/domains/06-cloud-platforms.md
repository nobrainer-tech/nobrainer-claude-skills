# Domain 6: Cloud Platform Integration (Bedrock & Vertex AI)

Platform-specific knowledge for deploying Claude on AWS and Google Cloud.

## What Are These Platforms?

Claude models are made by Anthropic, but you can access them three ways:
1. **Direct Anthropic API** - straight from Anthropic (console.anthropic.com)
2. **Amazon Bedrock** - Claude hosted inside AWS infrastructure
3. **Google Vertex AI** - Claude hosted inside Google Cloud infrastructure

### Why Use Cloud Platforms Instead of Direct API?
- **Enterprise compliance**: data stays within your AWS/GCP account, no third-party API calls
- **Existing cloud contracts**: use committed spend, enterprise discounts, consolidated billing
- **VPC/private networking**: Claude accessible only within your private network
- **IAM integration**: use existing AWS IAM or Google Cloud IAM for access control
- **Unified monitoring**: CloudWatch (AWS) or Cloud Logging (GCP) alongside other services
- **No separate Anthropic account needed**: provision access through cloud console

### When to Use Direct API Instead?
- Fastest access to newest models (cloud platforms lag slightly)
- Simpler setup for prototyping
- Multi-cloud or cloud-agnostic architecture
- Lower overhead for small teams

## Amazon Bedrock

Amazon Bedrock is AWS's managed service for accessing foundation models (Claude, Llama, Titan, etc.) through a unified API. Claude is one of many models available - you pick which to use per request.

### Setup
1. Enable model access in AWS Bedrock console (per-region)
2. Configure IAM permissions for `bedrock:InvokeModel`
3. Use AWS SDK (boto3) with Bedrock Runtime client

### API Access
- Uses AWS SDK (boto3) with Bedrock Runtime client
- Model IDs: `anthropic.claude-3-5-sonnet-20241022-v2:0`, etc.
- Authentication via AWS credentials (IAM roles, access keys)
- Region-specific endpoints

### Key Differences from Direct API
- Request format uses `invoke_model()` or `invoke_model_with_response_stream()`
- Body must be JSON string, not dict
- Model ID passed separately (not in body)
- Response parsing differs (need to parse response body)

### Bedrock-Specific Features
- Model access managed via AWS console (enable model access first)
- Supports provisioned throughput for consistent performance
- CloudWatch integration for monitoring
- VPC endpoints for private access

## Google Cloud Vertex AI

Google Vertex AI is Google Cloud's ML platform. Like Bedrock, it offers multiple models (Claude, Gemini, PaLM, etc.) through a unified API. Claude runs on Google's infrastructure.

### Setup
1. Enable Vertex AI API in Google Cloud Console
2. Request Claude model access (may require approval)
3. Configure IAM permissions for `aiplatform.endpoints.predict`
4. Install `anthropic[vertex]` package

### API Access
- Uses `anthropic[vertex]` Python package
- Requires Google Cloud project ID and region
- Authentication via `gcloud auth` or service account
- `AnthropicVertex(project_id=..., region=...)` client

### Key Differences from Direct API
- Model specified as `model="claude-sonnet-4-20250514"` (no anthropic. prefix)
- Client initialization requires project_id and region
- Otherwise API is nearly identical to direct Anthropic API

### Vertex-Specific Features
- Google Cloud IAM for access control
- Vertex AI Workbench integration
- Cloud Logging and Monitoring
- VPC Service Controls

## Shared Concepts (Both Platforms)

### Messages API Parameters
- `model`: model identifier
- `max_tokens`: maximum response length
- `messages`: conversation array with role/content
- `system`: system prompt (separate from messages)
- `temperature`: 0.0-1.0 (randomness)
- `stop_sequences`: strings that halt generation

### Multi-Turn Conversations
- API is stateless - does NOT store previous messages
- Must send entire conversation history with each request
- Alternating user/assistant messages

### Streaming
- Both platforms support response streaming
- Users see text appear immediately instead of waiting
- Essential for chat applications

### Tool Use (Both Platforms)
- Define tools with JSON schemas in `tools` parameter
- `tool_choice`: auto/any/specific tool
- Response includes `tool_use` content blocks
- Send results back as `tool_result` in next request
- Stop reason `"tool_use"` indicates tool call needed

### Prompt Caching (Both Platforms)
- Mark content with cache control headers
- Minimum 1024 tokens for cacheable content
- Saves computational work on repeated content
- Reduces cost and latency for repeated system prompts

### Extended Thinking
- Enable for complex reasoning tasks
- Two parts: reasoning process (thinking) + final answer
- Budget tokens for thinking process
- Use when prompt optimization alone isn't enough

### Citations
- Enable to get source references in responses
- Links response claims back to source documents
- Essential for RAG applications

### PDF Support
- Send PDFs as base64-encoded content
- Set type to "document" and media_type to "application/pdf"
- Supports multi-page documents

## Model Selection Guide

### Claude 3.5 Haiku
- Fastest, cheapest
- Best for: classification, simple extraction, routing, high-volume tasks
- Use when: speed matters more than depth

### Claude 3.5/4 Sonnet
- Balanced speed/capability
- Best for: code generation, analysis, conversation, most production tasks
- Default choice for most applications

### Claude 3/4 Opus
- Most capable, slowest
- Best for: complex reasoning, research, nuanced analysis
- Use when: quality matters more than speed

## Quiz-Validated Facts (Bedrock + Vertex)
- Tokens -> smallest units a language model can understand
- MMLU benchmark -> knowledge across 57 subjects
- Model selection criteria -> capabilities, speed, cost
- Constitutional AI -> embeds ethical principles from training start
- Pre-training vs fine-tuning -> pre-training creates base understanding, fine-tuning teaches behaviour
- Interpretability -> understanding how AI models make decisions
- Latency -> time delay between request and response
- What is MCP -> standardized protocol for secure external connections
