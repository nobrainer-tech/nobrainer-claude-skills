---
name: Bug report
about: Report reproducible incorrect behavior
labels: bug
---

- [ ] I searched open and closed issues for this problem.
- [ ] I removed secrets, credentials, private paths and personal data.

## Description

<!-- State what fails and under which condition. Keep it factual and concise. -->

## ENV

<!-- Keep ENV compact: include the environment name, exact URL and user together. Name must be
QA, DEV, TEST, PROD, PREPROD, BETA or UNKNOWN. Use N/A when a field does not
apply. User is a role or redacted/synthetic alias; never paste credentials. -->
| Field | Value |
|---|---|
| Name | |
| URL | |
| User | |
| Build/client (optional) | |

## Steps to reproduce

1.
2.
3.

## Current behavior

## Expected behavior

<!-- Keep only the surfaces that apply. Redact secrets, cookies, tokens and
personal data. API: paste a complete redacted curl command with method, URL, all
captured headers and body, then paste the response with status, all captured
headers and body in its own block. Database: paste the
read-only query and result in separate blocks. UI: attach a screenshot or MP4
under Evidence; attach a HAR only when the page-load/request chain matters. If
required proof is unavailable, write INPUT_REQUIRED and name the missing artifact
instead of substituting prose or a guess. -->

## API request (cURL)

```bash
# Complete redacted curl command: method, URL, headers and body.
```

## API response

```http
# Status, headers and body.
```

## Database query (read-only)

```sql
-- Read-only query.
```

## Database result

```text
# Observed result; use its actual format when useful.
```

## Evidence

<!-- For a UI issue, attach the screenshot or MP4 recording here. -->

## HAR (only when the page-load/request chain matters)

<!-- Attach a HAR file or write N/A. -->

## Definition of Done (DoD)

<!-- State the observable regression proof and any required test or check. -->

<!-- Redact sensitive values. Use private vulnerability reporting for security issues. -->
