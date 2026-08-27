# Security policy

## Reporting a vulnerability

Do not open a public issue containing a secret, exploit detail, private path,
account identifier or vulnerable production target. Use GitHub private
vulnerability reporting for this repository:

https://github.com/nobrainer-tech/nobrainer-tech-skills/security/advisories/new

Include the affected release or commit, impact, minimum reproduction, evidence
and a safe way to validate a fix. Redact credentials and personal data.

## Scope

Security reports may cover:

- unsafe installer overwrite, rollback or path handling;
- secret exposure through skills, examples, reports or generated artifacts;
- instructions that silently authorize publishing, spending, deletion,
  credential changes or production mutation;
- cross-session identity, checkout, lease or evidence confusion;
- manifest or adapter behavior that loads unintended content.

Third-party client, model, marketplace and Superpowers vulnerabilities should be
reported to their maintainers unless this repository's integration causes the
issue.

## Supported versions

Until the first public release, only the latest commit on the active release PR
is supported. After release, the latest published version and current `main`
receive fixes. Older Git history remains available for rollback, not support.
