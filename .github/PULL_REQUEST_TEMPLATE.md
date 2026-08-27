## Problem

<!-- Describe the observed failure, missing workflow, or user friction. -->

## Scope and exclusions

<!-- Name the exact skills, adapters, scripts, or docs changed and what is out. -->

## Authoring environment

| Field | Value |
|---|---|
| Human or agent author | |
| Harness and version | |
| Model | |
| Relevant plugins | |

## Behavior evidence

<!-- For skill changes: baseline failure, changed behavior, adversarial controls, holdout. -->

## Compatibility evidence

<!-- SOURCE_VALIDATED, ADAPTER_VALIDATED, RUNTIME_VERIFIED, or DISTRIBUTED. -->

## Verification

- [ ] `python3 scripts/validate_skills.py --suite`
- [ ] `python3 -m unittest discover -s tests -v`
- [ ] Changed scripts ran with their real interpreters
- [ ] Public-clean and secret scan completed
- [ ] Complete diff reviewed

## Risks, uncertainty, and rollback

<!-- State what is not proven and the exact rollback. -->

## Owner gate

- [ ] A human owner has reviewed this complete PR before merge or publication
