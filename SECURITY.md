# Security Policy

Il Dottore is a security tool; we hold ourselves to the bar we test others against.

## Reporting a vulnerability

Please report security issues **privately**: do not open a public issue.

- Email: **security@zynap.com** (PGP available on request).
- Include: affected version/commit, reproduction, impact, and any evidence (with secrets
  redacted).
- We aim to acknowledge within 3 business days and to coordinate disclosure.

## Scope & responsible use

Il Dottore is for **authorized** security testing only. It refuses out-of-scope targets by
design (signed `scope.yaml` + endpoint allowlist), never performs real destructive actions or
exfiltration (mocks/dry-run + planted canaries), and masks secrets/PII in logs, evidence and
reports. See `docs/02-threat-model.md` and `docs/11-data-leak-extraction.md §5`.

Using this tool against systems you are not authorized to test is prohibited and may be illegal.
