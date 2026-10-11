# Non-goals

What Il Dottore deliberately is **not**. Scope discipline is part of the design; these are choices,
not gaps.

- **Not an offensive framework or exploit kit.** It is a defensive assurance scanner. It never
  performs real destructive actions or real exfiltration: tools are mocked or dry-run, egress is
  allowlisted (default-deny), and every dangerous payload is flagged `test_only`.
- **Not a jailbreak-prompt dump.** The value is reproducibility, evidence and risk mapping, not the
  volume of jailbreak strings. An attack is a declarative spec with expected-secure behavior,
  evaluators and golden fixtures, not a copy-pasted prompt.
- **Not a guardrail or moderation product.** It *tests* whether a target's guardrails hold; it does
  not provide input/output filtering as a service.
- **Not a benchmark leaderboard.** It produces an auditable per-target assurance report, not a
  public score to rank models.
- **Not a replacement for human red-teaming.** It is the reproducible, automatable layer beneath a
  human engagement, not a substitute for one.
- **Not a general agent runner or an MCP client.** MCP support is read-only discovery only; it never
  calls a tool (`tools/call`).
- **Not tied to any one provider.** Adapters are thin and swappable; no SDK lock-in.
- **Not a signing or key-management system (yet).** The scope's optional `checksum:` is an
  integrity check: it catches an accidental edit, not an editor who recomputes it. Who wrote or
  approved a scope is proved out of band, with a signature the operator's own tooling makes and
  verifies before the run (SSH signatures, sigstore, a signed commit behind review), made by the
  reviewer with a key only they hold and checked against trusted keys the scope's editors cannot
  write (`docs/MANUAL.md` §4.1), and every
  report's `scope_sha256` ties the run to the signed bytes. Built-in verification waits for key
  management: a list of trusted keys, who signs, and revocation (OD-2, decided 2026-10-11,
  revisable).
