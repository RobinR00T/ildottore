# Supply-chain policy

Il Dottore is a security tool, so its own supply chain is held to the standard it checks for in
others. This is the policy; the enforcement lives in CI and the dependency config.

## Runtime dependencies

Deliberately small and all permissive-licensed:

- `pydantic`, `pyyaml`, `jsonschema`, `httpx`, `jinja2`, `typer`, `rich`.

No heavyweight or native-extension dependency is pulled for the core. The multimodal image renderer
is **pure stdlib** (`zlib` + a bitmap font, no Pillow), on purpose, so a scan has no imaging
dependency. `dev` is the only optional dependency group (linters, mypy, pytest, bandit, pip-audit).

## Dependency policy

- **Permissive licenses only.** Copyleft / source-available dependencies are not accepted; license
  discipline is reviewed at PR time (CODEOWNERS) alongside the dependency change.
- **Weekly, grouped Dependabot.** Python deps and the pinned GitHub Actions are scanned weekly and
  arrive as one grouped PR per ecosystem (`.github/dependabot.yml`). Nothing auto-merges.
- **Major bumps of the two runtime pillars (Pydantic, Typer) are held for manual review**, so a
  breaking major never lands unattended.
- **Pinned GitHub Actions.** Workflow actions are version-pinned and bumped through Dependabot.

## Vulnerability scanning

Enforced in CI (`.github/workflows/ci.yml`, mirrored locally by `make gates`):

- **`pip-audit`** over the installed environment: a known-vulnerable dependency fails the build.
- **`bandit`** static security scan of `src/`: medium+ findings fail the build.
- **Self-scan**: the tool runs its own adversarial judge corpus against itself; any new
  high/critical flip fails CI.
- A weekly scheduled `audit` workflow re-runs the wall to catch drift between releases.

## Secrets and credentials

- No secret is ever committed. Target credentials are referenced (`env://NAME`, `vault://…`), never
  inlined, and are read only at send time.
- Evidence is redacted at rest (fail-closed): a write is refused if a secret/PII shape survives
  redaction. Multimodal carrier bytes are elided from evidence (reference + digest kept).

## Reporting a vulnerability

See [`SECURITY.md`](SECURITY.md).
