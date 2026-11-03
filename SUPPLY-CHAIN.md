# Supply-chain policy

Il Dottore is a security tool, so its own supply chain is held to the standard it checks for in
others. This is the policy; the enforcement lives in CI and the dependency config.

## Runtime dependencies

Deliberately small, and permissive-licensed with one recorded exception (below):

- `pydantic`, `pyyaml`, `jsonschema`, `httpx`, `jinja2`, `typer`, `rich`, `websockets` (the
  client of the `provider: websocket` adapter, BSD-3-Clause, no dependencies of its own; added
  2026-10-07 at `>=14.0`, `>=15.0` since 2026-10-16 for its `proxy` argument), plus `anyio`,
  which `httpx` already pulls in and which `pyproject.toml` lists only to set a security floor
  (`>=4.14.2`). The floors are tested by the `floors` CI job (u12 A-84): every direct dependency
  installed at the version after its `>=`, the suite run on Python 3.11 under the `floors`
  Hypothesis profile (no per-example deadline: that runner is slower, and a deadline there only
  measured it; `tests/conftest.py`, 2026-11-01).

No heavyweight or native-extension dependency is pulled for the core. The multimodal image renderer
is **pure stdlib** (`zlib` + a bitmap font, no Pillow), on purpose, so a scan has no imaging
dependency. `dev` is the only optional dependency group: pytest (with asyncio and cov), hypothesis,
respx, coverage, ruff, mypy, import-linter and two type-stub packages. `bandit` and `pip-audit` are
**not** in it; `make bandit` and `make audit` need them installed separately.

## Dependency policy

- **Permissive licenses only.** Copyleft / source-available dependencies are not accepted; license
  discipline is reviewed at PR time (CODEOWNERS) alongside the dependency change.
- **Recorded exception: `certifi` (MPL-2.0).** The runtime dependency closure, read from the
  installed distributions' metadata on 2026-10-04, is MIT, BSD-2-Clause, BSD-3-Clause, ISC and
  PSF-2.0, except `certifi` (2026.6.17 at that date), a required dependency of `httpx` that
  supplies the CA bundle. MPL-2.0 is a weak, file-level copyleft: its obligations attach to
  modified MPL-covered files. Il Dottore neither vendors nor modifies `certifi`; pip installs it
  unmodified beside the tool. The exception is accepted on that basis and recorded here because
  it is not literally "permissive only"; vendoring or patching `certifi` would need a fresh
  review. Re-check the closure when a runtime dependency is added or bumped. Re-checked on
  2026-10-07 for `websockets` 17.2: BSD-3-Clause, `Requires-Dist` empty, so the closure above
  is unchanged.
- **Weekly, grouped Dependabot.** Python deps and the pinned GitHub Actions are scanned weekly and
  arrive as grouped PRs (`.github/dependabot.yml`: Python split into a runtime group and a dev
  group, Actions in one). Nothing auto-merges.
- **The PR jobs install one pinned set; a nightly run installs the newest releases (OD-49,
  u14 A-123).** `ci-constraints-requirements.txt` pins every package the `static`, `validate`
  and `package` jobs install, direct and transitive, at one version (`pip install -c`), resolved
  for CPython 3.11 on Linux by `scripts/ci_constraints.py`; Dependabot's pip ecosystem bumps it
  with `pyproject.toml`. A release therefore reaches a PR only through a Dependabot PR (or a
  hand bump) that names it, instead of failing whatever PR runs next. `audit.yml`'s
  `full-sweep` installs with no constraints every night (the static checks, spec lint and the
  full suite with coverage), so a release that breaks the code is reported the night it lands.
  The file is a constraints file, not a lock: it has no hashes, and an operator's
  `pip install` still resolves the newest releases.
- **Dependabot never proposes a major bump of the two runtime pillars (Pydantic, Typer).** The
  `ignore` rules in `.github/dependabot.yml` drop `version-update:semver-major` for both, so a
  major upgrade is a deliberate manual change, never a Dependabot PR; a breaking major cannot
  land unattended. Every other Python dependency gets major bumps proposed like minor ones.
- **GitHub Actions pinned to a major version tag** (`actions/checkout@v4`,
  `actions/setup-python@v7`, `actions/upload-artifact@v7`), not to a commit SHA, so a re-pointed
  tag would change what runs. Dependabot bumps them weekly, except that it never proposes a
  major bump of `actions/checkout` (also an `ignore` rule); that one is upgraded by hand.

## Vulnerability scanning

What CI runs (`.github/workflows/ci.yml`, on every pull request, every push to `main`, and
weekly): a static job (ruff lint and format check, `mypy --strict`, import-linter) and the twelve
ordered gates of `docs/07 §5`: spec lint, import contract, the test suites, the **self-scan**
(the tool runs its own adversarial judge corpus against itself; every flip it provokes is
recorded as a critical finding, and the gate fails on any high or critical finding: there is no
baseline, so "new" does not apply) and the coverage gate (`--cov-fail-under=85` over the
aggregate of `src/ildottore`; the threshold lives on the command line in the workflows and the
Makefile, not in `pyproject.toml`). The scheduled `audit`
workflow re-runs the golden snapshot, metamorphic, determinism and self-scan, and the static
checks, spec lint and full suite with coverage, every night at the newest releases (weekly until
OD-49). Every
workflow runs with `permissions: contents: read`.

**Not in CI: `pip-audit` and `bandit`.** Neither workflow has a step for them, so CI enforces
no vulnerability or bandit threshold at all. They exist only as `make audit` (`pip-audit` with
no options: it fails on any known vulnerability in the environment, whatever its severity) and
`make bandit` (`bandit -q -c pyproject.toml -r src`: it fails on any finding, of any severity,
that the `B105` skip does not cover), which the Makefile groups under an "advisory" heading.
Both are part of `make gates`, so a local `make gates` on a fresh `pip install -e ".[dev]"`
stops at `bandit` until the two tools are installed by hand. A known-vulnerable dependency or a
bandit finding therefore does not fail the build today. Also not in place: a lock file with
hashes (`pyproject.toml` sets lower bounds only; the CI constraints file pins versions, not
artifacts) and a published SBOM.

## Secrets and credentials

- No secret is ever committed. Target credentials are referenced (`env://NAME`), never inlined,
  and are read only at send time. `env://` is the only scheme the resolver accepts; `vault://`
  is deferred and raises.
- Evidence is redacted at rest (fail-closed): a write is refused if a secret/PII shape survives
  redaction. Multimodal carrier bytes are elided from evidence (reference + digest kept).

## Reporting a vulnerability

See [`SECURITY.md`](SECURITY.md).
