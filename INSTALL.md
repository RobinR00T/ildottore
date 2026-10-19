# Install

## Requirements

- **Python 3.11+** (3.11 is the CI baseline; newer works).
- A POSIX shell. macOS and Linux are the tested platforms.
- Optional, only for the scenarios that use them:
  - **Ollama** to run local models (target and/or judge) with no API key.
  - An API key (as an environment variable) to scan a hosted model.

## From source (recommended today)

```bash
git clone <repo> && cd ildottore
python3 -m venv .venv
.venv/bin/python -m pip install -e ".[dev]"
```

The `[dev]` extra pulls in the test and lint toolchain (pytest, pytest-asyncio, pytest-cov,
Hypothesis, respx, coverage, ruff, mypy, import-linter and type stubs). It does **not** include
bandit or pip-audit, which the last two steps of `make gates` call; install them into the same
venv to run the whole wall:

```bash
.venv/bin/python -m pip install bandit pip-audit
```

## Runtime only (no checkout to keep)

Drop `[dev]` and `-e`: a wheel carries the built-in battery and the attack-spec schema, which live
inside the package (`src/ildottore/battery/`, `src/ildottore/registry/schemas/`), so an installed
copy needs no checkout beside it. From a clone, or from a commit you have reviewed (the package is
not on PyPI: `pip install ildottore` finds nothing):

```bash
python3 -m venv .venv && .venv/bin/python -m pip install .
.venv/bin/python -m pip install "ildottore @ git+https://github.com/RobinR00T/ildottore@<commit>"
```

`<commit>` is a full commit SHA of `main` from the change that put the battery in the package
(`5edeb0a7`, #119, CHANGELOG `[Unreleased]`) on; the CI example pins `fef4963e`, `main` on
2026-10-17. An older one, the `v0.1.0` tag included, builds a wheel that
carries neither the battery nor the schema: from outside a checkout `dottore run --dry-run` and
`registry ls` exit 3 (`spec path not found: specs`), and `lint <checkout>/specs` exits 3 on the
missing `schemas/attack-spec.schema.json` (`unexpected FileNotFoundError`; measured on `7d01521f`,
2026-10-16). Measured on 2026-10-16, with a wheel built offline by the selection `pyproject.toml`
declares (hatchling itself was not installed) and installed with
`pip install --no-index --no-deps --target`: run from a directory
outside the checkout, `--version`, `registry ls` (75 specs), `schema export`, `lint` of the
installed battery (75 specs, 14 suites) and `run --dry-run` printed exactly what the checkout
prints, and both computed the same judging digest; a run against an offline mock judged the same
way. CI builds the real wheel and sdist with hatchling and repeats that comparison (the `package`
job, `tests/test_packaging.py`).

With no `--spec-path`, a command reads the built-in battery and says so on stderr, with its path
(and as a `::warning::` annotation under GitHub Actions), unless the directory it runs in has a
`specs/` directory, which it reads instead and refuses (exit 3) when it holds no attack spec
(Troubleshooting below).

Two console scripts are installed: `dottore` and its short alias `dott`.

## Verify

```bash
.venv/bin/dottore --help
.venv/bin/dottore registry ls          # 78 specs, fully offline
.venv/bin/dottore lint src/ildottore/battery   # schema + policy + fixtures-prove-detection
make test                              # the full test suite (or: make gates)
```

`make gates` runs what the CI merge gate (`.github/workflows/ci.yml`) runs (lint, format
check, mypy strict, import boundaries, spec lint, the test suite with coverage >=85%, the
self-scan) and then two checks CI does not run: bandit and pip-audit. It is the fastest way to
know you are green.

## Optional: local models via Ollama (no API key)

Lets you run and scan real models entirely on your machine, and use one as the LLM judge:

```bash
brew install ollama        # or see ollama.com for Linux
ollama serve &
ollama pull llama3.2:1b    # a small target
ollama pull llama3.2:3b    # a slightly stronger judge
```

Point a target file at `http://localhost:11434/v1/chat/completions` with `provider: openai`
(Ollama speaks the OpenAI-compatible API). Ready-made files are in
[`examples/`](examples/): `target.local.yaml`, `target.judge.yaml`, `scope.local.yaml`.

## Optional: hosted models (API key by env var)

Keys are **never** written into target or scope files. A target references an env var:

```yaml
# target.openai.yaml
auth_ref: "env://OPENAI_API_KEY"
```

```bash
export OPENAI_API_KEY=sk-...
```

The scope must contain a `targets` entry whose id matches the target and whose `endpoints`
cover the host, or the run refuses to send (default-deny).

## Troubleshooting

- **`target(s) not authorized by the scope`** (exit 3, before anything is sent), with the
  cause in brackets: `endpoint '<url>' not on allowlist for '<id>'` when the target's
  `endpoint` host/path is not in that target's `endpoints` in the scope, or
  `target '<id>' not in scope` when the target id is not among the scope's `targets`. This is
  the authorization gate doing its job; add the entry deliberately. (`endpoint not allowed by
  scope` is the adapter's own second check, which you should only meet if the first one was
  bypassed.)
- **Live findings all come back inconclusive**, the `semantic_judge` evaluator abstains
  without a judge. Pass `--judge <judge-target.yaml>`. Deterministic evaluators still fire
  without it.
- **`connection refused` to `localhost:11434`**, Ollama is not running (`ollama serve`) or
  the model is not pulled (`ollama pull …`).
- **A run does nothing but validates**, you passed `--dry-run` (resolve + validate, send
  nothing). Drop it to actually scan.
- **`spec path not found: specs`** (exit 3), no `--spec-path` was given and there is neither a
  `specs/` directory where you run nor a built-in battery in the installed package: an install of
  a commit from before the battery moved into the package (the runtime install above). `run`,
  `fleet --run`, `registry ls`, `describe` and `coverage` read `specs/` in the working directory
  when there is one, else the built-in battery inside the installed package, and say on stderr
  when they read the battery; `dottore lint` reads `specs/` here only.
- **`spec path specs holds no attack spec or suite to read`** (exit 3), the directory you run in
  has a `specs/` (an OpenAPI folder, say) and no `--spec-path` was given: it is read, never
  swapped for the built-in battery. Run from another directory or pass `--spec-path`.
- **`...; it is now <path> (the built-in battery moved into the package)`** (or `(the example
  files moved from specs/ to examples/)`), a path of the layout before the battery moved into the
  package: `specs/attacks`, `specs/suites`, `specs/pack.yaml` (now under
  `src/ildottore/battery/`), a `--spec-path <checkout>/specs` that held the battery (it holds the
  unit contracts now), `specs/scope.example.yaml`, `specs/fleet.example.yaml` and
  `specs/targets/example-openai.yaml` (now `examples/scope.example.yaml`,
  `examples/fleet.example.yaml`, `examples/target.example-openai.yaml`). Point at the path it
  names, or drop `--spec-path` to read the built-in battery.
- **`cannot open the run store at <path>`** or **`cannot write evidence under <root>`** (exit 3,
  before anything is sent), `--run-db` names a directory or a file that is not SQLite, or
  `--evidence-root` is a regular file. Point them at a new path.
