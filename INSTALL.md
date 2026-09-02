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

The `[dev]` extra pulls in the toolchain (ruff, mypy, pytest, import-linter, bandit,
pip-audit) so you can run the gates. For a runtime-only install, drop `[dev]`.

Two console scripts are installed: `dottore` and its short alias `dott`.

## Verify

```bash
.venv/bin/dottore --help
.venv/bin/dottore registry ls          # 47 specs, fully offline
.venv/bin/dottore lint specs/          # schema + policy + fixtures-prove-detection
make test                              # the full test suite (or: make gates)
```

`make gates` runs the same wall as CI: lint, format check, mypy (strict), import
boundaries, spec lint, the test suite, coverage (>=85%), the self-scan, bandit and
pip-audit. It is the fastest way to know you are green.

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

- **`endpoint not allowed by scope`**, the target's `endpoint` host/path is not in that
  target's `endpoints` in the scope, or the target id is not among the scope's `targets`.
  This is the authorization gate doing its job; add the entry deliberately.
- **Live findings all come back inconclusive**, the `semantic_judge` evaluator abstains
  without a judge. Pass `--judge <judge-target.yaml>`. Deterministic evaluators still fire
  without it.
- **`connection refused` to `localhost:11434`**, Ollama is not running (`ollama serve`) or
  the model is not pulled (`ollama pull …`).
- **A run does nothing but validates**, you passed `--dry-run` (resolve + validate, send
  nothing). Drop it to actually scan.
