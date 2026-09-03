# Releasing Il Dottore

Il Dottore is currently distributed as source (clone + `pip install -e .`); there is no published
package yet. This is the process for cutting a tagged, GPG-signed release on GitHub.

## Prerequisites

- A clean `main` with the release content merged and green CI.
- The maintainer's GPG key available locally (commits and tags are signed).
- `gh` authenticated.

## Pre-release checklist

1. `make gates` is green locally (the full wall: ruff, `ruff format --check`, mypy --strict,
   import-linter, `dottore lint specs`, pytest + coverage >=85%, self-scan, bandit, pip-audit).
2. `CHANGELOG.md` has an entry for the version under `## [Unreleased]`; rename it to the version and
   date.
3. Docs and counts are accurate (README / MANUAL spec+suite counts, `ROADMAP.md`).
4. No em/en dashes in the diff (house rule; check the added lines with Python, not a zsh grep).

## Branch, sign, merge

Work never lands unsigned on `main`. The build loop commits on a branch **without** signing (it has
no passphrase); the maintainer signs the batch and it merges via PR:

```bash
# on the release branch, after the checklist passes:
"$HOME/AI projects/ildottore/scripts/sign-branch.sh"   # warms gpg-agent, then rebase-signs from main
```

`scripts/sign-branch.sh` avoids the pinentry-in-rebase hang (it warms the gpg-agent first) and runs
from any working directory. Never run the raw `git rebase --exec ... -S` by hand. Then open a PR,
wait for CI green, and merge with a **merge commit** (not squash/rebase) so the signed commits are
preserved on `main`.

## Tag and GitHub release

```bash
git checkout main && git pull --ff-only
git tag -s vX.Y.Z -m "Il Dottore vX.Y.Z: <one-line theme>"
git push origin vX.Y.Z
gh release create vX.Y.Z --title "Il Dottore vX.Y.Z" --notes-file <notes.md>
```

Release notes should carry: the theme, the highlights (new suites/specs, counts), install, a short
example, and the supply-chain note (see [`SUPPLY-CHAIN.md`](SUPPLY-CHAIN.md)).

## Post-release

- Verify the tag shows as **Verified** on GitHub.
- Smoke-test a fresh clone: `pip install -e ".[dev]"` then `make gates`.
- Start a new `## [Unreleased]` section in `CHANGELOG.md`.
