# ADR-0013: the package carries what it reads (u12 A-84)

* **Status:** accepted, 2026-10-16, under the owner's delegation (best practice, revisable)
* **Date:** 2026-10-16
* **Context:** the `docs/12` P1 row "An installable package" (found 2026-10-12), clause u12 §7
  A-84 in `specs/contracts/u12-cli.md`, ADR-0004 (one distribution in a `src/` layout).

## The problem, measured

The program reads two kinds of data file of its own: the built-in battery (the pack manifest, 75
attack specs with one audio asset, 14 suites) and the hand-authored JSON Schema every attack spec
is validated against. Both sat at the repository root (`specs/pack.yaml`, `specs/attacks/`,
`specs/suites/`, `schemas/attack-spec.schema.json`) and were found three directories above the
package (`Path(__file__).resolve().parents[3]`), which is the repository root only in a source
checkout or an editable install. The wheel `pyproject.toml` selects (`packages = ["src/ildottore"]`)
carries neither. Measured on `7d01521f` with a wheel built by that selection and installed with
`pip install --no-index --no-deps --target`, from a directory outside the checkout: `dottore
registry ls` and `run --dry-run` exited 3 (`spec path not found: specs`) and `lint
<checkout>/specs` exited 3 on the missing schema (`unexpected FileNotFoundError`).

## The decision

Move the files into the package, as git renames: the battery to `src/ildottore/battery/`
(`pack.yaml`, `attacks/` with `assets/`, `suites/`), the schema to
`src/ildottore/registry/schemas/attack-spec.schema.json`, beside the report schemas
(`reporting/schemas/`), the fingerprint signatures and the HTML template, which already lived in
the package and shipped with it. One module finds both, `shared/package_data.py`, through
`importlib.resources.files("ildottore")`: the same place relative to the package in a source
checkout, an editable install and an installed wheel. The hatch configuration does not change;
the selection it has carries every file under the package that `.gitignore` does not exclude.

Only what the program reads moves. `specs/` keeps the unit contracts (`specs/contracts/`), which
are documentation. The three example files that sat beside the battery (`specs/scope.example.yaml`,
`specs/fleet.example.yaml`, `specs/targets/example-openai.yaml`) move to `examples/`
(`scope.example.yaml`, `fleet.example.yaml`, `target.example-openai.yaml`), with the other
examples, because a `specs/` that still held YAML would be read as a spec path by every command
run in the repository root.

Two consequences follow, and are part of the decision:

* **The default spec path.** With no `--spec-path`, a command reads `specs/` in the working
  directory whenever it is a directory, as before, and refuses it (exit 3) when it holds nothing to
  read; it reads the built-in battery when there is no `specs/`, and at the root of this package's
  own checkout, the one exception, a deterministic one (the working directory resolves to the
  directory three above the battery), whose `specs/` holds the unit contracts. stderr says which,
  and under GitHub Actions a `::warning::` line says it too. The first build of this decision
  read a `specs/` with no YAML file in it as no `specs/` and scanned the battery in its place:
  the pre-merge audit measured an empty `specs/attacks` beside a vulnerable mock exiting 2 after
  18 built-in specs, and a `specs/` reaching its pack through a link exiting 0 on all 75, where
  `7d01521f` exits 3. A default that swaps the battery in for what the operator's directory holds
  fails open, so it was dropped before landing. A name for the battery itself, so a pipeline can
  ask for it whatever its directory holds (`--spec-path builtin`), is OD-51, open.
* **The paths a user may have written.** Every old path is refused as before (exit 3), and the
  refusal names where it is now, and what moved it, when that exists in the same checkout (`; it
  is now <path> (the built-in battery moved into the package)`, `(the example files moved from
  specs/ to examples/)`, or `; the built-in battery it held moved into the package: it is now
  <path>` for a `specs/`):
  `shared.package_data.MOVED` lists them, and the loader, the scope and policy-pack readers and the
  CLI's error text use it. Nothing old is read in its place: a path that silently became another
  would change what gates a pipeline without a word.

## The judging digest

`shared.judging_rules.judging_digest` covers every file of the package but the test harness, the
data files by suffix (`DATA_SUFFIXES`). Inside the package, the battery and the schema are covered
(the battery's audio asset by `.wav`, added to `DATA_SUFFIXES`); a new kind of asset fails
`tests/shared/test_judging_rules.py` until its suffix is added. The digest covers 264 files where it
covered 171 and costs the same (0.355 s against 0.378 s, Python 3.14, best of five).

What a spec says is part of what judges an attempt: its evaluators, its patterns, its rubric. The
per-spec battery digest (`shared.digest.spec_digests`) already binds a resume to the specs it ran,
over a behavioural projection that forgives a description or a reflowed line. The judging digest is
stricter, byte for byte, and binds the built-in battery a second time: a resume after any edit of a
built-in spec, its description included, is refused, naming the file. That is the deny-by-default
reading of A-81, and in practice the battery changes only with the installation, which changes the
code too. The refusal names the files that differ in clear: they ride on the refusal as names the
CLI's masking keeps, since a battery label read as a high-entropy secret in the first build (the
pre-merge audit's MEDIUM 1). A spec given with `--spec-path` stays bound by the spec digests alone,
as before. A run halted before this change is refused by a resume after it, as after any change of
the code (the refusal names the files that differ, the moved battery among them).

## Alternatives not taken

* **Map the files into the wheel with hatch `force-include`, leaving them at the root.** Smallest
  diff, and the brief's first suggestion. Not taken: the files would live in two places by install
  kind (inside the package in a wheel, at the repository root in a checkout or an editable install,
  where `force-include` does not apply), so the code would need two lookups, the second the
  `parents[3]` one that was the defect; and the judging digest, computed from the package
  directory, would differ between a wheel and a checkout of the same commit, unless it also
  learned where the battery is in each case. A second copy kept in sync by the build was the same
  problem with a drift risk added.
* **A symlink from the package to the root `specs/`.** Breaks on a checkout without symlinks
  (Windows by default), and the loader's containment checks and the digest's `rglob` would each have
  to follow it on purpose.
* **Move `specs/` whole, contracts included.** Keeps the cwd rule as it was, since the repository
  root would have no `specs/`, but moves the unit contracts the method names (`AGENTS.md` §1,
  every contract's cross-references) and ships documentation in the wheel.
* **Keep the old paths working by reading the new ones in their place.** Rejected above: a
  refusal that names the new path costs one edit and never changes what gates without a word.
* **A `builtin` spec-path keyword now.** Not needed for the fix, and a new public spelling of a
  path deserves its own decision: OD-51.
* **Read the battery in place of a `specs/` that holds no YAML file.** Built first, and dropped
  before landing: it fails open (above).

## Consequences

* (+) A wheel (`pip install .`, or pip's build of `git+https://...@<commit>`) runs with no
  checkout; the CI `package` job builds the real wheel and sdist with hatchling and runs the wheel
  from outside the checkout.
* (+) One lookup, the standard one, for every install kind; the judging digest is the same for a
  wheel and its checkout (measured with the offline stand-in: equal).
* (-) Paths in the docs, the contracts, the tests and the CI gates change (`dottore lint
  src/ildottore/battery`), and a pipeline that names an old path must change it: CHANGELOG lists
  each, as breaking.
* (-) A resume after a description edit of a built-in spec is refused, where the spec digests alone
  forgave it.
