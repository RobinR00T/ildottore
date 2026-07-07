"""Spec/pack/suite discovery + safe parse + schema-validate + model-construct.

Contract §5.2. The load path is fixed (contract §4 KEEP):

    yaml.safe_load  →  JSON-Schema / Pydantic validate  →  model-construct  →  register

**No code execution, no network, no imports of pack content** happen here. Discovery walks
the filesystem only. Two on-disk shapes are supported:

* **Spec pack** — a directory containing ``pack.yaml`` (+ ``attacks/*.yaml`` and
  ``suites/*.yaml``). Discovered recursively from each search path.
* **Loose spec tree** — a directory (or file) of bare ``*.yaml`` attack specs with no
  ``pack.yaml`` (e.g. the repo ``specs/`` tree or a test fixture dir). These are gathered
  under a synthetic pack so the registry API is uniform.

Every unparseable / schema-invalid document yields a :class:`LintError` rather than an
exception, so ``dottore lint`` can itemize *all* problems in one pass.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from pydantic import ValidationError as PydanticValidationError

from ildottore.shared import AttackSpec, Pack, Suite

from .errors import LintCode, LintError
from .pack import LoadedPack
from .schema import SafeLoadError, load_yaml_file, validate_attack_spec_schema

_SYNTHETIC_PACK_ID = "loose-specs"


@dataclass(slots=True)
class LoadResult:
    """Outcome of a load pass: the packs that parsed + any load-time findings."""

    packs: list[LoadedPack] = field(default_factory=list)
    errors: list[LintError] = field(default_factory=list)

    def extend(self, other: LoadResult) -> None:
        """Merge another result into this one (preserving order)."""
        self.packs.extend(other.packs)
        self.errors.extend(other.errors)


def _rel(path: Path, root: Path) -> str:
    """A stable, root-relative display path for error messages."""
    try:
        return str(path.relative_to(root))
    except ValueError:
        return str(path)


def _load_attack_spec(path: Path, display_root: Path) -> tuple[AttackSpec | None, list[LintError]]:
    """Parse + schema-validate + construct a single attack spec YAML file."""
    rel = _rel(path, display_root)
    try:
        data = load_yaml_file(path)
    except SafeLoadError as exc:
        return None, [LintError(code=LintCode.PARSE_ERROR, message=str(exc), path=rel)]

    if not isinstance(data, dict):
        return None, [
            LintError(
                code=LintCode.PARSE_ERROR,
                message="document root is not a mapping",
                path=rel,
            )
        ]

    schema_errors = validate_attack_spec_schema(data)
    if schema_errors:
        spec_id = data.get("id") if isinstance(data.get("id"), str) else None
        return None, [
            LintError(code=LintCode.SCHEMA, message=msg, path=rel, spec_id=spec_id)
            for msg in schema_errors
        ]

    # Schema-valid; construct the model. Pydantic post-init invariants (e.g. fixtures
    # verdict polarity, attack anyOf) are a second, stricter gate → surface as SCHEMA.
    try:
        spec = AttackSpec.model_validate(data)
    except PydanticValidationError as exc:
        spec_id = data.get("id") if isinstance(data.get("id"), str) else None
        return None, [LintError(code=LintCode.SCHEMA, message=str(exc), path=rel, spec_id=spec_id)]
    return spec, []


def _load_suite(path: Path, display_root: Path) -> tuple[Suite | None, list[LintError]]:
    """Parse + construct a suite YAML (Pydantic-first validation, ADR-0006)."""
    rel = _rel(path, display_root)
    try:
        data = load_yaml_file(path)
    except SafeLoadError as exc:
        return None, [LintError(code=LintCode.PARSE_ERROR, message=str(exc), path=rel)]
    if not isinstance(data, dict):
        return None, [
            LintError(code=LintCode.PARSE_ERROR, message="suite root is not a mapping", path=rel)
        ]
    try:
        suite = Suite.model_validate(data)
    except PydanticValidationError as exc:
        return None, [LintError(code=LintCode.SCHEMA, message=str(exc), path=rel)]
    return suite, []


def _load_pack_manifest(path: Path, display_root: Path) -> tuple[Pack | None, list[LintError]]:
    """Parse + construct a ``pack.yaml`` manifest (Pydantic-first, ADR-0006)."""
    rel = _rel(path, display_root)
    try:
        data = load_yaml_file(path)
    except SafeLoadError as exc:
        return None, [LintError(code=LintCode.PARSE_ERROR, message=str(exc), path=rel)]
    if not isinstance(data, dict):
        return None, [
            LintError(
                code=LintCode.PARSE_ERROR, message="pack.yaml root is not a mapping", path=rel
            )
        ]
    try:
        manifest = Pack.model_validate(data)
    except PydanticValidationError as exc:
        return None, [LintError(code=LintCode.SCHEMA, message=str(exc), path=rel)]
    return manifest, []


def _yaml_files(root: Path) -> list[Path]:
    """All ``*.yaml`` / ``*.yml`` files directly under ``root`` (non-recursive), sorted."""
    files = [*root.glob("*.yaml"), *root.glob("*.yml")]
    return sorted(files)


def _load_pack_dir(pack_dir: Path, display_root: Path) -> LoadResult:
    """Load one directory that contains a ``pack.yaml`` manifest."""
    result = LoadResult()
    manifest, merr = _load_pack_manifest(pack_dir / "pack.yaml", display_root)
    result.errors.extend(merr)
    if manifest is None:
        return result

    specs: list[AttackSpec] = []
    attacks_dir = pack_dir / "attacks"
    if attacks_dir.is_dir():
        for f in _yaml_files(attacks_dir):
            spec, errs = _load_attack_spec(f, display_root)
            result.errors.extend(errs)
            if spec is not None:
                specs.append(spec)

    suites: list[Suite] = []
    suites_dir = pack_dir / "suites"
    if suites_dir.is_dir():
        for f in _yaml_files(suites_dir):
            suite, errs = _load_suite(f, display_root)
            result.errors.extend(errs)
            if suite is not None:
                suites.append(suite)

    result.packs.append(LoadedPack(manifest=manifest, root=pack_dir, specs=specs, suites=suites))
    return result


def _load_loose_tree(root: Path, display_root: Path) -> LoadResult:
    """Load a flat tree of bare attack specs (no ``pack.yaml``) under a synthetic pack."""
    result = LoadResult()
    files = [root] if root.is_file() else _yaml_files(root)
    specs: list[AttackSpec] = []
    for f in files:
        spec, errs = _load_attack_spec(f, display_root)
        result.errors.extend(errs)
        if spec is not None:
            specs.append(spec)
    if specs or not result.errors:
        manifest = Pack(
            id=_SYNTHETIC_PACK_ID,
            pack_version="0.0",
            name="Loose specs (no pack.yaml)",
            specs=[s.id for s in specs],
        )
        result.packs.append(LoadedPack(manifest=manifest, root=root, specs=specs))
    return result


def _find_pack_dirs(root: Path) -> list[Path]:
    """Directories under ``root`` (inclusive) that contain a ``pack.yaml``."""
    found: list[Path] = []
    if (root / "pack.yaml").is_file():
        found.append(root)
    found.extend(sorted(p.parent for p in root.rglob("pack.yaml") if p.parent != root))
    return found


def load_path(path: Path) -> LoadResult:
    """Load every pack / loose spec discoverable under a single search path."""
    result = LoadResult()
    if path.is_file():
        return _load_loose_tree(path, path.parent)
    if not path.is_dir():
        result.errors.append(
            LintError(code=LintCode.PARSE_ERROR, message=f"path not found: {path}")
        )
        return result

    pack_dirs = _find_pack_dirs(path)
    if pack_dirs:
        for pd in pack_dirs:
            result.extend(_load_pack_dir(pd, path))
        return result
    # No pack.yaml anywhere → treat the directory as a loose spec tree.
    return _load_loose_tree(path, path)


def load_paths(paths: list[Path]) -> LoadResult:
    """Load and concatenate every search path in order (contract §5.3 merge order)."""
    result = LoadResult()
    for p in paths:
        result.extend(load_path(p))
    return result
