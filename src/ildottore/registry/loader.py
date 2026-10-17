"""Spec/pack/suite discovery + safe parse + schema-validate + model-construct.

Contract §5.2. The load path is fixed (contract §4 KEEP):

    yaml.safe_load  →  JSON-Schema / Pydantic validate  →  model-construct  →  register

**No code execution, no network, no imports of pack content** happen here. Discovery walks
the filesystem only. Two on-disk shapes are supported:

* **Spec pack** - a directory containing ``pack.yaml`` (+ ``attacks/*.yaml`` and
  ``suites/*.yaml``). Discovered recursively from each search path.
* **Loose spec tree** - a directory (or file) of bare ``*.yaml`` attack specs with no
  ``pack.yaml`` (e.g. a test fixture dir). These are gathered
  under a synthetic pack so the registry API is uniform.

Every unparseable / schema-invalid document yields a :class:`LintError` rather than an
exception, so ``dottore lint`` can itemize *all* problems in one pass.
"""

from __future__ import annotations

import base64
import os
from dataclasses import dataclass, field
from pathlib import Path

from pydantic import ValidationError as PydanticValidationError

from ildottore.shared import AttackSpec, Pack, Suite
from ildottore.shared.config_errors import validation_problems
from ildottore.shared.package_data import moved_note

from .errors import PATH_NOT_FOUND_TEXT, LintCode, LintError, Severity
from .pack import LoadedPack
from .schema import SafeLoadError, encodes_utf8, load_yaml_file, validate_attack_spec_schema

_SYNTHETIC_PACK_ID = "loose-specs"

# Upper bound on a single media asset. A carrier is a short clip/image; anything larger is almost
# certainly a mistake, and reading it (then base64-encoding it ~1.33x, resident on the registry)
# would inflate memory during lint/run. Device files and symlinks-out are already refused, so this
# is bounded by real bytes on disk.
_MAX_ASSET_BYTES = 25 * 1024 * 1024


class _AssetError(ValueError):
    """A media ``asset`` reference could not be safely resolved."""


def _resolve_asset_bytes(spec_dir: Path, asset: str, read: list[Path] | None = None) -> bytes:
    """Read a media ``asset`` file, refusing any path that escapes the spec's own directory.

    A binary carrier (an audio clip) is stored as a file next to the spec and referenced by a
    RELATIVE path. This resolves it with strict containment: no absolute path, no ``..`` segment,
    and the resolved real path must stay under ``spec_dir`` (symlinks resolved). That keeps a
    spec from reading an arbitrary file off disk via its ``asset`` field. Every failure, including a
    filesystem error (permission denied, out of memory, oversize), is raised as :class:`_AssetError`
    so one bad asset becomes a single lint finding rather than crashing the whole load pass.
    """

    if asset.startswith("/") or asset.startswith("\\"):
        raise _AssetError(f"asset path must be relative, not {asset!r}")
    parts = Path(asset).parts
    if ".." in parts or any(p == "" for p in parts):
        raise _AssetError(f"asset path must not contain '..' segments: {asset!r}")
    try:
        base = spec_dir.resolve()
        resolved = (base / asset).resolve()
        if not resolved.is_relative_to(base):
            raise _AssetError(f"asset path escapes the spec directory: {asset!r}")
        if not resolved.is_file():
            raise _AssetError(f"asset file not found: {asset!r}")
        size = resolved.stat().st_size
        if size > _MAX_ASSET_BYTES:
            raise _AssetError(
                f"asset {asset!r} is {size} bytes, over the {_MAX_ASSET_BYTES}-byte cap"
            )
        if read is not None:
            read.append(resolved)
        return resolved.read_bytes()
    except _AssetError:
        raise
    except (OSError, MemoryError) as exc:
        raise _AssetError(f"could not read asset {asset!r}: {exc}") from exc


def _inline_media_assets(
    data: dict[str, object], spec_dir: Path, read: list[Path] | None = None
) -> None:
    """Resolve every ``attack.media[*].asset`` into ``data_b64`` in place (safe, load-time).

    Downstream (``shared.media``, adapters) then only sees pinned bytes, so no component needs
    filesystem access. Raises :class:`_AssetError` on an unsafe or missing asset.
    """

    attack = data.get("attack")
    if not isinstance(attack, dict):
        return
    media = attack.get("media")
    if not isinstance(media, list):
        return
    for part in media:
        if not isinstance(part, dict):
            continue
        asset = part.get("asset")
        if isinstance(asset, str) and asset and not part.get("data_b64"):
            part["data_b64"] = base64.b64encode(_resolve_asset_bytes(spec_dir, asset, read)).decode(
                "ascii"
            )


def _short_id(data: dict[str, object]) -> str | None:
    """The spec's ``id`` to attach to its findings, when it is a plausible id.

    Attached to every schema error, a 1 MB id printed 21 MB for one spec (pre-merge audit of
    #39); a real id is short. One holding half a character (a lone surrogate) is not attached:
    printing the finding header raised ``UnicodeEncodeError``, a lint traceback with exit 1, and
    the finding that reports it is the id's own (delta audit of A-54).
    """

    value = data.get("id")
    if isinstance(value, str) and len(value) <= _MAX_ID_CHARS and encodes_utf8(value):
        return value
    return None


_MAX_ID_CHARS = 128


def _problems(exc: PydanticValidationError) -> str:
    """Field and reason per error, no input value, at most 20 (the rest counted).

    ``str(exc)`` quoted every offending value: a 112 KB suite of aliased text printed 1.2 GB
    (pre-commit audit of the SEC-09 fix).
    """

    return validation_problems(exc, limit=20)


@dataclass(slots=True)
class LoadResult:
    """Outcome of a load pass: the packs that parsed + any load-time findings."""

    packs: list[LoadedPack] = field(default_factory=list)
    #: Load-time findings, the ``FILES_NOT_READ`` warning included (``severity`` says which).
    errors: list[LintError] = field(default_factory=list)
    #: Every file the pass read: each ``pack.yaml``, spec and suite file, and each media asset a
    #: spec inlined. What a run's report may not overwrite (u12 A-80): the files under a spec path
    #: that the loader never reads (a report written there by an earlier run) are not in it.
    files: list[Path] = field(default_factory=list)
    #: Spec and suite files read, whether they loaded or not: zero for a path is ``NO_SPECS``
    #: (u12 A-82). ``files`` holds more (a ``pack.yaml``, a media asset), so it cannot say it.
    spec_files_read: int = 0

    def extend(self, other: LoadResult) -> None:
        """Merge another result into this one (preserving order)."""
        self.packs.extend(other.packs)
        self.errors.extend(other.errors)
        self.files.extend(other.files)
        self.spec_files_read += other.spec_files_read


def _rel(path: Path, root: Path) -> str:
    """A stable, root-relative display path for error messages."""
    try:
        return str(path.relative_to(root))
    except ValueError:
        return str(path)


def _load_attack_spec(
    path: Path,
    display_root: Path,
    pack_root: Path | None = None,
    read: list[Path] | None = None,
) -> tuple[AttackSpec | None, list[LintError]]:
    """Parse + schema-validate + construct a single attack spec YAML file."""
    rel = _rel(path, display_root)
    try:
        data = load_yaml_file(path, root=pack_root)
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
        spec_id = _short_id(data)
        return None, [
            LintError(code=LintCode.SCHEMA, message=msg, path=rel, spec_id=spec_id)
            for msg in schema_errors
        ]

    # Resolve any media asset references (a binary carrier stored next to the spec) into inline
    # bytes, refusing a path that escapes the spec directory (a path-traversal guard).
    try:
        _inline_media_assets(data, path.parent, read)
    except _AssetError as exc:
        spec_id = _short_id(data)
        return None, [
            LintError(code=LintCode.ASSET_ERROR, message=str(exc), path=rel, spec_id=spec_id)
        ]

    # Schema-valid; construct the model. Pydantic post-init invariants (e.g. fixtures
    # verdict polarity, attack anyOf) are a second, stricter gate → surface as SCHEMA.
    try:
        spec = AttackSpec.model_validate(data)
    except PydanticValidationError as exc:
        spec_id = _short_id(data)
        return None, [
            LintError(code=LintCode.SCHEMA, message=_problems(exc), path=rel, spec_id=spec_id)
        ]
    return spec, []


def _load_suite(
    path: Path, display_root: Path, pack_root: Path | None = None
) -> tuple[Suite | None, list[LintError]]:
    """Parse + construct a suite YAML (Pydantic-first validation, ADR-0006)."""
    rel = _rel(path, display_root)
    try:
        data = load_yaml_file(path, root=pack_root)
    except SafeLoadError as exc:
        return None, [LintError(code=LintCode.PARSE_ERROR, message=str(exc), path=rel)]
    if not isinstance(data, dict):
        return None, [
            LintError(code=LintCode.PARSE_ERROR, message="suite root is not a mapping", path=rel)
        ]
    try:
        suite = Suite.model_validate(data)
    except PydanticValidationError as exc:
        return None, [LintError(code=LintCode.SCHEMA, message=_problems(exc), path=rel)]
    return suite, []


def _load_pack_manifest(path: Path, display_root: Path) -> tuple[Pack | None, list[LintError]]:
    """Parse + construct a ``pack.yaml`` manifest (Pydantic-first, ADR-0006)."""
    rel = _rel(path, display_root)
    try:
        data = load_yaml_file(path, root=path.parent)
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
        return None, [LintError(code=LintCode.SCHEMA, message=_problems(exc), path=rel)]
    return manifest, []


def _yaml_files(root: Path) -> list[Path]:
    """All ``*.yaml`` / ``*.yml`` files directly under ``root`` (non-recursive), sorted."""
    files = [*root.glob("*.yaml"), *root.glob("*.yml")]
    return sorted(files)


def _load_pack_dir(pack_dir: Path, display_root: Path) -> LoadResult:
    """Load one directory that contains a ``pack.yaml`` manifest."""
    result = LoadResult()
    result.files.append(pack_dir / "pack.yaml")
    manifest, merr = _load_pack_manifest(pack_dir / "pack.yaml", display_root)
    result.errors.extend(merr)
    if manifest is None:
        return result

    specs: list[AttackSpec] = []
    spec_files: list[str] = []
    attacks_dir = pack_dir / "attacks"
    if attacks_dir.is_dir():
        for f in _yaml_files(attacks_dir):
            result.spec_files_read += 1
            result.files.append(f)
            spec, errs = _load_attack_spec(f, display_root, pack_dir, result.files)
            result.errors.extend(errs)
            if spec is not None:
                specs.append(spec)
                spec_files.append(str(f))

    suites: list[Suite] = []
    suites_dir = pack_dir / "suites"
    if suites_dir.is_dir():
        for f in _yaml_files(suites_dir):
            result.spec_files_read += 1
            result.files.append(f)
            suite, errs = _load_suite(f, display_root, pack_dir)
            result.errors.extend(errs)
            if suite is not None:
                suites.append(suite)

    result.packs.append(
        LoadedPack(
            manifest=manifest, root=pack_dir, specs=specs, suites=suites, spec_files=spec_files
        )
    )
    return result


def _load_loose_tree(root: Path, display_root: Path) -> LoadResult:
    """Load a flat tree of bare attack specs (no ``pack.yaml``) under a synthetic pack."""
    result = LoadResult()
    files = [root] if root.is_file() else _yaml_files(root)
    result.spec_files_read = len(files)
    specs: list[AttackSpec] = []
    spec_files: list[str] = []
    for f in files:
        # A file named on the command line is the operator's choice; one found in a directory
        # must resolve inside it, like a pack's.
        result.files.append(f)
        spec, errs = _load_attack_spec(
            f, display_root, None if root.is_file() else root, result.files
        )
        result.errors.extend(errs)
        if spec is not None:
            specs.append(spec)
            spec_files.append(str(f))
    if specs or not result.errors:
        manifest = Pack(
            id=_SYNTHETIC_PACK_ID,
            pack_version="0.0",
            name="Loose specs (no pack.yaml)",
            specs=[s.id for s in specs],
        )
        result.packs.append(
            LoadedPack(manifest=manifest, root=root, specs=specs, spec_files=spec_files)
        )
    return result


#: How many YAML files (and directories) below a loose tree :func:`_unread_yaml` counts before it
#: stops: it is a courtesy note, and an operator pointing at a large tree should not wait for it.
_MAX_UNREAD_SCAN = 1000
#: How many of their directories a note names; the rest are counted.
_MAX_UNREAD_DIRS = 5


def _unread_yaml(root: Path) -> tuple[int, list[str]]:
    """The YAML files in ``root``'s subdirectories, which a loose tree does not read, and the
    directories that hold them (relative, ``attacks/``), up to :data:`_MAX_UNREAD_SCAN` files.

    ``os.walk`` without following links, so a link loop under the tree costs nothing.
    """

    count = 0
    dirs: list[str] = []
    for visited, (current, subdirs, names) in enumerate(os.walk(root, followlinks=False)):
        if visited >= _MAX_UNREAD_SCAN:
            break
        subdirs.sort()
        here = Path(current)
        if here == root:
            continue
        found = [n for n in names if n.endswith((".yaml", ".yml"))]
        if found:
            dirs.append(here.relative_to(root).as_posix() + "/")
            count += len(found)
            if count >= _MAX_UNREAD_SCAN:
                break
    return count, dirs


def _shown_dirs(count: int, dirs: list[str]) -> tuple[str, str]:
    """``("<count> YAML file(s)", "<dir>, <dir> and N more")`` for a note."""

    names = ", ".join(dirs[:_MAX_UNREAD_DIRS])
    more = f" and {len(dirs) - _MAX_UNREAD_DIRS} more" if len(dirs) > _MAX_UNREAD_DIRS else ""
    figure = f"{count:,} or more" if count >= _MAX_UNREAD_SCAN else f"{count:,}"
    return f"{figure} YAML file(s)", f"{names}{more}"


def _loose_tree_notes(path: Path, result: LoadResult) -> None:
    """What a loose directory left unread, said (u12 A-82, CLI audit M9).

    ``lint sp`` with the specs under ``sp/attacks/`` and no ``pack.yaml`` read nothing and
    printed ``lint OK ... across 0 spec(s)``, exit 0, an invalid spec there included. A loose
    tree still reads its own files only (docs/06 §2); with none it is ``NO_SPECS``, an error
    that names what is below it, and with some, the files below it are a ``FILES_NOT_READ``
    warning.
    """

    count, dirs = _unread_yaml(path)
    if result.spec_files_read == 0:
        unread = ""
        if count:
            figure, names = _shown_dirs(count, dirs)
            unread = (
                f"; {figure} in its subdirectories ({names}) are not read: add a pack.yaml to it "
                "(docs/06 §2) to load attacks/ and suites/, or point at the directory that holds "
                "the specs"
            )
        result.errors.append(
            LintError(
                code=LintCode.NO_SPECS,
                message=(
                    f"spec path {path} holds no attack spec or suite to read: a directory "
                    "without a pack.yaml is read as loose specs, the *.yaml and *.yml files "
                    f"directly in it, and it has none{unread}{moved_note(path)}"
                ),
            )
        )
    elif count:
        figure, names = _shown_dirs(count, dirs)
        result.errors.append(
            LintError(
                code=LintCode.FILES_NOT_READ,
                severity=Severity.WARNING,
                message=(
                    f"{figure} in the subdirectories of a directory without a pack.yaml are not "
                    f"read ({names}): {path} is read as loose specs, its own *.yaml and *.yml "
                    "files only; add a pack.yaml (docs/06 §2) to load attacks/ and suites/"
                ),
                path=str(path),
            )
        )


def _find_pack_dirs(root: Path) -> list[Path]:
    """Directories under ``root`` (inclusive) that contain a ``pack.yaml``."""
    found: list[Path] = []
    if (root / "pack.yaml").is_file():
        found.append(root)
    found.extend(sorted(p.parent for p in root.rglob("pack.yaml") if p.parent != root))
    return found


#: A path name longer than this is described by its length, not printed (PATH_MAX on macOS).
_MAX_SHOWN_PATH = 1024


def _shown_path(path: Path) -> str:
    """``path`` as a finding prints it: whole, or by its length when no file system could hold it.

    ``--spec-path <5,000 digits>`` printed ``path not found: «REDACTED:phone»``, the CLI's
    redactor reading the digits as a phone number (round-2 audit of A-82, LOW 6).
    """

    text = str(path)
    if len(text) > _MAX_SHOWN_PATH or any(len(part) > 255 for part in path.parts):
        return f"a name of {len(text):,} characters"
    return text


def load_path(path: Path) -> LoadResult:
    """Load every pack / loose spec discoverable under a single search path."""
    result = LoadResult()
    try:
        is_file, is_dir = path.is_file(), path.is_dir()
    except OSError:  # a name too long to look up raises on some Pythons: no such path
        is_file = is_dir = False
    if is_file:
        return _load_loose_tree(path, path.parent)
    if not is_dir:
        result.errors.append(
            LintError(
                code=LintCode.PATH_NOT_FOUND,
                message=f"{PATH_NOT_FOUND_TEXT}{_shown_path(path)}{moved_note(path)}",
            )
        )
        return result

    pack_dirs = _find_pack_dirs(path)
    if pack_dirs:
        for pd in pack_dirs:
            result.extend(_load_pack_dir(pd, path))
        # A pack whose manifest failed has its own error; one that loaded and holds nothing
        # read nothing, as an empty directory (u12 A-82).
        if result.spec_files_read == 0 and not any(
            e.severity is Severity.ERROR for e in result.errors
        ):
            result.errors.append(
                LintError(
                    code=LintCode.NO_SPECS,
                    message=(
                        f"spec path {path} holds no attack spec or suite to read: its pack.yaml "
                        "is there, and its attacks/ and suites/ hold no *.yaml or *.yml file"
                    ),
                )
            )
        return result
    # No pack.yaml anywhere → treat the directory as a loose spec tree.
    result = _load_loose_tree(path, path)
    _loose_tree_notes(path, result)
    return result


def load_paths(paths: list[Path]) -> LoadResult:
    """Load and concatenate every search path in order (contract §5.3 merge order)."""
    result = LoadResult()
    for p in paths:
        result.extend(load_path(p))
    return result
