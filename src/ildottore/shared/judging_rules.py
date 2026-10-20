"""The rules that turn one reply into the verdict stored beside it, named and bound (u12 A-81).

A resumed run keeps the attempts its halted half stored, **with the verdicts that half gave
them**, and judges only what it sends. Those verdicts are not recomputed: the stored reply is the
redacted one (a leaked canary is kept as ``«REDACTED:canary:…»``, a secret as its mask, and no
logprob is stored, ``docs/11`` DL2), so the evaluators that would have to see the raw value cannot
judge it again, and the judge would have to be asked again, which is traffic. So when the rules
changed between the halt and the resume, one report holds the same kind of reply judged two ways:
measured on ``de122e26``, a halt on ``f12ba83`` against a stub whose every reply was cut by the
provider's filter kept 4 attempts that ``f12ba83`` had judged ``pass`` beside 2 the new rules judge
``cut_by_provider_output_filter``, and the summary said ``Cut by the provider's output filter: 6
attempt(s) in 2 spec(s) came back cut or replaced ... never a pass`` although all 10 were cut
(OD-42, u08 A-70). OD-16, OD-19, OD-21 and OD-41 changed verdicts the same way the same week, and
``--version`` said ``0.1.0`` before and after every one of them.

Two records bind a run to its rules, both written when it starts and both checked by a resume:

* :func:`judging_digest`, computed at run time from the installed package itself: a SHA-256 over
  **every file of the package** but the test harness (:data:`JUDGING_EXEMPT`), Python sources
  with their comments, docstrings and blank lines left out (decorators kept), the data files the
  package reads (:data:`DATA_SUFFIXES`) byte for byte, the built-in battery among them. Deny by
  default: what is not exempted is covered, a subclass override, a default, a decorator, the
  offline judge, a renderer and a new module included, with no list to keep up to date. A resume
  under any other digest, or another interpreter (:func:`python_build`), is refused, whoever
  forgot what, naming the files that differ (:func:`judging_files`).
* :data:`JUDGING_RULES_VERSION`, the human name of those rules, which ``dottore --version`` prints
  and a refusal quotes. ``tests/shared/test_judging_rules.py`` pins the digest of each version, so
  a change to covered code fails it until the version is bumped (with a CHANGELOG line) or the
  same version is re-pinned with a reason, in an append-only history.

The first design listed the verdict code instead (an allow-list with a reference walk): two
audits found verdict code it did not reach (a default of the REST template, a subclass's override,
the offline judge, a decorator), so the default was inverted under the owner's delegation (best
practice, 2026-10-13).

**Landing.** Version ``1`` is the rules as of the merge that introduced the version: main at
``a906cea9`` (the six branches before it) merged in on :data:`JUDGING_RULES_SINCE`, the one place
the docs name for that date, and the pin made on that tree, replacing the provisional pin of the
day before. Version ``2`` (u08 A-85, 2026-10-16) changes verdicts and figures: a crossing of a
canary the request carries is a fail that needs review, never a confirmed one, and
``secret_shape`` detects every key format the redactor masks; its pin is made on the tree that
lands it. Version ``5`` (u08 A-87, 2026-10-20) changes them again: each attempt's own reply is
read against the scope's canary owner map, the identity sweep is one trial of its spec counted
once, and a canary of the scope's floors is read case-folded with its format characters removed.
Version ``6`` (u08 A-92, 2026-10-20) removes the default ignorable code points as well (a
variation selector, the combining grapheme joiner, a Hangul filler), which hid a crossing.
"""

from __future__ import annotations

import ast
import hashlib
import io
import textwrap
import tokenize
from functools import cache
from pathlib import Path
from typing import Final

__all__ = [
    "DATA_SUFFIXES",
    "JUDGING_EXEMPT",
    "JUDGING_RULES_SINCE",
    "JUDGING_RULES_VERSION",
    "RECORDED_DEPENDENCIES",
    "JudgingCodeUnreadable",
    "covered_files",
    "dependency_versions",
    "judging_digest",
    "judging_files",
    "normalized_source",
    "python_build",
]

#: Bumped by one whenever a change can alter the verdict stored for an attempt. ``1``: the rules as
#: of the merge that introduced the version, the first that records it (OD-16, OD-19, OD-21, OD-38,
#: OD-40, OD-41, OD-42 and OD-43 in force). ``2``: u08 A-85, a crossing of a canary the identity
#: sweep's request carries is a fail that needs review, not a confirmed one; ``secret_shape``
#: reads the redactor's documented key formats. ``3``: u06 A-89, a call's JSON-string arguments
#: holding an integer longer than ``int`` converts are read, where they read as ``{}`` and passed.
#: ``4``: u06 A-90, so are arguments a reply carries as a JSON object (Anthropic's ``input``, an
#: OpenAI ``function.arguments`` written as an object, a WebSocket frame's calls), where the
#: integer made the reply unreadable, not evaluated. ``5``: u08 A-87, every reply received under an
#: identity is read against the owner map, the identity sweep is one trial counted once, and a
#: canary is read case-folded without format characters. ``6``: u08 A-92, nor default ignorable
#: code points (a variation selector, the combining grapheme joiner, a Hangul filler hid a
#: crossing: inconclusive or pass, where it is a fail).
JUDGING_RULES_VERSION: Final = 6

#: The day runs began to record their rules (version 1 took its value), which the refusal of a run
#: that records none quotes and the docs name (as ``JUDGING_RULES_SINCE``) instead of writing the
#: date: set once, at that merge. A later version's day is its CHANGELOG line's, since a run that
#: records version 1 does record its rules and is refused for them, naming them.
JUDGING_RULES_SINCE: Final = "2026-10-15"

#: The modules :func:`judging_digest` leaves out, each with its reason. Only a module no part of a
#: run can execute may be here: outside the import closure of the console entry point
#: (``ildottore.cli.main``, which ``dottore`` and ``dott`` call), and named by no dynamic import of
#: covered code, both of which ``tests/shared/test_judging_rules.py`` checks. A module the entry
#: point imports runs its top-level code in the process of every run, so an edit to it can change
#: a verdict as a side effect (the third audit appended to the exempt ``cli/render.py`` a line that
#: emptied ``shared.provider_filter.FILTER_STOPS``, and a resume mixed verdicts): the renderers,
#: the other commands, ``cli.app`` and ``cli.main`` are covered for that reason, and a resume after
#: an edit to their help text is refused, as after any other edit.
JUDGING_EXEMPT: Final = {
    "ildottore.testing": (
        "the offline golden harness of the test suite: no module the dottore entry point loads "
        "imports it"
    ),
}

#: The suffixes of the package's own data files, which the digest covers byte for byte: the
#: fingerprint signatures and the built-in battery's specs, suites and manifest (``.yaml``), the
#: run store schema (``.sql``), the report schemas and the attack-spec schema (``.json``), the
#: HTML report template (``.j2``) and the battery's audio asset (``.wav``), the battery and the
#: attack-spec schema inside the package since u12 A-84. Anything else is not read by the
#: package: a stray file (a ``.DS_Store``) is not a change of the code that judges (the third
#: audit: one refused every resume). A new kind of asset under ``battery/`` fails
#: ``tests/shared/test_judging_rules.py`` until its suffix is added here.
DATA_SUFFIXES: Final = frozenset({".yaml", ".sql", ".json", ".j2", ".wav"})

#: Hex digits of a per-file digest, which a refusal uses to name the files that changed.
FILE_DIGEST_LENGTH: Final = 8


class JudgingCodeUnreadable(ValueError):
    """The package's own source files cannot be read, so the code that judges cannot be bound.

    A ``ValueError``, so the CLI exits 3: a zip or frozen install has no file under the package
    directory, and a digest of nothing would pass every resume (third audit, LOW).
    """


#: The package directory the digest covers.
_PACKAGE: Final = Path(__file__).resolve().parents[1]


def normalized_source(source: str) -> str:
    """``source`` with every comment, docstring and blank line removed, lines right-stripped.

    By ``tokenize`` and ``ast`` positions rather than by an ``ast.dump`` or ``ast.unparse``, whose
    text differs between Python versions, so a pin holds on every supported one. A decorator, a
    default, a string that is not a docstring and a ``#`` inside a string are code, and kept.
    """

    source = textwrap.dedent(source)
    lines = source.splitlines()
    drop: set[int] = set()
    for node in ast.walk(ast.parse(source)):
        if isinstance(node, (ast.Module, ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)):
            first = node.body[0] if node.body else None
            if (
                isinstance(first, ast.Expr)
                and isinstance(first.value, ast.Constant)
                and isinstance(first.value.value, str)
                and first.end_lineno is not None
            ):
                drop.update(range(first.lineno - 1, first.end_lineno))
    cuts: dict[int, int] = {}
    for token in tokenize.generate_tokens(io.StringIO(source).readline):
        if token.type == tokenize.COMMENT:
            row, col = token.start
            cuts[row - 1] = min(col, cuts.get(row - 1, col))
    kept = []
    for index, line in enumerate(lines):
        if index in drop:
            continue
        line = line[: cuts[index]] if index in cuts else line
        if line.strip():
            kept.append(line.rstrip())
    return "\n".join(kept)


def _module_of(relative: Path) -> str:
    return ".".join(("ildottore", *relative.with_suffix("").parts)).removesuffix(".__init__")


def _exempt(module: str) -> bool:
    return any(module == name or module.startswith(f"{name}.") for name in JUDGING_EXEMPT)


def covered_files(package: Path = _PACKAGE) -> list[tuple[str, Path]]:
    """``(label, path)`` of every file the digest covers, sorted: the package minus the exempt.

    A Python source is labelled by its module, a data file (:data:`DATA_SUFFIXES`) by its path; a
    dotfile, a cache and any other suffix are not the package's source.
    """

    out: list[tuple[str, Path]] = []
    for path in sorted(package.rglob("*")):
        relative = path.relative_to(package)
        if not path.is_file() or any(
            part.startswith(".") or part == "__pycache__" for part in relative.parts
        ):
            continue
        if path.suffix == ".py":
            module = _module_of(relative)
            if not _exempt(module):
                out.append((module, path))
            continue
        if path.suffix not in DATA_SUFFIXES:
            continue
        owner = _module_of(relative.parent / "__init__.py") if relative.parent.parts else ""
        if owner and _exempt(owner):
            continue
        out.append((relative.as_posix(), path))
    return out


def _scan(package: Path) -> tuple[str, dict[str, str]]:
    """``(digest, {label: short digest})`` over :func:`covered_files`."""

    files = covered_files(package)
    if not any(path.suffix == ".py" for _, path in files):
        raise JudgingCodeUnreadable(
            f"cannot read Il Dottore's own source files under {package} (a zip or a frozen "
            "install?): the code that judges a run cannot be recorded, so no run is started. "
            "Install the package from its files (pip install, or the source tree)."
        )
    digest = hashlib.sha256()
    each: dict[str, str] = {}
    for label, path in files:
        if path.suffix == ".py":
            content = normalized_source(path.read_text(encoding="utf-8")).encode("utf-8")
        else:
            content = path.read_bytes()
        digest.update(label.encode("utf-8") + b"\0" + content + b"\0")
        each[label] = hashlib.sha256(content).hexdigest()[:FILE_DIGEST_LENGTH]
    return digest.hexdigest(), each


def _digest(package: Path) -> str:
    return _scan(package)[0]


@cache
def _scanned(package: Path) -> tuple[str, dict[str, str]]:
    return _scan(package)


def judging_digest(package: Path = _PACKAGE) -> str:
    """The SHA-256 of the code that judges, computed from the installed package (deny by default).

    Taken once per process (the files do not change under a running scan): 0.35 to 0.38 s for the
    171 files of the package at landing on Python 3.12 and 3.14 (0.74 s on 3.9), the parse and the
    tokenizer being most of it; 0.355 s for the 264 files since u12 A-84 put the battery and the
    attack-spec schema in the package (3.14, best of five), data files being read, not parsed.
    """

    return _scanned(package)[0]


def judging_files(package: Path = _PACKAGE) -> dict[str, str]:
    """``{label: short digest}`` of each covered file, so a refusal can name what changed."""

    return dict(_scanned(package)[1])


def python_build() -> str:
    """The interpreter that judges, as a run records it: implementation and ``major.minor``.

    Compared by a resume: the standard library's ``re``, ``json`` and Unicode tables are part of
    how a reply is read, and they change between minor versions.
    """

    import platform
    import sys

    return f"{platform.python_implementation()} {sys.version_info[0]}.{sys.version_info[1]}"


#: The third-party packages whose versions a run records, not compares: the models, the HTTP and
#: the WebSocket clients a reply goes through.
RECORDED_DEPENDENCIES: Final = ("pydantic", "httpx", "websockets")


def dependency_versions() -> dict[str, str | None]:
    """``{distribution: version or None}`` of :data:`RECORDED_DEPENDENCIES`, for the record."""

    from importlib.metadata import PackageNotFoundError, version

    out: dict[str, str | None] = {}
    for name in RECORDED_DEPENDENCIES:
        try:
            out[name] = version(name)
        except PackageNotFoundError:
            out[name] = None
    return out
