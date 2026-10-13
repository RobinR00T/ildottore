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
  **every file of the package** but the few modules :data:`JUDGING_EXEMPT` names, Python sources
  with their comments, docstrings and blank lines left out (decorators kept), other files byte for
  byte. Deny by default: what is not exempted is covered, a subclass override, a default, a
  decorator, the offline judge and a new module included, with no list to keep up to date. A
  resume under any other digest is refused, whoever forgot what.
* :data:`JUDGING_RULES_VERSION`, the human name of those rules, which ``dottore --version`` prints
  and a refusal quotes. ``tests/shared/test_judging_rules.py`` pins the digest of each version, so
  a change to covered code fails it until the version is bumped (with a CHANGELOG line) or the
  same version is re-pinned with a reason, in an append-only history.

The first design listed the verdict code instead (an allow-list with a reference walk): two
audits found verdict code it did not reach (a default of the REST template, a subclass's override,
the offline judge, a decorator), so the default was inverted under the owner's delegation (best
practice, 2026-10-13).

**Landing.** Version ``1`` is the rules as of the merge that introduced the version. At the merge
the pin is re-pinned on the final tree and :data:`JUDGING_RULES_SINCE` set to the merge day, the
one place the docs name for that date.
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
    "JUDGING_EXEMPT",
    "JUDGING_RULES_SINCE",
    "JUDGING_RULES_VERSION",
    "covered_files",
    "judging_digest",
    "normalized_source",
]

#: Bumped by one whenever a change can alter the verdict stored for an attempt. ``1``: the rules as
#: of the merge that introduced the version, the first that records it (OD-16, OD-19, OD-21, OD-38,
#: OD-40, OD-41, OD-42 and OD-43 in force).
JUDGING_RULES_VERSION: Final = 1

#: The day :data:`JUDGING_RULES_VERSION` took its value, which a refusal quotes and the docs name
#: (as ``JUDGING_RULES_SINCE``) instead of writing the date: set once, at the merge.
JUDGING_RULES_SINCE: Final = "2026-10-12"

#: The modules :func:`judging_digest` leaves out: each is presentation or input only and cannot
#: change the verdict stored for an attempt. A package name exempts every module under it. Two
#: kinds, which ``tests/shared/test_judging_rules.py`` checks: a command a run never imports (it is
#: outside the import closure of ``ildottore.cli.run``), or a renderer a run imports only to show
#: what it already decided (imported by ``cli.run`` and ``cli.wiring`` alone among covered modules).
JUDGING_EXEMPT: Final = {
    # Commands that never run a campaign, outside the run's import closure.
    "ildottore.cli.app": (
        "parses the command line into RunOptions and prints help and errors; what a run does with "
        "them is in cli.run and below"
    ),
    "ildottore.cli.main": "the console entry point, which calls cli.app",
    "ildottore.cli.calibrate": "the calibrate command, which reads reports a run wrote",
    "ildottore.cli.coverage": "the coverage command, which reads the specs and runs nothing",
    "ildottore.cli.describe": "the describe command, which prints one spec",
    "ildottore.cli.diff": "the diff command, which compares two reports",
    "ildottore.cli.fingerprint": (
        "the fingerprint command; the -sV pass a run makes goes through cli.wiring and the "
        "fingerprint package, which are covered"
    ),
    "ildottore.cli.fleet": (
        "expands a fleet file into target and scope files, whose content the target digest binds "
        "(u12 A-24); its --run calls cli.run"
    ),
    "ildottore.cli.lint": "the lint command",
    "ildottore.cli.new_spec": "the new-spec scaffolding command",
    "ildottore.cli.registry": "the registry ls command",
    "ildottore.cli.render_media": "the render-media command",
    "ildottore.cli.replay": "the replay command, which reads a stored run and judges nothing",
    "ildottore.testing": "the offline golden harness of the test suite",
    # Renderers a run imports to show what it already decided.
    "ildottore.reporting": (
        "renders the JSON, HTML, SARIF and JUnit reports from findings a run has scored; nothing "
        "a run stores is read back from it"
    ),
    "ildottore.cli.render": "prints a run's progress and summary on the terminal",
    "ildottore.cli.exit_codes": "maps a finished run's findings to the process exit code",
}

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

    A Python source is labelled by its module, any other file (a schema, a signature pack, the
    SQL schema) by its path; compiled files and caches are not the package's source.
    """

    out: list[tuple[str, Path]] = []
    for path in sorted(package.rglob("*")):
        if not path.is_file() or "__pycache__" in path.parts or path.suffix in {".pyc", ".pyo"}:
            continue
        relative = path.relative_to(package)
        if path.suffix == ".py":
            module = _module_of(relative)
            if _exempt(module):
                continue
            out.append((module, path))
            continue
        owner = _module_of(relative.parent / "__init__.py") if relative.parent.parts else ""
        if owner and _exempt(owner):
            continue
        out.append((relative.as_posix(), path))
    return out


def _digest(package: Path) -> str:
    digest = hashlib.sha256()
    for label, path in covered_files(package):
        if path.suffix == ".py":
            content = normalized_source(path.read_text(encoding="utf-8")).encode("utf-8")
        else:
            content = path.read_bytes()
        digest.update(label.encode("utf-8") + b"\0" + content + b"\0")
    return digest.hexdigest()


@cache
def judging_digest(package: Path = _PACKAGE) -> str:
    """The SHA-256 of the code that judges, computed from the installed package (deny by default).

    Taken once per process (the files do not change under a running scan): about 0.3 s for the
    161 modules of the package, the parse and the tokenizer being most of it.
    """

    return _digest(package)
