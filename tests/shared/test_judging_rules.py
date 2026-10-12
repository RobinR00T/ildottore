"""The judging-rules version is bumped whenever the code that decides a stored verdict changes.

``shared.judging_rules.JUDGING_RULES_VERSION`` is what binds a resume to the rules that judged its
halted half (u12 A-81): a resume under other rules is refused, since the stored replies are
redacted and cannot be judged again. A version nobody bumps binds nothing, and that is the failure
this file is for: ``--version`` said ``0.1.0`` across OD-16, OD-19, OD-21, OD-41 and OD-42, five
changes to what a reply is judged as, and a run halted before them resumed after them into a
report that contradicted itself (CLI audit of 2026-10-11, H2).

The digest is over ``JUDGING_SOURCES`` with comments, docstrings and blank lines left out, so a
reworded comment needs nothing, while any change to the code fails here until the version is
bumped and the new digest pinned under it.
"""

from __future__ import annotations

import ast
import hashlib
import io
import textwrap
import tokenize
from pathlib import Path

import pytest

from ildottore.shared import judging_rules
from ildottore.shared.judging_rules import JUDGING_RULES_VERSION, JUDGING_SOURCES

#: The digest of ``JUDGING_SOURCES`` each version was pinned for. A history, appended to and never
#: edited: when the code changes, bump ``JUDGING_RULES_VERSION`` and pin the new digest under it.
PINNED: dict[int, str] = {
    1: "cdf2cacd2d7f432c3fde978470a44cf87f3516e4d04aba0c2de1a75739b26bf4",
}


def _without_comments_and_docstrings(source: str) -> str:
    """``source`` with every comment, docstring and blank line removed, lines right-stripped.

    By ``tokenize`` and ``ast`` positions rather than by an ``ast.dump``, whose text differs between
    the Python versions CI and a laptop run (3.11 and 3.14), so the pin holds on both.
    """

    source = textwrap.dedent(source)
    lines = source.splitlines()
    drop: set[int] = set()
    for node in ast.walk(ast.parse(source)):
        if isinstance(node, (ast.Module, ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)):
            body = node.body
            first = body[0] if body else None
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


_PACKAGE_ROOT = Path(__file__).resolve().parents[2] / "src"


def _module_files(name: str) -> list[tuple[str, Path]]:
    """``(module name, file)`` for ``name``, or for every module of it when it is a package.

    Found by path, not by import, so the digest reads the files as written and can be taken by a
    bare interpreter of any version (the pin was checked on 3.12 and 3.14; CI runs 3.11).
    """

    base = _PACKAGE_ROOT.joinpath(*name.split("."))
    if base.is_dir():
        return [
            (".".join(path.relative_to(_PACKAGE_ROOT).with_suffix("").parts), path)
            for path in sorted(base.rglob("*.py"))
        ]
    return [(name, base.with_suffix(".py"))]


def _function_source(path: Path, qualname: str) -> str:
    source = path.read_text(encoding="utf-8")
    scope: list[ast.stmt] = ast.parse(source).body
    node: ast.AST | None = None
    for part in qualname.split("."):
        node = next(
            (
                child
                for child in scope
                if isinstance(child, (ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef))
                and child.name == part
            ),
            None,
        )
        assert node is not None, f"{qualname} is not defined in {path}"
        scope = node.body  # type: ignore[attr-defined]
    segment = ast.get_source_segment(source, node)  # type: ignore[arg-type]
    assert segment is not None
    return segment


def _sources() -> list[tuple[str, str]]:
    """``(label, normalized source)`` for every entry of ``JUDGING_SOURCES``, in order."""

    out: list[tuple[str, str]] = []
    for entry in JUDGING_SOURCES:
        if ":" in entry:
            module_name, qualname = entry.split(":", 1)
            ((_, path),) = _module_files(module_name)
            out.append((entry, _without_comments_and_docstrings(_function_source(path, qualname))))
        else:
            for module_name, path in _module_files(entry):
                text = path.read_text(encoding="utf-8")
                out.append((module_name, _without_comments_and_docstrings(text)))
    return out


def judging_code_digest() -> str:
    digest = hashlib.sha256()
    for label, source in _sources():
        digest.update(label.encode("utf-8") + b"\0" + source.encode("utf-8") + b"\0")
    return digest.hexdigest()


def test_the_judging_code_is_the_code_its_version_was_pinned_for() -> None:
    current = judging_code_digest()
    pinned = PINNED.get(JUDGING_RULES_VERSION)
    assert pinned == current, (
        "the code that decides a stored verdict (shared.judging_rules.JUDGING_SOURCES) is not the "
        f"code JUDGING_RULES_VERSION {JUDGING_RULES_VERSION} was pinned for. If this change can "
        "alter the verdict stored for any attempt, bump JUDGING_RULES_VERSION to "
        f"{JUDGING_RULES_VERSION + 1} (and JUDGING_RULES_SINCE) and pin {current!r} under it in "
        "PINNED; a run halted on the old rules is then refused by a resume, as it must be. Never "
        "edit an existing pin: a version names one set of rules (u12 A-81)."
    )


def test_the_pins_are_a_history_that_ends_at_the_current_version() -> None:
    """No bump without a pin, no pin without a bump, and no version skipped or reused."""

    assert sorted(PINNED) == list(range(1, JUDGING_RULES_VERSION + 1))
    assert len(set(PINNED.values())) == len(PINNED), "two versions pinned to the same code"


def test_every_judging_source_resolves() -> None:
    labels = [label for label, _ in _sources()]
    assert "ildottore.evaluators.semantic_judge" in labels, "the package is walked, not listed"
    assert all(source for _, source in _sources())


def test_a_comment_or_a_docstring_is_not_a_change_and_a_token_is() -> None:
    base = 'def f(x):\n    """Doc."""\n    return x + 1  # one\n'
    commented = (
        'def f(x):\n    """Another doc,\n    on two lines."""\n\n    # a note\n    return x + 1\n'
    )
    changed = 'def f(x):\n    """Doc."""\n    return x + 2\n'
    assert _without_comments_and_docstrings(base) == _without_comments_and_docstrings(commented)
    assert _without_comments_and_docstrings(base) != _without_comments_and_docstrings(changed)
    # A string that is not a docstring is code, and a `#` inside a string is not a comment.
    assert "'#'" in _without_comments_and_docstrings("def g():\n    return '#'\n")


@pytest.mark.parametrize(
    "name", ["JUDGING_RULES_VERSION", "JUDGING_RULES_SINCE", "JUDGING_SOURCES"]
)
def test_the_module_exports_what_it_documents(name: str) -> None:
    assert name in judging_rules.__all__
