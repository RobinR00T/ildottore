"""The judging-rules version is bumped whenever the code that decides a stored verdict changes.

``shared.judging_rules.JUDGING_RULES_VERSION`` is what binds a resume to the rules that judged its
halted half (u12 A-81): a resume under other rules is refused, since the stored replies are
redacted and cannot be judged again. A version nobody bumps binds nothing, and that is the failure
this file is for: ``--version`` said ``0.1.0`` across OD-16, OD-19, OD-21, OD-41 and OD-42, five
changes to what a reply is judged as, and a run halted before them resumed after them into a
report that contradicted itself (CLI audit of 2026-10-11, H2).

Three checks. The digest is over ``JUDGING_SOURCES`` with comments, docstrings and blank lines left
out, so a reworded comment needs nothing, while any change to the code fails until the version is
bumped and the new digest pinned under it. The closure walks what each listed entry refers to, so
a name on the verdict path that is neither listed nor exempted fails: the first list missed four
one-line edits that each changed a verdict (pre-merge audit of ``22269e0c``, H-1: a constant of the
runner, a line of ``execute_attempt``, a constant of ``setup_delivery`` and the redactor's date
test the PII evaluator imports). And the pins are an append-only history.

Stdlib only and by path, never by import, so the digest can be taken by a bare interpreter of any
version (checked equal on 3.9, 3.12 and 3.14; CI runs 3.11).
"""

from __future__ import annotations

import ast
import hashlib
import io
import textwrap
import tokenize
from functools import cache
from pathlib import Path

import pytest

from ildottore.shared import judging_rules
from ildottore.shared.judging_rules import (
    JUDGING_EXEMPT,
    JUDGING_RULES_VERSION,
    JUDGING_SOURCES,
)

#: Every pin ever made, in order: ``(version, digest, reason)``. Append-only: a line is never
#: edited or removed. A new version is a new line; a version is re-pinned only by a new line whose
#: reason says ``re-pin`` and why (the landing re-pin on the final tree, or a change that cannot
#: alter a stored verdict), so changing a pin is an explicit edit a reviewer reads.
PIN_HISTORY: tuple[tuple[int, str, str], ...] = (
    (
        1,
        "cdf2cacd2d7f432c3fde978470a44cf87f3516e4d04aba0c2de1a75739b26bf4",
        "2026-10-12: the first list (evaluators, eight shared modules, twenty runner and execute "
        "functions)",
    ),
    (
        1,
        "c4627211d80fdf0913d74546006e89494d2e1a73fb50a60527512cdb3c345710",
        "re-pin 2026-10-12: the list the closure test requires (pre-merge audit of 22269e0c, H-1); "
        "version 1 is not released",
    ),
)

#: The digest each version is pinned to now: the last line of :data:`PIN_HISTORY` for it.
PINNED: dict[int, str] = {
    1: "c4627211d80fdf0913d74546006e89494d2e1a73fb50a60527512cdb3c345710",
}

_PACKAGE_ROOT = Path(__file__).resolve().parents[2] / "src"


# --- the digest -------------------------------------------------------------------------------


def _without_comments_and_docstrings(source: str) -> str:
    """``source`` with every comment, docstring and blank line removed, lines right-stripped.

    By ``tokenize`` and ``ast`` positions rather than by an ``ast.dump``, whose text differs between
    Python versions, so the pin holds on all of them.
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


def _module_file(name: str) -> Path | None:
    base = _PACKAGE_ROOT.joinpath(*name.split("."))
    if (base / "__init__.py").is_file():
        return base / "__init__.py"
    return base.with_suffix(".py") if base.with_suffix(".py").is_file() else None


def _module_files(name: str) -> list[tuple[str, Path]]:
    """``(module name, file)`` for ``name``, or for every module of it when it is a package."""

    base = _PACKAGE_ROOT.joinpath(*name.split("."))
    if base.is_dir():
        return [
            (".".join(path.relative_to(_PACKAGE_ROOT).with_suffix("").parts), path)
            for path in sorted(base.rglob("*.py"))
        ]
    return [(name, base.with_suffix(".py"))]


@cache
def _parsed(module: str) -> tuple[str, ast.Module]:
    path = _module_file(module)
    assert path is not None, f"{module} is not a module of the package"
    source = path.read_text(encoding="utf-8")
    return source, ast.parse(source)


def _top(statements: list[ast.stmt]) -> list[ast.stmt]:
    """A body's statements, with those under a top-level ``if`` or ``try`` (TYPE_CHECKING)."""

    out: list[ast.stmt] = []
    pending = list(statements)
    while pending:
        statement = pending.pop(0)
        out.append(statement)
        if isinstance(statement, ast.If):
            pending[0:0] = statement.body + statement.orelse
        elif isinstance(statement, ast.Try):
            pending[0:0] = (
                statement.body + [s for h in statement.handlers for s in h.body] + statement.orelse
            )
    return out


def _binds(statement: ast.stmt, name: str) -> bool:
    if isinstance(statement, (ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)):
        return statement.name == name
    if isinstance(statement, ast.Assign):
        return any(isinstance(t, ast.Name) and t.id == name for t in statement.targets)
    if isinstance(statement, ast.AnnAssign):
        return isinstance(statement.target, ast.Name) and statement.target.id == name
    return False


def _entry_node(module: str, qualname: str) -> ast.stmt:
    """The function, class or assignment ``qualname`` names in ``module`` (a method: ``C.m``)."""

    scope = _top(_parsed(module)[1].body)
    node: ast.stmt | None = None
    for part in qualname.split("."):
        node = next((s for s in reversed(scope) if _binds(s, part)), None)
        assert node is not None, f"{module}:{qualname} is not defined"
        scope = getattr(node, "body", [])
    assert node is not None
    return node


def _function_source(path: Path, qualname: str) -> str:
    """The source of a function, class or module-level assignment of the module at ``path``."""

    module = ".".join(path.relative_to(_PACKAGE_ROOT).with_suffix("").parts)
    source, _ = _parsed(module.removesuffix(".__init__"))
    segment = ast.get_source_segment(
        source, _entry_node(module.removesuffix(".__init__"), qualname)
    )
    assert segment is not None
    return segment


def _sources() -> list[tuple[str, str]]:
    """``(label, normalized source)`` for every entry of ``JUDGING_SOURCES``, in order."""

    out: list[tuple[str, str]] = []
    for entry in JUDGING_SOURCES:
        if ":" in entry:
            module_name, qualname = entry.split(":", 1)
            path = _module_file(module_name)
            assert path is not None, entry
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


# --- the closure ------------------------------------------------------------------------------

#: A reference: ``(module, name)``, the name ``None`` for a module itself.
Ref = tuple[str, "str | None"]


def _absolute(module: str, level: int, target: str | None) -> str:
    if level == 0:
        return target or ""
    path = _module_file(module)
    package = (
        module if path is not None and path.name == "__init__.py" else module.rpartition(".")[0]
    )
    for _ in range(level - 1):
        package = package.rpartition(".")[0]
    return f"{package}.{target}" if target else package


@cache
def _bindings(module: str) -> dict[str, Ref]:
    """What each top-level name of ``module`` is: an import's source, or a definition here."""

    out: dict[str, Ref] = {}
    for statement in _top(_parsed(module)[1].body):
        if isinstance(statement, ast.ImportFrom):
            source = _absolute(module, statement.level, statement.module)
            for alias in statement.names:
                out[alias.asname or alias.name] = (source, alias.name)
        elif isinstance(statement, ast.Import):
            for alias in statement.names:
                head = alias.name.split(".")[0]
                out[alias.asname or head] = (alias.name if alias.asname else head, None)
        elif isinstance(statement, (ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)):
            out[statement.name] = (module, statement.name)
        elif isinstance(statement, ast.Assign):
            for target in statement.targets:
                if isinstance(target, ast.Name):
                    out[target.id] = (module, target.id)
        elif isinstance(statement, ast.AnnAssign) and isinstance(statement.target, ast.Name):
            out[statement.target.id] = (module, statement.target.id)
    return out


def _resolve(module: str, name: str | None, depth: int = 0) -> Ref:
    """Follow a re-export to where ``name`` is defined; a submodule is a module reference."""

    if name is None or not module.startswith("ildottore") or _module_file(module) is None:
        return module, name
    if _module_file(f"{module}.{name}") is not None:
        return f"{module}.{name}", None
    if depth > 10 or any(_binds(s, name) for s in _top(_parsed(module)[1].body)):
        return module, name
    bound = _bindings(module).get(name)
    if bound is not None and bound != (module, name):
        return _resolve(bound[0], bound[1], depth + 1)
    return module, name


def _walked(node: ast.AST) -> list[ast.AST]:
    """``node`` and what is under it, annotations left out: they decide nothing at run time."""

    out: list[ast.AST] = []
    pending = [node]
    while pending:
        item = pending.pop()
        out.append(item)
        for field, value in ast.iter_fields(item):
            if field in {"annotation", "returns"}:
                continue
            if isinstance(value, ast.AST):
                pending.append(value)
            elif isinstance(value, list):
                pending.extend(v for v in value if isinstance(v, ast.AST))
    return out


def _refers_to(module: str, node: ast.AST, owner: str | None) -> set[Ref]:
    """The ``ildottore`` names ``node`` refers to: imports, module names, ``self.<method>``."""

    bound = _bindings(module)
    methods = (
        {
            s.name
            for s in getattr(_entry_node(module, owner), "body", [])
            if isinstance(s, (ast.FunctionDef, ast.AsyncFunctionDef))
        }
        if owner is not None
        else set()
    )
    out: set[Ref] = set()
    for item in _walked(node):
        if isinstance(item, ast.ImportFrom):
            source = _absolute(module, item.level, item.module)
            out.update(_resolve(source, alias.name) for alias in item.names)
        elif isinstance(item, ast.Import):
            out.update((alias.name, None) for alias in item.names)
        elif isinstance(item, ast.Attribute) and isinstance(item.value, ast.Name):
            base = item.value.id
            if base in {"self", "cls"} and item.attr in methods:
                out.add((module, f"{owner}.{item.attr}"))
            elif base in bound:
                target = _resolve(*bound[base])
                if target[1] is None:
                    out.add(_resolve(target[0], item.attr))
        elif isinstance(item, ast.Name) and item.id in bound:
            out.add(_resolve(*bound[item.id]))
    return {ref for ref in out if ref[0].startswith("ildottore")}


def _refs_of(entry: str) -> set[Ref]:
    if ":" in entry:
        module, qualname = entry.split(":", 1)
        owner = qualname.split(".")[0] if "." in qualname else None
        return _refers_to(module, _entry_node(module, qualname), owner)
    out: set[Ref] = set()
    for module, _path in _module_files(entry):
        name = module.removesuffix(".__init__")
        for item in ast.walk(_parsed(name)[1]):
            if isinstance(item, ast.ImportFrom):
                source = _absolute(name, item.level, item.module)
                out.update(_resolve(source, alias.name) for alias in item.names)
            elif isinstance(item, ast.Import):
                out.update((alias.name, None) for alias in item.names)
    return {ref for ref in out if ref[0].startswith("ildottore")}


def _covered(ref: Ref, entries: set[str]) -> bool:
    module, name = ref
    if any(module == e or module.startswith(f"{e}.") for e in entries if ":" not in e):
        return True
    return name is not None and (
        f"{module}:{name}" in entries or f"{module}:{name.split('.')[0]}" in entries
    )


def uncovered() -> dict[str, list[str]]:
    """Each name a listed entry refers to that is neither listed nor exempt, with who refers."""

    entries = set(JUDGING_SOURCES) | set(JUDGING_EXEMPT)
    out: dict[str, list[str]] = {}
    for entry in JUDGING_SOURCES:
        for ref in _refs_of(entry):
            if not _covered(ref, entries):
                key = f"{ref[0]}:{ref[1]}" if ref[1] is not None else ref[0]
                out.setdefault(key, []).append(entry)
    return out


# --- the tests --------------------------------------------------------------------------------


def test_the_judging_code_is_the_code_its_version_was_pinned_for() -> None:
    current = judging_code_digest()
    pinned = PINNED.get(JUDGING_RULES_VERSION)
    assert pinned == current, (
        "the code that decides a stored verdict (shared.judging_rules.JUDGING_SOURCES) is not the "
        f"code JUDGING_RULES_VERSION {JUDGING_RULES_VERSION} was pinned for. If this change can "
        "alter the verdict stored for any attempt, bump JUDGING_RULES_VERSION to "
        f"{JUDGING_RULES_VERSION + 1} (and JUDGING_RULES_SINCE), append "
        f"({JUDGING_RULES_VERSION + 1}, {current!r}, '<why>') to PIN_HISTORY and pin it in "
        "PINNED; a run halted on the old rules is then refused by a resume, as it must be. A "
        "re-pin of the same version is a new "
        "PIN_HISTORY line whose reason says 're-pin' and why the change cannot alter a verdict; "
        "never edit an existing line (u12 A-81)."
    )


def test_the_pins_are_an_append_only_history_that_ends_at_the_current_version() -> None:
    """No bump without a pin, no pin without a history line, no line without a reason."""

    versions = [version for version, _, _ in PIN_HISTORY]
    assert versions == sorted(versions), "the history is in order"
    assert sorted(set(versions)) == list(range(1, JUDGING_RULES_VERSION + 1))
    assert sorted(PINNED) == list(range(1, JUDGING_RULES_VERSION + 1))
    last = {version: digest for version, digest, _ in PIN_HISTORY}
    assert last == PINNED, (
        "a pin differs from the last PIN_HISTORY line for its version: a pin is changed only by "
        "appending a line with its reason"
    )
    seen: set[int] = set()
    for version, digest, reason in PIN_HISTORY:
        assert reason.strip(), f"version {version}'s line gives no reason"
        assert len(digest) == 64, f"version {version}'s line holds no digest"
        if version in seen:
            assert "re-pin" in reason, f"a second line for version {version} must say re-pin"
        seen.add(version)
    owners: dict[str, int] = {}
    for version, digest, _ in PIN_HISTORY:
        assert owners.setdefault(digest, version) == version, "one code pinned to two versions"


def test_every_name_a_listed_entry_refers_to_is_listed_or_exempt() -> None:
    """The closure: a name on the verdict path cannot be left out of the digest unseen.

    The first list held the runner's ``_cut_verdict`` and not the ``CUT_DECIDING_EVALUATORS`` it
    reads, the evaluators package and not the redactor's ``is_date_stamp`` the PII evaluator
    imports; an edit to either changed verdicts under an unchanged digest (H-1).
    """

    missing = uncovered()
    assert not missing, (
        "names on the verdict path that shared.judging_rules neither lists in JUDGING_SOURCES nor "
        "exempts in JUDGING_EXEMPT (with its reason): "
        + "; ".join(
            f"{name} (from {', '.join(sorted(refs)[:2])})" for name, refs in sorted(missing.items())
        )
    )


def test_every_entry_resolves_and_none_is_both_listed_and_exempt() -> None:
    labels = [label for label, _ in _sources()]
    assert "ildottore.evaluators.semantic_judge" in labels, "the package is walked, not listed"
    assert all(source for _, source in _sources())
    assert len(set(JUDGING_SOURCES)) == len(JUDGING_SOURCES), "an entry listed twice"
    assert not set(JUDGING_SOURCES) & set(JUDGING_EXEMPT)
    for entry, reason in JUDGING_EXEMPT.items():
        assert reason.strip(), f"{entry} is exempt with no reason"
        module, _, qualname = entry.partition(":")
        assert _module_file(module) is not None, entry
        if qualname:
            _entry_node(module, qualname)


@pytest.mark.parametrize(
    ("source", "edited"),
    [
        # A module-level constant a listed function reads (mut-a, H-1).
        ("CUT = {1, 2}\n", "CUT = {1}\n"),
        # A line inside a listed function (mut-c).
        ("def f(side):\n    return side if side else None\n", "def f(side):\n    return None\n"),
    ],
)
def test_an_edit_to_a_listed_assignment_or_function_changes_its_source(
    source: str, edited: str
) -> None:
    assert _without_comments_and_docstrings(source) != _without_comments_and_docstrings(edited)


def test_an_assignment_can_be_listed() -> None:
    path = _module_file("ildottore.core.runner")
    assert path is not None
    assert "CUT_DECIDING_EVALUATORS" in _function_source(path, "CUT_DECIDING_EVALUATORS")
    assert ("ildottore.core.runner", "CUT_DECIDING_EVALUATORS") in _refs_of(
        "ildottore.core.runner:CampaignRunner._cut_verdict"
    )
    assert ("ildottore.redactor", "is_date_stamp") in _refs_of("ildottore.evaluators")


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
    "name", ["JUDGING_EXEMPT", "JUDGING_RULES_SINCE", "JUDGING_RULES_VERSION", "JUDGING_SOURCES"]
)
def test_the_module_exports_what_it_documents(name: str) -> None:
    assert name in judging_rules.__all__
