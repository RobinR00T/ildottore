"""The code that judges is bound to a run, and its version is bumped when it changes (u12 A-81).

``shared.judging_rules`` binds a resume to the rules that judged its halted half twice: the
version a person names (``JUDGING_RULES_VERSION``) and a digest computed at run time from the
installed package (``judging_digest``). The digest is deny by default: every file of the package is
in it but the test harness, the one module ``JUDGING_EXEMPT`` names, with its reason. It
replaced an allow-list of verdict code with a reference walk, which two audits found blind to code
that decides verdicts: the CLI audit's H2 (a run halted before five changes to the rules resumed
after them into a report that contradicted itself), then four one-line edits the first list missed
(pre-merge audit of ``22269e0c``), then a default of the REST template, a subclass's override, the
offline judge and a decorator (second audit of ``6de5780b``).

What is checked here: the digest of the current code is the one pinned to its version (a change to
covered code fails until the version is bumped, or re-pinned with a reason); the pins are an
append-only history, which a frozen record of them keeps from being edited in place; each
exemption is presentation or input only by a test, not by a word; and the normalization keeps code
and drops comments and docstrings, the same on every Python version (checked equal on 3.9, 3.12
and 3.14; CI runs 3.11).
"""

from __future__ import annotations

import ast
import shutil
import time
from pathlib import Path

import pytest

from ildottore.shared import judging_rules
from ildottore.shared.judging_rules import (
    JUDGING_EXEMPT,
    JUDGING_RULES_VERSION,
    covered_files,
    judging_digest,
    normalized_source,
)

#: Every pin ever made, in order: ``(version, digest, reason)``. Append-only: a line is never edited
#: or removed, which ``judging_pins.frozen`` beside this file enforces. A new version is a new
#: line; a version is re-pinned only by a new line whose reason says ``re-pin`` and why (the
#: landing re-pin on the final tree, or a change that cannot alter a stored verdict). One line was
#: replaced instead, once: the provisional pin of 2026-10-14 (``b644c56b``, the tree merged with
#: main before the last branch landed), which never reached ``main``, by the landing pin, here and
#: in the frozen file at the same place, while version 1 was unreleased.
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
    (
        1,
        "c0c0f23b83a4e2c063d31f660a841a976cfdb9b049155a4b0d67085dd5370919",
        "re-pin 2026-10-12: the runner's _run_spec, _sweep_identities and the reproduction "
        "functions they call, which the scoring branch's audit named, and the class attributes "
        "the walk follows now (sends_sampling, logprobs_enabled, max_frame_bytes); version 1 is "
        "not released",
    ),
    (
        1,
        "d22739274adb405de5ca37f206962771e042b36ed426809968c914ffa990a809",
        "re-pin 2026-10-13: deny by default, the whole package but JUDGING_EXEMPT (second audit of "
        "6de5780b); version 1 is not released",
    ),
    (
        1,
        "094105ecb30f4edb5fc32504951510538dd590f151679b42ec64201f9e0c56a5",
        "re-pin 2026-10-13: the renderers, commands, cli.app and cli.main covered, data files by "
        "suffix only (third audit of 1d3d65c7); version 1 is not released",
    ),
    (
        1,
        "308311955bfec13158d1aff961d977e13dd4e1556ec9ebc091eab702791494c9",
        "re-pin 2026-10-15: the rules as of the merge that introduced the version, on main at "
        "a906cea9 (#111 to #116); replaces the provisional pin of 2026-10-14; version 1 is not "
        "released",
    ),
    (
        1,
        "dbfbedd793b731ab385a0c2bae7e9bc9e85c795a1230eeaf0814c83038335d0c",
        "re-pin 2026-10-15: help and docstring text only (cli.app's --help texts and docstrings, "
        "a docstring of cli.run), from docs/audit-2026-10-12 stacked on e92a7541; no verdict can "
        "change; version 1 is not released",
    ),
    (
        2,
        "69d8b855dc421934ba2d003d32f28900e837700ce6eca9379804425f48bd268e",
        "2026-10-16: u08 A-85 (fix/scoring-followups on 7d01521f): a crossing of a canary the "
        "identity sweep's request carries is needs-review, a sweep's crossing counts once, "
        "secret_shape reads the redactor's key formats; the stacked landing re-pins it",
    ),
)

#: The digest each version is pinned to now: the last line of :data:`PIN_HISTORY` for it.
PINNED: dict[int, str] = {
    1: "dbfbedd793b731ab385a0c2bae7e9bc9e85c795a1230eeaf0814c83038335d0c",
    2: "69d8b855dc421934ba2d003d32f28900e837700ce6eca9379804425f48bd268e",
}

#: One ``<version> <digest>`` line per pin, appended to and never edited: the history must start
#: with these lines, and may hold at most one more (the pin being made, frozen when it is
#: committed). An edit in place of a pin, its line and ``PINNED`` together, fails here.
FROZEN = Path(__file__).with_name("judging_pins.frozen")

_SRC = Path(judging_rules.__file__).resolve().parents[2]


# --- the import graph, for the exemptions ----------------------------------------------------


def _module_file(name: str) -> Path | None:
    base = _SRC.joinpath(*name.split("."))
    if (base / "__init__.py").is_file():
        return base / "__init__.py"
    return base.with_suffix(".py") if base.with_suffix(".py").is_file() else None


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


def _imports(module: str) -> set[str]:
    """The ``ildottore`` modules ``module`` imports, anywhere in it, with their parents."""

    path = _module_file(module)
    assert path is not None, module
    found: set[str] = set()
    for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
        if isinstance(node, ast.ImportFrom):
            source = _absolute(module, node.level, node.module)
            if source.startswith("ildottore"):
                found.add(source)
                found.update(
                    f"{source}.{a.name}" for a in node.names if _module_file(f"{source}.{a.name}")
                )
        elif isinstance(node, ast.Import):
            found.update(a.name for a in node.names if a.name.startswith("ildottore"))
    out: set[str] = set()
    for name in found:
        parts = name.split(".")
        out.update(
            ".".join(parts[:i])
            for i in range(1, len(parts) + 1)
            if _module_file(".".join(parts[:i]))
        )
    return out


def _closure(start: str) -> set[str]:
    seen: set[str] = set()
    pending = [start]
    while pending:
        module = pending.pop()
        if module in seen or _module_file(module) is None:
            continue
        seen.add(module)
        pending.extend(_imports(module))
    return seen


def _all_modules() -> list[str]:
    return sorted(
        ".".join(p.relative_to(_SRC).with_suffix("").parts).removesuffix(".__init__")
        for p in (_SRC / "ildottore").rglob("*.py")
    )


def _under(module: str, name: str) -> bool:
    return module == name or module.startswith(f"{name}.")


# --- the pin -----------------------------------------------------------------------------------


def test_the_judging_code_is_the_code_its_version_was_pinned_for() -> None:
    current = judging_digest()
    pinned = PINNED.get(JUDGING_RULES_VERSION)
    assert pinned == current, (
        "the code that judges (shared.judging_rules.judging_digest: the whole package but "
        f"JUDGING_EXEMPT) is not the code JUDGING_RULES_VERSION {JUDGING_RULES_VERSION} was "
        "pinned for. If this change can alter the verdict stored for an attempt, bump "
        f"JUDGING_RULES_VERSION to {JUDGING_RULES_VERSION + 1} (and JUDGING_RULES_SINCE), write "
        f"its CHANGELOG line and append ({JUDGING_RULES_VERSION + 1}, {current!r}, '<why>') to "
        "PIN_HISTORY, judging_pins.frozen and PINNED. If it cannot (a message, a refactor), "
        f"append ({JUDGING_RULES_VERSION}, {current!r}, 're-pin <date>: <why>') instead. Never "
        "edit an existing line. A run halted on other code is refused by its resume either way, "
        "by the digest it recorded (u12 A-81)."
    )


def test_the_pins_are_an_append_only_history_that_ends_at_the_current_version() -> None:
    """No bump without a pin, no pin without a line, no line without a reason or edited."""

    versions = [version for version, _, _ in PIN_HISTORY]
    assert versions == sorted(versions), "the history is in order"
    assert sorted(set(versions)) == list(range(1, JUDGING_RULES_VERSION + 1))
    assert sorted(PINNED) == list(range(1, JUDGING_RULES_VERSION + 1))
    last = {version: digest for version, digest, _ in PIN_HISTORY}
    assert last == PINNED, "a pin differs from the last PIN_HISTORY line for its version"
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


def test_the_history_starts_with_the_frozen_pins_so_none_is_edited_in_place() -> None:
    """The second audit edited the last line's digest and PINNED together, and passed: the
    frozen record is a third place, never edited, that such an edit does not match."""

    frozen = [
        (int(version), digest)
        for version, digest in (line.split() for line in FROZEN.read_text().splitlines() if line)
    ]
    history = [(version, digest) for version, digest, _ in PIN_HISTORY]
    assert history[: len(frozen)] == frozen, (
        "a pin of PIN_HISTORY differs from judging_pins.frozen: a pin is never edited; append a "
        "new line to both instead"
    )
    assert len(history) - len(frozen) <= 1, "freeze each pin in judging_pins.frozen"


# --- what the digest covers ------------------------------------------------------------------


def test_every_exemption_names_a_module_and_gives_its_reason() -> None:
    for name, reason in JUDGING_EXEMPT.items():
        assert reason.strip(), f"{name} is exempt with no reason"
        assert _module_file(name) is not None, f"{name} is not a module of the package"


#: The functions of the standard library that import a module named by a string.
_DYNAMIC_IMPORTS = frozenset({"import_module", "__import__"})


def test_no_part_of_a_run_can_import_an_exempt_module() -> None:
    """An exemption is checked, not taken on its word. A module the ``dottore`` entry point loads
    runs its top-level code in the process of every run, so an exempt one must be outside the
    import closure of ``ildottore.cli.main`` (the third audit: an exempt renderer emptied
    ``FILTER_STOPS`` at import time and a resume mixed verdicts)."""

    loaded = _closure("ildottore.cli.main")
    for name in JUDGING_EXEMPT:
        inside = sorted(m for m in loaded if _under(m, name))
        assert not inside, (
            f"{name} is exempt and the dottore entry point imports {inside}: cover it (it runs in "
            "every run's process)"
        )


def test_no_covered_code_imports_an_exempt_module_by_name() -> None:
    """A dynamic import is outside the static closure (the third audit's dyn-x reached an exempt
    command's constant through ``importlib.import_module``). One that names an ``ildottore``
    module must name a covered one, by a literal string; an argument that is not a literal is
    allowed only where no literal of its function names an ``ildottore`` module."""

    covered = {label for label, _ in covered_files()}
    for module in _all_modules():
        if module not in covered:
            continue
        path = _module_file(module)
        assert path is not None
        tree = ast.parse(path.read_text(encoding="utf-8"))
        scopes: list[ast.AST] = [tree] + [
            n for n in ast.walk(tree) if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))
        ]
        for scope in scopes:
            literals = [
                n.value
                for n in ast.walk(scope)
                if isinstance(n, ast.Constant) and isinstance(n.value, str)
            ]
            for call in (n for n in ast.walk(scope) if isinstance(n, ast.Call)):
                func = call.func
                called = func.attr if isinstance(func, ast.Attribute) else getattr(func, "id", "")
                if called not in _DYNAMIC_IMPORTS or not call.args:
                    continue
                first = call.args[0]
                if isinstance(first, ast.Constant) and isinstance(first.value, str):
                    assert not any(_under(first.value, n) for n in JUDGING_EXEMPT), (
                        f"{module} imports the exempt module {first.value} by name"
                    )
                else:
                    assert not any(v.startswith("ildottore") for v in literals), (
                        f"{module} imports a module by a computed name beside a literal naming an "
                        "ildottore module: cover what it can reach, or import it statically"
                    )


def test_every_other_file_of_the_package_is_covered() -> None:
    labels = {label for label, _ in covered_files()}
    for module in _all_modules():
        if not any(_under(module, name) for name in JUDGING_EXEMPT):
            assert module in labels, f"{module} is neither covered nor exempt"
    assert {
        "store/schema.sql",
        "fingerprint/signatures/pack.yaml",
        "reporting/schemas/report-1.0.schema.json",
        "reporting/templates/report.html.j2",
        "ildottore.reporting.json_reporter",
        "ildottore.cli.render",
        "ildottore.cli.app",
    } <= labels
    assert not any(label.startswith("ildottore.testing") for label in labels)


def test_only_the_suffixes_the_package_reads_are_data() -> None:
    """Every non-Python file of the package has a suffix of DATA_SUFFIXES, so none it reads is
    left out; a stray file (the third audit's evaluators/.DS_Store) is not one of them."""

    package = Path(judging_rules.__file__).resolve().parents[1]
    for path in package.rglob("*"):
        relative = path.relative_to(package)
        if (
            path.is_file()
            and path.suffix not in {".py", ".pyc"}
            and not any(part.startswith(".") or part == "__pycache__" for part in relative.parts)
        ):
            assert path.suffix in judging_rules.DATA_SUFFIXES, f"{relative} is read? classify it"


def _package_copy(tmp_path: Path) -> Path:
    copy = tmp_path / "ildottore"
    shutil.copytree(
        Path(judging_rules.__file__).resolve().parents[1],
        copy,
        ignore=shutil.ignore_patterns("__pycache__"),
    )
    return copy


@pytest.mark.parametrize(
    ("relative", "old", "new"),
    [
        # The second audit's HIGH 1: a default of the REST template no target file carries.
        (
            "adapters/rest.py",
            "    finish_path: str | None = None",
            '    finish_path: str | None = "finish_reason"',
        ),
        # The offline judge (its mut-g2).
        ("cli/wiring.py", 'verdict = "exploited"', 'verdict = "secure"'),
        # A decorator (its mut-h).
        ("adapters/rest.py", "    @property\n    def reads_array_body", "    def reads_array_body"),
        # The first audit's mut-a: a constant the runner reads.
        (
            "core/runner.py",
            "        EvaluatorType.REFUSAL,\n        EvaluatorType.SECRET_LEAKAGE,",
            "        EvaluatorType.SECRET_LEAKAGE,",
        ),
        # A data file.
        ("store/schema.sql", "CREATE TABLE", "CREATE  TABLE"),
    ],
)
def test_a_change_to_covered_code_changes_the_digest(
    tmp_path: Path, relative: str, old: str, new: str
) -> None:
    copy = _package_copy(tmp_path)
    before = judging_rules._digest(copy)
    target = copy / relative
    text = target.read_text(encoding="utf-8")
    assert old in text, (relative, old)
    target.write_text(text.replace(old, new, 1), encoding="utf-8")
    assert judging_rules._digest(copy) != before


def test_a_comment_a_docstring_or_a_stray_file_is_not_a_change(tmp_path: Path) -> None:
    copy = _package_copy(tmp_path)
    before = judging_rules._digest(copy)
    runner = copy / "core" / "runner.py"
    runner.write_text(runner.read_text(encoding="utf-8") + "\n# a note, and nothing else\n")
    (copy / "evaluators" / ".DS_Store").write_bytes(b"\x00\x01 Finder")
    (copy / "evaluators" / "notes.txt").write_text("nothing the package reads")
    (copy / "testing" / "golden.py").write_text("X = 1\n")
    assert judging_rules._digest(copy) == before


def test_a_side_effect_in_a_renderer_changes_the_digest(tmp_path: Path) -> None:
    """The third audit's mut-sidefx2, which an exemption of the renderer let through."""

    copy = _package_copy(tmp_path)
    before = judging_rules._digest(copy)
    render = copy / "cli" / "render.py"
    render.write_text(
        render.read_text(encoding="utf-8")
        + "\nimport ildottore.shared.provider_filter as _pf\n\n_pf.FILTER_STOPS = frozenset()\n"
    )
    assert judging_rules._digest(copy) != before


def test_a_package_with_no_source_is_refused_not_digested(tmp_path: Path) -> None:
    """A zip or frozen install has no file under the package directory: a digest of nothing would
    pass every resume (third audit, LOW). It is refused, a ValueError, which the CLI exits 3 on."""

    empty = tmp_path / "ildottore"
    empty.mkdir()
    (empty / "data.yaml").write_text("x: 1\n")
    with pytest.raises(judging_rules.JudgingCodeUnreadable, match="cannot read Il Dottore's own"):
        judging_rules._digest(empty)
    assert issubclass(judging_rules.JudgingCodeUnreadable, ValueError)


def test_each_covered_file_has_a_short_digest_for_the_refusal(tmp_path: Path) -> None:
    files = judging_rules.judging_files()
    assert set(files) == {label for label, _ in covered_files()}
    assert all(len(d) == judging_rules.FILE_DIGEST_LENGTH for d in files.values())
    copy = _package_copy(tmp_path)
    _, before = judging_rules._scan(copy)
    rest = copy / "adapters" / "rest.py"
    text = rest.read_text(encoding="utf-8")
    rest.write_text(
        text.replace("finish_path: str | None = None", 'finish_path: str | None = "x"', 1)
    )
    _, after = judging_rules._scan(copy)
    assert [k for k in before if before[k] != after[k]] == ["ildottore.adapters.rest"]


def test_the_digest_costs_well_under_a_second() -> None:
    """Taken once per process, at run start and by a resume: 0.35 to 0.38 s measured for the 171
    files at landing."""

    started = time.perf_counter()
    judging_rules._digest(Path(judging_rules.__file__).resolve().parents[1])
    assert time.perf_counter() - started < 3.0, "a regression past the measured 0.38 s"


def test_a_comment_or_a_docstring_is_not_a_change_and_a_token_or_a_decorator_is() -> None:
    base = 'def f(x):\n    """Doc."""\n    return x + 1  # one\n'
    commented = (
        'def f(x):\n    """Another doc,\n    on two lines."""\n\n    # a note\n    return x + 1\n'
    )
    changed = 'def f(x):\n    """Doc."""\n    return x + 2\n'
    assert normalized_source(base) == normalized_source(commented)
    assert normalized_source(base) != normalized_source(changed)
    assert "@property" in normalized_source(
        "class A:\n    @property\n    def p(self):\n        return 1\n"
    )
    # A string that is not a docstring is code, and a `#` inside a string is not a comment.
    assert "'#'" in normalized_source("def g():\n    return '#'\n")


@pytest.mark.parametrize(
    "name",
    [
        "JUDGING_EXEMPT",
        "JUDGING_RULES_SINCE",
        "JUDGING_RULES_VERSION",
        "covered_files",
        "judging_digest",
    ],
)
def test_the_module_exports_what_it_documents(name: str) -> None:
    assert name in judging_rules.__all__
