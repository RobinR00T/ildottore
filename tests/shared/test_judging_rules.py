"""The code that judges is bound to a run, and its version is bumped when it changes (u12 A-81).

``shared.judging_rules`` binds a resume to the rules that judged its halted half twice: the
version a person names (``JUDGING_RULES_VERSION``) and a digest computed at run time from the
installed package (``judging_digest``). The digest is deny by default: every file of the package is
in it but the few presentation and input modules ``JUDGING_EXEMPT`` names, each with its reason. It
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
#: landing re-pin on the final tree, or a change that cannot alter a stored verdict).
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
)

#: The digest each version is pinned to now: the last line of :data:`PIN_HISTORY` for it.
PINNED: dict[int, str] = {
    1: "d22739274adb405de5ca37f206962771e042b36ed426809968c914ffa990a809",
}

#: One ``<version> <digest>`` line per pin, appended to and never edited: the history must start
#: with these lines, and may hold at most one more (the pin being made, frozen when it is
#: committed). An edit in place of a pin, its line and ``PINNED`` together, fails here.
FROZEN = Path(__file__).with_name("judging_pins.frozen")

#: The renderers a run imports to show what it already decided: the only exemptions allowed inside
#: the run's import closure, and only ``cli.run`` and ``cli.wiring`` among covered modules may
#: import them.
PRESENTATION = frozenset(
    {"ildottore.reporting", "ildottore.cli.render", "ildottore.cli.exit_codes"}
)
_PRESENTATION_IMPORTERS = frozenset({"ildottore.cli.run", "ildottore.cli.wiring"})

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


def test_an_exempt_module_a_run_imports_is_a_renderer_only_the_composer_imports() -> None:
    """An exemption is checked, not taken on its word: a command is outside the run's import
    closure, and a renderer inside it is imported, among covered modules, by the composer alone
    (cli.run and cli.wiring), so no verdict code reads one."""

    run_path = _closure("ildottore.cli.run")
    for name in JUDGING_EXEMPT:
        inside = sorted(m for m in run_path if _under(m, name))
        if name in PRESENTATION:
            continue
        assert not inside, (
            f"{name} is exempt as a command a run never imports, and a run imports {inside}: "
            "cover it, or make the case that it only renders"
        )
    exempt = list(JUDGING_EXEMPT)
    for module in _all_modules():
        if any(_under(module, name) for name in exempt):
            continue
        for imported in _imports(module):
            for name in PRESENTATION:
                if _under(imported, name):
                    assert module in _PRESENTATION_IMPORTERS, (
                        f"covered module {module} imports the exempt renderer {imported}"
                    )


def test_every_other_file_of_the_package_is_covered() -> None:
    labels = {label for label, _ in covered_files()}
    for module in _all_modules():
        if not any(_under(module, name) for name in JUDGING_EXEMPT):
            assert module in labels, f"{module} is neither covered nor exempt"
    assert {"store/schema.sql", "fingerprint/signatures/pack.yaml"} <= labels
    assert not any(label.startswith("reporting/") for label in labels)


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


def test_a_comment_a_docstring_or_an_exempt_module_is_not_a_change(tmp_path: Path) -> None:
    copy = _package_copy(tmp_path)
    before = judging_rules._digest(copy)
    runner = copy / "core" / "runner.py"
    runner.write_text(runner.read_text(encoding="utf-8") + "\n# a note, and nothing else\n")
    html = copy / "reporting" / "html_reporter.py"
    html.write_text(html.read_text(encoding="utf-8") + "\nX_ONLY_A_RENDERER_READS = 1\n")
    assert judging_rules._digest(copy) == before


def test_the_digest_costs_well_under_a_second() -> None:
    """Taken once per process, at run start and by a resume: 0.3 s measured on the 161 modules."""

    started = time.perf_counter()
    judging_rules._digest(Path(judging_rules.__file__).resolve().parents[1])
    assert time.perf_counter() - started < 3.0, "a regression past the measured 0.3 s"


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
