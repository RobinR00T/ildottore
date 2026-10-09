"""Every exception class the package defines keeps its name through the redactor (u01 A-63).

The terminal, the stored evidence and the reports get an error through the redactor, and several
messages write an error with its class: ``<class>: <message>`` for an attempt's error and an
adapter's last failure, ``aborted on <class>: <message>`` for a halt reason, and the unreachable
reason quotes the first attempt's error. A class name the high-entropy rule masks reads
``«REDACTED:high_entropy:...»`` there: the failure class is lost and the line looks as if a
secret had been masked. Four of the WebSocket adapter's names were (PR #87), and on main
``ChecksumMismatchError``, ``ProbeCeilingReached``, ``BudgetExhaustedAfterReply`` and
``_ImpossibleFigure`` were too, though no message wrote those four with their class yet.

The walk imports every module of the package and takes every class ``BaseException`` reaches
through ``__subclasses__`` that one of them defines, so a class nested in another, or left out of
its module's namespace, is checked too. A class written inside a function body exists only once
the function runs, so whether the walk saw it would depend on which tests ran first: every class
written in a function body, at any depth, is read from the source instead and its name checked in
the same lines, exception or not, since the source does not say which it is. There are none today.
"""

from __future__ import annotations

import ast
import importlib
import pkgutil
from pathlib import Path

import ildottore
from ildottore.redactor import Redactor

#: How the messages that write a class put it (``core/execute.py``, ``core/runner.py``,
#: ``cli/run.py``'s unreachable reason, the fingerprint engine's failed probe).
_LINES = (
    "{name}",
    "{name}: ws-live: a text frame was not UTF-8 and the connection was closed (1007)",
    "every one of the 3 attempt(s) failed on transport, so nothing was evaluated: {name}: message",
    "live-t: aborted on {name}: message; 10 of 18 specs never ran or did not finish",
    "evaluating a stored reply also raised {name}: message",
    "behavioral/self_id: {name}",
)

#: Where a class was renamed because the rule masked its name (PR #87, then u01 A-63): a walk
#: that does not reach them all is not the walk this test means.
_RENAMED_IN = {
    "ildottore.adapters.base",
    "ildottore.adapters.websocket",
    "ildottore.cli.wiring",
    "ildottore.core.execute",
    "ildottore.policy.errors",
}


def _package_exceptions() -> dict[str, type[BaseException]]:
    for info in pkgutil.walk_packages(ildottore.__path__, "ildottore."):
        importlib.import_module(info.name)
    found: dict[str, type[BaseException]] = {}
    pending: list[type[BaseException]] = [BaseException]
    while pending:
        cls = pending.pop()
        pending.extend(cls.__subclasses__())
        if cls.__module__.split(".")[0] == "ildottore":
            found[f"{cls.__module__}.{cls.__qualname__}"] = cls
    return found


def _classes_in_function_bodies(source: str) -> set[tuple[int, str]]:
    """``(line, name)`` of each class written inside a function body of ``source``, at any depth."""

    found: set[tuple[int, str]] = set()
    for node in ast.walk(ast.parse(source)):
        if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef):
            found.update(
                (inner.lineno, inner.name)
                for inner in ast.walk(node)
                if isinstance(inner, ast.ClassDef)
            )
    return found


def _masked(names: dict[str, str]) -> list[str]:
    redactor = Redactor()
    return sorted(
        f"{where} in {line!r}"
        for where, name in names.items()
        for line in (template.format(name=name) for template in _LINES)
        if redactor.redact_text(line) != line
    )


def test_every_exception_class_name_survives_the_redactor() -> None:
    classes = _package_exceptions()
    assert {cls.__module__ for cls in classes.values()} >= _RENAMED_IN, "the walk missed a module"
    masked = _masked({where: cls.__name__ for where, cls in classes.items()})
    assert not masked, "rename the class to a name the redactor keeps:\n" + "\n".join(masked)


def test_no_class_written_in_a_function_body_has_a_name_the_redactor_masks() -> None:
    root = Path(ildottore.__file__).parent
    local: dict[str, str] = {}
    for path in sorted(root.rglob("*.py")):
        for line, name in _classes_in_function_bodies(path.read_text(encoding="utf-8")):
            local[f"{path.relative_to(root.parent)}:{line} {name}"] = name
    masked = _masked(local)
    assert not masked, "rename the class to a name the redactor keeps:\n" + "\n".join(masked)


def test_the_source_pass_finds_a_class_however_deep_in_a_function_body() -> None:
    """The pass above finds nothing today, so it is shown here to find what it looks for."""

    source = (
        "class Top(Exception):\n"
        "    class Nested(Exception): ...\n"
        "def f():\n"
        "    class InF(Exception): ...\n"
        "    if True:\n"
        "        class InIf: ...\n"
        "    def g():\n"
        "        class InG(Exception):\n"
        "            class InInG: ...\n"
        "class Holder:\n"
        "    async def m(self):\n"
        "        class InMethod(Exception): ...\n"
    )
    names = {name for _line, name in _classes_in_function_bodies(source)}
    assert names == {"InF", "InIf", "InG", "InInG", "InMethod"}
    assert _masked({"probe": "ProbeCeilingReached"}), "the masked lines are not checked"


def test_the_checksum_error_keeps_its_0_1_0_name() -> None:
    """``ildottore.policy`` exported ``ChecksumMismatchError`` in 0.1.0: the same class."""

    import ildottore.policy as policy
    from ildottore.policy.errors import ChecksumMismatchError, ScopeChecksumError

    assert policy.ChecksumMismatchError is ChecksumMismatchError is ScopeChecksumError
    assert {"ChecksumMismatchError", "ScopeChecksumError"} <= set(policy.__all__)
    assert ScopeChecksumError.__name__ == "ScopeChecksumError"
