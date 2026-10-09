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
the function runs, so it is not seen; the package has none.
"""

from __future__ import annotations

import importlib
import pkgutil

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

#: Names each fixed because the rule masked the one before (PR #87, then u01 A-63): the walk
#: has to reach the adapters, the CLI, the engine and the policy layer to see them all.
_RENAMED = {
    "WebSocketOverflow",
    "WebSocketUndecodable",
    "WebSocketLost",
    "WebSocketTooMany",
    "ScopeChecksumError",
    "ProbeCeilingHit",
    "ReplyOverBudget",
    "_ImpossibleLogprob",
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


def test_every_exception_class_name_survives_the_redactor() -> None:
    classes = _package_exceptions()
    names = {cls.__name__ for cls in classes.values()}
    assert names >= _RENAMED, "the walk missed a module"
    redactor = Redactor()
    masked = sorted(
        f"{where} in {line!r}"
        for where, cls in classes.items()
        for line in (template.format(name=cls.__name__) for template in _LINES)
        if redactor.redact_text(line) != line
    )
    assert not masked, "rename the class to a name the redactor keeps:\n" + "\n".join(masked)


def test_the_checksum_error_keeps_its_0_1_0_name() -> None:
    """``ildottore.policy`` exported ``ChecksumMismatchError`` in 0.1.0: the same class."""

    import ildottore.policy as policy
    from ildottore.policy.errors import ChecksumMismatchError, ScopeChecksumError

    assert policy.ChecksumMismatchError is ChecksumMismatchError is ScopeChecksumError
    assert {"ChecksumMismatchError", "ScopeChecksumError"} <= set(policy.__all__)
    assert ScopeChecksumError.__name__ == "ScopeChecksumError"
