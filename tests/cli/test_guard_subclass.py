"""The root group's exit-code closure holds through a subclass of it (u12 A-80, A-9).

Another branch composes its own root group with this one by subclassing it, so the behaviour is
pinned through a subclass that overrides `main` and `invoke` and calls `super()`, on an app of
its own: only findings exit 1 or 2, every crash and every error of the command-line library is
exit 3, an asked-for exit keeps its code, and Ctrl-C keeps 130.
"""

from __future__ import annotations

from typing import Any, ClassVar

import pytest
import typer
import typer._click.exceptions as click_errors
from typer.testing import CliRunner

from ildottore.cli.app import OperationalErrorGroup


class _Composed(OperationalErrorGroup):
    """What a subclass looks like: its own work around the parent's, through super()."""

    seen: ClassVar[list[str]] = []

    def main(self, *args: Any, **kwargs: Any) -> Any:
        type(self).seen.append("main")
        return super().main(*args, **kwargs)

    def invoke(self, ctx: Any) -> Any:
        type(self).seen.append("invoke")
        return super().invoke(ctx)


_RAISED: dict[str, BaseException] = {
    "runtime": RuntimeError("boom"),
    "key": KeyError("x"),
    "broken-pipe": BrokenPipeError(32, "Broken pipe"),
    "click-exception": click_errors.ClickException("boom"),
    "file-error": click_errors.FileError("x.yaml"),
    "usage": click_errors.UsageError("bad option"),
    "abort": click_errors.Abort(),
    "exit-1": SystemExit(1),
    "exit-2": SystemExit(2),
    "exit-text": SystemExit("stopped"),
}


def _app(raised: BaseException | None = None, code: int | None = None) -> typer.Typer:
    app = typer.Typer(cls=_Composed, add_completion=False)

    @app.command()
    def fail() -> None:
        if raised is not None:
            raise raised
        raise typer.Exit(code or 0)

    @app.command()
    def other() -> None:  # a second command, so `fail` is a subcommand as in dottore
        return None

    return app


@pytest.mark.parametrize("name", sorted(_RAISED))
def test_a_crash_or_a_library_error_exits_3_through_a_subclass(name: str) -> None:
    _Composed.seen = []
    result = CliRunner().invoke(_app(_RAISED[name]), ["fail"])
    assert result.exit_code == 3, (name, result.output)
    assert _Composed.seen == ["main", "invoke"]


@pytest.mark.parametrize("code", [0, 1, 2])
def test_an_asked_for_exit_keeps_its_code_through_a_subclass(code: int) -> None:
    """`typer.Exit(1)` is how `run` and `lint` say findings: it is never remapped."""

    result = CliRunner().invoke(_app(code=code), ["fail"])
    assert result.exit_code == code


def test_ctrl_c_keeps_130_through_a_subclass() -> None:
    result = CliRunner().invoke(_app(KeyboardInterrupt()), ["fail"])
    assert result.exit_code == 130


def test_an_abort_while_the_root_context_is_made_exits_3_through_a_subclass(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def eof(*args: object, **kwargs: object) -> list[str]:
        raise EOFError

    monkeypatch.setattr(_Composed, "parse_args", eof)
    result = CliRunner().invoke(_app(), ["fail"])
    assert result.exit_code == 3


def test_the_group_keeps_no_state_of_its_own() -> None:
    """Nothing a subclass would have to reset: no attribute set on the class or an instance."""

    own = {name for name in vars(OperationalErrorGroup) if not name.startswith("_")}
    assert own == {"main", "invoke"}
