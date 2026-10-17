"""No model field warns about pydantic's protected namespaces, on any supported pydantic (u12 A-84).

The `floors` CI job installs pydantic 2.6.0, the declared floor, and `WebSocketResponse`'s
`model_path` field met that version's default protection of every `model_` name: importing the
models printed `UserWarning: Field "model_path" has conflict with protected namespace "model_"`,
which every command an operator runs on pydantic below 2.10 would print too, and which failed
`tests/store/test_store_open_errors.py` (its subprocesses printed it before their `ok`). Pydantic
2.10 narrowed the default to `model_validate` and `model_dump`, so a run on the newest release
cannot see this: the first check is by rule, not by version.
"""

from __future__ import annotations

import importlib
import inspect
import os
import pkgutil
import subprocess
import sys

from pydantic import BaseModel

import ildottore

#: The default protection of pydantic before 2.10, which the floor (2.6) applies.
_OLD_DEFAULT = ("model_",)


def _models() -> list[type[BaseModel]]:
    found: dict[str, type[BaseModel]] = {}
    for info in pkgutil.walk_packages(ildottore.__path__, "ildottore."):
        module = importlib.import_module(info.name)
        for value in vars(module).values():
            if inspect.isclass(value) and issubclass(value, BaseModel) and value is not BaseModel:
                found[f"{value.__module__}.{value.__qualname__}"] = value
    return list(found.values())


def test_a_field_named_model_something_is_outside_every_protected_namespace() -> None:
    """A field whose name starts with `model_` sets `protected_namespaces` explicitly, and no
    prefix it sets matches the field, so pydantic 2.6 to the newest are quiet alike."""

    named = []
    for model in _models():
        for field in model.model_fields:
            if not field.startswith("model_"):
                continue
            named.append(f"{model.__qualname__}.{field}")
            protected = model.model_config.get("protected_namespaces", _OLD_DEFAULT)
            assert not any(field.startswith(str(prefix)) for prefix in protected), (
                model.__qualname__,
                field,
                protected,
            )
    assert named == ["WebSocketResponse.model_path"], named  # the one such field today


def test_importing_the_cli_warns_about_nothing() -> None:
    """On the floor job's pydantic this is the regression itself; on a newer one, a guard."""

    env = {**os.environ, "PYTHONWARNINGS": "error::UserWarning"}
    done = subprocess.run(
        [sys.executable, "-c", "import ildottore.cli.app"],
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )
    assert done.returncode == 0, done.stderr
    assert done.stderr == "", done.stderr
