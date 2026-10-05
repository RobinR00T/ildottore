"""PyYAML's safe loader, with a value it cannot build reported as a YAML error.

A leaf module (no in-repo imports), so the spec loader and the loaders of the operator's own
files share it. PyYAML's constructors raise plain Python errors for an impossible date
(``2026-02-31``), an integer past Python's digit limit or a bad ``!!int``/``!!float``/``!!bool``/
``!!timestamp``: they escaped as a lint traceback, and the scope, target, fleet, labels and
policy-pack loaders printed ``invalid literal for int() with base 10: '<value>'``, quoting the
operator's value (audits of 2026-10-05). Here they become a ``ConstructorError`` with a fixed
message and the position, which the callers already handle as a YAML error.
"""

from __future__ import annotations

from typing import Any

import yaml

__all__ = ["SafeValueLoader", "safe_load"]

_CANNOT_BUILD = "cannot build this value (an invalid date, number or tag)"


class SafeValueLoader(yaml.SafeLoader):
    """``yaml.SafeLoader`` whose constructor failures are ``ConstructorError``\\ s."""

    def construct_object(self, node: yaml.Node, deep: bool = False) -> Any:
        try:
            return super().construct_object(node, deep=deep)
        except (ValueError, KeyError, AttributeError, TypeError, OverflowError) as exc:
            # The original error quotes the literal; the message here does not.
            raise yaml.constructor.ConstructorError(
                None, None, _CANNOT_BUILD, node.start_mark
            ) from exc


def safe_load(text: str) -> Any:
    """``yaml.safe_load`` through :class:`SafeValueLoader`."""

    loader = SafeValueLoader(text)
    try:
        return loader.get_single_data()  # type: ignore[no-untyped-call,unused-ignore]
    except RecursionError as exc:  # thousands of nested levels: an error, not a traceback
        raise yaml.composer.ComposerError(
            None, None, "document is nested too deeply", None
        ) from exc
    finally:
        loader.dispose()  # type: ignore[no-untyped-call,unused-ignore]
