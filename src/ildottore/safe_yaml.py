"""PyYAML's safe loader, with a value it cannot build reported as a YAML error.

A leaf module (no in-repo imports), so the spec loader and the loaders of the operator's own
files share it. PyYAML's constructors raise plain Python errors for an impossible date
(``2026-02-31``), an integer past Python's digit limit or a bad ``!!int``/``!!float``/``!!bool``/
``!!timestamp``: they escaped as a lint traceback, and the scope, target, fleet, labels and
policy-pack loaders printed ``invalid literal for int() with base 10: '<value>'``, quoting the
operator's value (audits of 2026-10-05). Here they become a ``ConstructorError`` with a fixed
message and the position, which the callers already handle as a YAML error.

A key written twice in one mapping is refused the same way. PyYAML keeps the last value
without a word, so a scope target with two ``endpoints:`` lists authorized only what the
second one said, while a reviewer reading the first one approved something else (audit of
2026-10-06). Keys pulled in by a ``<<`` merge are not duplicates: overriding them is what a
merge is for. A map merged in is checked too, and so is a second ``<<`` in one mapping, which
PyYAML would also resolve to the last one.
"""

from __future__ import annotations

from collections.abc import Hashable
from typing import Any

import yaml

__all__ = ["SafeValueLoader", "safe_load"]

_CANNOT_BUILD = "cannot build this value (an invalid date, number or tag)"
_TWICE = "found a key written twice in one mapping"
_MERGE_TAG = "tag:yaml.org,2002:merge"
_VALUE_TAG = "tag:yaml.org,2002:value"
_STR_TAG = "tag:yaml.org,2002:str"


class SafeValueLoader(yaml.SafeLoader):
    """``yaml.SafeLoader`` whose constructor failures are ``ConstructorError``\\ s.

    It also refuses a key written twice in one mapping (``flatten_mapping``), as a
    ``ConstructorError`` with both positions and no value.
    """

    def construct_object(self, node: yaml.Node, deep: bool = False) -> Any:
        try:
            return super().construct_object(node, deep=deep)
        except (ValueError, KeyError, AttributeError, TypeError, OverflowError) as exc:
            # The original error quotes the literal; the message here does not.
            raise yaml.constructor.ConstructorError(
                None, None, _CANNOT_BUILD, node.start_mark
            ) from exc

    def __init__(self, stream: Any) -> None:
        super().__init__(stream)
        # The nodes themselves, not their ids: with ``yaml.load_all`` a later document's node
        # can reuse the address of a freed one, and its check was skipped (delta audit).
        self._checked_mappings: set[yaml.Node] = set()
        # Where each key written as an alias (``*k :``) was written, by mapping and pair index:
        # the node an alias returns carries its anchor's position, not the alias's.
        self._alias_keys: dict[tuple[yaml.Node, int], yaml.Mark] = {}

    def compose_node(self, parent: yaml.Node | None, index: Any) -> yaml.Node | None:
        if (
            index is None
            and isinstance(parent, yaml.MappingNode)
            and self.check_event(yaml.AliasEvent)  # type: ignore[no-untyped-call,unused-ignore]
        ):
            event = self.peek_event()  # type: ignore[no-untyped-call,unused-ignore]
            self._alias_keys[(parent, len(parent.value))] = event.start_mark
        return super().compose_node(parent, index)  # type: ignore[no-any-return,unused-ignore]

    def flatten_mapping(self, node: yaml.MappingNode) -> None:
        # Checked here, before PyYAML folds the merged keys into ``node.value``: once it has,
        # they look like keys written in the mapping, and a map merged elsewhere first was
        # refused for an override it is allowed (pre-commit audit of this block). PyYAML
        # flattens each map it merges through this method too, so an inline merged map is
        # checked as well; each node only once, the first time, while it is as written.
        if node not in self._checked_mappings:
            self._checked_mappings.add(node)
            self._refuse_repeated_keys(node)
        super().flatten_mapping(node)

    def _refuse_repeated_keys(self, node: yaml.MappingNode) -> None:
        first_seen: dict[Any, yaml.Mark] = {}
        first_merge: yaml.Mark | None = None
        for index, (key_node, _) in enumerate(node.value):
            written = self._alias_keys.get((node, index), key_node.start_mark)
            if key_node.tag == _MERGE_TAG:
                if first_merge is not None:
                    raise _written_twice(first_merge, written)
                first_merge = written
                continue
            if key_node.tag == _VALUE_TAG:
                key_node.tag = _STR_TAG  # what PyYAML's flattening does to a `=` key
            key = self.construct_object(key_node)
            if not isinstance(key, Hashable):
                continue  # PyYAML's own check refuses it, with its message
            if key in first_seen:
                raise _written_twice(first_seen[key], written)
            first_seen[key] = written


def _written_twice(first: yaml.Mark, again: yaml.Mark) -> yaml.constructor.ConstructorError:
    """The refusal of a repeated key: where it was first written and where again, no value.

    Both are where the key was written, an alias (``*k :``) included: the node an alias
    returns carries its anchor's position, which sent the reader to a value or to another
    mapping (pre-merge audit of #45, then the pre-commit audit of its follow-ups).
    """

    where = f"line {first.line + 1}, column {first.column + 1}"
    return yaml.constructor.ConstructorError(
        None, None, f"{_TWICE}, first at {where} and again", again
    )


def safe_load(text: str) -> Any:
    """``yaml.safe_load`` through :class:`SafeValueLoader`."""

    loader = SafeValueLoader(text)
    try:
        return loader.get_single_data()  # type: ignore[no-untyped-call,unused-ignore]
    except RecursionError as exc:  # hundreds of nested levels: an error, not a traceback
        raise yaml.composer.ComposerError(
            None, None, "document is nested too deeply", None
        ) from exc
    finally:
        loader.dispose()  # type: ignore[no-untyped-call,unused-ignore]
