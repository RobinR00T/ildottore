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

A value nested deeper than :data:`MAX_DEPTH` once its aliases are expanded is refused too. The
composer's own guard sees only the nesting as written, and anchors chained through aliases built
a value 1,600 levels deep from 4 KB of text, which the linter, the target loader and the labels
of ``calibrate`` overflowed on: a traceback and exit 1 (pre-commit audit of the nesting fix,
2026-10-07).

So is a value larger than :data:`MAX_NODES` once its aliases are expanded, the spec loader's cap
since audit SEC-09, measured here so that every loader shares it. The others had none: an
835-byte labels file of 45 anchors, each a list of two aliases of the one before, ran
``calibrate`` past 25 s at 1.7 GB while it formatted the verdict, and a ``<<`` merging the
previous map twice doubles the work inside PyYAML itself, before any caller sees the value
(pre-merge audit of the nesting fix, 2026-10-07).

Two values cost far more to build than they weigh, and are refused as they are composed, before
anything is built (pre-commit audit of the size cap, 2026-10-07). A number written in more than
:data:`MAX_NUMBER_CHARS` characters: YAML 1.1 reads ``1:59:59`` as a base-60 integer, which PyYAML
builds with a loop whose time grows with the square of its length, and a spec just under the 1 MiB
cap took the linter 55 s. And more than :data:`MAX_NUMBER_KEYS` keys that are numbers in one
document: integers that differ by a multiple of ``sys.hash_info.modulus`` share one hash, so the
dict of a mapping of them is built in time that grows with the square of their count, and 36,320 of
them, a 1 MiB spec, took the linter 24 s. Keys that are text, dates or bytes hash with a key Python
draws at random for each process.

A list or a map written inside :data:`MAX_DEPTH` others is refused where it starts, before it is
composed, as a document too deep. PyYAML's pure-Python scanner keeps one possible simple key per
open flow level and walks them all on every token, so the depth measured after composition came
after a cost that grows with the levels open: a 198 KB list of chains of ``[`` 320 deep was
composed whole, 3 to 7 times what as many flat texts take (depending on the machine's load),
before it was refused (pre-commit audit of the construction-cost fix, 2026-10-07). A text or an
alias opens no level and is not refused here. Under the limit the cost stays: chains of ``[``
close to 100 deep still take a few times what flat texts do.
"""

from __future__ import annotations

from collections.abc import Hashable
from typing import Any, cast

import yaml

__all__ = [
    "MAX_DEPTH",
    "MAX_NODES",
    "MAX_NUMBER_CHARS",
    "MAX_NUMBER_KEYS",
    "SafeValueLoader",
    "check_expanded",
    "safe_load",
]

#: The deepest nesting a document may hold with its aliases expanded. The files this tool reads
#: (specs, scopes, targets, fleets, labels, packs) nest about 10 levels.
MAX_DEPTH = 100
#: The nodes a document may hold with every alias counted where it is used. The largest file this
#: tool ships, the signature corpus, holds about 400.
MAX_NODES = 100_000
#: The longest number a document may write, in characters. In hexadecimal, the densest form, that
#: is an integer of about 1,204 decimal digits, under the 4,300 Python converts by default.
MAX_NUMBER_CHARS = 1_000
#: The keys that are numbers a document may hold, a key merged in by ``<<`` counted in every mapping
#: it is merged into. The files this tool reads key their mappings with text.
MAX_NUMBER_KEYS = 1_000
#: A text counts one more node per this many characters, so a long text repeated through aliases
#: costs what its copies weigh: the cap bounds the expanded text at about 6 MB.
_CHARS_PER_NODE = 64

_TOO_LARGE = (
    f"document is too large (over {MAX_NODES} nodes, counting every alias where it is used and "
    f"a text as one node per {_CHARS_PER_NODE} characters)"
)
_CANNOT_BUILD = "cannot build this value (an invalid date, number or tag)"
_TOO_DEEP = "document is nested too deeply"
#: The events that open a level, in the composer and, in flow style, in the scanner.
_OPENS_A_LEVEL = (yaml.SequenceStartEvent, yaml.MappingStartEvent)
_NUMBER_TOO_LONG = (
    f"cannot build this value (a number written in over {MAX_NUMBER_CHARS} characters)"
)
_TOO_MANY_NUMBER_KEYS = (
    f"document has over {MAX_NUMBER_KEYS} keys that are numbers (a key merged in by `<<` counted "
    "in every mapping it is merged into)"
)
_NUMBER_TAGS = frozenset({"tag:yaml.org,2002:int", "tag:yaml.org,2002:float"})
#: Longer than any tag this tool's files use (``!!binary`` is ``tag:yaml.org,2002:binary``).
_MAX_TAG_CHARS = 256
_TAG_TOO_LONG = f"found a tag longer than {_MAX_TAG_CHARS} characters"
_TWICE = "found a key written twice in one mapping"
_MERGE_TAG = "tag:yaml.org,2002:merge"
_VALUE_TAG = "tag:yaml.org,2002:value"
_STR_TAG = "tag:yaml.org,2002:str"


class SafeValueLoader(yaml.SafeLoader):
    """``yaml.SafeLoader`` whose constructor failures are ``ConstructorError``\\ s.

    It also refuses a key written twice in one mapping (``flatten_mapping``), as a
    ``ConstructorError`` with both positions and no value, and stops composing a document once
    the nodes written in it pass :data:`MAX_NODES`, a tag passes ``_MAX_TAG_CHARS`` or a list or a
    map is written inside :data:`MAX_DEPTH` others (``compose_node``). It refuses there too,
    before anything is built, a number written in more than :data:`MAX_NUMBER_CHARS` characters
    and the key that takes the document past :data:`MAX_NUMBER_KEYS` keys that are numbers.
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
        # The weight of the nodes composed so far, each counted once where it is written.
        self._composed = 0
        # The lists and maps open around the node being composed, as written.
        self._open = 0
        # The keys that are numbers composed so far, and those each mapping holds, merges included.
        self._number_keys = 0
        self._numbers_held: dict[yaml.Node, int] = {}

    def compose_document(self) -> yaml.Node | None:
        # Per document: ``yaml.load_all`` composes several with one loader.
        self._composed = self._number_keys = 0
        return super().compose_document()  # type: ignore[no-any-return,unused-ignore]

    def compose_node(self, parent: yaml.Node | None, index: Any) -> yaml.Node | None:
        event = self.peek_event()  # type: ignore[no-untyped-call,unused-ignore]
        alias = isinstance(event, yaml.AliasEvent)
        if alias and index is None and isinstance(parent, yaml.MappingNode):
            self._alias_keys[(parent, len(parent.value))] = event.start_mark
        if len(getattr(event, "tag", None) or "") > _MAX_TAG_CHARS:
            # A ``%TAG`` prefix is copied into the tag of every node that uses its handle: 1,000
            # nodes of a 100,000-character prefix held 187 MB, and PyYAML's refusal quoted the
            # whole tag (delta audit). Refused at the first one, without quoting it.
            raise _refusal(event.start_mark, _TAG_TOO_LONG)
        opens = isinstance(event, _OPENS_A_LEVEL)
        if opens:
            if self._open >= MAX_DEPTH:
                # The scanner walks one possible key per open flow level on every token, so the
                # nesting written was paid for before ``check_expanded`` measured it: a 198 KB
                # list of chains 320 deep took 3 to 7 times what as many flat texts take (audit of
                # the construction-cost fix). Written depth is at most the expanded one, so where
                # that measure runs this refuses earlier only what it refuses, at the first list or
                # map written past the limit (the measure names the deepest branch).
                raise _refusal(event.start_mark, _TOO_DEEP)
            self._open += 1
        try:
            # PyYAML returns a node here every time; its type stub says ``Node | None``.
            node = cast("yaml.Node", super().compose_node(parent, index))
        finally:
            if opens:
                self._open -= 1
        # The value expanded weighs at least what is written, and an alias at least what it
        # names, so the rest of a document is not composed once that passes the cap: a 3 MB list
        # of plain texts took 785 MB to compose before its measure refused it (pre-commit audit),
        # and a list of aliases, uncounted, was still composed whole (delta audit). The refusal
        # is where the count crosses, at the alias if it is one.
        self._composed += _weight(node)
        if self._composed > MAX_NODES:
            raise _refusal(event.start_mark if alias else node.start_mark, _TOO_LARGE)
        if not alias and _is_number(node) and len(node.value) > MAX_NUMBER_CHARS:
            raise _refusal(node.start_mark, _NUMBER_TOO_LONG)
        if isinstance(parent, yaml.MappingNode):
            self._count_number_keys(parent, index, node, event.start_mark if alias else None)
        return node

    def _count_number_keys(
        self, mapping: yaml.MappingNode, index: Any, node: yaml.Node, alias_mark: yaml.Mark | None
    ) -> None:
        """Count the keys that are numbers ``mapping`` holds, as each is composed.

        ``node`` is a key when ``index`` is ``None``, and else the value of the key ``index``. A
        ``<<`` folds the keys of the maps it names into ``mapping``, whose dict then hashes them
        again, so they count once more there: the maps a merge names were composed before it.
        The refusal is at the key, or at what the ``<<`` merges in, that takes the document past
        the limit, before any key is hashed.
        """

        if index is None:
            held = 1 if _is_number(node) else 0
        elif index.tag == _MERGE_TAG:
            merged = node.value if isinstance(node, yaml.SequenceNode) else [node]
            held = sum(self._numbers_held.get(item, 0) for item in merged)
        else:
            return
        if held:
            self._numbers_held[mapping] = self._numbers_held.get(mapping, 0) + held
            self._number_keys += held
            if self._number_keys > MAX_NUMBER_KEYS:
                raise _refusal(alias_mark or node.start_mark, _TOO_MANY_NUMBER_KEYS)

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


def check_expanded(root: yaml.Node) -> None:
    """Refuse a node graph past :data:`MAX_DEPTH` or :data:`MAX_NODES` with its aliases expanded.

    Each node's expanded depth and size are computed once, bottom up and without recursion, so a
    document of shared aliases is measured without being expanded. The size counts a node every
    time an alias uses it (:func:`_weight`), and stops counting just past the cap. A recursive
    alias (``&a [*a]``) has neither and is refused as such. Too deep is reported before too
    large, as the nesting fix reported it.
    """

    depth: dict[yaml.Node, int] = {}
    size: dict[yaml.Node, int] = {}
    on_path: set[yaml.Node] = set()
    stack: list[tuple[yaml.Node, bool]] = [(root, False)]
    while stack:
        node, children_done = stack.pop()
        if children_done:
            on_path.discard(node)
            children = _children(node)
            depth[node] = 1 + max((depth[child] for child in children), default=0)
            size[node] = min(_weight(node) + sum(size[child] for child in children), MAX_NODES + 1)
        elif node not in depth:
            if node in on_path:
                raise _refusal(node.start_mark, "document contains a recursive alias")
            on_path.add(node)
            stack.append((node, True))
            stack.extend((child, False) for child in _children(node) if child not in depth)
    if depth[root] > MAX_DEPTH:
        # The position is where the nesting crosses the limit, down the deepest branch: the node
        # that first measured too deep was the root of any document just past it (delta audit).
        node = root
        for _ in range(MAX_DEPTH):
            node = max(_children(node), key=depth.__getitem__)
        raise _refusal(node.start_mark, _TOO_DEEP)
    if size[root] > MAX_NODES:
        # Where the size crosses the cap: down the first branch over it, to the node none of whose
        # children is, such as the anchor whose aliases double it past the cap.
        node = root
        while (over := next((c for c in _children(node) if size[c] > MAX_NODES), None)) is not None:
            node = over
        raise _refusal(node.start_mark, _TOO_LARGE)


def _is_number(node: yaml.Node) -> bool:
    """A scalar YAML builds as an integer or a float, whatever its notation."""

    return isinstance(node, yaml.ScalarNode) and node.tag in _NUMBER_TAGS


def _weight(node: yaml.Node) -> int:
    """A node counts one, and a text one more per :data:`_CHARS_PER_NODE` characters."""

    if isinstance(node, yaml.ScalarNode):
        return 1 + len(node.value) // _CHARS_PER_NODE
    return 1


def _children(node: yaml.Node) -> list[yaml.Node]:
    if isinstance(node, yaml.MappingNode):
        return [part for pair in node.value for part in pair]
    if isinstance(node, yaml.SequenceNode):
        return list(node.value)
    return []


def _refusal(where: yaml.Mark, problem: str) -> yaml.composer.ComposerError:
    """The refusal, where the value crossed a limit or recurses, quoting nothing of the file."""

    return yaml.composer.ComposerError(None, None, problem, where)


def safe_load(text: str) -> Any:
    """``yaml.safe_load`` through :class:`SafeValueLoader`, refusing a value that recurses or
    that is too deep or too large with its aliases expanded (:func:`check_expanded`)."""

    loader = SafeValueLoader(text)
    try:
        node = loader.get_single_node()  # type: ignore[no-untyped-call,unused-ignore]
        if node is None:
            return None
        check_expanded(node)
        return loader.construct_document(node)  # type: ignore[no-untyped-call,unused-ignore]
    except RecursionError as exc:  # a caller with little stack left: an error, not a traceback
        raise yaml.composer.ComposerError(None, None, _TOO_DEEP, None) from exc
    finally:
        loader.dispose()  # type: ignore[no-untyped-call,unused-ignore]
