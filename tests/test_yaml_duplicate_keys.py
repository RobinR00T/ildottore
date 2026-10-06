"""A key written twice in one YAML mapping is refused, not resolved to the last value.

PyYAML keeps the last value without a word. A scope target with two ``endpoints:`` lists
authorized only what the second one said, while a reviewer reading the first one approved
something else. Every loader goes through ``safe_yaml.SafeValueLoader``, so the refusal is in
one place and reaches the scope, target, fleet, labels, policy-pack, signature-pack and spec
loaders alike.
"""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest
import yaml

from ildottore import safe_yaml
from ildottore.shared.config_errors import yaml_problem

_DUPLICATE = "found a key written twice in one mapping"
_SECRET = "sk-live-0123456789abcdef"


def _problem(text: str) -> str:
    with pytest.raises(yaml.YAMLError) as caught:
        safe_yaml.safe_load(text)
    return yaml_problem(caught.value)


@pytest.mark.parametrize(
    ("text", "where"),
    [
        ("a: 1\na: 2\n", "first at line 1, column 1 and again at line 2, column 1"),
        ("x:\n  b: 1\n  c: 2\n  b: 3\n", "first at line 2, column 3 and again at line 4, column 3"),
        ("{a: 1, a: 2}", "first at line 1, column 2 and again at line 1, column 8"),
        ("- {k: 1}\n- {k: 1, k: 2}\n", "and again at line 2, column 10"),
        ("true: 1\nTrue: 2\n", "and again at line 2, column 1"),  # one key once built
        ("1: a\n1.0: b\n", "and again at line 2, column 1"),
        ("~: a\nnull: b\n", "and again at line 2, column 1"),
        ("=: 1\n=: 2\n", "and again at line 2, column 1"),
        ("s: !!set {a, a}\n", "and again at line 1, column 14"),
        # The pre-commit audit's ways past the first version: a map merged in, inline or in a
        # list, and a second `<<` (written plain or as `!!merge`), each kept the last value.
        ("m: {<<: {e: [a], e: [b]}}\n", "at line 1, column 10 and again at line 1, column 18"),
        ("m:\n  <<: [{a: 1, a: 2}]\n", "and again at line 2, column 15"),
        ("m:\n  <<: {a: 1}\n  <<: {b: 2}\n", "at line 2, column 3 and again at line 3, column 3"),
        ("m:\n  !!merge p: {a: 1}\n  !!merge q: {a: 2}\n", "and again at line 3, column 3"),
        # A key written as an alias is reported where the alias is, not where its anchor is
        # (that was a value, or another mapping, in the two audits of this message).
        ("&k a: 1\n*k : 2\n", "first at line 1, column 1 and again at line 2, column 1"),
        (
            "x: &k a\nm:\n  a: 1\n  *k : 2\n",
            "first at line 3, column 3 and again at line 4, column 3",
        ),
        (
            "x: &k a\nm:\n  *k : 1\n  a: 2\n",
            "first at line 3, column 3 and again at line 4, column 3",
        ),
        (
            "m:\n  x: &k a\n  *k : 1\n  a: 2\n",
            "first at line 3, column 3 and again at line 4, column 3",
        ),
        ("x: &k a\na: 1\n*k : 2\n", "first at line 2, column 1 and again at line 3, column 1"),
        ("{x: &k a, *k : 1, a: 2}", "first at line 1, column 11 and again at line 1, column 19"),
    ],
)
def test_a_repeated_key_is_refused_at_the_second_one(text: str, where: str) -> None:
    shown = _problem(text)
    assert _DUPLICATE in shown and where in shown


def test_a_later_document_is_checked_too() -> None:
    # The checked mappings were kept by id: a node of the second document could reuse the
    # address of a freed node of the first and skip its check (delta audit of this block).
    text = "".join(f"- {{k: {n}}}\n" for n in range(2000)) + "---\na: 1\na: 2\n"
    for _ in range(20):
        with pytest.raises(yaml.YAMLError, match=_DUPLICATE):
            list(yaml.load_all(text, Loader=safe_yaml.SafeValueLoader))


def test_the_message_quotes_neither_the_key_nor_the_value() -> None:
    shown = _problem(f"{_SECRET}: 1\n{_SECRET}: {_SECRET}\n")
    assert _DUPLICATE in shown and _SECRET not in shown


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        # A merge is how YAML overrides keys on purpose: the explicit key wins, as before.
        (
            "base: &b {a: 1, b: 2}\nm:\n  <<: *b\n  a: 9\n",
            {"base": {"a": 1, "b": 2}, "m": {"a": 9, "b": 2}},
        ),
        (
            "x: &x {a: 1}\ny: &y {a: 2}\nm:\n  <<: [*x, *y]\n",
            {"x": {"a": 1}, "y": {"a": 2}, "m": {"a": 1}},
        ),
        # A key written before the `<<` wins too, as in PyYAML.
        ("base: &b {a: 1}\nm:\n  a: 9\n  <<: *b\n", {"base": {"a": 1}, "m": {"a": 9}}),
        # A map with its own merge and override, merged by a map built before it: its merged
        # key is not counted as written twice (the first version refused this).
        (
            "v: 1\nouter:\n  inner: &i\n    <<: {p: ['/']}\n    p: ['/v1']\nm:\n  <<: *i\n",
            {"v": 1, "outer": {"inner": {"p": ["/v1"]}}, "m": {"p": ["/v1"]}},
        ),
        ("=: 1\nx:\n  =: 2\n", {"=": 1, "x": {"=": 2}}),  # `=` is a plain key, as before
        ("1: a\n'1': b\n", {1: "a", "1": "b"}),  # an int and a string are two keys
        ("- {k: 1}\n- {k: 2}\n", [{"k": 1}, {"k": 2}]),
        ("a: &x {q: 1}\nb: *x\n", {"a": {"q": 1}, "b": {"q": 1}}),
    ],
)
def test_what_is_not_a_repeated_key_still_loads(text: str, expected: object) -> None:
    assert safe_yaml.safe_load(text) == expected


def test_an_unhashable_key_keeps_pyyamls_own_refusal() -> None:
    assert "found unhashable key" in _problem("? [1]\n: 2\n")


_SCOPE = (
    'version: "1.0"\ntargets:\n  - id: t\n    base_url: "https://a.example.com/v1"\n'
    '    endpoints:\n      - host: "a.example.com"\n        path_prefixes: ["/v1"]\n'
    '    identities:\n      - name: default\n        auth_ref: "env://K"\n'
)


def test_a_scope_with_a_target_declaring_endpoints_twice_is_refused(tmp_path: Path) -> None:
    from ildottore.policy.scope import ScopeError, load_scope_with_digest

    scope = tmp_path / "scope.yaml"
    scope.write_text(
        _SCOPE + '    endpoints:\n      - host: "b.example.com"\n        path_prefixes: ["/"]\n'
    )
    with pytest.raises(ScopeError) as caught:
        load_scope_with_digest(scope)
    shown = str(caught.value)
    assert "first at line 5, column 5 and again at line 11, column 5" in shown
    assert "b.example.com" not in shown


def test_a_scope_without_repeated_keys_still_loads(tmp_path: Path) -> None:
    from ildottore.policy.scope import load_scope_with_digest

    scope = tmp_path / "scope.yaml"
    scope.write_text(_SCOPE)
    loaded, _ = load_scope_with_digest(scope)
    assert [e.host for e in loaded.targets[0].endpoints] == ["a.example.com"]


def test_a_target_file_with_two_endpoints_is_refused(tmp_path: Path) -> None:
    from ildottore.cli.wiring import load_target

    target = tmp_path / "target.yaml"
    target.write_text(
        "id: t\ntype: chatbot\nendpoint: https://a.example.com/v1\n"
        "endpoint: https://b.example.com/v1\n"
    )
    with pytest.raises(ValueError, match=_DUPLICATE):
        load_target(target)


def test_a_policy_pack_with_a_repeated_key_is_refused(tmp_path: Path) -> None:
    from ildottore.policy.packs import PolicyPackError, load_pack

    pack = tmp_path / "pack.yaml"
    pack.write_text("name: a\nname: b\n")
    with pytest.raises(PolicyPackError, match=_DUPLICATE):
        load_pack(pack)


def test_the_signature_pack_loader_refuses_it_without_quoting_the_line(tmp_path: Path) -> None:
    from ildottore.fingerprint.signatures import SignaturePackError, load_pack

    pack = tmp_path / "signatures.yaml"
    pack.write_text(f"pack_version: 1\npack_version: {_SECRET}\n")
    with pytest.raises(SignaturePackError) as caught:
        load_pack(pack)
    assert _DUPLICATE in str(caught.value) and _SECRET not in str(caught.value)


def test_a_spec_with_a_repeated_key_is_a_parse_error() -> None:
    from ildottore.registry.schema import SafeLoadError, safe_load_yaml

    with pytest.raises(SafeLoadError, match=_DUPLICATE):
        safe_load_yaml("id: a\nattack:\n  prompt: x\n  prompt: y\n")


def _repeats_a_key(text: str) -> bool:
    """True if a mapping of any document repeats a key. Values are not built, so a value that
    cannot be built (a fixture broken on purpose) does not hide a repeated key after it; a
    mapping is checked only up to a key that cannot be built, which lint refuses anyway."""

    loader = safe_yaml.SafeValueLoader(text)
    try:
        while loader.check_node():
            stack = [loader.get_node()]
            visited: set[yaml.Node] = set()
            while stack:
                node = stack.pop()
                if node in visited:
                    continue
                visited.add(node)
                if isinstance(node, yaml.MappingNode):
                    pairs = list(node.value)
                    try:
                        loader.flatten_mapping(node)
                    except yaml.constructor.ConstructorError as exc:
                        if _DUPLICATE in yaml_problem(exc):
                            return True  # a key that cannot be built is not a repetition
                    stack.extend(child for pair in pairs for child in pair)
                elif isinstance(node, yaml.SequenceNode):
                    stack.extend(node.value)
    finally:
        loader.dispose()
    return False


def test_the_repository_check_sees_past_other_errors_and_documents() -> None:
    assert _repeats_a_key("m: {x: !!int abc}\nn: {a: 1, a: 2}\n")
    assert _repeats_a_key("a: 1\n---\nb: 1\nb: 2\n")
    assert _repeats_a_key("x: !!python/object:os.system {}\ny: {k: 1, k: 2}\n")
    assert not _repeats_a_key("a: 1\n---\nb: {<<: {c: 1}, c: 2}\n")


def _yaml_files(root: Path) -> list[Path]:
    """The YAML files git knows of, tracked or new and not ignored, or without git the five
    folders that hold them. A tracked file deleted in the working tree is not read."""

    try:
        listed = subprocess.run(  # noqa: S603 - fixed argv, no shell
            [
                *("git", "ls-files", "-z", "--cached", "--others", "--exclude-standard"),
                *("*.yaml", "*.yml"),
            ],
            cwd=root,
            capture_output=True,
            check=True,
        ).stdout.decode("utf-8")
        names = [name for name in listed.split("\0") if name]
    except (OSError, subprocess.CalledProcessError):
        names = []
    if names:
        return [path for path in (root / name for name in names) if path.is_file()]
    folders = (".github", "examples", "specs", "src", "tests")
    return [
        p for f in folders for pattern in ("*.yaml", "*.yml") for p in (root / f).rglob(pattern)
    ]


def test_no_yaml_file_in_the_repository_repeats_a_key() -> None:
    root = Path(__file__).resolve().parent.parent
    listed = _yaml_files(root)
    assert len(listed) > 100
    repeated = []
    for path in listed:
        try:
            if _repeats_a_key(path.read_text(encoding="utf-8")):
                repeated.append(path.relative_to(root).as_posix())
        except yaml.YAMLError:  # a file that does not parse is the linter's to report
            continue
    assert repeated == []
