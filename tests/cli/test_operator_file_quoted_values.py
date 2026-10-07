"""A refusal of an operator's file quotes a value of it up to 300 characters, and names a file
that is not UTF-8.

Clause A-43 capped the read of the scope, target, fleet and labels files at 1 MiB and the list of
validation errors at 20, each cut at 300 characters, but the refusals written by hand quoted the
offending value whole: a 1 MB ``type:`` printed an ``error:`` line of 1,000,108 bytes, a
duplicated target id of 500 KB one of 500,136, and PyYAML's "found undefined alias" one of about
1,000,100 bytes, in ``run``, ``calibrate`` and ``lint`` (pre-commit audit of A-43, 2026-10-07).
And a byte that is not UTF-8 printed ``'utf-8' codec can't decode byte 0xff ...`` with no file
name, where the spec loader says ``not UTF-8 text (byte N)`` beside its path. Clause A-51 (u01).
"""

from __future__ import annotations

import errno
import tracemalloc
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path

import pytest
import yaml
from hypothesis import given
from hypothesis import strategies as st
from typer.testing import CliRunner

from ildottore import safe_yaml
from ildottore.cli.calibrate import load_labels
from ildottore.cli.exit_codes import ExitCode
from ildottore.cli.fleet import _shown_endpoint
from ildottore.cli.main import app
from ildottore.cli.resume import _assert_same_target
from ildottore.cli.wiring import load_target, resolve_auth_ref, shown_auth_ref, target_uses_mock
from ildottore.policy.allowlist import EndpointAllowlist
from ildottore.policy.scope import Endpoint
from ildottore.shared.config_errors import (
    MAX_PROBLEM_CHARS,
    _repr_head,
    listed,
    quoted,
    yaml_problem,
)
from ildottore.shared.files import read_text_capped
from ildottore.shared.models import Target
from ildottore.store.run_sqlite import SqliteRunStore

from .conftest import make_spec, write_spec_tree

runner = CliRunner()

#: A value of a million characters: with its file around it, under the 1 MiB read cap.
BIG = "a" * 1_000_000
#: For a file that holds a value twice, or two values.
HALF = "b" * 400_000

SCOPE_HEAD = 'version: "1.0"\ntargets:\n'
TARGET = "id: mock-target\ntype: chatbot\n"
FLEET = (
    'version: "1"\n'
    "targets:\n"
    "  - id: local-llama\n"
    "    endpoint: http://localhost:11434/v1/chat/completions\n"
    "    model: llama3.2:1b\n"
)
LIVE_URL = "https://api.openai.com/v1/chat/completions"
JUDGE_BLOCK = (
    "judge:\n  id: judge\n  endpoint: http://localhost:1/v1/chat/completions\n  model: m\n"
)


def scope_entry(
    target_id: str = "mock-target",
    identities: tuple[tuple[str, str, str | None], ...] = (("default", "env://MOCK_KEY", None),),
    *,
    live: bool = False,
) -> str:
    """One ``targets:`` entry; ``identities`` holds (name, auth_ref, canary)."""

    base_url, host, prefix = (
        (LIVE_URL, "api.openai.com", "/v1/chat/completions")
        if live
        else ("mock://mock-target", "mock-target", "/")
    )
    text = (
        f'  - id: "{target_id}"\n'
        f'    base_url: "{base_url}"\n'
        "    endpoints:\n"
        f'      - host: "{host}"\n'
        f'        path_prefixes: ["{prefix}"]\n'
        "    identities:\n"
    )
    for name, auth_ref, canary in identities:
        text += f'      - name: "{name}"\n        auth_ref: "{auth_ref}"\n'
        if canary is not None:
            text += f'        canary: "{canary}"\n'
    return text


def live_target(target_id: str = "live", auth_ref: str = "env://LIVE_KEY") -> str:
    return (
        f'id: "{target_id}"\ntype: model\nprovider: openai\nendpoint: "{LIVE_URL}"\n'
        f'model: m\nauth_ref: "{auth_ref}"\n'
    )


def cut_of(value: object) -> str:
    """How the refusal must show ``value``: the clause's figures, pinned here, not read back.

    A text is cut with the length of its repr; a list, mapping or set with how many items it
    holds, since its repr is never built whole.
    """

    shown = repr(value)
    assert len(shown) > 300
    if isinstance(value, list | dict | set | tuple | frozenset):
        return f"{shown[:300]}... ({len(value)} items)"
    return f"{shown[:300]}... ({len(shown)} characters)"


# --- the helpers ------------------------------------------------------------------------------


def test_the_cut_is_300_characters() -> None:
    assert MAX_PROBLEM_CHARS == 300


@pytest.mark.parametrize(
    # A repr of exactly 300 characters, a text's and a list's, is quoted whole.
    "value",
    ["chatbot ", 5, None, ["model"], "x" * 298, ["x" * 146, "y" * 146], {"k": [1, (2,)]}],
)
def test_a_short_value_is_quoted_as_repr(value: object) -> None:
    assert quoted(value) == repr(value)


@pytest.mark.parametrize(
    "value",
    [BIG, "x" * 299, ["x" * 100] * 9_000, {"k" * 400: 1}, {("a",) * 200}, ["x" * 146, "y" * 147]],
)
def test_a_long_value_is_cut_and_its_size_given(value: object) -> None:
    assert quoted(value) == cut_of(value)


_LEAVES = st.one_of(
    st.none(),
    st.booleans(),
    st.integers(),
    st.floats(),
    st.text(max_size=20),
    st.binary(max_size=5),
)
_HASHABLE = _LEAVES | st.tuples(_LEAVES, _LEAVES) | st.frozensets(_LEAVES, max_size=3)
_VALUES = st.recursive(
    _LEAVES,
    lambda inner: (
        st.lists(inner, max_size=6)
        | st.tuples(inner)
        | st.dictionaries(_HASHABLE, inner, max_size=4)
        | st.sets(_HASHABLE, max_size=4)
        | st.frozensets(_HASHABLE, max_size=4)
    ),
    max_leaves=40,
)


@given(value=_VALUES, budget=st.integers(min_value=1, max_value=400))
def test_the_head_is_the_start_of_repr(value: object, budget: int) -> None:
    assert _repr_head(value, budget) == repr(value)[:budget]
    if len(repr(value)) <= MAX_PROBLEM_CHARS:
        assert quoted(value) == repr(value)


#: 90 KB of YAML whose ``type`` is 20,000 aliases of one 10 KB text: a repr of 200,080,000
#: characters, 2.6 s and 202 MiB to build whole. As a list, and as a mapping of 20,000 keys.
ANCHOR = "x: &a " + "a" * 10_000 + "\n"
ALIASES = "[" + ", ".join(["*a"] * 20_000) + "]"
ALIASED = {
    "list": f"{ANCHOR}type: {ALIASES}\n",
    "mapping": ANCHOR + "type: {" + ", ".join(f"k{i}: *a" for i in range(20_000)) + "}\n",
    # One level down, where a walk that wrote each item whole would build it all again.
    "nested-list": f"{ANCHOR}type: [{ALIASES}]\n",
    "nested-mapping": ANCHOR + "type: {k: " + ALIASES + "}\n",
}
#: How each one's quote starts, and how many items its outer container holds.
ALIASED_HEAD = {
    "list": ("['", 20_000),
    "mapping": ("{'k0': '", 20_000),
    "nested-list": ("[['", 1),
    "nested-mapping": ("{'k': ['", 1),
}


def peak_of(call: Callable[[], object]) -> tuple[object, int]:
    """What ``call`` returns or raises, and the most memory Python held during it."""

    tracemalloc.start()
    try:
        try:
            result: object = call()
        except ValueError as exc:
            result = exc
        return result, tracemalloc.get_traced_memory()[1]
    finally:
        tracemalloc.stop()


@pytest.mark.parametrize("shape", list(ALIASED))
def test_aliases_are_quoted_without_building_the_repr(shape: str) -> None:
    value = safe_yaml.safe_load(ALIASED[shape])["type"]

    shown, peak = peak_of(lambda: quoted(value))

    head, items = ALIASED_HEAD[shape]
    assert shown == f"{head}{'a' * (300 - len(head))}... ({items} items)"
    assert peak < 1_000_000, peak


@pytest.mark.parametrize("shape", list(ALIASED))
def test_an_aliased_type_is_refused_without_building_the_repr(tmp_path: Path, shape: str) -> None:
    # The enum's own error built it before the refusal could quote the value: 474 MB of
    # memory for this 90 KB file (audit of A-51).
    path = tmp_path / "target.yaml"
    path.write_text("id: mock-target\n" + ALIASED[shape], encoding="utf-8")
    loaded, reference = peak_of(lambda: safe_yaml.safe_load(path.read_text(encoding="utf-8")))
    assert isinstance(loaded, dict)

    refused, peak = peak_of(lambda: load_target(path))

    assert isinstance(refused, ValueError) and "has invalid type" in str(refused), refused
    assert peak < reference + 8_000_000, (peak, reference)


def test_an_integer_python_will_not_write_is_described() -> None:
    # A YAML integer in hex or base 60 can pass the 4,300 digits Python converts to text.
    huge = int("f" * 5_000, 16)
    with pytest.raises(ValueError):
        repr(huge)

    assert quoted(huge) == "<an integer of 20000 bits>"
    assert quoted([1, huge]) == "[1, <an integer of 20000 bits>]"
    assert _repr_head({"k": huge}, 10) == "{'k': <an "


class _ReprRaises:
    def __repr__(self) -> str:
        raise ValueError("not an integer")


def test_only_an_integer_python_will_not_write_is_described() -> None:
    # Any other failure of repr is not hidden behind a description that would be false.
    with pytest.raises(ValueError, match="not an integer"):
        quoted(_ReprRaises())


def test_a_list_names_twenty_texts_each_cut_and_counts_the_rest() -> None:
    names = [f"t{i:02d}" for i in range(25)]
    assert listed(names[:20]) == ", ".join(names[:20])
    assert listed(names) == ", ".join(names[:20]) + ", and 5 more"
    assert listed(["a", BIG]) == f"a, {BIG[:300]}... ({len(BIG)} characters)"
    assert listed([]) == ""


def test_an_auth_ref_reference_is_cut_and_a_literal_still_never_shown() -> None:
    assert shown_auth_ref("env://OPENAI_API_KEY") == "'env://OPENAI_API_KEY'"
    assert shown_auth_ref("env://" + BIG) == cut_of("env://" + BIG)
    assert shown_auth_ref("sk-" + BIG) == "a literal value (not shown)"


def test_a_yaml_problem_is_cut_and_keeps_its_position() -> None:
    with pytest.raises(yaml.YAMLError) as caught:
        yaml.safe_load("version: *" + BIG + "\n")
    problem = caught.value.problem  # type: ignore[attr-defined]
    assert problem == "found undefined alias " + repr(BIG)

    assert yaml_problem(caught.value) == (
        f"{problem[:300]}... ({len(problem)} characters) at line 1, column 10"
    )


def test_a_short_yaml_problem_is_unchanged() -> None:
    with pytest.raises(yaml.YAMLError) as caught:
        yaml.safe_load("version: *anchor\n")
    assert yaml_problem(caught.value) == "found undefined alias 'anchor' at line 1, column 10"


def test_text_that_is_not_utf8_is_refused_with_its_path_and_the_offset_in_the_file(
    tmp_path: Path,
) -> None:
    # Past 8 KiB, the size of a decoder's chunk: the offset is the file's, not the chunk's.
    raw = b"a: 1\n#" + b"x" * 10_000 + b"\n\xc3\x28\n"
    path = tmp_path / "f.yaml"
    path.write_bytes(raw)

    with pytest.raises(OSError) as caught:
        read_text_capped(path)

    assert caught.value.errno == errno.EILSEQ
    assert caught.value.filename == str(path)
    offset = raw.index(b"\xc3")
    assert caught.value.strerror == f"not UTF-8 text (byte {offset})"
    assert isinstance(caught.value.__cause__, UnicodeDecodeError)


# --- the CLI ----------------------------------------------------------------------------------


@dataclass
class Case:
    """A command, the operator files it names, and what its one ``error:`` line must say."""

    args: list[str]
    files: list[Path]
    reason: str
    cuts: list[str] = field(default_factory=list)
    exit_code: int = ExitCode.ERROR
    stream: str = "stderr"


def _write(tmp_path: Path, name: str, text: str | bytes) -> Path:
    path = tmp_path / name
    path.write_bytes(text if isinstance(text, bytes) else text.encode("utf-8"))
    return path


def _run(tmp_path: Path, target: str | bytes = TARGET, scope: str | bytes | None = None) -> Case:
    """``run --dry-run`` with this target and scope file."""

    target_path = _write(tmp_path, "target.yaml", target)
    scope_path = _write(tmp_path, "scope.yaml", scope or SCOPE_HEAD + scope_entry())
    specs = write_spec_tree(tmp_path, [make_spec("PI-DIRECT-001")])
    args = ["run", "-t", str(target_path), "--scope", str(scope_path), "--spec-path", str(specs)]
    return Case([*args, "--dry-run"], [target_path, scope_path], "")


def _with(case: Case, file: int | None, reason: str, *cuts: str) -> Case:
    """``case`` with the file its line must name (``None``: the line names no file)."""

    case.files = [] if file is None else [case.files[file]]
    case.reason = reason
    case.cuts = list(cuts)
    return case


def _calibrate(tmp_path: Path, labels: str | bytes) -> Case:
    report = _write(tmp_path, "report.json", "[]")
    path = _write(tmp_path, "labels.yaml", labels)
    return Case(["calibrate", str(report), str(path)], [path], "")


def _fleet(tmp_path: Path, fleet: str | bytes, judge: str | None = None) -> Case:
    path = _write(tmp_path, "fleet.yaml", fleet)
    args = ["fleet", str(path), "--out", str(tmp_path / "out")]
    files = [path]
    if judge is not None:
        judge_path = _write(tmp_path, "judge.yaml", judge)
        args += ["--judge", str(judge_path)]
        files = [judge_path]
    return Case(args, files, "")


def _fingerprint(tmp_path: Path, target: str | bytes) -> Case:
    target_path = _write(tmp_path, "target.yaml", target)
    scope_path = _write(tmp_path, "scope.yaml", SCOPE_HEAD + scope_entry())
    return Case(["fingerprint", str(target_path), "--scope", str(scope_path)], [target_path], "")


def _lint(tmp_path: Path, spec: str) -> Case:
    specs = tmp_path / "specs"
    specs.mkdir()
    _write(specs, "X.yaml", spec)
    case = Case(["lint", str(specs)], [], "PARSE_ERROR", exit_code=1, stream="stdout")
    case.cuts = [ALIAS_CUT]
    return case


#: PyYAML's problem text is cut as it is, not as a repr.
ALIAS = "found undefined alias " + repr(BIG)
ALIAS_CUT = f"{ALIAS[:300]}... ({len(ALIAS)} characters)"
#: Three values of 300,000 characters fit one file under the cap; three of 400,000 do not.
ENTRY = "c" * 300_000
NAME = "d" * 300_000
DUPLICATE_IDENTITY = (
    ("default", "env://MOCK_KEY", None),
    (NAME, "env://A", None),
    (NAME, "env://B", None),
)
SHARED_CANARY = (("default", "env://A", "canary-1"), (NAME, "env://B", "canary-1"))

#: Every refusal that quoted a value of the file whole on the base, built by its command.
QUOTING: dict[str, Callable[[Path], Case]] = {
    "target-type": lambda t: _with(
        _run(t, f"id: mock-target\ntype: {BIG}\n"), 0, "has invalid type", cut_of(BIG)
    ),
    "target-type-list": lambda t: _with(
        _run(t, "id: mock-target\ntype: [" + ", ".join(["x" * 100] * 9_000) + "]\n"),
        0,
        "has invalid type",
        cut_of(["x" * 100] * 9_000),
    ),
    "target-mock-scenario": lambda t: _with(
        _run(t, TARGET + f"mock_scenario: {BIG}\n"), 0, "has invalid mock_scenario", cut_of(BIG)
    ),
    "scope-duplicate-target-id": lambda t: _with(
        _run(t, scope=SCOPE_HEAD + scope_entry(HALF) + scope_entry(HALF)),
        1,
        "more than once",
        cut_of(HALF),
    ),
    "scope-duplicate-identity": lambda t: _with(
        _run(t, scope=SCOPE_HEAD + scope_entry(ENTRY, DUPLICATE_IDENTITY)),
        1,
        "more than once",
        cut_of(ENTRY),
        cut_of(NAME),
    ),
    "scope-shared-canary": lambda t: _with(
        _run(t, scope=SCOPE_HEAD + scope_entry(ENTRY, SHARED_CANARY)),
        1,
        "declares the canary of another identity",
        cut_of(ENTRY),
        cut_of(NAME),
    ),
    "scope-undefined-alias": lambda t: _with(
        _run(t, scope=f"version: *{BIG}\n"), 1, "found undefined alias", ALIAS_CUT
    ),
    "run-two-targets-one-id": lambda t: _run_two_targets(t),
    "run-target-not-in-scope": lambda t: _with(
        _run(t, f"id: {BIG}\ntype: chatbot\n"), None, "not authorized by the scope", cut_of(BIG)
    ),
    "run-auth-ref-not-authorized": lambda t: _with(
        _run(
            t,
            live_target(ENTRY, "env://" + NAME),
            SCOPE_HEAD + scope_entry(ENTRY, (("default", "env://OTHER", None),), live=True),
        ),
        None,
        "is not authorized by the scope",
        cut_of(ENTRY),
        cut_of("env://" + NAME),
    ),
    "run-endpoint-not-on-allowlist": lambda t: _run_endpoint_not_allowed(t),
    "fingerprint-endpoint-not-on-allowlist": lambda t: _fingerprint_endpoint_not_allowed(t),
    "run-stdio-command-not-authorized": lambda t: _run_stdio(t),
    "run-auth-ref-unsupported": lambda t: _with(
        _run(
            t,
            live_target(auth_ref="vault://" + HALF),
            SCOPE_HEAD + scope_entry("live", (("default", "vault://" + HALF, None),), live=True),
        ),
        None,
        "unsupported auth_ref scheme",
        cut_of("vault://" + HALF),
    ),
    "run-hardened-live-target": lambda t: _run_hardened(t),
    "fingerprint-target-not-in-scope": lambda t: _with(
        _fingerprint(t, f"id: {BIG}\ntype: chatbot\n"),
        None,
        "not authorized by the scope",
        cut_of(BIG),
    ),
    "calibrate-undefined-alias": lambda t: _with(
        _calibrate(t, f"x: *{BIG}\n"), 0, "found undefined alias", ALIAS_CUT
    ),
    "calibrate-invalid-verdict": lambda t: _with(
        _calibrate(t, f"? {BIG}\n: maybe\n"), 0, "has an invalid verdict", cut_of(BIG)
    ),
    "fleet-invalid-port": lambda t: _with(
        _fleet(
            t,
            'version: "1"\ntargets:\n  - id: x\n    endpoint: "http://localhost:x/'
            + BIG
            + '"\n    model: m\n',
        ),
        None,
        "has an invalid port",
        cut_of("http://localhost:x/" + BIG),
    ),
    "fleet-judge-not-declared": lambda t: _with(
        _fleet(t, FLEET, judge=f"id: {BIG}\ntype: model\n"), None, "--judge names", cut_of(BIG)
    ),
    "fleet-judge-mismatch": lambda t: _with(
        _fleet(
            t,
            FLEET + JUDGE_BLOCK,
            judge=f'id: judge\ntype: model\nendpoint: "http://localhost:1/{BIG}"\nmodel: m\n',
        ),
        None,
        "does not match the fleet's judge",
        cut_of(f"http://localhost:1/{BIG}"),
    ),
    "lint-undefined-alias": lambda t: _lint(t, f"id: *{BIG}\n"),
    "target-seeded-setup-unknown-key": lambda t: _with(
        _run(t, TARGET + f"seeded_setup:\n  ? {BIG}\n  : x\n"),
        0,
        "has unknown key(s)",
        f"{BIG[:300]}... ({len(BIG)} characters)",
    ),
    "target-seeded-setup-mapped-and-granted": lambda t: _with(
        _run(
            t,
            TARGET + f"seeded_setup:\n  tools: {{lookup: {HALF}}}\n  granted_tools: [{HALF}]\n",
        ),
        0,
        "both maps and grants",
        f"{HALF[:300]}... ({len(HALF)} characters)",
    ),
}


def _run_two_targets(tmp_path: Path) -> Case:
    first = _write(tmp_path, "a.yaml", f"id: {HALF}\ntype: chatbot\n")
    second = _write(tmp_path, "b.yaml", f"id: {HALF}\ntype: chatbot\n")
    scope = _write(tmp_path, "scope.yaml", SCOPE_HEAD + scope_entry())
    specs = write_spec_tree(tmp_path, [make_spec("PI-DIRECT-001")])
    args = ["run", "-t", str(first), "-t", str(second), "--scope", str(scope)]
    return Case(
        [*args, "--spec-path", str(specs), "--dry-run"],
        [first, second],
        "two target files declare the id",
        [cut_of(HALF)],
    )


#: A live target the scope names and whose endpoint it does not allowlist (it allows another
#: path): the id comes back in the list of what the scope authorizes too.
NOT_ALLOWED_ENDPOINT = f"{LIVE_URL}/{NAME}"
NOT_ALLOWED_TARGET = live_target(ENTRY).replace(LIVE_URL, NOT_ALLOWED_ENDPOINT)
NOT_ALLOWED_SCOPE = SCOPE_HEAD + scope_entry(ENTRY, live=True).replace(
    '/v1/chat/completions"]', '/x"]'
)
NOT_ALLOWED_CUTS = (
    cut_of(NOT_ALLOWED_ENDPOINT),
    cut_of(ENTRY),
    f"The scope authorizes: {ENTRY[:300]}... ({len(ENTRY)} characters).",
)


def _run_endpoint_not_allowed(tmp_path: Path) -> Case:
    case = _run(tmp_path, NOT_ALLOWED_TARGET, NOT_ALLOWED_SCOPE)
    return _with(case, None, "not on allowlist", *NOT_ALLOWED_CUTS)


def _fingerprint_endpoint_not_allowed(tmp_path: Path) -> Case:
    case = _fingerprint(tmp_path, NOT_ALLOWED_TARGET)
    _write(tmp_path, "scope.yaml", NOT_ALLOWED_SCOPE)
    return _with(case, None, "not on allowlist", *NOT_ALLOWED_CUTS)


def _run_stdio(tmp_path: Path) -> Case:
    target = (
        f'id: "{ENTRY}"\ntype: api\nprovider: mcp\ntransport: stdio\n'
        'command: ["python", "server.py"]\n'
    )
    scope = SCOPE_HEAD + scope_entry(ENTRY) + '    commands: ["python other.py"]\n'
    return _with(
        _run(tmp_path, target, scope),
        None,
        "stdio command not authorized",
        cut_of(ENTRY),
        f"{ENTRY[:300]}... ({len(ENTRY)} characters) (stdio command not authorized for",
        'commands: ["python server.py"]',
    )


def _run_hardened(tmp_path: Path) -> Case:
    case = _run(
        tmp_path,
        live_target(BIG, "env://LIVE_KEY"),
        SCOPE_HEAD + scope_entry(BIG, (("default", "env://LIVE_KEY", None),), live=True),
    )
    case.args.append("--hardened")
    return _with(case, 0, "--hardened replays", cut_of(BIG))


@pytest.mark.parametrize("name", list(QUOTING))
def test_a_refusal_quotes_a_value_of_the_file_up_to_300_characters(
    tmp_path: Path, name: str
) -> None:
    case = QUOTING[name](tmp_path)

    result = runner.invoke(app, case.args)

    assert result.exit_code == case.exit_code, (result.exception, result.output[:2000])
    lines = getattr(result, case.stream).splitlines()
    line = next((x for x in lines if case.reason in x), None)
    assert line is not None, [x[:300] for x in lines]
    # Length first, so the base fails on the defect (a line of 500 KB to 2 MB), not the text.
    assert len(line) < 2_500, len(line)
    assert all(str(path) in line for path in case.files), line
    assert all(cut in line for cut in case.cuts), line
    assert "REDACTED" not in line, line


#: A file that is not UTF-8, as each command reads it: one byte 0xff after a valid first line.
NOT_UTF8: dict[str, Callable[[Path], Case]] = {
    "run-target": lambda t: _with(_run(t, b"id: mock-target\n\xff\n"), 0, ""),
    "run-scope": lambda t: _with(_run(t, scope=b'version: "1.0"\n\xff\n'), 1, ""),
    "calibrate-labels": lambda t: _calibrate(t, b"x: pass\n\xff\n"),
    "fleet": lambda t: _fleet(t, b'version: "1"\n\xff\n'),
    "fingerprint-target": lambda t: _fingerprint(t, b"id: mock-target\n\xff\n"),
}


@pytest.mark.parametrize("name", list(NOT_UTF8))
def test_a_file_that_is_not_utf8_is_named_with_the_offset_and_exit_3(
    tmp_path: Path, name: str
) -> None:
    case = NOT_UTF8[name](tmp_path)
    [path] = case.files
    offset = path.read_bytes().index(b"\xff")

    result = runner.invoke(app, case.args)

    assert result.exit_code == ExitCode.ERROR, (result.exception, result.output[:2000])
    [line] = result.stderr.splitlines()
    assert line.startswith("error: ") and str(path) in line, line
    assert f"not UTF-8 text (byte {offset})" in line, line
    assert "codec" not in line, line


# --- refusals outside the CLI table -------------------------------------------------------


def test_a_resume_refusal_quotes_the_target_ids_up_to_300_characters(tmp_path: Path) -> None:
    target = Target(id=NAME, type="chatbot")  # type: ignore[arg-type]
    db = tmp_path / "runs.sqlite"

    with pytest.raises(ValueError, match="no run store") as missing:
        _assert_same_target(db, "run-1", target)
    with SqliteRunStore(db) as store:
        store.save_run_context("run-1", target_id=ENTRY)
    with pytest.raises(ValueError, match="is not in the run store") as unknown:
        _assert_same_target(db, "run-2", target)
    with pytest.raises(ValueError, match="was made against target") as other:
        _assert_same_target(db, "run-1", target)

    for caught in (missing, unknown, other):
        assert len(str(caught.value)) < 2_500 and cut_of(NAME) in str(caught.value)
    assert cut_of(ENTRY) in str(other.value)


#: A scope of 25 targets, none of them the one a command names.
MANY_TARGETS = SCOPE_HEAD + "".join(
    scope_entry(f"t{i:02d}").replace('"mock-target"', f'"t{i:02d}"') for i in range(25)
)
LISTED_25 = ", ".join(f"t{i:02d}" for i in range(20)) + ", and 5 more."


@pytest.mark.parametrize("command", ["run", "fingerprint"])
def test_an_authorization_refusal_lists_twenty_ids_of_the_scope(
    tmp_path: Path, command: str
) -> None:
    if command == "run":
        case = _run(tmp_path, TARGET, MANY_TARGETS)
    else:
        case = _fingerprint(tmp_path, TARGET)
        _write(tmp_path, "scope.yaml", MANY_TARGETS)

    result = runner.invoke(app, case.args)

    assert result.exit_code == ExitCode.ERROR, result.output
    assert f"The scope authorizes: {LISTED_25}" in result.stderr, result.stderr


def test_a_credential_refusal_lists_twenty_declared_references(tmp_path: Path) -> None:
    identities = tuple((f"id{i:02d}", f"env://K{i:02d}", None) for i in range(25))
    case = _run(
        tmp_path,
        live_target(auth_ref="env://OTHER"),
        SCOPE_HEAD + scope_entry("live", identities, live=True),
    )

    result = runner.invoke(app, case.args)

    assert result.exit_code == ExitCode.ERROR, result.output
    declared = ", ".join(f"'env://K{i:02d}'" for i in range(20)) + ", and 5 more"
    assert f"(declared: {declared});" in result.stderr, result.stderr


# --- values turned into text before they are checked -----------------------------------------

#: A YAML integer of 20,000 bits, written in hex: past the 4,300 digits Python writes as text.
HEX = "0x" + "f" * 5_000


@pytest.mark.parametrize(
    ("load", "body"),
    [
        # The anchor inside the list: a label before it would be refused first.
        (load_labels, "y: [&a " + "a" * 10_000 + ", " + ALIASES[1:] + "\n"),
        (
            target_uses_mock,
            f"{ANCHOR}id: t\ntype: chatbot\nprovider: {ALIASES}\ntransport: stdio\n",
        ),
    ],
    ids=["labels-verdict", "target-provider"],
)
def test_a_list_of_aliases_is_not_turned_into_text(
    tmp_path: Path, load: Callable[[Path], object], body: str
) -> None:
    # `str()` of it wrote about 675 MB of text before the value was checked (audit of A-51).
    path = tmp_path / "file.yaml"
    path.write_text(body, encoding="utf-8")
    loaded, reference = peak_of(lambda: safe_yaml.safe_load(path.read_text(encoding="utf-8")))
    assert isinstance(loaded, dict)

    _, peak = peak_of(lambda: load(path))

    assert peak < reference + 8_000_000, (peak, reference)


def test_an_integer_label_key_is_refused_as_a_key_not_as_its_verdict(tmp_path: Path) -> None:
    case = _calibrate(tmp_path, f"? {HEX}\n: pass\n")

    result = runner.invoke(app, case.args)

    assert result.exit_code == ExitCode.ERROR, result.output
    [line] = result.stderr.splitlines()
    assert str(case.files[0]) in line and "verdict" not in line, line
    assert "<an integer of 20000 bits> cannot be a spec id: an integer that long" in line, line


def test_an_integer_key_or_provider_of_a_target_is_not_turned_into_text(tmp_path: Path) -> None:
    path = tmp_path / "target.yaml"
    path.write_text(f"id: t\ntype: chatbot\nprovider: {HEX}\ntransport: {HEX}\n", "utf-8")
    assert target_uses_mock(path) is True

    case = _with(_run(tmp_path, TARGET + f"seeded_setup:\n  ? {HEX}\n  : x\n"), 0, "")
    result = runner.invoke(app, case.args)
    assert result.exit_code == ExitCode.ERROR, result.output
    assert "has unknown key(s) <an integer of 20000 bits>;" in result.stderr, result.stderr


def test_a_credential_variable_is_named_up_to_300_characters(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    name = "K" * 100_000
    monkeypatch.setenv(name, "line\nbreak")

    with pytest.raises(ValueError, match="contains a control character") as caught:
        resolve_auth_ref(f"env://{name}")

    assert len(str(caught.value)) < 2_500 and cut_of(name) in str(caught.value)


# --- URLs urllib cannot read --------------------------------------------------------------

#: A long host or port urllib refuses, and quoted whole: 900 KB with no file named (pre-merge
#: audit of A-51). The fullwidth solidus is a host NFKC turns into a path.
LONG = "x" * 300_000
SOLIDUS = chr(0xFF0F)
NBSP = chr(0xA0)
BAD_PORT = f"https://api.openai.com:{LONG}/v1/chat/completions"


def _live(tmp_path: Path, endpoint: str, scope_host: str = "api.openai.com") -> Case:
    target = live_target().replace(LIVE_URL, endpoint)
    scope = SCOPE_HEAD + scope_entry("live", live=True).replace(
        '"api.openai.com"', f'"{scope_host}"'
    )
    return _run(tmp_path, target, scope)


URLS: dict[str, Callable[[Path], Case]] = {
    "target-endpoint-open-bracket": lambda t: _with(
        _live(t, f"https://[{LONG}/v1"), 0, "'endpoint' is not a URL that can be read"
    ),
    "target-endpoint-nfkc-host": lambda t: _with(
        _live(t, f"https://h{SOLIDUS}{LONG}/v1"), 0, "'endpoint' is not a URL that can be read"
    ),
    # Not an IP between the brackets: urllib quoted the whole host.
    "target-endpoint-bracketed-host": lambda t: _with(
        _live(t, f"https://[{LONG}]/v1"), 0, "'endpoint' is not a URL that can be read"
    ),
    # The gate strips the endpoint; read raw, U+00A0 in front hid the host from the check.
    "target-endpoint-nbsp-nfkc-host": lambda t: _with(
        _live(t, f"{NBSP}https://h{SOLIDUS}{LONG}/v1"),
        0,
        "'endpoint' is not a URL that can be read",
    ),
    "scope-base-url-bracketed-host": lambda t: _with(
        _run(t, scope=SCOPE_HEAD + scope_entry().replace("mock://mock-target", f"mock://[{LONG}]")),
        None,
        "not on allowlist",
        cut_of(f"mock://[{LONG}]"),
    ),
    "fleet-endpoint-nbsp-nfkc-host": lambda t: _with(
        _fleet(
            t,
            f'version: "1"\ntargets:\n  - id: x\n    endpoint: "{NBSP}http://h{SOLIDUS}{LONG}"\n'
            "    model: m\n",
        ),
        None,
        "is not a URL that can be read",
        cut_of(f"{NBSP}http://h{SOLIDUS}{LONG}"),
    ),
    "run-target-port": lambda t: _with(
        _live(t, BAD_PORT), None, "not on allowlist", cut_of(BAD_PORT)
    ),
    "fingerprint-target-port": lambda t: _fingerprint_port(t),
    "scope-base-url-port": lambda t: _with(
        _run(t, scope=SCOPE_HEAD + scope_entry().replace("mock://mock-target", f"mock://h:{LONG}")),
        None,
        "not on allowlist",
        cut_of(f"mock://h:{LONG}"),
    ),
    "scope-base-url-open-bracket": lambda t: _with(
        _run(t, scope=SCOPE_HEAD + scope_entry().replace("mock://mock-target", f"mock://[{LONG}")),
        None,
        "not on allowlist",
        cut_of(f"mock://[{LONG}"),
    ),
    "fleet-endpoint-open-bracket": lambda t: _with(
        _fleet(
            t,
            'version: "1"\ntargets:\n  - id: x\n    endpoint: "http://['
            + LONG
            + '"\n    model: m\n',
        ),
        None,
        "is not a URL that can be read",
        cut_of(f"http://[{LONG}"),
    ),
    "run-target-port-of-5000-digits": lambda t: _with(
        _live(t, "https://api.openai.com:" + "9" * 5_000 + "/v1/chat/completions"),
        None,
        "not on allowlist",
    ),
    "scope-host-port-of-5000-digits": lambda t: _with(
        _live(t, LIVE_URL, scope_host="api.openai.com:" + "9" * 5_000), None, "not on allowlist"
    ),
}


def _fingerprint_port(tmp_path: Path) -> Case:
    case = _fingerprint(tmp_path, live_target().replace(LIVE_URL, BAD_PORT))
    _write(tmp_path, "scope.yaml", SCOPE_HEAD + scope_entry("live", live=True))
    return _with(case, None, "not on allowlist", cut_of(BAD_PORT))


@pytest.mark.parametrize("name", list(URLS))
def test_a_url_urllib_cannot_read_is_refused_without_its_error(tmp_path: Path, name: str) -> None:
    case = URLS[name](tmp_path)

    result = runner.invoke(app, case.args)

    assert result.exit_code == ExitCode.ERROR, (result.exception, result.output[:2000])
    [line] = result.stderr.splitlines()
    assert len(line) < 2_500, len(line)
    assert case.reason in line and all(str(p) in line for p in case.files), line
    assert all(cut in line for cut in case.cuts), line
    assert "Exceeds the limit" not in line and "could not be cast" not in line, line
    if case.reason.startswith("'endpoint'"):
        # The target loader names the field, never the value: an endpoint can hold a password.
        assert "x" * 50 not in line, line


@pytest.mark.parametrize("command", ["run", "fingerprint"])
def test_an_endpoint_urllib_cannot_read_never_prints_its_password(
    tmp_path: Path, command: str
) -> None:
    endpoint = f"{NBSP}https://admin:Hunter2!Secret@gateway{SOLIDUS}v1/chat/completions"
    target = live_target().replace(LIVE_URL, endpoint)
    case = _run(tmp_path, target) if command == "run" else _fingerprint(tmp_path, target)

    result = runner.invoke(app, case.args)

    assert result.exit_code == ExitCode.ERROR, result.output
    [line] = result.stderr.splitlines()
    assert "'endpoint' is not a URL that can be read" in line and str(case.files[0]) in line
    assert "Hunter2" not in line and "netloc" not in line, line


def test_an_entry_the_allowlist_cannot_read_matches_nothing_and_blocks_nothing() -> None:
    # Pinned to a port of 5,000 digits it raised, and denied every URL checked after it, so a
    # good entry behind it was refused and in front of it allowed (delta audit of A-51).
    bad = Endpoint(host="api.openai.com:" + "9" * 5_000, path_prefixes=["/"])
    good = Endpoint(host="api.openai.com", path_prefixes=["/"])

    assert EndpointAllowlist([bad, good]).is_allowed(LIVE_URL)
    assert EndpointAllowlist([good, bad]).is_allowed(LIVE_URL)
    assert not EndpointAllowlist([bad]).is_allowed(LIVE_URL)
    for port in (chr(0xB2), "abc"):
        entry = Endpoint(host=f"api.openai.com:{port}")
        assert not EndpointAllowlist([entry]).is_allowed(LIVE_URL), port
    # Read as a bare host, an unreadable port matched an IPvFuture literal that repeated it.
    for port in (chr(0xB2), "9" * 5_000):
        entry = Endpoint(host=f"v1.a:{port}")
        for url in (f"https://[v1.a:{port}]/x", f"mock://[v1.a:{port}]/x"):
            assert not EndpointAllowlist([entry]).is_allowed(url), url[:40]


@pytest.mark.parametrize(
    ("fleet", "judge"),
    [
        (f"http://:Hunter2Secret@h{SOLIDUS}x", None),
        ("http://u:pass word Hunter2@localhost:x/v1", None),
        (f"{NBSP}http://a@b:Hunter2@h{SOLIDUS}x", None),
        (
            "http://localhost:1/v1/chat/completions",
            "http://u:pass word Hunter2@localhost:2/v1/chat/completions",
        ),
    ],
    ids=["empty-user", "space-in-password", "second-at", "judge-mismatch"],
)
def test_fleet_never_prints_an_endpoint_password(
    tmp_path: Path, fleet: str, judge: str | None
) -> None:
    # The CLI masks a password only in the `user:password@` shape (delta audit of A-51).
    body = f'version: "1"\ntargets:\n  - id: x\n    endpoint: "{fleet}"\n    model: m\n'
    judge_file = None
    if judge is not None:
        body += f'judge:\n  id: judge\n  endpoint: "{judge}"\n  model: m\n'
        judge_file = f'id: judge\ntype: model\nendpoint: "{fleet}"\nmodel: m\n'
    case = _fleet(tmp_path, body, judge=judge_file)

    result = runner.invoke(app, case.args)

    assert result.exit_code == ExitCode.ERROR, result.output
    assert "Hunter2" not in result.stderr, result.stderr


# --- what the text checks kept as it was -----------------------------------------------------


def test_a_verdict_is_read_in_any_case_and_with_spaces(tmp_path: Path) -> None:
    path = tmp_path / "labels.yaml"
    path.write_text('A: PASS\nB: " fail "\nC: Inconclusive\n', encoding="utf-8")

    assert {k: v.value for k, v in load_labels(path).items()} == {
        "A": "pass",
        "B": "fail",
        "C": "inconclusive",
    }


@pytest.mark.parametrize(
    ("lines", "uses_mock"),
    [
        ('provider: " MCP "\ntransport: STDIO\ncommand: [server]\n', False),
        ("provider: mcp\ntransport: stdio\n", True),
        ("provider: mcp\ntransport: stdio\ncommand: []\n", True),
        ("provider: mcp\ntransport: http\ncommand: [server]\n", True),
    ],
    ids=["stdio-with-command", "no-command", "empty-command", "not-stdio"],
)
def test_a_stdio_target_is_real_only_with_a_command(
    tmp_path: Path, lines: str, uses_mock: bool
) -> None:
    path = tmp_path / "target.yaml"
    path.write_text("id: t\ntype: agent\n" + lines, encoding="utf-8")
    assert target_uses_mock(path) is uses_mock


def test_a_transport_of_aliases_is_not_turned_into_text(tmp_path: Path) -> None:
    # `provider` is checked first, so it says `mcp` here and `transport` is the one read.
    path = tmp_path / "target.yaml"
    path.write_text(
        f"{ANCHOR}id: t\ntype: agent\nprovider: mcp\ntransport: {ALIASES}\ncommand: [s]\n",
        encoding="utf-8",
    )
    loaded, reference = peak_of(lambda: safe_yaml.safe_load(path.read_text(encoding="utf-8")))
    assert isinstance(loaded, dict)

    uses_mock, peak = peak_of(lambda: target_uses_mock(path))

    assert uses_mock is True
    assert peak < reference + 8_000_000, (peak, reference)


def test_a_date_key_of_seeded_setup_is_written_as_before(tmp_path: Path) -> None:
    case = _run(tmp_path, TARGET + "seeded_setup:\n  2024-01-01: x\n")

    result = runner.invoke(app, case.args)

    assert result.exit_code == ExitCode.ERROR, result.output
    assert "has unknown key(s) 2024-01-01;" in result.stderr, result.stderr


@pytest.mark.parametrize(
    ("endpoint", "shown"),
    [
        ("http://u:Hunter2@h/v1@x", "'http://h/v1@x'"),
        ("//u:Hunter2@h/v1", "'//h/v1'"),
        ("https://h/v1", "'https://h/v1'"),
        ("no-authority@h", "'no-authority@h'"),
    ],
)
def test_an_endpoint_is_quoted_without_what_precedes_the_last_at_of_its_authority(
    endpoint: str, shown: str
) -> None:
    assert _shown_endpoint(endpoint) == shown
