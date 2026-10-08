"""A target file's top level holds the keys a reader reads, and text where text is read.

``load_target`` read the top level of a target file with ``raw.get(...)`` and never looked at
the rest, and read ``name``, ``provider``, ``endpoint``, ``model``, ``auth_ref`` and
``transport`` as absent when they were not text. So a misspelled key (``endpont:``) or an
endpoint written as a list was dropped without a word, the target had no endpoint, and
``target_uses_mock`` sent the run to the offline mock: ``dottore run`` against a live model
sent it nothing and scored the mock's replies (one spec inconclusive with exit 0; the full
battery a FAIL and a PASS with exit 1). A ``capabilities:`` whose children
lost their indent left ``tools``, ``rag`` and ``memory`` at the top level, ignored, and the specs
that need them out of the plan (a ``type: model`` target planned 34 specs instead of 59, on
``2f6201a``). Found while writing u12 A-50; clause u12 A-53, owner's decision OD-31.
"""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml
from typer.testing import CliRunner

from ildottore.cli import fleet as fleet_mod
from ildottore.cli import wiring
from ildottore.cli.app import _masked
from ildottore.cli.main import app
from ildottore.shared.models import Target
from tests.cli.test_target_file_validation import dry_run, pieces, refusal

runner = CliRunner()

REPO = Path(__file__).resolve().parents[2]

#: Every key a target file may hold at its top level: the target's own fields, plus the offline
#: mock's selector, which :func:`wiring.load_mock_scenario` reads.
LEGAL = {*Target.model_fields, "mock_scenario"}

#: The fields read as text: anything else written there was read as absent.
TEXT_FIELDS = ("name", "provider", "endpoint", "model", "auth_ref", "transport")

#: A live target, routed to the real adapter when nothing is wrong with it.
LIVE = (
    "id: mock-target\ntype: chatbot\nprovider: openai\n"
    "endpoint: https://relay.example.org/v1/chat/completions\nmodel: relay-model-alpha\n"
)

#: (the file's text, the value in it the output must not quote, what the error must say).
#: Each value is one the CLI's redactor leaves readable, so its absence is the loader's doing.
BAD_FILES = {
    "misspelled endpoint": (
        "id: mock-target\ntype: chatbot\nprovider: openai\n"
        "endpont: https://{value}/v1/chat/completions\nmodel: relay-model-alpha\n",
        "relay-gateway.example.org",
        "failed validation: endpont: Extra inputs are not permitted",
    ),
    "capabilities lost their indent": (
        LIVE + "capabilities:\ntools: true\nrag: {value}\n",
        "maybe-later",
        "failed validation: tools: Extra inputs are not permitted; "
        "rag: Extra inputs are not permitted",
    ),
    "sampling key at the top level": (
        LIVE + "temperature: {value}\n",
        "0.25",
        "failed validation: temperature: Extra inputs are not permitted",
    ),
    "name not text": (
        "id: mock-target\ntype: chatbot\nname: [{value}]\n",
        "support-bot-eu",
        "failed validation: name: Input should be a valid string",
    ),
    "provider not text": (
        "id: mock-target\ntype: chatbot\nprovider: [{value}]\n"
        "endpoint: https://relay.example.org/v1/chat/completions\n",
        "openai-relay",
        "failed validation: provider: Input should be a valid string",
    ),
    "endpoint not text": (
        "id: mock-target\ntype: chatbot\nprovider: openai\n"
        "endpoint: [https://{value}/v1/chat/completions]\nmodel: relay-model-alpha\n",
        "relay-gateway.example.org",
        "failed validation: endpoint: Input should be a valid string",
    ),
    "model read as a number": (
        "id: mock-target\ntype: chatbot\nprovider: openai\n"
        "endpoint: https://relay.example.org/v1/chat/completions\nmodel: {value}\n",
        "20240613",
        "failed validation: model: Input should be a valid string",
    ),
    "model written as binary": (
        # pydantic reads bytes as text unless the field is strict: the one value a plain `str`
        # field would let through, decoded.
        "id: mock-target\ntype: chatbot\nprovider: openai\n"
        "endpoint: https://relay.example.org/v1/chat/completions\nmodel: !!binary {value}\n",
        "bW9kZWw=",
        "failed validation: model: Input should be a valid string",
    ),
    "auth_ref not text": (
        LIVE + "auth_ref: {{env: {value}}}\n",
        "RELAY_API_KEY_PROD",
        "failed validation: auth_ref: Input should be a valid string",
    ),
    "transport read as a number": (
        "id: mock-target\ntype: api\nprovider: mcp\ntransport: {value}\n"
        "command: [python, server.py]\n",
        "2.5",
        "failed validation: transport: Input should be a valid string",
    ),
    "key not text": (
        LIVE + "1: {value}\n",
        "stray-number-key",
        "failed validation: 1: Keys should be strings",
    ),
}


def write_scope(tmp_path: Path) -> Path:
    """A scope authorizing ``mock-target`` and ``mock-judge`` at the live endpoint the files
    name, so that on ``2f6201a`` a file this test refuses ran (exit 0) rather than being refused
    by the scope for another reason."""

    entries = "".join(
        f"  - id: {target_id}\n"
        '    base_url: "https://relay.example.org"\n'
        "    endpoints:\n"
        '      - host: "relay.example.org"\n'
        '        path_prefixes: ["/"]\n'
        "    identities:\n"
        "      - name: default\n"
        '        auth_ref: "env://MOCK_KEY"\n'
        for target_id in ("mock-target", "mock-judge")
    )
    path = tmp_path / "scope.yaml"
    path.write_text(f'version: "1.0"\ntargets:\n{entries}', encoding="utf-8")
    return path


def write_file(tmp_path: Path, case: str, *, target_id: str = "mock-target") -> Path:
    text, value, _ = BAD_FILES[case]
    path = tmp_path / f"{target_id}.yaml"
    path.write_text(text.format(value=value).replace("mock-target", target_id), encoding="utf-8")
    return path


@pytest.mark.parametrize("case", sorted(BAD_FILES))
def test_run_refuses_the_file_naming_it_and_the_key(tmp_path: Path, case: str) -> None:
    _, value, where = BAD_FILES[case]
    target = write_file(tmp_path, case)

    result = dry_run(target, write_scope(tmp_path))

    assert where in refusal(result, target, value)


@pytest.mark.parametrize("case", sorted(BAD_FILES))
def test_a_judge_file_is_refused_the_same_way(tmp_path: Path, case: str) -> None:
    _, value, where = BAD_FILES[case]
    target = tmp_path / "target.yaml"
    target.write_text("id: mock-target\ntype: chatbot\nmock_scenario: hardened\n", encoding="utf-8")
    judge = write_file(tmp_path, case, target_id="mock-judge")

    result = dry_run(target, write_scope(tmp_path), "--judge", str(judge))

    assert where in refusal(result, judge, value)


def test_a_live_run_with_a_misspelled_endpoint_is_refused_not_run_on_the_mock(
    tmp_path: Path,
) -> None:
    """The run itself, not only the dry run: on ``2f6201a`` it ran every spec against the
    offline mock and exited 0, inconclusive, without a word about the endpoint."""

    _, value, where = BAD_FILES["misspelled endpoint"]
    target = write_file(tmp_path, "misspelled endpoint")
    spec = REPO / "specs" / "attacks" / "PI-DIRECT-001.yaml"

    args = ["-t", str(target), "--scope", str(write_scope(tmp_path)), "--spec-path", str(spec)]
    stores = ["--evidence-root", str(tmp_path / "ev"), "--run-db", str(tmp_path / "run.db")]

    result = runner.invoke(app, ["run", *args, *stores])

    assert where in refusal(result, target, value)
    assert "Specs run" not in result.output
    assert not (tmp_path / "ev").exists()


def test_fingerprint_refuses_the_file(tmp_path: Path) -> None:
    _, value, where = BAD_FILES["endpoint not text"]
    target = write_file(tmp_path, "endpoint not text")

    result = runner.invoke(
        app, ["fingerprint", str(target), "--scope", str(write_scope(tmp_path)), "--offline"]
    )

    assert where in refusal(result, target, value)


def test_fleet_refuses_a_judge_file_with_an_unknown_key(tmp_path: Path) -> None:
    judge = tmp_path / "local-judge.yaml"
    judge.write_text(
        "id: local-judge\ntype: model\nprovider: openai\n"
        "endpoint: http://localhost:11434/v1/chat/completions\nmodle: j\n",
        encoding="utf-8",
    )
    fleet = tmp_path / "fleet.yaml"
    fleet.write_text(
        'version: "1"\ntargets:\n  - id: local\n'
        "    endpoint: http://localhost:11434/v1/chat/completions\n    model: m\n"
        "judge:\n  id: local-judge\n"
        "  endpoint: http://localhost:11434/v1/chat/completions\n  model: j\n",
        encoding="utf-8",
    )

    result = runner.invoke(
        app, ["fleet", str(fleet), "--judge", str(judge), "--out", str(tmp_path / "out")]
    )

    assert "failed validation: modle: Extra inputs are not permitted" in refusal(
        result, judge, "localhost:11434"
    )


@pytest.mark.parametrize("case", sorted(BAD_FILES))
def test_every_reader_of_the_file_refuses_it(tmp_path: Path, case: str) -> None:
    """``target_uses_mock`` decides the route before ``load_target`` reads the target: a
    non-text ``endpoint`` sent the run to the mock there, so each reader checks the file."""

    _, value, where = BAD_FILES[case]
    path = write_file(tmp_path, case)

    for read in (wiring.load_target, wiring.target_uses_mock, wiring.load_mock_scenario):
        with pytest.raises(ValueError) as refused:
            read(path)
        assert type(refused.value) is ValueError, read
        message = str(refused.value)
        assert message.startswith(f"target file {path} failed validation: "), (read, message)
        assert where in message, (read, message)
        assert "\n" not in message
        for piece in pieces(value):
            assert piece not in message, (read, piece)


@pytest.mark.parametrize("case", sorted(BAD_FILES))
def test_the_cli_redactor_leaves_each_value_readable(case: str) -> None:
    """Otherwise the CLI tests above could pass on a value the redactor masked, not omitted."""

    value = BAD_FILES[case][1]
    assert value in _masked(ValueError(f"got {value} here"))


def test_a_file_with_each_key_the_manual_lists_loads(tmp_path: Path) -> None:
    """The thirteen keys docs/MANUAL.md section 4.2 lists, in one file, through every reader. A
    field added to ``Target`` with its own rules (another branch's ``websocket`` needs
    ``provider: websocket``) is covered key by key below, not by adding it here."""

    path = tmp_path / "t.yaml"
    path.write_text(
        "id: t\ntype: chatbot\nname: Support bot\nprovider: mcp\n"
        "endpoint: https://relay.example.org/mcp\nmodel: relay-model-alpha\n"
        "auth_ref: env://RELAY_KEY\ncapabilities: { tools: true }\n"
        "sampling_defaults: { temperature: 0.0 }\ntransport: http\ncommand: [python, server.py]\n"
        "seeded_setup: { specs: [PI-INDIRECT-TOOL-001] }\nmock_scenario: hardened\n",
        encoding="utf-8",
    )
    written = yaml.safe_load(path.read_text(encoding="utf-8"))
    assert len(written) == 13 and set(written) <= LEGAL

    target = wiring.load_target(path)

    assert (target.name, target.transport, target.command) == (
        "Support bot",
        "http",
        ["python", "server.py"],
    )
    assert wiring.target_uses_mock(path)
    assert wiring.load_mock_scenario(path) == "hardened"


@pytest.mark.parametrize("field", TEXT_FIELDS)
def test_a_text_field_written_as_bytes_is_refused(tmp_path: Path, field: str) -> None:
    """pydantic reads bytes as text unless the field is strict: a lax ``endpoint`` let a
    ``!!binary`` endpoint through, which ``target_uses_mock`` then sent to the mock (audit)."""

    path = tmp_path / "t.yaml"
    # The base64 of `https://relay.example.org/v1`.
    path.write_text(
        f"id: t\ntype: chatbot\n{field}: !!binary aHR0cHM6Ly9yZWxheS5leGFtcGxlLm9yZy92MQ==\n",
        encoding="utf-8",
    )

    for read in (wiring.load_target, wiring.target_uses_mock, wiring.load_mock_scenario):
        with pytest.raises(
            ValueError, match=f"failed validation: {field}: Input should be a valid"
        ):
            read(path)


@pytest.mark.parametrize(
    ("line", "refusal"),
    [
        ("id: [t]\ntype: chatbot\n", "is missing a string 'id'"),
        ("id: t\ntype: 7\n", "has invalid type 7"),
    ],
    ids=["id", "type"],
)
def test_id_and_type_keep_their_own_refusals(tmp_path: Path, line: str, refusal: str) -> None:
    """The top-level check leaves ``id`` and ``type`` to ``load_target``, whose messages say what
    the file needs (and quote ``type``, as A-45 lists)."""

    path = tmp_path / "t.yaml"
    path.write_text(line, encoding="utf-8")

    with pytest.raises(ValueError, match=refusal):
        wiring.load_target(path)


@pytest.mark.parametrize("field", TEXT_FIELDS)
@pytest.mark.parametrize("empty", ["", " null", " ~"])
def test_a_text_field_with_nothing_or_null_is_still_absent(
    tmp_path: Path, field: str, empty: str
) -> None:
    path = tmp_path / "t.yaml"
    path.write_text(f"id: t\ntype: chatbot\n{field}:{empty}\n", encoding="utf-8")

    target = wiring.load_target(path)

    assert getattr(target, field) is None
    assert wiring.target_uses_mock(path)


def test_load_target_reads_every_field_of_target(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The check takes every field of ``Target`` as a key the file may hold; one that
    ``load_target`` never read would be accepted and dropped, the silence A-53 closes (audit)."""

    seen: set[str] = set()

    def recording(**fields: object) -> Target:
        seen.update(fields)
        return Target(**fields)

    monkeypatch.setattr(wiring, "Target", recording)
    path = tmp_path / "t.yaml"
    path.write_text("id: t\ntype: chatbot\n", encoding="utf-8")

    wiring.load_target(path)

    assert seen == set(Target.model_fields)


def test_every_text_field_of_target_is_refused_as_bytes(tmp_path: Path) -> None:
    """``_TEXT_FIELDS`` is every ``str | None`` field of ``Target``: these six at least, and a
    text field added there is refused as bytes too, as a lax ``str`` would not (audit)."""

    assert set(TEXT_FIELDS) <= set(wiring._TEXT_FIELDS)
    for field in wiring._TEXT_FIELDS:
        path = tmp_path / f"{field}.yaml"
        path.write_text(f"id: t\ntype: chatbot\n{field}: !!binary aGk=\n", encoding="utf-8")
        with pytest.raises(
            ValueError, match=f"failed validation: {field}: Input should be a valid"
        ):
            wiring.target_uses_mock(path)


@pytest.mark.parametrize("key", sorted(LEGAL - {"id", "type"}))
def test_every_legal_key_passes_the_top_level_check(tmp_path: Path, key: str) -> None:
    """Every field of :class:`Target`, and ``mock_scenario``, with nothing after it: what is
    tested is the top-level check alone, not each block's own reader. The check is built from
    ``Target``, so a field added there (another branch adds ``websocket``) is legal at once
    (pre-merge audit: a list kept by hand refused it)."""

    path = tmp_path / "t.yaml"
    path.write_text(f"id: t\ntype: chatbot\n{key}:\n", encoding="utf-8")

    assert wiring._read_target_yaml(path)[key] is None


# --- every target file the repository ships or documents still loads ----------------------

_FENCED_YAML = r"```ya?ml\n(.*?)```"
_MAN_BLOCK = r"^\.nf\n(.*?)^\.fi"


def _repository_texts() -> list[tuple[str, str]]:
    """Every YAML file under examples/, specs/ and tests/, every fenced YAML block of the
    Markdown docs and every literal block of the man pages, as (where, text)."""

    import re

    texts: list[tuple[str, str]] = []
    for folder in ("examples", "specs", "tests"):
        for path in sorted((REPO / folder).rglob("*")):
            if path.suffix in (".yaml", ".yml"):
                texts.append((str(path), path.read_text(encoding="utf-8")))
    markdown = [
        *sorted(REPO.glob("*.md")),
        *sorted((REPO / "docs").rglob("*.md")),
        *sorted((REPO / "examples").rglob("*.md")),
        *sorted((REPO / "specs").rglob("*.md")),
    ]
    for path in markdown:
        blocks = re.findall(_FENCED_YAML, path.read_text(encoding="utf-8"), re.S)
        texts += [(f"{path} block {index}", block) for index, block in enumerate(blocks)]
    for path in sorted((REPO / "man").rglob("*.[1-9]")):
        blocks = re.findall(_MAN_BLOCK, path.read_text(encoding="utf-8"), re.S | re.M)
        texts += [(f"{path} block {index}", block) for index, block in enumerate(blocks)]
    return texts


def _is_target(doc: object) -> bool:
    """A mapping with a target's ``type`` and an ``id``, an endpoint or a provider (a spec has
    no ``type``; a scope's targets are under ``targets``)."""

    return (
        isinstance(doc, dict)
        and doc.get("type") in ("model", "chatbot", "agent", "rag", "api")
        and bool({"id", "endpoint", "provider"} & set(doc))
    )


def test_every_target_file_in_the_repository_still_loads(tmp_path: Path) -> None:
    targets: list[tuple[str, str, dict[str, object]]] = []
    for where, text in _repository_texts():
        try:
            docs = list(yaml.safe_load_all(text))
        except yaml.YAMLError:
            continue  # a broken fixture belongs to the YAML tests; a target example is below
        targets += [(where, text, doc) for doc in docs if _is_target(doc)]
    # Not vacuous: the shipped examples and the target blocks of the docs are among them.
    names = {Path(where.split(" block ")[0]).name for where, _, _ in targets}
    shipped = {
        "target.local.yaml",
        "target.app.yaml",
        "target.judge.yaml",
        "target.mcp.yaml",
        "target.openai.yaml",
        "example-openai.yaml",
    }
    assert shipped | {"MANUAL.md", "USAGE.md", "dottore-scope.5"} <= names, names

    # The text as written, not a re-dump: what must load is what the operator copies.
    for index, (where, text, doc) in enumerate(targets):
        path = tmp_path / f"target-{index}.yaml"
        path.write_text(text, encoding="utf-8")
        assert wiring.load_target(path).id == doc["id"], where
        if wiring.target_uses_mock(path):
            wiring.load_mock_scenario(path)
        assert set(doc) <= LEGAL, where


@pytest.mark.parametrize("fleet", ["examples/fleet.yaml", "specs/fleet.example.yaml"])
def test_every_target_file_fleet_writes_loads(tmp_path: Path, fleet: str) -> None:
    """``dottore fleet`` writes target files for ``run`` to read: every key it writes is one
    the reader takes."""

    out = fleet_mod.materialize_fleet(fleet_mod.load_fleet(REPO / fleet), tmp_path / "out")

    written = [*out.target_paths, *([out.judge_path] if out.judge_path else [])]
    assert written
    for path in written:
        wiring.load_target(path)
        assert set(yaml.safe_load(path.read_text(encoding="utf-8"))) <= LEGAL, path
