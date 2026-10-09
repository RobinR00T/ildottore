"""A target file's ``capabilities`` is a mapping of the keys it knows, or nothing at all.

``load_target`` validated only the keys of ``capabilities`` that ``Capabilities`` knows and
dropped the rest without a word, so ``tool: true`` (for ``tools``) ran the target with tools off
and took the tool specs out of the plan: on ``2f6201a``, with ``rag`` and ``memory`` on, the dry
run planned 40 specs instead of 59 and nothing named the key. ``capabilities`` that was not a
mapping but empty or false (``false``, ``0``, ``[]``, ``""``) read as no capabilities, while
``true`` or a list with an item was refused as "must be a mapping". ``sampling_defaults`` refuses
both. ``dottore fleet`` copied an unknown key into the target file it wrote, where the loader then
dropped it. Clause A-50 (u12); refusing both is the owner's decision, OD-29.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest
import yaml
from typer.testing import CliRunner, Result

from ildottore.cli import fleet as fleet_mod
from ildottore.cli.app import _masked
from ildottore.cli.exit_codes import ExitCode
from ildottore.cli.main import app
from ildottore.cli.wiring import load_target
from ildottore.shared.models import Capabilities

from .conftest import write_scope

runner = CliRunner()

REPO = Path(__file__).resolve().parents[2]
SPEC = REPO / "specs" / "attacks" / "PI-DIRECT-001.yaml"

#: Shaped like a key pasted in the wrong place, as in ``test_target_file_validation``.
PASTED = "797c48a81f494d0f3e8d13bd49459b6f" * 2

#: (``capabilities`` block, the field path and reason the refusal must give).
UNKNOWN_KEYS = {
    "the finding's typo": ("capabilities:\n  tool: true\n", "tool: Extra inputs are not permitted"),
    "a capital letter": ("capabilities:\n  Tools: true\n", "Tools: Extra inputs are not permitted"),
    "a typo beside known keys": (
        "capabilities:\n  tools: true\n  rag: true\n  memroy: true\n",
        "memroy: Extra inputs are not permitted",
    ),
    "a key that is not text": ("capabilities:\n  1: true\n", "1: Keys should be strings"),
    "a pasted value under a typo": (
        f"capabilities:\n  tool: {PASTED}\n",
        "tool: Extra inputs are not permitted",
    ),
}

#: What ``capabilities:`` holds when it is not a mapping. The first six read as no capabilities
#: on ``2f6201a``; the rest were already refused and stay so.
NOT_A_MAPPING = ["false", "0", "0.0", "[]", '""', "no", "true", "1", "[tools]", "tools", PASTED]

#: Blocks that declare no capabilities and still load as none.
NO_CAPABILITIES = {
    "absent": "",
    "empty": "capabilities:\n",
    "null": "capabilities: null\n",
    "tilde": "capabilities: ~\n",
    "empty mapping": "capabilities: {}\n",
}


def write_target(tmp_path: Path, block: str, *, target_id: str = "mock-target") -> Path:
    path = tmp_path / f"{target_id}.yaml"
    path.write_text(
        f"id: {target_id}\ntype: chatbot\nmock_scenario: hardened\n" + block, encoding="utf-8"
    )
    return path


def pieces(value: str) -> list[str]:
    """Every 8-character run of ``value``, the width ``test_target_file_validation`` checks."""

    return [value[start : start + 8] for start in range(max(1, len(value) - 7))]


def refusal(result: Result, path: Path) -> str:
    """The command's one ``error:`` line, which names ``path``, with no mask and no pasted value."""

    assert result.exit_code == ExitCode.ERROR, (result.exception, result.output)
    lines = result.stderr.splitlines()
    assert len(lines) == 1, result.stderr
    assert lines[0].startswith(f"error: target file {path} "), lines[0]
    assert "REDACTED" not in result.output
    for piece in pieces(PASTED):
        assert piece not in result.output, piece
    return lines[0]


def dry_run(target: Path, scope: Path, *extra: str) -> Result:
    args = ["-t", str(target), *extra, "--scope", str(scope), "--spec-path", str(SPEC)]
    return runner.invoke(app, ["run", *args, "--dry-run"])


# --- load_target ------------------------------------------------------------------------------


@pytest.mark.parametrize("case", sorted(UNKNOWN_KEYS))
def test_load_target_refuses_a_key_capabilities_does_not_know(tmp_path: Path, case: str) -> None:
    block, where = UNKNOWN_KEYS[case]
    path = write_target(tmp_path, block)

    with pytest.raises(ValueError) as refused:
        load_target(path)

    assert type(refused.value) is ValueError
    message = str(refused.value)
    assert message.startswith(f"target file {path} 'capabilities' failed validation: "), message
    assert where in message
    assert "\n" not in message
    for piece in pieces(PASTED):
        assert piece not in message, piece


@pytest.mark.parametrize("value", NOT_A_MAPPING)
def test_load_target_refuses_capabilities_that_is_not_a_mapping(tmp_path: Path, value: str) -> None:
    path = write_target(tmp_path, f"capabilities: {value}\n")

    with pytest.raises(ValueError) as refused:
        load_target(path)

    assert str(refused.value) == f"target file {path} 'capabilities' must be a mapping"


@pytest.mark.parametrize("case", sorted(NO_CAPABILITIES))
def test_a_file_that_declares_no_capabilities_loads_with_none(tmp_path: Path, case: str) -> None:
    target = load_target(write_target(tmp_path, NO_CAPABILITIES[case]))

    assert target.capabilities == Capabilities()


def test_every_known_key_still_loads(tmp_path: Path) -> None:
    keys = sorted(Capabilities.model_fields)
    block = "capabilities:\n" + "".join(f"  {key}: true\n" for key in keys)

    target = load_target(write_target(tmp_path, block))

    assert target.capabilities == Capabilities(**dict.fromkeys(keys, True))


# --- through the commands ---------------------------------------------------------------------


def test_run_refuses_a_typo_naming_the_file_and_the_key(tmp_path: Path) -> None:
    target = write_target(tmp_path, UNKNOWN_KEYS["the finding's typo"][0])

    result = dry_run(target, write_scope(tmp_path))

    line = refusal(result, target)
    assert "'capabilities' failed validation: tool: Extra inputs are not permitted" in line
    assert "would send" not in result.output


def test_run_refuses_a_judge_file_with_a_typo(tmp_path: Path) -> None:
    """The scope authorizes the judge too, so on ``2f6201a`` the dry run went through (exit 0)."""

    target = write_target(tmp_path, "capabilities:\n  tools: false\n")
    judge = write_target(tmp_path, f"capabilities:\n  tool: {PASTED}\n", target_id="mock-judge")
    scope = write_scope(tmp_path)
    judge_entry = scope.read_text(encoding="utf-8").split("targets:\n", 1)[1]
    with scope.open("a", encoding="utf-8") as handle:
        handle.write(judge_entry.replace("mock-target", "mock-judge"))

    result = dry_run(target, scope, "--judge", str(judge))

    assert "tool: Extra inputs are not permitted" in refusal(result, judge)


def test_fingerprint_refuses_a_typo(tmp_path: Path) -> None:
    target = write_target(tmp_path, UNKNOWN_KEYS["a typo beside known keys"][0])
    scope = write_scope(tmp_path)

    result = runner.invoke(app, ["fingerprint", str(target), "--scope", str(scope), "--offline"])

    assert "memroy: Extra inputs are not permitted" in refusal(result, target)


@pytest.mark.parametrize("value", ["false", "[]", PASTED])
def test_run_refuses_capabilities_that_is_not_a_mapping(tmp_path: Path, value: str) -> None:
    target = write_target(tmp_path, f"capabilities: {value}\n")

    result = dry_run(target, write_scope(tmp_path))

    assert (
        refusal(result, target) == f"error: target file {target} 'capabilities' must be a mapping"
    )


@pytest.mark.parametrize("value", [PASTED, "tool", "memroy"])
def test_the_cli_redactor_leaves_each_test_value_readable(value: str) -> None:
    """Otherwise the CLI tests above could pass on a value the redactor masked, not omitted."""

    assert value in _masked(ValueError(f"got {value} here"))


# --- dottore fleet ----------------------------------------------------------------------------

FLEET_HEAD = 'version: "1"\ntargets:\n'
LLM = "  - id: local\n    endpoint: http://localhost:11434/v1/chat/completions\n    model: m\n"
MCP = "  - id: tools-server\n    kind: mcp\n    endpoint: http://localhost:3000/mcp\n"


def write_fleet(tmp_path: Path, body: str) -> Path:
    path = tmp_path / "fleet.yaml"
    path.write_text(FLEET_HEAD + body, encoding="utf-8")
    return path


def test_load_fleet_refuses_a_key_capabilities_does_not_know(tmp_path: Path) -> None:
    path = write_fleet(tmp_path, LLM + MCP + "    capabilities: { tool: true, rag: true }\n")

    with pytest.raises(ValueError) as refused:
        fleet_mod.load_fleet(path)

    message = str(refused.value)
    assert message.startswith(f"fleet file {path} failed validation: "), message
    assert "targets.1.capabilities.tool: Extra inputs are not permitted" in message


def test_the_fleet_command_refuses_a_typo_and_writes_nothing(tmp_path: Path) -> None:
    """On ``2f6201a`` this wrote ``tool: true`` beside ``tools: false`` and exited 0."""

    path = write_fleet(tmp_path, LLM + "    capabilities: { tool: true }\n")
    out = tmp_path / "out"

    result = runner.invoke(app, ["fleet", str(path), "--out", str(out)])

    assert result.exit_code == ExitCode.ERROR, (result.exception, result.output)
    assert "targets.0.capabilities.tool: Extra inputs are not permitted" in result.stderr
    assert not out.exists()


def test_the_fleet_command_refuses_a_judge_file_with_a_typo(tmp_path: Path) -> None:
    """The judge file matches the fleet's declaration, so on ``2f6201a`` `fleet --judge` wrote
    the scope and the files with exit 0 (delta audit: no test went through this path)."""

    endpoint = "http://localhost:11434/v1/chat/completions"
    path = write_fleet(
        tmp_path, LLM + f"judge:\n  id: local-judge\n  endpoint: {endpoint}\n  model: j\n"
    )
    judge = tmp_path / "judge.yaml"
    judge.write_text(
        f"id: local-judge\ntype: model\nprovider: openai\nendpoint: {endpoint}\nmodel: j\n"
        "capabilities:\n  tool: true\n",
        encoding="utf-8",
    )
    out = tmp_path / "out"

    result = runner.invoke(app, ["fleet", str(path), "--judge", str(judge), "--out", str(out)])

    assert "tool: Extra inputs are not permitted" in refusal(result, judge)
    assert not out.exists()


#: (fleet entry, the ``capabilities`` the generated target file must hold, key for key).
FLEET_CAPABILITIES = {
    "llm, none written": (LLM, {"tools": False, "rag": False}),
    "llm, two written": (
        LLM + "    capabilities: { rag: true, seed: true }\n",
        {"tools": False, "rag": True, "seed": True},
    ),
    "llm, read as written": (
        LLM + "    capabilities: { tools: 'on', streaming: 'off' }\n",
        {"tools": True, "rag": False, "streaming": False},
    ),
    "mcp, none written": (MCP, {"tools": True, "rag": False}),
    "mcp, tools turned off": (
        MCP + "    capabilities: { tools: false }\n",
        {"tools": False, "rag": False},
    ),
}


@pytest.mark.parametrize("case", sorted(FLEET_CAPABILITIES))
def test_fleet_writes_the_capabilities_written_and_its_defaults_only(
    tmp_path: Path, case: str
) -> None:
    """Typing the fleet's map as ``Capabilities`` must not write the model's other defaults."""

    entry, expected = FLEET_CAPABILITIES[case]
    out = fleet_mod.materialize_fleet(
        fleet_mod.load_fleet(write_fleet(tmp_path, entry)), tmp_path / "out"
    )

    written = yaml.safe_load(out.target_paths[0].read_text(encoding="utf-8"))
    assert written["capabilities"] == expected
    loaded = load_target(out.target_paths[0]).capabilities
    assert loaded == Capabilities(**expected)


# --- the repository's own files ---------------------------------------------------------------

_FENCED_YAML = re.compile(r"^```ya?ml\n(.*?)^```", re.MULTILINE | re.DOTALL)
_MAN_BLOCK = re.compile(r"^\.nf\n(.*?)^\.fi$", re.MULTILINE | re.DOTALL)


def _repository_texts() -> list[tuple[str, str]]:
    """Every YAML file under examples/, specs/ and tests/, every fenced YAML block of the
    Markdown docs and every literal block of the man pages, as (where, text)."""

    texts: list[tuple[str, str]] = []
    for folder in ("examples", "specs", "tests"):
        for path in sorted((REPO / folder).rglob("*")):
            if path.suffix in (".yaml", ".yml"):
                texts.append((str(path), path.read_text(encoding="utf-8")))
    markdown = [*sorted(REPO.glob("*.md")), *sorted((REPO / "docs").glob("*.md"))]
    for path in [*markdown, REPO / "examples" / "README.md"]:
        blocks = _FENCED_YAML.findall(path.read_text(encoding="utf-8"))
        texts += [(f"{path} block {index}", block) for index, block in enumerate(blocks)]
    for path in sorted((REPO / "man").rglob("*.[1-9]")):
        blocks = _MAN_BLOCK.findall(path.read_text(encoding="utf-8"))
        texts += [(f"{path} block {index}", block) for index, block in enumerate(blocks)]
    return texts


def _repository_documents() -> list[tuple[str, str, object]]:
    """``_repository_texts`` parsed. A text that does not parse is left out unless it mentions
    ``capabilities``: a broken fixture belongs to the YAML tests, a broken target example here."""

    documents: list[tuple[str, str, object]] = []
    for where, text in _repository_texts():
        try:
            documents.append((where, text, yaml.safe_load(text)))
        except yaml.YAMLError as exc:
            assert "capabilities" not in text, (where, exc)
    return documents


def _is_target(doc: object) -> bool:
    return isinstance(doc, dict) and {"id", "type", "capabilities"} <= set(doc)


def _is_fleet(doc: object) -> bool:
    targets = doc.get("targets") if isinstance(doc, dict) else None
    return isinstance(targets, list) and any(
        isinstance(t, dict) and "endpoint" in t and "base_url" not in t for t in targets
    )


def test_every_target_file_and_fleet_in_the_repository_still_loads(tmp_path: Path) -> None:
    documents = _repository_documents()
    targets = [(where, text, doc) for where, text, doc in documents if _is_target(doc)]
    fleets = [(where, text) for where, text, doc in documents if _is_fleet(doc)]
    # Not vacuous: the shipped examples and the target blocks of the docs are among them.
    names = {Path(where.split(" block ")[0]).name for where, _, _ in targets}
    shipped = {"target.local.yaml", "target.app.yaml", "example-openai.yaml"}
    assert shipped | {"MANUAL.md", "USAGE.md", "dottore-scope.5"} <= names, names
    assert len(fleets) >= 3, [where for where, _ in fleets]

    # The text as written, not a re-dump: a duplicate key or a tag is part of what must load.
    for index, (where, text, doc) in enumerate(targets):
        path = tmp_path / f"target-{index}.yaml"
        path.write_text(text, encoding="utf-8")
        assert load_target(path).id == doc["id"], where  # type: ignore[index]
    for index, (where, text) in enumerate(fleets):
        path = tmp_path / f"fleet-{index}.yaml"
        path.write_text(text, encoding="utf-8")
        assert fleet_mod.load_fleet(path).targets, where
