"""A number an operator's file gives is a finite number, or the file is refused (u12 A-82;
CLI audit of 2026-10-11, M6).

A spec file has refused ``.nan`` and ``.inf`` since A-54 (JSON cannot hold them), but a target
file's ``sampling_defaults`` took them: ``{temperature: .nan, top_p: .inf}`` loaded, a mock run
wrote bare ``NaN`` and ``Infinity`` into the JSON report (no JSON parser in strict mode reads
them), and a live run sent them and stopped on the provider's 400 without naming the field.
``Sampling`` now refuses a value that is not finite wherever it is built (``allow_inf_nan``), and
so do the other numbers a file from outside the code gives: a fingerprint signature pack's
centroids and weights, and a WebSocket block's ``timeout_seconds`` and ``final_value`` (which its
loader already refused, as values JSON cannot hold, and the model now refuses when built in code).
"""

from __future__ import annotations

import math
from pathlib import Path

import pytest
from pydantic import ValidationError
from typer.testing import CliRunner

from ildottore.cli import wiring
from ildottore.cli.app import app
from ildottore.fingerprint.signatures import SignaturePackError, load_pack
from ildottore.shared.models import Sampling, WebSocketResponse

from .conftest import write_scope

runner = CliRunner()


@pytest.mark.parametrize(
    ("block", "field"),
    [
        ("{temperature: .nan}", "temperature"),
        ("{temperature: .inf}", "temperature"),
        ("{temperature: -.inf}", "temperature"),
        ("{top_p: .NaN}", "top_p"),
        ("{temperature: 0.0, top_p: .Inf}", "top_p"),
    ],
)
def test_a_target_file_with_a_non_finite_sampling_default_is_refused(
    tmp_path: Path, block: str, field: str
) -> None:
    target = tmp_path / "t.yaml"
    target.write_text(
        f"id: mock-target\ntype: chatbot\nmock_scenario: vulnerable\nsampling_defaults: {block}\n"
    )
    result = runner.invoke(
        app,
        [
            "run",
            "-t",
            str(target),
            "--scope",
            str(write_scope(tmp_path)),
            "--spec",
            "PI-DIRECT-001",
            "--dry-run",
            "-q",
            "--evidence-root",
            str(tmp_path / "ev"),
            "--run-db",
            str(tmp_path / "r.db"),
        ],
    )
    assert result.exit_code == 3, result.output
    assert (
        f"target file {target} 'sampling_defaults' failed validation: {field}: Input should be "
        "a finite number"
    ) in result.output.replace("\n", "")


def test_finite_sampling_defaults_still_load(tmp_path: Path) -> None:
    target = tmp_path / "t.yaml"
    target.write_text(
        "id: t\ntype: chatbot\nmock_scenario: vulnerable\n"
        "sampling_defaults: {temperature: 0.0, top_p: 1.0, seed: 7, max_tokens: 400}\n"
    )
    sampling = wiring.load_target(target).sampling_defaults
    assert sampling is not None and (sampling.temperature, sampling.top_p) == (0.0, 1.0)


@pytest.mark.parametrize("value", [math.nan, math.inf, -math.inf])
def test_sampling_refuses_a_non_finite_value_however_it_is_built(value: float) -> None:
    with pytest.raises(ValidationError, match="finite number"):
        Sampling(temperature=value)
    with pytest.raises(ValidationError, match="finite number"):
        Sampling.model_validate({"top_p": value})


def _websocket_target(tmp_path: Path, response_extra: str) -> Path:
    path = tmp_path / "ws.yaml"
    path.write_text(
        "id: ws\ntype: chatbot\nprovider: websocket\nendpoint: wss://chat.example.test/ws\n"
        "websocket:\n"
        "  message:\n    send: { text: '{{prompt}}' }\n"
        "  response:\n    text_path: delta.text\n    final_path: type\n" + response_extra
    )
    return path


@pytest.mark.parametrize(
    ("extra", "field"),
    [
        ("    timeout_seconds: .nan\n", "timeout_seconds"),
        ("    timeout_seconds: .inf\n", "timeout_seconds"),
        ("    final_value: .nan\n", "final_value"),
        ("    final_value: -.inf\n", "final_value"),
    ],
)
def test_a_websocket_block_number_is_finite(tmp_path: Path, extra: str, field: str) -> None:
    """The block's own check of values JSON cannot hold refused these already (PR #87)."""

    with pytest.raises(ValueError, match=f"websocket/response/{field}: .*JSON cannot hold"):
        wiring.load_target(_websocket_target(tmp_path, extra))


@pytest.mark.parametrize("value", [math.nan, math.inf])
def test_the_websocket_model_refuses_them_however_it_is_built(value: float) -> None:
    """For a caller that builds the block in code, past the loader's check."""

    with pytest.raises(ValidationError, match="finite"):
        WebSocketResponse(text_path="t", final_path="f", final_value=value)
    with pytest.raises(ValidationError, match="finite"):
        WebSocketResponse(text_path="t", final_path="f", timeout_seconds=value)


def test_a_websocket_final_value_that_is_a_finite_number_still_loads(tmp_path: Path) -> None:
    target = wiring.load_target(_websocket_target(tmp_path, "    final_value: 1.5\n"))
    assert target.websocket is not None and target.websocket.response.final_value == 1.5


@pytest.mark.parametrize(
    "entry",
    [
        "  - family: f\n    stat: { centroid: [0.1, .nan] }\n",
        "  - family: f\n    weights: { lexical: .inf }\n",
    ],
    ids=["centroid", "weight"],
)
def test_a_signature_pack_holds_finite_numbers(tmp_path: Path, entry: str) -> None:
    pack = tmp_path / "pack.yaml"
    pack.write_text("pack_version: 1\nname: p\nentries:\n" + entry)
    with pytest.raises(SignaturePackError, match="finite number"):
        load_pack(pack)


def test_the_shipped_signature_pack_still_loads() -> None:
    assert load_pack().entries
