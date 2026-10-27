"""The ``isolation`` block of a target file: loaded, refused, wired, hashed, shown (u04 A-104).

The adapter's half (the container's argv, the launch, no fallback to the host) is in
``tests/adapters/test_mcp_isolation.py``.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest
from typer.testing import CliRunner

from ildottore.adapters import MCPAdapter
from ildottore.cli import wiring
from ildottore.cli.app import app
from ildottore.policy import EndpointAllowlist
from ildottore.shared.digest import target_digest, target_field_digests

REPO = Path(__file__).resolve().parents[2]
_TARGET = REPO / "examples" / "target.mcp-stdio.yaml"
_SCOPE = REPO / "examples" / "scope.mcp-stdio.yaml"
_IMAGE = "ghcr.io/example/mcp-server@sha256:" + "b" * 64
_HEAD = 'id: t\ntype: api\nprovider: mcp\ntransport: stdio\ncommand: ["node", "server.js"]\n'


def _write(tmp_path: Path, text: str) -> Path:
    path = tmp_path / "target.yaml"
    path.write_text(text, encoding="utf-8")
    return path


def _isolated(tmp_path: Path, extra: str = "") -> Path:
    return _write(tmp_path, f'{_HEAD}isolation:\n  image: "{_IMAGE}"\n{extra}')


def test_the_example_loads_with_its_block() -> None:
    target = wiring.load_target(_TARGET)
    assert target.isolation is not None
    assert target.isolation.runtime == "docker" and target.isolation.mounts == []
    assert target.command == ["node", "/app/dist/index.js"]


def test_a_block_with_a_mount_loads(tmp_path: Path) -> None:
    data = Path(os.path.realpath(tmp_path)) / "data"
    data.mkdir()
    target = wiring.load_target(
        _isolated(
            tmp_path,
            f"  runtime: podman\n  mounts:\n    - {{ source: {data}, target: /data }}\n"
            "  workdir: /data\n",
        )
    )
    assert target.isolation is not None
    assert target.isolation.mounts[0].source == str(data)
    assert target.isolation.workdir == "/data"


@pytest.mark.parametrize(
    "head",
    [
        'id: t\ntype: api\nprovider: mcp\nendpoint: "http://localhost:3000/mcp"\n',
        'id: t\ntype: model\nprovider: openai\nendpoint: "https://api.openai.com/v1/x"\n',
        'id: t\ntype: api\nendpoint: "http://localhost:8080/chat"\n',
    ],
)
def test_only_a_stdio_mcp_target_takes_the_block(tmp_path: Path, head: str) -> None:
    path = _write(tmp_path, f'{head}isolation:\n  image: "{_IMAGE}"\n')
    with pytest.raises(ValueError, match="read only by provider mcp with transport stdio"):
        wiring.load_target(path)


def test_the_block_is_a_mapping_and_validated(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="'isolation' must be a mapping"):
        wiring.load_target(_write(tmp_path, f"{_HEAD}isolation: docker\n"))
    with pytest.raises(ValueError, match=r"failed validation: image: .*pinned by digest"):
        wiring.load_target(_write(tmp_path, f"{_HEAD}isolation:\n  image: node:22\n"))


def test_a_mount_that_is_not_a_directory_is_refused(tmp_path: Path) -> None:
    missing = Path(os.path.realpath(tmp_path)) / "missing"
    path = _isolated(tmp_path, f"  mounts:\n    - {{ source: {missing}, target: /d }}\n")
    with pytest.raises(ValueError, match="which is not a directory"):
        wiring.load_target(path)


def test_a_mount_through_a_symbolic_link_is_refused(tmp_path: Path) -> None:
    real = Path(os.path.realpath(tmp_path)) / "real"
    real.mkdir()
    link = Path(os.path.realpath(tmp_path)) / "link"
    link.symlink_to(real)
    path = _isolated(tmp_path, f"  mounts:\n    - {{ source: {link}, target: /d }}\n")
    with pytest.raises(ValueError, match="through a symbolic link; write the resolved path"):
        wiring.load_target(path)


def test_a_mount_that_holds_the_home_directory_is_refused(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    base = Path(os.path.realpath(tmp_path))
    home = base / "users" / "operator"
    home.mkdir(parents=True)
    monkeypatch.setenv("HOME", str(home))
    for source in (home, base / "users"):
        path = _isolated(tmp_path, f"  mounts:\n    - {{ source: {source}, target: /d }}\n")
        with pytest.raises(ValueError, match="which holds the home directory"):
            wiring.load_target(path)
    beside = base / "users" / "operator-data"
    beside.mkdir()
    path = _isolated(tmp_path, f"  mounts:\n    - {{ source: {beside}, target: /d }}\n")
    assert wiring.load_target(path).isolation is not None


def test_the_adapter_gets_the_block(tmp_path: Path) -> None:
    target = wiring.load_target(_isolated(tmp_path))
    adapter = wiring.build_real_adapter(
        target, EndpointAllowlist([]), api_key=None, authorized_commands=("node server.js",)
    )
    assert isinstance(adapter, MCPAdapter)
    assert adapter.isolation == target.isolation


def test_the_digest_holds_what_answers_and_not_where_it_runs(tmp_path: Path) -> None:
    plain = wiring.load_target(_write(tmp_path, _HEAD))
    isolated = wiring.load_target(_isolated(tmp_path))
    assert "isolation" not in target_field_digests(plain)
    assert target_digest(plain) != target_digest(isolated)

    elsewhere = wiring.load_target(
        _isolated(tmp_path, "  runtime: podman\n  memory: 2g\n  cpus: 4\n  pids: 512\n")
    )
    assert target_digest(elsewhere) == target_digest(isolated)

    other_image = wiring.load_target(
        _write(tmp_path, f'{_HEAD}isolation:\n  image: "{_IMAGE[:-1]}c"\n')
    )
    assert target_digest(other_image) != target_digest(isolated)


def test_dry_run_says_where_the_server_runs() -> None:
    result = CliRunner().invoke(
        app, ["run", "--dry-run", "--suite", "mcp", "-t", str(_TARGET), "--scope", str(_SCOPE)]
    )
    assert result.exit_code == 0, result.output
    assert (
        "  isolation: docker, image ghcr.io/example/mcp-server@sha256:"
        + "0" * 64
        + " (not pulled); no network, read-only root, 512m memory, 1 CPU, 128 pids"
    ) in result.output


def test_a_run_with_no_runtime_stops_before_anything_starts(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    empty = tmp_path / "empty"
    empty.mkdir()
    monkeypatch.setenv("PATH", str(empty))
    result = CliRunner().invoke(
        app,
        [
            "run",
            "--suite",
            "mcp",
            "-t",
            str(_TARGET),
            "--scope",
            str(_SCOPE),
            "--evidence-root",
            str(tmp_path / "ev"),
            "--run-db",
            str(tmp_path / "r.db"),
        ],
    )
    assert result.exit_code == 3, result.output
    assert "aborted on IsolationUnavailable" in result.output
    assert "docker, which is not on PATH; nothing was started" in result.output
