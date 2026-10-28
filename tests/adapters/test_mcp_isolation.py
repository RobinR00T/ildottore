"""A stdio MCP server run in a container, never on the host (u04 A-104, ADR-0016).

The argv is a pure function, checked flag by flag. The launch runs against a stand-in runtime: a
script named ``docker`` on ``PATH`` that logs each call, answers ``image inspect`` and runs the
command after the image as the real runtime would. One test starts a real container, opt-in by
``DOTTORE_TEST_DOCKER_IMAGE`` (an image with ``python3``, pinned by digest).
"""

from __future__ import annotations

import json
import os
import shutil
import sys
from pathlib import Path

import pytest
from pydantic import ValidationError

from ildottore.adapters import EndpointNotAllowed, MCPAdapter, RetryConfig
from ildottore.adapters.base import AdapterError
from ildottore.adapters.isolation import (
    CONTAINER_LABEL,
    IsolationUnavailable,
    container_argv,
    container_name,
)
from ildottore.policy import EndpointAllowlist
from ildottore.shared.models import IsolationMount, IsolationSpec, ModelRequest

_IMAGE = "ghcr.io/example/mcp-server@sha256:" + "a" * 64
_RETRY = RetryConfig(backoff_base_s=0.0, backoff_cap_s=0.0, timeout_s=10.0)

_SERVER = """\
import json, sys
for line in sys.stdin:
    msg = json.loads(line)
    m, i = msg.get("method"), msg.get("id")
    if m == "initialize":
        r = {"protocolVersion": "2025-06-18", "serverInfo": {"name": "boxed", "version": "1"}}
    elif m == "tools/list":
        r = {"tools": [{"name": "read_file", "description": "Read a file."}]}
    elif m in ("resources/list", "prompts/list"):
        r = {m.split("/")[0]: []}
    else:
        continue
    print(json.dumps({"jsonrpc": "2.0", "id": i, "result": r}), flush=True)
"""

#: The stand-in runtime. It logs its argv and whether two variables reached it, then does what
#: the real one would: ``image inspect`` answers from a marker file, ``run`` executes the
#: entrypoint with the arguments after the image, ``rm`` succeeds.
_FAKE_RUNTIME = """\
import json, os, sys
LOG, MISSING = {log!r}, {missing!r}
args = sys.argv[1:]
with open(LOG, "a") as fh:
    fh.write(json.dumps({{"args": args, "host_secret": "HOST_SECRET" in os.environ,
                         "docker_host": os.environ.get("DOCKER_HOST")}}) + "\\n")
if args[:2] == ["image", "inspect"]:
    sys.exit(1 if os.path.exists(MISSING) else 0)
if args[:1] == ["run"]:
    entry = next(a.split("=", 1)[1] for a in args if a.startswith("--entrypoint="))
    image = next(i for i, a in enumerate(args) if "@sha256:" in a)
    os.execv(entry, [entry, *args[image + 1:]])
sys.exit(0)
"""


def _spec(**kw: object) -> IsolationSpec:
    return IsolationSpec.model_validate({"image": _IMAGE, **kw})


def _server(tmp_path: Path) -> list[str]:
    script = tmp_path / "server.py"
    script.write_text(_SERVER, encoding="utf-8")
    return [sys.executable, str(script)]


def _fake_runtime(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Put the stand-in ``docker`` alone on ``PATH``; return its log."""

    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    log = tmp_path / "runtime.log"
    body = tmp_path / "runtime.py"
    body.write_text(
        _FAKE_RUNTIME.format(log=str(log), missing=str(tmp_path / "gone")), encoding="utf-8"
    )
    # A shell wrapper, as a shebang cannot hold the space a checkout path may have.
    runtime = bin_dir / "docker"
    runtime.write_text(f'#!/bin/sh\nexec "{sys.executable}" "{body}" "$@"\n', encoding="utf-8")
    runtime.chmod(0o755)
    monkeypatch.setenv("PATH", str(bin_dir))
    return log


def _calls(log: Path) -> list[dict[str, object]]:
    if not log.exists():
        return []
    return [json.loads(line) for line in log.read_text(encoding="utf-8").splitlines()]


def _adapter(cmd: list[str], spec: IsolationSpec | None, *, authorized: bool = True) -> MCPAdapter:
    return MCPAdapter(
        id="boxed-mcp",
        base_url="stdio://local",
        allowlist=EndpointAllowlist([]),
        transport="stdio",
        command=tuple(cmd),
        authorized_commands=(" ".join(cmd),) if authorized else (),
        retry=_RETRY,
        isolation=spec,
    )


# --- the argv ------------------------------------------------------------------------------


def test_the_argv_holds_every_restriction_whatever_the_block_says() -> None:
    spec = _spec(
        memory="256m",
        cpus=0.5,
        pids=64,
        mounts=[{"source": "/srv/data", "target": "/data"}],
        workdir="/data",
    )
    argv = container_argv(spec, ["node", "server.js", "--stdio"], runtime="/bin/docker", name="n1")

    assert argv[:2] == ["/bin/docker", "run"]
    joined = " ".join(argv)
    for flag in (
        "--rm -i",
        "--pull never",
        "--init",
        "--name n1",
        f"--label {CONTAINER_LABEL}",
        "--network none",
        "--read-only",
        "--tmpfs /tmp:rw,noexec,nosuid,nodev,size=64m",
        "--cap-drop ALL",
        "--security-opt no-new-privileges",
        "--user 65534:65534",
        "--memory 256m --memory-swap 256m",
        "--cpus 0.5",
        "--pids-limit 64",
        "--mount type=bind,source=/srv/data,target=/data,readonly",
        "--workdir /data",
    ):
        assert flag in joined, flag
    # The authorized command runs as the entrypoint; what follows the image is not parsed.
    assert argv[-4:] == ["--entrypoint=node", _IMAGE, "server.js", "--stdio"]
    # Nothing from the host goes in, and nothing widens the box.
    for widening in ("-e", "--env", "--env-file", "--privileged", "--cap-add", "--volume", "-v"):
        assert widening not in argv
    assert "host" not in argv


def test_a_flag_shaped_command_is_the_entrypoint_not_a_flag() -> None:
    argv = container_argv(_spec(), ["--privileged"], runtime="docker", name="n")
    assert "--privileged" not in argv
    assert argv[-2:] == ["--entrypoint=--privileged", _IMAGE]


def test_the_defaults_and_a_fresh_name() -> None:
    argv = container_argv(_spec(), ["srv"], runtime="podman", name="n")
    joined = " ".join(argv)
    assert "--memory 512m" in joined and "--cpus 1 " in joined and "--pids-limit 128" in joined
    assert "--mount" not in argv and "--workdir" not in argv
    first, second = container_name(), container_name()
    assert first != second and first.startswith("dottore-mcp-") and len(first) == 24
    with pytest.raises(ValueError, match="needs a command"):
        container_argv(_spec(), [], runtime="docker", name="n")


# --- the block -----------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("block", "reason"),
    [
        ({"image": "ghcr.io/example/mcp-server:latest"}, "pinned by digest"),
        ({"image": "ghcr.io/example/mcp-server@sha256:abc"}, "pinned by digest"),
        ({"image": _IMAGE, "runtime": "lxc"}, "runtime"),
        ({"image": _IMAGE, "memory": "lots"}, "memory"),
        ({"image": _IMAGE, "memory": "0m"}, "memory"),
        ({"image": _IMAGE, "cpus": 0}, "cpus"),
        ({"image": _IMAGE, "pids": 4}, "pids"),
        ({"image": _IMAGE, "network": "host"}, "network"),
        ({"image": _IMAGE, "workdir": "data"}, "workdir"),
        ({"image": _IMAGE, "mounts": [{"source": "srv", "target": "/d"}]}, "absolute"),
        ({"image": _IMAGE, "mounts": [{"source": "/srv/../etc", "target": "/d"}]}, "normalized"),
        ({"image": _IMAGE, "mounts": [{"source": "/", "target": "/d"}]}, "other than /"),
        ({"image": _IMAGE, "mounts": [{"source": "/srv", "target": "/"}]}, "other than /"),
        ({"image": _IMAGE, "mounts": [{"source": "/a,b", "target": "/d"}]}, "comma"),
        ({"image": _IMAGE, "mounts": [{"source": "/srv", "target": "/d:rw"}]}, "colon"),
        ({"image": _IMAGE, "mounts": [{"source": "/srv", "target": "/d", "mode": "rw"}]}, "mode"),
        (
            {
                "image": _IMAGE,
                "mounts": [{"source": "/a", "target": "/d"}, {"source": "/b", "target": "/d"}],
            },
            "share a target",
        ),
    ],
)
def test_the_block_refuses(block: dict[str, object], reason: str) -> None:
    with pytest.raises(ValidationError, match=reason):
        IsolationSpec.model_validate(block)


def test_a_mount_is_read_only_with_no_way_to_say_otherwise() -> None:
    assert set(IsolationMount.model_fields) == {"source", "target"}


# --- the launch, against a stand-in runtime ------------------------------------------------


async def test_a_contained_server_is_listed_through_the_runtime_and_removed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    cmd = _server(tmp_path)
    log = _fake_runtime(tmp_path, monkeypatch)
    monkeypatch.setenv("HOST_SECRET", "not-for-the-server")
    monkeypatch.setenv("DOCKER_HOST", "unix:///tmp/fake.sock")

    reply = await _adapter(cmd, _spec()).send(ModelRequest(prompt="ignored"))

    assert "MCP server: boxed v1" in reply.text and "read_file" in reply.text
    calls = _calls(log)
    assert [c["args"][:2] for c in calls] == [["image", "inspect"], ["run", "--rm"], ["rm", "-f"]]
    run = calls[1]["args"]
    assert isinstance(run, list)
    name = run[run.index("--name") + 1]
    assert calls[2]["args"] == ["rm", "-f", name]
    assert run[-2:] == [_IMAGE, cmd[1]] and f"--entrypoint={cmd[0]}" in run
    # The runtime reaches its daemon; no other host variable reaches it, or the server.
    assert all(c["docker_host"] == "unix:///tmp/fake.sock" for c in calls)
    assert not any(c["host_secret"] for c in calls)


async def test_no_local_image_starts_nothing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    cmd = _server(tmp_path)
    log = _fake_runtime(tmp_path, monkeypatch)
    (tmp_path / "gone").touch()

    with pytest.raises(IsolationUnavailable, match="never pulls an image") as raised:
        await _adapter(cmd, _spec()).send(ModelRequest(prompt="x"))

    assert "isolation.image" in str(raised.value) and "docker pull <image>" in str(raised.value)
    assert [c["args"][:2] for c in _calls(log)] == [["image", "inspect"]]


async def test_no_runtime_never_falls_back_to_the_host(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    marker = tmp_path / "ran-on-the-host"
    script = tmp_path / "server.py"
    script.write_text(f"open({str(marker)!r}, 'w').close()\n", encoding="utf-8")
    cmd = [sys.executable, str(script)]
    empty = tmp_path / "empty"
    empty.mkdir()
    monkeypatch.setenv("PATH", str(empty))

    with pytest.raises(IsolationUnavailable, match="docker, which is not on PATH"):
        await _adapter(cmd, _spec()).send(ModelRequest(prompt="x"))
    with pytest.raises(IsolationUnavailable, match="podman, which is not on PATH"):
        await _adapter(cmd, _spec(runtime="podman")).send(ModelRequest(prompt="x"))
    assert not marker.exists()


async def test_an_unauthorized_command_reaches_no_runtime(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    cmd = _server(tmp_path)
    log = _fake_runtime(tmp_path, monkeypatch)

    with pytest.raises(EndpointNotAllowed):
        await _adapter(cmd, _spec(), authorized=False).send(ModelRequest(prompt="x"))
    assert _calls(log) == []


async def test_the_container_is_removed_when_the_server_dies(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    script = tmp_path / "server.py"
    script.write_text("import sys\nsys.exit(3)\n", encoding="utf-8")
    cmd = [sys.executable, str(script)]
    log = _fake_runtime(tmp_path, monkeypatch)

    with pytest.raises(AdapterError):
        await _adapter(cmd, _spec()).send(ModelRequest(prompt="x"))

    assert [c["args"][:2] for c in _calls(log)][-1] == ["rm", "-f"]


async def test_without_the_block_the_server_runs_on_the_host_as_before(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    cmd = _server(tmp_path)
    log = _fake_runtime(tmp_path, monkeypatch)

    reply = await _adapter(cmd, None).send(ModelRequest(prompt="ignored"))

    assert "boxed" in reply.text
    assert _calls(log) == []


# --- a real container, opt-in --------------------------------------------------------------


@pytest.mark.skipif(
    not os.environ.get("DOTTORE_TEST_DOCKER_IMAGE") or shutil.which("docker") is None,
    reason="set DOTTORE_TEST_DOCKER_IMAGE to a local image with python3, pinned by digest",
)
async def test_a_real_container_lists_the_server_with_no_network(tmp_path: Path) -> None:
    source = Path(os.path.realpath(tmp_path)) / "srv"
    source.mkdir()
    (source / "server.py").write_text(_SERVER, encoding="utf-8")
    (source / "server.py").chmod(0o644)
    source.chmod(0o755)
    spec = _spec(
        image=os.environ["DOTTORE_TEST_DOCKER_IMAGE"],
        mounts=[{"source": str(source), "target": "/srv"}],
    )
    cmd = ["python3", "/srv/server.py"]

    reply = await _adapter(cmd, spec).send(ModelRequest(prompt="ignored"))

    assert "MCP server: boxed v1" in reply.text
