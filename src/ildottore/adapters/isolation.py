"""Run a stdio MCP server in a container, never on the host (u04 A-104, ADR-0016).

A ``provider: mcp``, ``transport: stdio`` target that declares ``isolation:`` is launched through
Docker or Podman instead of directly. What the container gets is fixed here, whatever the block
says: no network, a read-only root with a small ``noexec`` ``/tmp``, every capability dropped,
``no-new-privileges``, the user ``65534:65534``, an init process, the block's limits, its
read-only mounts and no variable from the host. The image is never pulled: one that is not
present locally stops the run before anything starts, as does a runtime that is not on ``PATH``,
so a target that asked for a container never runs on the host.

The scope still authorizes the command run inside (``MCPAdapter``); it runs as the container's
entrypoint, so the image's own entrypoint adds nothing to it.
"""

from __future__ import annotations

import asyncio
import os
import secrets
import shutil
from collections.abc import Mapping, Sequence
from dataclasses import dataclass

from ildottore.adapters.base import AdapterProductError
from ildottore.shared.models import IsolationSpec

__all__ = [
    "ContainedLaunch",
    "IsolationUnavailable",
    "container_argv",
    "prepare_container",
]

#: What the runtime's own process reads to reach its daemon or socket. It goes to the runtime's
#: command line tool, never into the container, which is given no variable (no ``-e``).
RUNTIME_ENV_PASSTHROUGH: tuple[str, ...] = (
    "DOCKER_HOST",
    "DOCKER_CONTEXT",
    "DOCKER_CONFIG",
    "DOCKER_CERT_PATH",
    "DOCKER_TLS_VERIFY",
    "CONTAINER_HOST",
    "CONTAINERS_CONF",
    "XDG_RUNTIME_DIR",
)

#: The only place a contained server can write; discarded with the container. A path inside the
#: container, not the host's temporary directory.
TMPFS = "/tmp:rw,noexec,nosuid,nodev,size=64m"  # noqa: S108  # nosec B108
#: The unprivileged user and group the server runs as (``nobody``).
CONTAINER_USER = "65534:65534"
#: The label every container this tool starts carries, so an operator can find a stray one.
CONTAINER_LABEL = "dottore.mcp=1"
#: How long the runtime gets to answer an image check or a removal.
RUNTIME_TIMEOUT_S = 30.0


class IsolationUnavailable(AdapterProductError):
    """The container cannot be started as declared, so nothing is (u04 A-104).

    A product error, not an environment one: no retry can supply a missing runtime or image,
    and falling back to the host is what the block exists to prevent. The run stops naming it.
    """


def container_name() -> str:
    """A fresh container name: ``dottore-mcp-`` and 12 random hex digits."""

    return f"dottore-mcp-{secrets.token_hex(6)}"


def container_argv(
    spec: IsolationSpec, command: Sequence[str], *, runtime: str, name: str
) -> list[str]:
    """The runtime's argv that runs ``command`` in the container ``spec`` declares.

    ``command[0]`` is the entrypoint (``--entrypoint=``, so it is never read as a flag) and the
    rest its arguments after the image, which the runtime does not parse.
    """

    if not command:
        raise ValueError("a contained server needs a command")
    argv = [
        runtime,
        "run",
        *_option("rm"),
        "-i",
        *_option("pull", "never"),
        *_option("init"),
        *_option("name", name),
        *_option("label", CONTAINER_LABEL),
        *_option("network", "none"),
        *_option("read-only"),
        *_option("tmpfs", TMPFS),
        *_option("cap-drop", "ALL"),
        *_option("security-opt", "no-new-privileges"),
        *_option("user", CONTAINER_USER),
        *_option("memory", spec.memory),
        *_option("memory-swap", spec.memory),
        *_option("cpus", format(spec.cpus, "g")),
        *_option("pids-limit", str(spec.pids)),
    ]
    for mount in spec.mounts:
        argv += _option("mount", f"type=bind,source={mount.source},target={mount.target},readonly")
    if spec.workdir is not None:
        argv += _option("workdir", spec.workdir)
    argv += [*_option(f"entrypoint={command[0]}"), spec.image, *command[1:]]
    return argv


def _option(name: str, *values: str) -> list[str]:
    """The runtime's long option ``name`` and its values. The dashes are added here, not written,
    so these options of another program are not read as options this tool names."""

    return ["--" + name, *values]


@dataclass(frozen=True)
class ContainedLaunch:
    """A container ready to start: its argv, name and the runtime's environment."""

    argv: tuple[str, ...]
    runtime: str
    name: str
    env: dict[str, str]

    async def remove(self) -> None:
        """Remove the container whether it exited, hung or was killed (best effort)."""

        await _run_runtime(self.runtime, ("rm", "-f", self.name), self.env)


async def prepare_container(
    spec: IsolationSpec,
    command: Sequence[str],
    *,
    target_id: str,
    environment: Mapping[str, str],
) -> ContainedLaunch:
    """Check the runtime and the image, then build the launch; nothing is started here.

    ``environment`` is what the server would have inherited on the host; the runtime gets it
    and :data:`RUNTIME_ENV_PASSTHROUGH`, the container none of it.
    """

    runtime = shutil.which(spec.runtime, path=environment.get("PATH"))
    if runtime is None:
        raise IsolationUnavailable(
            f"{target_id}: isolation runs the server with {spec.runtime}, which is not on PATH; "
            "nothing was started (a target that asks for a container never runs on the host)"
        )
    env = dict(environment)
    env.update({name: os.environ[name] for name in RUNTIME_ENV_PASSTHROUGH if name in os.environ})
    code = await _run_runtime(runtime, ("image", "inspect", spec.image), env)
    if code != 0:
        # The image is not quoted: the redactor masks its digest as a high-entropy string, and
        # the operator has it in the target file.
        raise IsolationUnavailable(
            f"{target_id}: {spec.runtime} has no local copy of the image, or cannot reach its "
            "daemon; the scan never pulls an image, so nothing was started. Pull the image the "
            f"target file's isolation.image names first ({spec.runtime} pull <image>)"
        )
    name = container_name()
    argv = container_argv(spec, command, runtime=runtime, name=name)
    return ContainedLaunch(argv=tuple(argv), runtime=runtime, name=name, env=env)


async def _run_runtime(runtime: str, args: Sequence[str], env: Mapping[str, str]) -> int | None:
    """Run the runtime with ``args``, discarding its output; its exit code, ``None`` if it
    could not start or did not answer within :data:`RUNTIME_TIMEOUT_S`."""

    try:
        proc = await asyncio.create_subprocess_exec(
            runtime,
            *args,
            stdin=asyncio.subprocess.DEVNULL,
            stdout=asyncio.subprocess.DEVNULL,
            stderr=asyncio.subprocess.DEVNULL,
            env=dict(env),
        )
    except OSError:
        return None
    try:
        return await asyncio.wait_for(proc.wait(), timeout=RUNTIME_TIMEOUT_S)
    except TimeoutError:
        proc.kill()
        await proc.wait()
        return None
