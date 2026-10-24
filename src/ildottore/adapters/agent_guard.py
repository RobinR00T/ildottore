"""The guard of a deployed agent (``websocket.guard``): what keeps a scan polite and contained.

A model API is built for traffic; a deployed assistant (a copilot, an agent with tools, a chat
over a tenant's data) often is not. It may lock an address out after a few failed logins, share
a rate limit with every other tenant behind the same gateway, or act on the tenant while it
answers. The target file says what this agent needs, and this module keeps it:

* the credential is checked **before** it is sent: its JWT payload (read, never verified) names
  the configured tenant and does not expire within ``min_lifetime_seconds``;
* the **first** authentication failure stops the run, and the agent is left alone for
  ``auth.cooldown_seconds``, by this process and the next; a credential refused outright is
  remembered (by its sha256, never its value) and not sent again;
* queries are paced (``min_interval_seconds`` between two, ``max_per_hour`` in any hour) across
  processes, in a state file under a lock;
* a tool or agent name the target reports from ``stop_on_tools`` closes the connection at once.
  Closing cannot undo what the agent already started; it stops the next step.

Every stop is a :class:`GuardStop`, which halts the campaign (it is not an environment error, so
nothing retries it) and names why, never the credential. The state file lives under
:func:`guard_state_dir` (``ILDOTTORE_STATE_DIR``, else ``$XDG_STATE_HOME/ildottore``, else
``~/.local/state/ildottore``), one file per endpoint, named by the endpoint's digest so the
directory does not list the hosts it was pointed at.
"""

from __future__ import annotations

import base64
import binascii
import contextlib
import fcntl
import hashlib
import json
import os
import time
from collections.abc import Callable, Iterator, Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Final

from ildottore.adapters.base import AdapterProductError
from ildottore.adapters.rest import get_path
from ildottore.shared.models import WebSocketGuard

__all__ = [
    "STATE_DIR_ENV",
    "AgentAuthRefused",
    "AgentGuardState",
    "AgentPacingStop",
    "AgentTenantMismatch",
    "AgentToolStop",
    "GuardStop",
    "check_token",
    "guard_state_dir",
    "reported_tools",
    "token_claims",
]

#: The variable that moves the guard's state directory (tests, a shared CI runner).
STATE_DIR_ENV: Final = "ILDOTTORE_STATE_DIR"
#: Longest credential read as a JWT: a payload past it is no token a login issues.
_MAX_TOKEN_CHARS: Final = 16384
#: Refused credentials remembered per endpoint (their digests): the oldest is forgotten past it.
_MAX_REFUSED: Final = 32
#: Seconds in the window ``max_per_hour`` counts over.
_HOUR: Final = 3600.0


class GuardStop(AdapterProductError):
    """The guard stopped the run: nothing more is sent to this agent in this campaign.

    Not an environment error, so no retry sends it again; the runner halts the campaign as
    ``aborted`` and names the reason. The message never quotes the credential.
    """


class AgentAuthRefused(GuardStop):
    """The agent refused the credential (or closed before it answered the handshake)."""


class AgentTenantMismatch(GuardStop):
    """The credential, or the handshake reply, names a tenant other than the configured one."""


class AgentPacingStop(GuardStop):
    """The hourly cap is reached, or the agent is in its cooldown after an auth failure."""


class AgentToolStop(GuardStop):
    """The target reported a tool from ``stop_on_tools``; the connection was closed."""


def guard_state_dir() -> Path:
    """Where the guard keeps its state: ``ILDOTTORE_STATE_DIR``, the XDG state home, or
    ``~/.local/state/ildottore``."""

    explicit = os.environ.get(STATE_DIR_ENV, "").strip()
    if explicit:
        return Path(explicit).expanduser()
    xdg = os.environ.get("XDG_STATE_HOME", "").strip()
    base = Path(xdg).expanduser() if xdg else Path.home() / ".local" / "state"
    return base / "ildottore"


def token_claims(token: str) -> dict[str, Any] | None:
    """The payload of a JWT, decoded and **not** verified; ``None`` for anything else."""

    if len(token) > _MAX_TOKEN_CHARS:
        return None
    parts = token.split(".")
    if len(parts) != 3:
        return None
    payload = parts[1] + "=" * (-len(parts[1]) % 4)
    try:
        claims = json.loads(base64.urlsafe_b64decode(payload.encode("ascii")))
    except (ValueError, UnicodeError, binascii.Error):
        return None
    return claims if isinstance(claims, dict) else None


def check_token(
    target_id: str,
    token: str,
    *,
    tenant: str,
    tenant_claims: list[str],
    min_lifetime_s: float,
    now: float,
) -> None:
    """Refuse a credential that is no JWT, names another tenant, or is about to expire.

    The messages name the claim, never its value: a tenant id is the operator's data, and the
    error reaches the evidence and the reports.
    """

    claims = token_claims(token)
    if claims is None:
        raise AgentTenantMismatch(
            f"{target_id}: guard.token is declared and the credential is not a JWT; "
            "nothing was sent"
        )
    found = next((claims[name] for name in tenant_claims if claims.get(name) is not None), None)
    if found is None:
        raise AgentTenantMismatch(
            f"{target_id}: the credential carries none of the tenant claims guard.token names; "
            "nothing was sent"
        )
    if str(found) != tenant:
        raise AgentTenantMismatch(
            f"{target_id}: the credential's tenant is not the one guard.token.tenant configures; "
            "nothing was sent"
        )
    exp = claims.get("exp")
    if isinstance(exp, bool) or not isinstance(exp, (int, float)):
        raise AgentTenantMismatch(f"{target_id}: the credential has no exp claim; nothing was sent")
    left = float(exp) - now
    if left < min_lifetime_s:
        state = "has expired" if left <= 0 else f"expires in {int(left)}s"
        raise AgentAuthRefused(
            f"{target_id}: the credential {state} (guard.token.min_lifetime_seconds is "
            f"{min_lifetime_s:g}); set a fresh one; nothing was sent"
        )


def _digest(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


@dataclass
class AgentGuardState:
    """The cross-process state of one endpoint's guard: pacing, cooldown, refused credentials.

    ``now`` is wall-clock seconds (shared between processes, unlike a monotonic clock); it and
    ``directory`` are injected by the tests.
    """

    target_id: str
    url: str
    guard: WebSocketGuard
    directory: Path | None = None
    now: Callable[[], float] = field(default=time.time)

    @property
    def path(self) -> Path:
        """The state file: one per endpoint, named by the endpoint's digest."""

        base = self.directory if self.directory is not None else guard_state_dir()
        return base / "guard" / f"{_digest(self.url)[:32]}.json"

    @contextlib.contextmanager
    def _locked(self) -> Iterator[dict[str, Any]]:
        """The state, read and written back under an exclusive lock (0600 file, 0700 dir)."""

        path = self.path
        path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        fd = os.open(path, os.O_RDWR | os.O_CREAT, 0o600)
        with os.fdopen(fd, "r+", encoding="utf-8") as handle:
            fcntl.flock(handle, fcntl.LOCK_EX)
            try:
                raw = handle.read()
                try:
                    loaded = json.loads(raw) if raw.strip() else {}
                except ValueError:
                    loaded = {}  # a torn or foreign file: start over rather than stop for ever
                state: dict[str, Any] = loaded if isinstance(loaded, dict) else {}
                yield state
                handle.seek(0)
                handle.truncate()
                json.dump(state, handle, sort_keys=True)
                handle.flush()
            finally:
                fcntl.flock(handle, fcntl.LOCK_UN)

    # --- before a dial ---------------------------------------------------------------

    def admit(self, token: str | None) -> None:
        """Refuse to dial while the agent is in its cooldown, or with a credential it refused."""

        cooldown = self.guard.auth.cooldown_seconds
        with self._locked() as state:
            refused = _strings(state.get("refused_credentials"))
            failed_at = _number(state.get("auth_failed_at"))
        if token is not None and _digest(token) in refused:
            raise AgentAuthRefused(
                f"{self.target_id}: the agent refused this credential before; set a fresh one "
                "(the guard keeps its digest, never its value); nothing was sent"
            )
        since = self.now() - failed_at if failed_at is not None else None
        if since is not None and 0.0 <= since < cooldown:
            raise AgentPacingStop(
                f"{self.target_id}: the last authentication failure was {int(since)}s ago; the "
                f"guard waits {int(cooldown - since)}s more (guard.auth.cooldown_seconds); "
                "nothing was sent"
            )

    def record_auth_failure(self, token: str | None, *, refused: bool) -> None:
        """Start the cooldown; ``refused`` also remembers the credential's digest."""

        with self._locked() as state:
            state["auth_failed_at"] = self.now()
            if refused and token is not None:
                kept = [
                    d for d in _strings(state.get("refused_credentials")) if d != _digest(token)
                ]
                state["refused_credentials"] = [*kept, _digest(token)][-_MAX_REFUSED:]

    # --- before a query --------------------------------------------------------------

    def reserve(self) -> float:
        """Reserve the next query's slot; the seconds to wait before sending it.

        The slot is ``min_interval_seconds`` after the last one reserved (by any process), and a
        slot that would make more than ``max_per_hour`` in its hour is refused: waiting out an
        hour inside a campaign is not pacing, it is a stalled run.
        """

        pacing = self.guard.pacing
        if pacing is None:
            return 0.0
        now = self.now()
        with self._locked() as state:
            sent = sorted(t for t in _numbers(state.get("sent")) if now - t < _HOUR)
            due = max(now, sent[-1] + pacing.min_interval_seconds) if sent else now
            if pacing.max_per_hour is not None:
                in_window = [t for t in sent if due - t < _HOUR]
                if len(in_window) >= pacing.max_per_hour:
                    free_in = int(in_window[0] + _HOUR - due) + 1
                    raise AgentPacingStop(
                        f"{self.target_id}: {pacing.max_per_hour} queries in the last hour "
                        f"(guard.pacing.max_per_hour); the next slot frees in {free_in}s; resume "
                        "the run then"
                    )
            state["sent"] = [*sent, due]
        return max(0.0, due - now)


def _strings(value: object) -> list[str]:
    return [v for v in value if isinstance(v, str)] if isinstance(value, list) else []


def _numbers(value: object) -> list[float]:
    if not isinstance(value, list):
        return []
    return [float(v) for v in value if isinstance(v, (int, float)) and not isinstance(v, bool)]


def _number(value: object) -> float | None:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    return float(value)


def reported_tools(frame: Mapping[str, Any], path: str) -> list[str]:
    """The tool or agent names a frame reports at ``path``: one name, or a list of them."""

    value = get_path(frame, path)
    if isinstance(value, str):
        return [value]
    if isinstance(value, list):
        return [v for v in value if isinstance(v, str)]
    return []
