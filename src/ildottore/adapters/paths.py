"""A dotted path into a JSON payload (``a.b.0.c``), read by every template-driven adapter.

Its own module so :mod:`.rest` and :mod:`.agent_guard` (which :mod:`.rest` imports for its
``guard``) both read it without importing each other; :mod:`.rest` re-exports it.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any

__all__ = ["get_path"]


def get_path(payload: Any, path: str) -> Any:
    """Resolve a dotted path (``a.b.0.c``) into a nested JSON payload.

    Integer-looking segments index into sequences. Returns ``None`` if any
    segment is missing rather than raising, so a missing optional field (e.g.
    ``finish_reason``) is simply absent.
    """

    current: Any = payload
    for segment in path.split("."):
        if current is None:
            return None
        if segment.lstrip("-").isdigit():
            if not isinstance(current, Sequence) or isinstance(current, (str, bytes)):
                return None
            idx = int(segment)
            if -len(current) <= idx < len(current):
                current = current[idx]
            else:
                return None
        elif isinstance(current, Mapping):
            current = current.get(segment)
        else:
            return None
    return current
