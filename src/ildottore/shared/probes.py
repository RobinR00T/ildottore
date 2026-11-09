"""The request metadata that asks an adapter for a probe in place of a query (u04 A-133).

A spec whose ``requires`` names :attr:`~ildottore.shared.enums.RequiresCapability.WEBSOCKET_ORIGIN`
is not a prompt: the runner marks its request ``metadata[PROBE] = WEBSOCKET_ORIGIN_PROBE`` and the
WebSocket adapter tries the upgrade with a chosen ``Origin`` instead of sending the prompt
(OD-75). It lives in ``shared`` because ``core`` writes it and an adapter reads it, and neither
may import the other.
"""

from __future__ import annotations

from typing import Final

__all__ = ["CROSS_SITE_ORIGIN", "PROBE", "WEBSOCKET_ORIGIN_PROBE"]

#: The metadata key that names the probe a request asks for.
PROBE: Final = "probe"
#: The WebSocket handshake probe: a control upgrade, then one with :data:`CROSS_SITE_ORIGIN`.
WEBSOCKET_ORIGIN_PROBE: Final = "websocket_origin"
#: The ``Origin`` the probe offers as a site the endpoint must not trust. Under ``.invalid``
#: (RFC 2606, RFC 6761), which never resolves: it names no real site and reaches none.
CROSS_SITE_ORIGIN: Final = "https://dottore-cross-site.invalid"
