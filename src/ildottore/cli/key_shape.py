"""Whether a value or a parameter name an operator writes is shaped like a credential (u12 A-82).

``dottore fleet`` copies an endpoint into ``scope.yaml`` and the target file, and ``dottore
new-spec`` writes a family into a scaffold, so each refuses a credential in them. The whole
redactor read too much as one: its PII rules took ``alice@example.com``, ``CVE-2021-44228`` and a
UUID for secrets, and its entropy rule a trace or request id, which legitimate endpoints carry in
their query (round-2 audit of A-82, LOWs 3 and 4). A value here is shaped like a key when one of
the redactor's credential formats matches it, or when it is a high-entropy token that is not a
hexadecimal identifier (``4bf92f35...``, ``req_8f7e6d5c...``, a UUID). A parameter names a
credential when its whole name, normalised, is one of :data:`CREDENTIAL_NAMES`: matching the last
word of a name refused ``sort_key``, ``session`` and ``max_token``.
"""

from __future__ import annotations

import math
import re
from typing import Final
from urllib.parse import unquote_plus

from ildottore.redactor import Redactor, credential_patterns

__all__ = ["CREDENTIAL_NAMES", "key_shape", "names_a_credential", "normalised_name"]

_FORMATS: Final = Redactor(patterns=credential_patterns(), entropy_threshold=math.inf)
_ENTROPY: Final = Redactor(patterns=[])
#: A hexadecimal identifier, with a short lowercase prefix (`proj_`, `req_`) or none, or a UUID:
#: what a trace, request, tenant or project id looks like, high in entropy and no key.
_IDENTIFIER: Final = re.compile(
    r"(?:[a-z][a-z0-9]{0,15}[_-])?[0-9a-f]{8,64}"
    r"|[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
    re.IGNORECASE,
)
#: Parameter names, normalised (:func:`normalised_name`), that carry a credential.
CREDENTIAL_NAMES: Final = frozenset(
    {
        "access_key",
        "access_token",
        "accesskey",
        "api_key",
        "api_secret",
        "api_token",
        "apikey",
        "app_key",
        "application_key",
        "auth",
        "auth_code",
        "auth_key",
        "auth_token",
        "authkey",
        "authorization",
        "bearer",
        "client_secret",
        "code",
        "credential",
        "credentials",
        "hapikey",
        "id_token",
        "jwt",
        "k",
        "key",
        "oauth_signature",
        "oauth_token",
        "ocp_apim_subscription_key",
        "pass",
        "passcode",
        "passphrase",
        "passwd",
        "password",
        "personal_access_token",
        "private_key",
        "private_token",
        "pwd",
        "refresh_token",
        "sas_token",
        "secret",
        "secret_key",
        "secretkey",
        "session_id",
        "session_token",
        "sessionid",
        "sig",
        "signature",
        "subscription_key",
        "token",
        "token_secret",
        "x_amz_credential",
        "x_amz_security_token",
        "x_amz_signature",
        "x_api_key",
        "x_goog_api_key",
        "x_goog_credential",
        "x_goog_signature",
        "xapi_key",
        "xapikey",
    }
)


def normalised_name(name: str) -> str:
    """``name`` as it is compared: decoded (up to three times, for ``%2561pi_key``), stripped,
    without a trailing ``[]``, camelCase split, case-folded, its words joined by ``_``."""

    text = name
    for _ in range(3):
        decoded = unquote_plus(text)
        if decoded == text:
            break
        text = decoded
    text = text.strip()
    if text.endswith("[]"):
        text = text[:-2].strip()
    text = re.sub(r"(?<=[a-z0-9])(?=[A-Z])", "_", text)
    return "_".join(word for word in re.split(r"[^A-Za-z0-9]+", text.casefold()) if word)


def names_a_credential(name: str) -> bool:
    """Whether the parameter ``name``, normalised, is one of :data:`CREDENTIAL_NAMES`."""

    return normalised_name(name) in CREDENTIAL_NAMES


def key_shape(text: str) -> str | None:
    """``"a credential format"`` or ``"a high-entropy token"`` when ``text`` is shaped like a key,
    else ``None``."""

    value = text.strip()
    if not value:
        return None
    if _FORMATS.redact_text(value) != value:
        return "a credential format"
    if _IDENTIFIER.fullmatch(value):
        return None
    if _ENTROPY.redact_text(value) != value:
        return "a high-entropy token"
    return None
