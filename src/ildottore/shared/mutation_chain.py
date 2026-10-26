"""Chained mutations: one attempt's carrier built from several mutators in order (u05 A-99).

A mutation string names one mutator (``rot13``), one with a parameter (``encode:base32``), or a
chain of them joined by ``+`` (``structured:json+encode:base32``): the payload goes through each
link from left to right, so the example writes the request as a JSON file and then base32-encodes
the file. Every link is looked up, checked and seeded on its own, as if it stood alone, so a chain
is exactly as replayable as its links.

Kept in ``shared`` because three peers read it and may not import each other: the runner (u08)
applies a chain, the linter (u02) refuses a bad link, and the CLI (u12) builds chains for
``--obfuscate`` and ``--fuzz``.
"""

from __future__ import annotations

__all__ = [
    "CHAIN_SEPARATOR",
    "IMAGE_LINK",
    "MAX_CHAIN_LINKS",
    "chain_links",
    "chain_problem",
    "ends_in_image",
    "link_base",
]

#: Joins the links of a chain. No mutator name or parameter contains it.
CHAIN_SEPARATOR = "+"

#: The most links one mutation may chain. Every encoding link multiplies the payload (binary by
#: nine, morse by about four), so a longer chain only buys a request no model reads, at a price.
MAX_CHAIN_LINKS = 4

#: The link that moves the carrier into an image (``image``, ``image:figstep``). It ends a chain:
#: once the payload is in pixels, no text mutator can reach it.
IMAGE_LINK = "image"


def chain_links(mutation: str) -> list[str]:
    """The links of ``mutation`` in the order they apply (one link for a plain mutation)."""

    return mutation.split(CHAIN_SEPARATOR)


def link_base(link: str) -> str:
    """Registry name of one link (``encode:base32`` -> ``encode``)."""

    return link.split(":", 1)[0]


def ends_in_image(mutation: str) -> bool:
    """True when ``mutation`` sends its carrier as an image (its last link is ``image``)."""

    return link_base(chain_links(mutation)[-1]) == IMAGE_LINK


def chain_problem(mutation: str) -> str | None:
    """Why ``mutation`` cannot be a chain, or ``None`` when its shape is sound.

    Checks the shape only: an empty link (``a++b``, a trailing ``+``), ``identity`` inside a
    chain (it changes nothing, so the chain would be recorded under a name it does not send), an
    ``image`` link anywhere but last, and the link ceiling. Whether each link names a registered
    mutator is the caller's check, against its own registry.
    """

    links = chain_links(mutation)
    if any(link_base(link) == IMAGE_LINK for link in links[:-1]):
        return f"mutation {mutation!r} has an image link before its end; image goes last"
    if len(links) == 1:
        return None
    if any(not link.strip() for link in links):
        return f"mutation {mutation!r} has an empty link"
    if any(link_base(link) == "identity" for link in links):
        return f"mutation {mutation!r} chains identity, which changes nothing"
    if len(links) > MAX_CHAIN_LINKS:
        return (
            f"mutation {mutation!r} chains {len(links)} links; at most {MAX_CHAIN_LINKS} "
            "(each encoding link multiplies the request)"
        )
    return None
