"""``dottore registry mutators`` and ``dottore mutate``: see what a mutation sends (u05 A-99).

Two read-only helpers for ``--obfuscate`` and ``--fuzz``. ``registry mutators`` lists every
registered mutator with the parameters it takes and the presets, so an operator can write a
mutation or a chain without reading the source. ``mutate`` applies one mutation (or chain) to a
text the operator types and prints exactly what would be sent; when the chain ends in an image
link it writes the PNG too, with the SHA-256 a run records. Nothing reaches a target.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from pathlib import Path

from ildottore.mutators.obfuscation import PRESETS, mutation_problem
from ildottore.mutators.registry import MutatorRegistry
from ildottore.shared.media import render_media_part
from ildottore.shared.mutation_chain import (
    CHAIN_SEPARATOR,
    IMAGE_LINK,
    chain_links,
    ends_in_image,
    link_base,
)

__all__ = [
    "PREVIEW_SPEC_ID",
    "MutateError",
    "Preview",
    "preview",
    "render_mutators",
    "render_preview",
]

#: The spec id a preview seeds its links with when the operator names none.
PREVIEW_SPEC_ID = "PREVIEW"


class MutateError(ValueError):
    """A mutation the preview cannot apply (unknown mutator, bad parameter, bad chain)."""


@dataclass(frozen=True)
class Preview:
    """What one mutation sends: the text turn, and the image it attaches, if any."""

    mutation: str
    text: str
    image_text: str | None = None
    image_path: Path | None = None
    image_sha256: str | None = None


def render_mutators(registry: MutatorRegistry) -> str:
    """The registered mutators with their parameters, then the ``--obfuscate`` presets."""

    rows = ["MUTATOR                     REVERSIBLE  PARAMETERS"]
    for name in sorted(registry.names()):
        mutator = registry.get(name)
        accepted = getattr(mutator, "accepted_params", None)
        if accepted is None:
            params = "(not declared)"
        elif not accepted:
            params = "-"
        elif all(p.isdigit() for p in accepted):
            params = f"{min(accepted, key=int)} to {max(accepted, key=int)}"
        else:
            params = ", ".join(sorted(accepted))
        reversible = "yes" if getattr(mutator, "reversible", False) else "no"
        rows.append(f"{name:<27} {reversible:<11} {params}")
    rows.append("")
    rows.append("PRESETS (--obfuscate <preset>)")
    for preset, mutations in PRESETS.items():
        rows.append(f"{preset:<12} {len(mutations):>3}  {', '.join(mutations)}")
    rows.append("")
    rows.append(
        f"A chain joins links with '{CHAIN_SEPARATOR}' and applies them left to right "
        f"(structured:js+encode:uu+{IMAGE_LINK}:decode); '{IMAGE_LINK}' goes last."
    )
    return "\n".join(rows)


def preview(
    registry: MutatorRegistry,
    text: str,
    mutation: str,
    *,
    spec_id: str = PREVIEW_SPEC_ID,
    out_dir: Path | None = None,
) -> Preview:
    """Apply ``mutation`` to ``text`` as the runner would for ``spec_id``.

    Each link is seeded ``<spec_id>::<link>``, the runner's seed, so a preview with a spec's id
    shows byte for byte what a run sends for that spec. An image link's PNG is written to
    ``out_dir`` (the current directory by default).
    """

    problem = mutation_problem(mutation, registry)
    if problem is not None:
        raise MutateError(f"{mutation!r}: {problem}")
    links = chain_links(mutation)
    text_links = links[:-1] if ends_in_image(mutation) else links
    for link in text_links:
        if link == "identity":
            continue
        text = registry.get(link_base(link)).mutate(text, f"{spec_id}::{link}")
    if not ends_in_image(mutation):
        return Preview(mutation=mutation, text=text)
    mutate_result = getattr(registry.get(IMAGE_LINK), "mutate_result", None)
    if mutate_result is None:  # pragma: no cover - a plugin that replaced `image`
        raise MutateError(f"{mutation!r}: the {IMAGE_LINK!r} mutator draws no media part")
    drawn = mutate_result(text, f"{spec_id}::{links[-1]}")
    part = drawn.provenance["media"]
    if not isinstance(part, dict):  # pragma: no cover - the image mutator always sets it
        raise MutateError(f"{mutation!r}: the image link drew no media part")
    _, raw = render_media_part(part)
    digest = hashlib.sha256(raw).hexdigest()
    target_dir = out_dir if out_dir is not None else Path()
    target_dir.mkdir(parents=True, exist_ok=True)
    path = target_dir / f"{spec_id}-{digest[:12]}.png"
    path.write_bytes(raw)
    return Preview(
        mutation=mutation,
        text=drawn.text,
        image_text=str(part.get("render_text", "")),
        image_path=path,
        image_sha256=digest,
    )


def render_preview(result: Preview) -> str:
    """The preview as the operator reads it: the text turn, then the image, if any."""

    lines = [f"mutation: {result.mutation}", "--- text sent ---", result.text]
    if result.image_path is not None:
        lines += [
            "--- image attached ---",
            f"{result.image_path} (sha256 {result.image_sha256})",
            "--- text drawn in the image ---",
            result.image_text or "",
        ]
    return "\n".join(lines)
