"""``dottore render-media <spec-id>``: render a multimodal spec's carrier to inspect it.

A multimodal spec (``attack.media``) sends an image the target must read. Before pointing a scan
at a real vision model, an operator will want to SEE exactly what image gets sent, and to record
its digest. This is that read-only preview: it loads the spec, renders each declarative media part
deterministically (``shared.media``), writes the PNG(s) to disk and reports the path, size and the
SHA-256 chain-of-custody digest. It sends nothing and touches no target.

Thin delegator (contract §5.5): the registry look-up is u02, the rendering is ``shared.media``;
no parsing or verdict logic here.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from ildottore.cli import wiring
from ildottore.registry import SpecNotFoundError
from ildottore.shared.media import MediaError, media_digest, render_media_part

__all__ = ["RenderMediaError", "RenderedCarrier", "render_carrier_report", "render_spec_media"]


class RenderMediaError(ValueError):
    """The spec is absent or declares no renderable media."""


@dataclass(frozen=True)
class RenderedCarrier:
    """One rendered media part written to disk."""

    index: int
    path: Path
    mime: str
    size: int
    sha256: str


def render_spec_media(spec_paths: list[Path], spec_id: str, out_dir: Path) -> list[RenderedCarrier]:
    """Render every ``attack.media`` part of ``spec_id`` into ``out_dir`` (one file per part).

    Each part is written with the extension implied by its rendered MIME type (image/png -> .png,
    audio/wav -> .wav). Raises :class:`RenderMediaError` if the spec is not found, has no media, or
    a part cannot be rendered (a :class:`~ildottore.shared.media.MediaError` is wrapped so the CLI
    reports one clean error).
    """

    registry = wiring.build_registry(spec_paths)
    try:
        spec = registry.get(spec_id)
    except SpecNotFoundError as exc:
        raise RenderMediaError(f"spec {spec_id!r} not found") from exc

    media = spec.attack.media or []
    if not media:
        raise RenderMediaError(f"spec {spec_id!r} declares no attack.media (not a multimodal spec)")

    out_dir.mkdir(parents=True, exist_ok=True)
    rendered: list[RenderedCarrier] = []
    for index, part in enumerate(media):
        try:
            mime, raw = render_media_part(part)
        except MediaError as exc:
            raise RenderMediaError(f"attack.media[{index}] is not renderable: {exc}") from exc
        ext = mime.split("/", 1)[1] if "/" in mime else "bin"  # image/png -> png, audio/wav -> wav
        path = out_dir / f"{spec_id}.media-{index}.{ext}"
        path.write_bytes(raw)
        rendered.append(
            RenderedCarrier(
                index=index,
                path=path,
                mime=mime,
                size=len(raw),
                sha256=media_digest(part),
            )
        )
    return rendered


def render_carrier_report(carriers: list[RenderedCarrier]) -> str:
    """A compact human-readable summary of what was written."""

    lines = [f"rendered {len(carriers)} media carrier(s):"]
    for carrier in carriers:
        lines.append(f"  [{carrier.index}] {carrier.path}  ({carrier.mime}, {carrier.size} bytes)")
        lines.append(f"      sha256 {carrier.sha256}")
    return "\n".join(lines)
