"""Deterministic media rendering for multimodal attacks (``docs/12`` P0, MVP-3 phase).

A multimodal attack carries its payload in a non-text modality: a visual/typographic prompt
injection renders an instruction *inside an image* and checks whether the target obeys text it
read off a picture. To stay faithful to the reproducibility thesis (``docs/00``) the carrier must
be **byte-stable**: the same declarative part always renders to the same bytes, on any machine,
with no timestamp or randomness. That rules out a heavyweight imaging library; this module is a
tiny, dependency-free PNG encoder (stdlib ``zlib`` + ``struct``) driving a fixed 5x7 bitmap font.

A declarative media part (``attack.media[i]`` / ``ModelRequest.media[i]``) is a mapping:

* ``{"kind": "image", "format": "png", "render_text": "IGNORE ..."}`` renders the text into a
  black-on-white PNG (the reproducible, declarative path: no binary in the spec).
* ``{"kind": "image", "format": "png", "data_b64": "<base64>"}`` uses pinned bytes verbatim (for
  a fixed asset a spec wants to reuse). Still byte-stable; no rendering.

``render_media_part`` returns ``(mime_type, raw_bytes)``. The adapter base64-encodes the bytes
into the provider's image content block; the runner keeps the *declarative* part on the request,
so a stored run re-renders to identical bytes on replay.

Safe-by-design: rendering only turns text into pixels. Nothing here reaches the network, the
filesystem or a subprocess.
"""

from __future__ import annotations

import base64
import hashlib
import struct
import zlib
from collections.abc import Mapping, Sequence

__all__ = [
    "MediaError",
    "media_digest",
    "media_digests",
    "render_media_part",
    "render_text_png",
]


class MediaError(ValueError):
    """A declarative media part could not be rendered (unknown kind/format, bad data)."""


# --- 5x7 bitmap font (public-domain style dot-matrix) ------------------------------------------
# Each glyph is 7 rows of 5 columns; "#" is ink, "." is background. Lowercase maps to uppercase;
# an unknown character renders as a filled box so a missing glyph is visible, never silent.

_GLYPH_ROWS = 7
_GLYPH_COLS = 5

_FONT: dict[str, tuple[str, ...]] = {
    " ": (".....", ".....", ".....", ".....", ".....", ".....", "....."),
    "A": (".###.", "#...#", "#...#", "#####", "#...#", "#...#", "#...#"),
    "B": ("####.", "#...#", "#...#", "####.", "#...#", "#...#", "####."),
    "C": (".####", "#....", "#....", "#....", "#....", "#....", ".####"),
    "D": ("###..", "#..#.", "#...#", "#...#", "#...#", "#..#.", "###.."),
    "E": ("#####", "#....", "#....", "####.", "#....", "#....", "#####"),
    "F": ("#####", "#....", "#....", "####.", "#....", "#....", "#...."),
    "G": (".####", "#....", "#....", "#.###", "#...#", "#...#", ".####"),
    "H": ("#...#", "#...#", "#...#", "#####", "#...#", "#...#", "#...#"),
    "I": ("#####", "..#..", "..#..", "..#..", "..#..", "..#..", "#####"),
    "J": ("..###", "...#.", "...#.", "...#.", "#..#.", "#..#.", ".##.."),
    "K": ("#...#", "#..#.", "#.#..", "##...", "#.#..", "#..#.", "#...#"),
    "L": ("#....", "#....", "#....", "#....", "#....", "#....", "#####"),
    "M": ("#...#", "##.##", "#.#.#", "#.#.#", "#...#", "#...#", "#...#"),
    "N": ("#...#", "##..#", "#.#.#", "#..##", "#...#", "#...#", "#...#"),
    "O": (".###.", "#...#", "#...#", "#...#", "#...#", "#...#", ".###."),
    "P": ("####.", "#...#", "#...#", "####.", "#....", "#....", "#...."),
    "Q": (".###.", "#...#", "#...#", "#...#", "#.#.#", "#..#.", ".##.#"),
    "R": ("####.", "#...#", "#...#", "####.", "#.#..", "#..#.", "#...#"),
    "S": (".####", "#....", "#....", ".###.", "....#", "....#", "####."),
    "T": ("#####", "..#..", "..#..", "..#..", "..#..", "..#..", "..#.."),
    "U": ("#...#", "#...#", "#...#", "#...#", "#...#", "#...#", ".###."),
    "V": ("#...#", "#...#", "#...#", "#...#", "#...#", ".#.#.", "..#.."),
    "W": ("#...#", "#...#", "#...#", "#.#.#", "#.#.#", "##.##", "#...#"),
    "X": ("#...#", "#...#", ".#.#.", "..#..", ".#.#.", "#...#", "#...#"),
    "Y": ("#...#", "#...#", ".#.#.", "..#..", "..#..", "..#..", "..#.."),
    "Z": ("#####", "....#", "...#.", "..#..", ".#...", "#....", "#####"),
    "0": (".###.", "#...#", "#..##", "#.#.#", "##..#", "#...#", ".###."),
    "1": ("..#..", ".##..", "..#..", "..#..", "..#..", "..#..", "#####"),
    "2": (".###.", "#...#", "....#", "...#.", "..#..", ".#...", "#####"),
    "3": ("#####", "...#.", "..#..", "...#.", "....#", "#...#", ".###."),
    "4": ("...#.", "..##.", ".#.#.", "#..#.", "#####", "...#.", "...#."),
    "5": ("#####", "#....", "####.", "....#", "....#", "#...#", ".###."),
    "6": (".###.", "#....", "#....", "####.", "#...#", "#...#", ".###."),
    "7": ("#####", "....#", "...#.", "..#..", ".#...", ".#...", ".#..."),
    "8": (".###.", "#...#", "#...#", ".###.", "#...#", "#...#", ".###."),
    "9": (".###.", "#...#", "#...#", ".####", "....#", "....#", ".###."),
    ".": (".....", ".....", ".....", ".....", ".....", ".##..", ".##.."),
    ",": (".....", ".....", ".....", ".....", ".##..", ".##..", ".#..."),
    ":": (".....", ".##..", ".##..", ".....", ".##..", ".##..", "....."),
    ";": (".....", ".##..", ".##..", ".....", ".##..", ".##..", ".#..."),
    "!": ("..#..", "..#..", "..#..", "..#..", "..#..", ".....", "..#.."),
    "?": (".###.", "#...#", "....#", "...#.", "..#..", ".....", "..#.."),
    "'": ("..#..", "..#..", "..#..", ".....", ".....", ".....", "....."),
    '"': (".#.#.", ".#.#.", ".#.#.", ".....", ".....", ".....", "....."),
    "-": (".....", ".....", ".....", "#####", ".....", ".....", "....."),
    "/": ("....#", "....#", "...#.", "..#..", ".#...", "#....", "#...."),
    "(": ("..##.", ".#...", "#....", "#....", "#....", ".#...", "..##."),
    ")": (".##..", "...#.", "....#", "....#", "....#", "...#.", ".##.."),
    "_": (".....", ".....", ".....", ".....", ".....", ".....", "#####"),
}
_UNKNOWN: tuple[str, ...] = ("#####", "#####", "#####", "#####", "#####", "#####", "#####")


def _glyph(char: str) -> tuple[str, ...]:
    return _FONT.get(char.upper(), _UNKNOWN)


def _png_chunk(tag: bytes, data: bytes) -> bytes:
    return (
        struct.pack(">I", len(data))
        + tag
        + data
        + struct.pack(">I", zlib.crc32(tag + data) & 0xFFFFFFFF)
    )


def _encode_png_grayscale(pixels: list[list[int]]) -> bytes:
    """Encode a rectangular list of 0..255 grayscale rows to an 8-bit grayscale PNG (byte-stable).

    Fixed filter byte 0 per scanline and a fixed zlib level so the output depends only on the
    pixels: identical input always yields identical bytes (reproducibility thesis).
    """

    height = len(pixels)
    width = len(pixels[0]) if height else 0
    raw = bytearray()
    for row in pixels:
        raw.append(0)  # filter type 0 (None)
        raw.extend(row)
    signature = b"\x89PNG\r\n\x1a\n"
    ihdr = struct.pack(">IIBBBBB", width, height, 8, 0, 0, 0, 0)  # 8-bit grayscale
    idat = zlib.compress(bytes(raw), 9)
    return (
        signature + _png_chunk(b"IHDR", ihdr) + _png_chunk(b"IDAT", idat) + _png_chunk(b"IEND", b"")
    )


def render_text_png(text: str, *, scale: int = 3, columns: int = 32, margin: int = 4) -> bytes:
    """Render ``text`` into a deterministic black-on-white 8-bit grayscale PNG.

    ``columns`` wraps the text into lines of at most that many characters (word-preserving is not
    attempted: a fixed hard wrap keeps the layout byte-stable regardless of locale). ``scale``
    nearest-neighbour-magnifies each pixel so the 5x7 font is legible to a vision model. The
    output is a pure function of ``(text, scale, columns, margin)``.
    """

    if scale < 1 or columns < 1 or margin < 0:
        raise MediaError("render_text_png: scale/columns must be >= 1 and margin >= 0")

    lines = _wrap(text, columns)
    cell_w = _GLYPH_COLS + 1  # 1px inter-glyph gap
    cell_h = _GLYPH_ROWS + 1  # 1px inter-line gap
    grid_w = columns * cell_w
    grid_h = max(1, len(lines)) * cell_h

    # 1px-per-unit grid, white (255) background, black (0) ink.
    grid = [[255] * grid_w for _ in range(grid_h)]
    for line_idx, line in enumerate(lines):
        y0 = line_idx * cell_h
        for col_idx, char in enumerate(line):
            x0 = col_idx * cell_w
            glyph = _glyph(char)
            for gy in range(_GLYPH_ROWS):
                pattern = glyph[gy]
                for gx in range(_GLYPH_COLS):
                    if pattern[gx] == "#":
                        grid[y0 + gy][x0 + gx] = 0

    scaled = _scale_and_pad(grid, scale=scale, margin=margin)
    return _encode_png_grayscale(scaled)


def _wrap(text: str, columns: int) -> list[str]:
    """Hard-wrap into fixed-width lines; newlines in the source start a new line."""

    lines: list[str] = []
    for source_line in text.split("\n"):
        if source_line == "":
            lines.append("")
            continue
        for start in range(0, len(source_line), columns):
            lines.append(source_line[start : start + columns])
    return lines or [""]


def _scale_and_pad(grid: list[list[int]], *, scale: int, margin: int) -> list[list[int]]:
    """Nearest-neighbour magnify by ``scale`` and add a white ``margin`` border."""

    inner_h = len(grid) * scale
    inner_w = (len(grid[0]) if grid else 0) * scale
    out_h = inner_h + 2 * margin
    out_w = inner_w + 2 * margin
    out = [[255] * out_w for _ in range(out_h)]
    for y, row in enumerate(grid):
        for x, value in enumerate(row):
            if value == 255:
                continue
            for dy in range(scale):
                oy = margin + y * scale + dy
                base = out[oy]
                for dx in range(scale):
                    base[margin + x * scale + dx] = value
    return out


def _decode_b64(data_b64: str) -> bytes:
    try:
        return base64.b64decode(data_b64, validate=True)
    except ValueError as exc:  # binascii.Error is a ValueError subclass
        raise MediaError("media data_b64 is not valid base64") from exc


def render_media_part(part: Mapping[str, object]) -> tuple[str, bytes]:
    """Resolve one declarative media part to ``(mime_type, raw_bytes)``.

    * ``kind == "image"`` (``format == "png"``): from ``render_text`` (rendered deterministically
      here) or ``data_b64`` (pinned bytes).
    * ``kind == "audio"`` (``format == "wav"``): from ``data_b64`` (pinned bytes). Audio cannot be
      synthesized from text with the stdlib, so an audio carrier is always pinned bytes; the spec
      declares it as an ``asset`` path that the loader resolves into ``data_b64`` before this runs.

    Raises :class:`MediaError` on an unknown kind/format or malformed data (fail loudly).
    """

    kind = part.get("kind")
    if kind == "image":
        return _render_image_part(part)
    if kind == "audio":
        return _render_audio_part(part)
    raise MediaError(f"unsupported media kind {kind!r} (only 'image' / 'audio' in this build)")


def _render_image_part(part: Mapping[str, object]) -> tuple[str, bytes]:
    fmt = part.get("format", "png")
    if fmt != "png":
        raise MediaError(f"unsupported image format {fmt!r} (only 'png' in this build)")

    data_b64 = part.get("data_b64")
    if isinstance(data_b64, str) and data_b64:
        return "image/png", _decode_b64(data_b64)

    render_text = part.get("render_text")
    if isinstance(render_text, str):
        scale = part.get("scale", 3)
        columns = part.get("columns", 32)
        if not isinstance(scale, int) or not isinstance(columns, int):
            raise MediaError("media 'scale'/'columns' must be integers")
        return "image/png", render_text_png(render_text, scale=scale, columns=columns)

    raise MediaError("image media part needs either 'render_text' or 'data_b64'")


def _render_audio_part(part: Mapping[str, object]) -> tuple[str, bytes]:
    fmt = part.get("format", "wav")
    if fmt != "wav":
        raise MediaError(f"unsupported audio format {fmt!r} (only 'wav' in this build)")
    data_b64 = part.get("data_b64")
    if isinstance(data_b64, str) and data_b64:
        return "audio/wav", _decode_b64(data_b64)
    raise MediaError("audio media part needs 'data_b64' (resolved from its 'asset' by the loader)")


def media_digest(part: Mapping[str, object]) -> str:
    """SHA-256 (hex) of the bytes a declarative media part renders to.

    The digest is the chain-of-custody for a multimodal carrier: recorded on the request, it lets
    a run's evidence prove exactly which image bytes were sent, and an auditor re-renders the
    declarative part and re-computes the hash to verify. Because the renderer is deterministic, the
    digest equals ``sha256`` of what the adapter puts on the wire for the same part.
    """

    return hashlib.sha256(render_media_part(part)[1]).hexdigest()


def media_digests(parts: Sequence[Mapping[str, object]]) -> list[str]:
    """Per-part :func:`media_digest` for a media list (order preserved)."""

    return [media_digest(part) for part in parts]
