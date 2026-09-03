"""Media asset resolution in the loader: inline bytes, with a strict path-traversal guard."""

from __future__ import annotations

import base64
from pathlib import Path

import pytest

from ildottore.registry.loader import _AssetError, _inline_media_assets, _resolve_asset_bytes


def test_resolve_asset_reads_file_under_spec_dir(tmp_path: Path) -> None:
    (tmp_path / "assets").mkdir()
    asset = tmp_path / "assets" / "clip.wav"
    asset.write_bytes(b"RIFFfake")
    assert _resolve_asset_bytes(tmp_path, "assets/clip.wav") == b"RIFFfake"


@pytest.mark.parametrize(
    "bad",
    [
        "/etc/passwd",  # absolute
        "../secrets.wav",  # parent escape
        "assets/../../secrets.wav",  # nested escape
        "assets/missing.wav",  # not found
    ],
)
def test_resolve_asset_rejects_unsafe_or_missing(tmp_path: Path, bad: str) -> None:
    (tmp_path / "assets").mkdir()
    with pytest.raises(_AssetError):
        _resolve_asset_bytes(tmp_path, bad)


def test_resolve_asset_rejects_symlink_escape(tmp_path: Path) -> None:
    # A symlink inside the spec dir pointing outside must not grant a read outside it.
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "secret.wav").write_bytes(b"SECRET")
    spec_dir = tmp_path / "spec"
    (spec_dir / "assets").mkdir(parents=True)
    link = spec_dir / "assets" / "link.wav"
    try:
        link.symlink_to(outside / "secret.wav")
    except OSError:  # pragma: no cover - platform without symlink permission
        pytest.skip("symlinks not permitted here")
    with pytest.raises(_AssetError):
        _resolve_asset_bytes(spec_dir, "assets/link.wav")


def test_inline_media_assets_injects_data_b64(tmp_path: Path) -> None:
    (tmp_path / "assets").mkdir()
    (tmp_path / "assets" / "clip.wav").write_bytes(b"AUDIOBYTES")
    data = {
        "attack": {
            "user_prompt": "listen",
            "media": [{"kind": "audio", "format": "wav", "asset": "assets/clip.wav"}],
        }
    }
    _inline_media_assets(data, tmp_path)
    part = data["attack"]["media"][0]
    assert part["data_b64"] == base64.b64encode(b"AUDIOBYTES").decode("ascii")
    assert part["asset"] == "assets/clip.wav"  # kept for provenance


def test_inline_media_assets_noop_without_media(tmp_path: Path) -> None:
    data = {"attack": {"user_prompt": "hi"}}
    _inline_media_assets(data, tmp_path)  # must not raise
    assert "media" not in data["attack"]
