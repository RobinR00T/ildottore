"""A spec file that fails to load is refused, not dropped (audit 2026-10-03, F-10).

`dottore run` built its registry from whatever parsed, so a one-letter typo removed a spec
from the battery and the run still printed "Specs run: 1 of 1 planned" and `complete`.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from typer.testing import CliRunner

from ildottore.cli.app import app

REPO = Path(__file__).resolve().parents[2]


def test_a_spec_that_fails_to_load_refuses_the_run(tmp_path: Path) -> None:
    (tmp_path / "scope.yaml").write_text(
        'version: "1.0"\ntargets:\n  - id: mock-target\n    base_url: "mock://mock-target"\n'
        '    endpoints:\n      - host: "mock-target"\n        path_prefixes: ["/"]\n'
        '    identities:\n      - name: default\n        auth_ref: "env://NONE"\n'
    )
    (tmp_path / "target.yaml").write_text(
        "id: mock-target\ntype: chatbot\nmock_scenario: hardened\n"
        "capabilities:\n  tools: false\n  rag: false\n"
    )
    pack = tmp_path / "pack"
    (pack / "attacks").mkdir(parents=True)
    (pack / "pack.yaml").write_text("id: pack\npack_version: '1.0'\nname: pack\n")
    good = (REPO / "specs" / "attacks" / "PI-DIRECT-001.yaml").read_text()
    (pack / "attacks" / "PI-DIRECT-001.yaml").write_text(good)
    (pack / "attacks" / "broken.yaml").write_text(
        good.replace("id: PI-DIRECT-001", "id: PI-TYPO-001").replace(
            "severity: high", "severty: high"
        )
    )
    result = CliRunner().invoke(
        app,
        [
            "run",
            "-t",
            str(tmp_path / "target.yaml"),
            "--scope",
            str(tmp_path / "scope.yaml"),
            "--spec-path",
            str(pack),
            "--evidence-root",
            str(tmp_path / "ev"),
            "--run-db",
            str(tmp_path / "runs.sqlite"),
            "--no-color",
            "-q",
        ],
    )
    assert result.exit_code == 3, result.output
    assert "failed to load" in result.output
    assert not (tmp_path / "ev").exists() or not any((tmp_path / "ev").iterdir())


def _workspace(tmp_path: Path, files: dict[str, str]) -> Path:
    """A scope, a target and a pack whose `attacks/` holds ``files`` (name -> body)."""

    (tmp_path / "scope.yaml").write_text(
        'version: "1.0"\ntargets:\n  - id: mock-target\n    base_url: "mock://mock-target"\n'
        '    endpoints:\n      - host: "mock-target"\n        path_prefixes: ["/"]\n'
        '    identities:\n      - name: default\n        auth_ref: "env://NONE"\n'
    )
    (tmp_path / "target.yaml").write_text(
        "id: mock-target\ntype: chatbot\nmock_scenario: hardened\n"
        "capabilities:\n  tools: false\n  rag: false\n"
    )
    pack = tmp_path / "pack"
    (pack / "attacks").mkdir(parents=True)
    (pack / "pack.yaml").write_text("id: pack\npack_version: '1.0'\nname: pack\n")
    for name, body in files.items():
        (pack / "attacks" / name).write_text(body)
    return pack


def _dry_run(tmp_path: Path, pack: Path) -> str:
    result = CliRunner().invoke(
        app,
        [
            "run",
            "-t",
            str(tmp_path / "target.yaml"),
            "--scope",
            str(tmp_path / "scope.yaml"),
            "--spec-path",
            str(pack),
            "--dry-run",
            "--no-color",
        ],
    )
    assert result.exit_code == 3, result.output
    return result.output


def _broken(spec_id: str, extra_key: str = "severty") -> str:
    good = (REPO / "specs" / "attacks" / f"{spec_id}.yaml").read_text()
    return good.replace("severity: high", f"{extra_key}: high", 1)


def test_the_load_refusal_names_the_spec_file_it_could_not_load(tmp_path: Path) -> None:
    """The entropy rule read `attacks/DL-PII-ELICIT-001` (a lowercase directory glued to an
    uppercase id fits neither exempt shape) as a key, and the refusal said
    `«REDACTED:high_entropy:…».yaml`: the operator could not tell which file to fix
    (pre-merge audit of PR #47)."""

    pack = _workspace(tmp_path, {"DL-PII-ELICIT-001.yaml": _broken("DL-PII-ELICIT-001")})
    shown = _dry_run(tmp_path, pack)
    assert "attacks/DL-PII-ELICIT-001.yaml: " in shown
    assert "REDACTED" not in shown


def test_a_secret_in_the_same_refusal_is_still_masked(tmp_path: Path) -> None:
    """Only the file name is kept: what the loader quotes from inside the file still goes
    through the entropy rule."""

    key = "Xq9vT2mLp8RzK4wN7bYcD3"
    pack = _workspace(tmp_path, {"DL-PII-ELICIT-001.yaml": _broken("DL-PII-ELICIT-001", key)})
    shown = _dry_run(tmp_path, pack)
    assert "attacks/DL-PII-ELICIT-001.yaml: " in shown
    assert key not in shown
    assert "«REDACTED:high_entropy:" in shown


@pytest.mark.usefixtures("no_known_secrets")
def test_a_registered_credential_overlapping_the_name_masks_it(tmp_path: Path) -> None:
    """A name that is part of a credential the run read is masked outright (the entropy rule
    passes an id-shaped name), and one that holds a credential loses it to the value rule."""

    from ildottore.redactor import register_known_secret

    inside = "attacks/ZZ-OVERLAP-NAME-001.yaml"
    register_known_secret(f"pw-{inside}-tail")
    body = _broken("DL-PII-ELICIT-001").replace("id: DL-PII-ELICIT-001", "id: ZZ-OVERLAP-001")
    (tmp_path / "a").mkdir()
    shown = _dry_run(tmp_path / "a", _workspace(tmp_path / "a", {"ZZ-OVERLAP-NAME-001.yaml": body}))
    assert inside not in shown
    assert "«REDACTED:credential»: <root>: " in shown

    register_known_secret("pw7Kq2Lm9x")
    (tmp_path / "b").mkdir()
    shown = _dry_run(tmp_path / "b", _workspace(tmp_path / "b", {"ZZ-pw7Kq2Lm9x-001.yaml": body}))
    assert "pw7Kq2Lm9x" not in shown
    assert "attacks/ZZ-«REDACTED:credential:" in shown


@pytest.mark.usefixtures("no_known_secrets")
def test_a_short_name_inside_a_credential_stays_readable() -> None:
    """Below the registration floor a name is part of a credential only by chance: masking `x`
    would tell the reader the password holds an `x` (pre-commit audit)."""

    from ildottore.cli.app import _masked
    from ildottore.cli.run import SpecLoadError
    from ildottore.redactor import register_known_secret

    register_known_secret("Tq7xWm2Kp9")
    assert _masked(SpecLoadError("x: bad", spec_files=("x",))) == "x: bad"


@pytest.mark.usefixtures("no_known_secrets")
def test_a_digest_or_artifact_name_inside_a_credential_is_masked_outright() -> None:
    """The entropy rule passes a low-entropy 64-hex run, so a carried digest or an evidence file
    name that is part of a registered credential printed in clear."""

    from ildottore.cli.app import _masked
    from ildottore.redactor import register_known_secret
    from ildottore.store.replay import TamperError

    low = "ab" * 32
    register_known_secret(f"sk-{low}")
    shown = _masked(TamperError(f"content hashes to {low}", digests=(low,)))
    assert shown == "content hashes to «REDACTED:credential»"
    shown = _masked(ValueError(f"artifact {low}.json is missing"))
    assert shown == "artifact «REDACTED:credential» is missing"


@pytest.mark.parametrize("glue", ["/", "-", "+", "=", "_", "x"])
def test_a_kept_name_never_splits_a_longer_token(glue: str) -> None:
    """The tail or head of a longer token is not kept apart from the rest of it: the rest alone
    could fall under the entropy rule's length floor and print in clear."""

    from ildottore.cli.app import _masked
    from ildottore.cli.run import SpecLoadError

    name = "attacks/DL-PII-ELICIT-001.yaml"
    for glued in (f"Xq9vT2mLp8Rz{glue}{name}", f"{name}{glue}Xq9vT2mLp8Rz"):
        shown = _masked(SpecLoadError(f"{glued}: bad", spec_files=(name,)))
        assert "Xq9vT2mLp8Rz" not in shown, glued


def test_a_name_glued_to_a_kept_digest_is_not_kept() -> None:
    """A split piece equal to a name was re-matched on its own, with nothing before it, so the
    glue that refused it in context was lost (pre-commit audit)."""

    import hashlib

    from ildottore.cli.app import _masked
    from ildottore.store.replay import TamperError

    digest = hashlib.sha256(b"scope body").hexdigest()
    name = "-attacks/DL-PII-ELICIT-001.yaml"
    exc = TamperError(f"see {digest}{name}", digests=(digest,))
    exc.spec_files = (name,)  # type: ignore[attr-defined]
    shown = _masked(exc)
    assert shown.startswith(f"see {digest}«REDACTED:high_entropy:"), shown


def test_only_an_entry_on_disk_under_a_spec_path_is_kept(tmp_path: Path) -> None:
    from ildottore.cli.run import _spec_files_on_disk

    pack = tmp_path / "pack"
    (pack / "attacks").mkdir(parents=True)
    (pack / "attacks" / "A-001.yaml").write_text("x")
    (tmp_path / "outside.yaml").write_text("x")
    names = ["attacks/A-001.yaml", "attacks/GONE-001.yaml", "../outside.yaml"]
    names += [str(tmp_path / "outside.yaml"), "attacks/NUL\x00.yaml", "a" * 5000]
    assert _spec_files_on_disk([pack], names) == ("attacks/A-001.yaml",)
    # A spec path given as a file is shown relative to its own folder, as the loader does.
    single = pack / "attacks" / "A-001.yaml"
    assert _spec_files_on_disk([single], ["A-001.yaml"]) == ("A-001.yaml",)


def test_a_directory_or_a_dangling_link_named_as_a_spec_is_named(tmp_path: Path) -> None:
    """Both fail to load, and both are entries of the operator's tree (pre-commit audit)."""

    pack = _workspace(tmp_path, {})
    (pack / "attacks" / "DL-PII-ELICIT-002.yaml").mkdir()
    (pack / "attacks" / "DL-PII-ELICIT-003.yaml").symlink_to(tmp_path / "gone.yaml")
    shown = _dry_run(tmp_path, pack)
    assert "attacks/DL-PII-ELICIT-002.yaml: " in shown
    assert "attacks/DL-PII-ELICIT-003.yaml: " in shown
    assert "REDACTED" not in shown
