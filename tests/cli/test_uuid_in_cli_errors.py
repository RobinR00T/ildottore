"""A UUID in a CLI error is masked as the reports mask it (u01/u12 A-83, item 4).

The redactor masks a UUID whole (u01 A-78): what its number rules read inside one is written in
stand-ins, which its entropy rule reads as main read the number masks and masks with the UUID the
pieces main masked around it (``redactor._Cuts``). The CLI masks an error in two passes, every rule
but the entropy fallback first and the entropy fallback on what it does not keep (``_masked``), and
its first pass had no stand-ins: a number rule masked the UUID's digit-only groups, and the rest
was judged in pieces. On ``7d01521f`` ``tenant 3f2a9c1d-6819-4748-9c2d-1234567890ab`` printed
``tenant 3f2a9c1d-«REDACTED:phone»«REDACTED:high_entropy:...»``, its first group in clear, and a
UUID no number rule reads printed ``«REDACTED:high_entropy:...»`` where a report wrote
``«REDACTED:uuid:...»``. The two passes now share the stand-ins (``redactor.UuidCuts``), the second
masks a UUID as ``uuid``, and what is kept (an existing path, a spec file name) is found with the
stand-ins read back, so a UUID in it is kept whatever digits its groups hold.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from typer.testing import CliRunner

from ildottore.cli.app import _masked, app
from ildottore.redactor import Redactor

#: Registered credentials are process-wide: none from an earlier test changes a mask here.
pytestmark = pytest.mark.usefixtures("no_known_secrets")

CUT = "3f2a9c1d-6819-4748-9c2d-1234567890ab"  # two groups a phone number to the number rules
DIGITS = "12345678-1234-1234-1234-123456789012"  # every group, one number
LETTERS = "8edfde5b-3c4a-4e1f-9b2d-7a6c5e4f3a2b"  # no number rule reads it

CONTEXTS = [
    "tenant {u} not found",
    "id {u} x",
    "x_{u}",
    "tenant-{u}",
    "tel +34 600 123 456\n{u}",
    "run {u}.json",
    "password: {u}",
    "Zk3P9qLmW2xY-{u}",
    "two: {u} and {u}",
    "{u}@corp.io",
    "https://ops:{u}@db.internal/v1",
    "a\x00b {u}",
    "card 4111 1111 1111 1111 then {u}",
]


@pytest.mark.parametrize("uuid", [CUT, DIGITS, LETTERS], ids=["cut", "digits", "letters"])
@pytest.mark.parametrize("context", CONTEXTS)
def test_a_cli_error_masks_a_uuid_as_a_report_does(context: str, uuid: str) -> None:
    text = context.format(u=uuid)
    shown = _masked(ValueError(text))
    assert shown == Redactor().redact_text(text).replace("\n", "␊"), shown
    for group in uuid.split("-"):
        if group not in context.replace("{u}", ""):
            assert group not in shown, shown
    assert "-«REDACTED:phone»" not in shown


def test_no_group_of_a_cut_uuid_is_readable() -> None:
    shown = _masked(ValueError(f"id a{DIGITS[1:]} x"))
    assert shown.startswith("id «REDACTED:uuid:"), shown


def test_an_existing_path_under_a_uuid_a_number_rule_reads_is_kept(tmp_path: Path) -> None:
    """Main masked the number in it, so the path no longer existed and nothing of it was kept."""

    for uuid in (CUT, DIGITS):
        root = tmp_path / uuid / "ev"
        root.mkdir(parents=True)
        shown = _masked(ValueError(f"the evidence root {root} is not writable"))
        assert f"{root} is not writable" in shown, shown


def test_a_missing_path_under_a_uuid_masks_it_whole(tmp_path: Path) -> None:
    shown = _masked(ValueError(f"cannot write {tmp_path}/missing/{CUT}/r.json"))
    assert CUT[:8] not in shown and "«REDACTED:uuid:" in shown, shown


class _SpecLoadError(ValueError):
    """Shaped as ``registry.SpecLoadError``: the spec file names it carries are kept."""

    def __init__(self, message: str, spec_files: tuple[str, ...]) -> None:
        super().__init__(message)
        self.spec_files = spec_files


def test_a_spec_file_name_holding_such_a_uuid_is_kept() -> None:
    name = f"attacks/pi-{DIGITS}.yaml"
    shown = _masked(_SpecLoadError(f"cannot load {name}: bad YAML", (name,)))
    assert f"cannot load {name}: bad YAML" == shown, shown


def test_through_the_cli(specs_dir: Path) -> None:
    """``describe`` quotes the id it did not find, through the CLI's mask."""

    result = CliRunner().invoke(app, ["describe", DIGITS, "--spec-path", str(specs_dir)])
    assert result.exit_code == 3
    assert result.stderr.startswith("error: spec '«REDACTED:uuid:"), result.stderr
    assert "«REDACTED:phone»" not in result.stderr
