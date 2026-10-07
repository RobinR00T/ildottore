"""A CLI error keeps the operator's file names readable and still masks what is not one.

``_masked`` (cli/app.py) exempts from the entropy rule only the paths it can show exist, and it
recognised one only as an absolute path that ends where a space or a quote does. So a report
named after a commit SHA lost its name to the high-entropy mask when the message wrote it
``{path}: ...`` (the colon made it a path that does not exist), when it was relative, or when a
directory on the way held a space or a parenthesis. And ``dottore diff`` printed an incomplete
report's ``status.reason``, which quotes a target's transport error, without the redactor that
``calibrate`` applies to the same text (audits of PR #61, 2026-10-07). The name of a file that
does not exist stays masked, as on main (OD-25): the pre-commit audit printed keys given where
a file belongs once it was kept.
"""

from __future__ import annotations

import json
import os
from collections.abc import Callable
from pathlib import Path

import pytest
from typer.testing import CliRunner

import ildottore.redactor as redactor_mod
from ildottore.cli.app import _masked
from ildottore.cli.exit_codes import ExitCode
from ildottore.cli.main import app
from ildottore.fingerprint.signatures import SignaturePackError, load_pack
from ildottore.redactor import register_known_secret

from .conftest import make_spec, write_spec_tree, write_target

runner = CliRunner()

SHA = "9f86d081884c7d659a2feaa0c55ad015b3a4f6e2"
#: Mixed case, 22 characters: the entropy rule masks it wherever it is not part of a kept path.
SECRET = "Zq8Xw3Rt6Yu1Io4Pa7Sd0Fg"
#: A directory name for every character that used to end a kept path early.
AWKWARD_DIRS = [
    "plain",
    "with space",
    "par(en)s",
    "brack[et]s",
    "comma,dir",
    "semi;colon",
    "quote'd",
    'dquote"d',
]


def _complete_report(path: Path) -> Path:
    path.write_text(json.dumps({"schema_version": "1.0", "findings": []}), encoding="utf-8")
    return path


def _not_a_report(path: Path) -> Path:
    path.write_text(json.dumps({"findings": 3}), encoding="utf-8")
    return path


# --- a file name followed by a colon, in any directory --------------------------------------


@pytest.mark.parametrize("name", AWKWARD_DIRS)
def test_an_existing_report_named_before_a_colon_is_kept(tmp_path: Path, name: str) -> None:
    """``load_findings`` writes ``f"{path}: expected a JSON run report ..."``."""

    folder = tmp_path / name
    folder.mkdir()
    bad = _not_a_report(folder / f"report-{SHA}.json")
    res = runner.invoke(app, ["diff", str(bad), str(_complete_report(folder / "ok.json"))])
    assert res.exit_code == int(ExitCode.ERROR)
    assert f"{bad}: expected a JSON run report" in res.stderr


def test_a_relative_report_keeps_its_name(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    cwd = tmp_path / "with space (1)"
    (cwd / "runs").mkdir(parents=True)
    _not_a_report(cwd / "runs" / f"report-{SHA}.json")
    _complete_report(cwd / "ok.json")
    monkeypatch.chdir(cwd)
    for given in (f"runs/report-{SHA}.json", f"./runs/report-{SHA}.json"):
        res = runner.invoke(app, ["diff", given, "ok.json"])
        assert res.exit_code == int(ExitCode.ERROR)
        assert f"runs/report-{SHA}.json: expected a JSON run report" in res.stderr


def test_a_scope_file_named_before_a_colon_is_kept(tmp_path: Path) -> None:
    """``invalid YAML in scope file {path}: ...`` (policy/scope.py)."""

    folder = tmp_path / "ci (run 7)"
    folder.mkdir()
    scope = folder / f"scope-{SHA}.yaml"
    scope.write_text("targets: [unclosed\n", encoding="utf-8")
    target = write_target(tmp_path)
    spec_dir = write_spec_tree(tmp_path, [make_spec("PI-DIRECT-001")])
    args = ["run", "-t", str(target), "--scope", str(scope), "--spec-path", str(spec_dir)]
    res = runner.invoke(app, [*args, "--dry-run"])
    assert res.exit_code == int(ExitCode.ERROR)
    assert f"invalid YAML in scope file {scope}:" in res.stderr


def test_a_labels_file_named_before_a_colon_is_kept(tmp_path: Path) -> None:
    """``labels file {path}: spec ... has an invalid verdict`` (cli/calibrate.py)."""

    labels = tmp_path / f"labels-{SHA}.yaml"
    labels.write_text("PI-DIRECT-001: maybe\n", encoding="utf-8")
    res = runner.invoke(app, ["calibrate", str(_complete_report(tmp_path / "r.json")), str(labels)])
    assert res.exit_code == int(ExitCode.ERROR)
    assert f"labels file {labels}: spec" in res.stderr


def test_a_signature_pack_named_before_a_colon_is_kept(tmp_path: Path) -> None:
    """``invalid YAML in {path}: ...`` (fingerprint/signatures.py); no flag names a pack."""

    pack = tmp_path / f"signatures-{SHA}.yaml"
    pack.write_text("families: [unclosed\n", encoding="utf-8")
    with pytest.raises(SignaturePackError) as caught:
        load_pack(pack)
    assert f"invalid YAML in {pack}:" in _masked(caught.value)


def test_a_path_that_ends_a_sentence_is_kept(tmp_path: Path) -> None:
    report = _complete_report(tmp_path / f"report-{SHA}.json")
    assert f"could not replace {report}." in _masked(ValueError(f"could not replace {report}."))


def test_the_slash_before_a_masked_name_stays(tmp_path: Path) -> None:
    """The mask took the separator with it: ``.../out«REDACTED...».json`` read as a sibling."""

    shown = _masked(ValueError(f"cannot write the report {tmp_path}/{SECRET}/r.json"))
    assert SECRET not in shown
    assert f"{tmp_path}/" in shown and "REDACTED" in shown


def test_a_file_name_holding_a_space_is_kept_whole(tmp_path: Path) -> None:
    """The longest name that exists, not the first: `report` here is another file."""

    _complete_report(tmp_path / "report")
    report = _not_a_report(tmp_path / f"report (copy)-{SHA}.json")
    res = runner.invoke(app, ["diff", str(report), str(_complete_report(tmp_path / "ok.json"))])
    assert f"{report}: expected a JSON run report" in res.stderr


def test_an_existing_file_written_before_a_slash_keeps_its_name(tmp_path: Path) -> None:
    """``[Errno 20] Not a directory: '<dir>/report-<sha>.json/x'`` names the file."""

    report = _complete_report(tmp_path / f"report-{SHA}.json")
    shown = _masked(NotADirectoryError(20, "Not a directory", f"{report}/x"))
    assert f"'{report}/x'" in shown


def test_prose_after_a_slash_does_not_use_up_the_lookups_of_a_later_path(tmp_path: Path) -> None:
    """A name is at most 255 characters, so one start tries no more candidates than that."""

    report = _not_a_report(tmp_path / f"report-{SHA}.json")
    text = "/" + "a " * 3000 + f"then {report}: expected a JSON run report"
    assert f"{report}: expected" in _masked(ValueError(text))


def test_a_relative_path_after_an_absolute_one_is_kept(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """``(<abs>/a-<sha>.yaml and targets/b-<sha>.yaml)``: the walk that kept the first had read
    past it, and the second was not tried (pre-merge audit)."""

    first = _complete_report(tmp_path / f"a-{SHA}.yaml")
    (tmp_path / "targets").mkdir()
    _complete_report(tmp_path / "targets" / f"b-{SHA}.yaml")
    monkeypatch.chdir(tmp_path)
    text = f"two targets ({first} and targets/b-{SHA}.yaml) share one id"
    assert _masked(ValueError(text)) == text


def _count_main_rule_calls(monkeypatch: pytest.MonkeyPatch) -> list[int]:
    """How many times main's rule asks `Path.exists` (cached or not)."""

    from ildottore.cli import app as app_mod

    calls = [0]
    real = app_mod._Lookups.as_main

    def counting(self: object, path: Path) -> bool | None:
        calls[0] += 1
        return real(self, path)  # type: ignore[arg-type]

    monkeypatch.setattr(app_mod._Lookups, "as_main", counting)
    return calls


def test_a_token_longer_than_path_max_is_not_walked(monkeypatch: pytest.MonkeyPatch) -> None:
    """Main's rule skips it: no path is longer than PATH_MAX, and its 2,100 parents would each
    cost a check."""

    calls = _count_main_rule_calls(monkeypatch)
    _masked(ValueError("cannot write /tmp" + "/x" * 2100 + " then stop"))
    assert calls[0] == 0


def test_a_path_written_again_is_walked_once(monkeypatch: pytest.MonkeyPatch) -> None:
    """Main walked the 501 parents of each of 600 copies again; the answer is the same."""

    calls = _count_main_rule_calls(monkeypatch)
    _masked(ValueError(" ".join(["/a" * 500] * 600)))
    assert calls[0] <= 501


def test_main_rule_does_not_stop_at_the_cost_cap() -> None:
    """Stopped past 1,024 lookups, it kept nothing where main kept `/usr`, and the rest of the
    token, judged with it, was path-shaped and printed (audit of commit 4)."""

    text = "upstream said: " + " ".join(f"/x{i}" for i in range(1025)) + " /usr/q8xv3lm9pw2rt7y"
    assert "q8xv3lm9pw2rt7y" not in _masked(ValueError(text))


# --- what is not a path the operator has stays masked ------------------------------------------


def test_a_value_after_a_kept_path_is_still_masked(tmp_path: Path) -> None:
    report = _complete_report(tmp_path / f"report-{SHA}.json")
    for text in (f"{report}: {SECRET}", f"{report}:{SECRET}", f"'{report}' ({SECRET})"):
        shown = _masked(ValueError(text))
        assert str(report) in shown and SECRET not in shown, text


def test_a_value_glued_to_an_existing_directory_is_not_kept(tmp_path: Path) -> None:
    folder = tmp_path / "out"
    folder.mkdir()
    for text in (f"cannot write {folder}{SECRET}", f"cannot write {folder}-{SECRET}.json"):
        shown = _masked(ValueError(text))
        assert SECRET not in shown, text
    # Kept up to `out`, the 15 characters after it were judged alone, under the rule's minimum.
    head = SECRET[:15]
    assert head not in _masked(ValueError(f"cannot write {folder}{head}"))


def test_a_relative_name_that_does_not_exist_is_still_masked(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(tmp_path)
    for text in (f"bad value {SECRET}.json", f"bad value {SECRET}: x", f"bad value ./{SECRET}"):
        assert SECRET not in _masked(ValueError(text)), text


def test_an_existing_relative_name_inside_a_word_is_not_kept(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Keeping ``ok-<sha>.json`` inside a longer token would leave its head to be read alone."""

    _complete_report(tmp_path / f"ok-{SHA}.json")
    monkeypatch.chdir(tmp_path)
    shown = _masked(ValueError(f"bad value {SECRET}ok-{SHA}.json"))
    assert SECRET not in shown


def test_the_tail_of_an_absolute_path_is_not_a_relative_one(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """``(x)/<name>`` names ``/<name>``, and a URL's path is not a file: a file of that name
    here is another file."""

    _complete_report(tmp_path / f"ok-{SHA}.json")
    monkeypatch.chdir(tmp_path)
    assert f"ok-{SHA}" not in _masked(ValueError(f"cannot write (x)/ok-{SHA}.json"))
    assert f"ok-{SHA}" not in _masked(ValueError(f"bad endpoint http://[::1]/ok-{SHA}.json"))


#: Keys given where a file belongs, as the pre-commit audit found them printed once the name an
#: ``OSError`` carries was kept when it looked like a file's: the redactor recognises the first
#: three only by their entropy (S6), and an Azure key sits in a string ending ``.windows.net``.
AZURE_KEY = (
    "Zq8Xw3Rt6Yu1Io4Pa7Sd0FgHj2Kl5Zx9Cv3Bn6Mq1We4Rt7Yu0Io3Pa6Sd9Fg2Hj5Kl8Zx1Cv4Bn7Mq0We3Rt6Yu9Io2=="
)
KEYS_GIVEN_AS_FILES = [
    ("Kx9mP2vL8qR4tN7wZ3yB6cF1", "Kx9mP2vL8qR4tN7wZ3yB6cF1"),
    ("Kx9mP2vL8qR4tN7wZ3yB6cF1.json", "Kx9mP2vL8qR4tN7wZ3yB6cF1"),
    (
        "sk-ant-api03-Xq7Lm2Pz9Rt4Vw8Ny3Bc6Df1Gh5Jk0Ls9Qa2We7Rt4Yu1Io8Pz3Mx6Nc.json",
        "Xq7Lm2Pz9Rt4Vw8Ny3Bc6Df1Gh5Jk0Ls9Qa2We7Rt4Yu1Io8Pz3Mx6Nc",
    ),
    ("sk-proj-Ab3dEf9hIj2kLm4QxYz7Wv1Ut6Sr5Qp0On8Ml.yaml", "Ab3dEf9hIj2kLm4QxYz7Wv1Ut6Sr5Qp0On8Ml"),
    (
        "DefaultEndpointsProtocol=https;AccountName=acme;"
        f"AccountKey={AZURE_KEY};EndpointSuffix=core.windows.net",
        AZURE_KEY,
    ),
]


@pytest.mark.parametrize(("given", "key"), KEYS_GIVEN_AS_FILES)
def test_a_key_given_where_a_file_belongs_is_still_masked(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, given: str, key: str
) -> None:
    """``dottore diff "$API_KEY.json" ok.json``: the name of a file that does not exist."""

    _complete_report(tmp_path / "ok.json")
    monkeypatch.chdir(tmp_path)
    res = runner.invoke(app, ["diff", given, "ok.json"])
    assert res.exit_code == int(ExitCode.ERROR)
    assert "No such file or directory" in res.stderr and key not in res.stderr
    assert key not in _masked(
        FileNotFoundError(2, "No such file or directory", f"{tmp_path}/{given}")
    )


@pytest.mark.parametrize(
    ("text", "key", "entries"),
    [
        # `//` after a directory: kept up to it, the key was judged with both slashes.
        ("invalid YAML in */var//+rc1+umkBsS/W+Ey", "+rc1+umkBsS/W+Ey", []),
        # A relative file or directory kept as the head of a key left the rest to be judged alone.
        ("value +/aB5uqsbjYBVrCX, rejected", "+/aB5uqsbjYBVrCX", ["+"]),
        ("bad value x/Ab3dEf9hIj2kLm", "Ab3dEf9hIj2kLm", ["x/"]),
        # `//` after directories that exist: main's `Path` folded it and kept nothing (delta audit).
        ("cannot read /usr/bin/hTrqrHJYZ//D+awO: not a report", "hTrqrHJYZ//D+awO", []),
        # `/.` kept as the root after a `+` left a 15-character head of the key (delta audit).
        ("auth failed for key DtXbiufMdI8X2Y+/.", "DtXbiufMdI8X2Y+", []),
        # `/./` after directories that exist: main's `Path` folded it and kept nothing.
        ("cannot read /usr/bin/6gD0Y4gnNScP/UNv/./x (not a report)", "6gD0Y4gnNScP/UNv", []),
    ],
)
def test_a_short_key_cut_by_a_kept_name_is_still_masked(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, text: str, key: str, entries: list[str]
) -> None:
    for entry in entries:
        assert not os.path.exists(f"/{entry}"), "the case needs a relative name"
        if entry.endswith("/"):
            (tmp_path / entry).mkdir()
        else:
            (tmp_path / entry).write_text("", encoding="utf-8")
    monkeypatch.chdir(tmp_path)
    assert key not in _masked(ValueError(text.format(root=tmp_path)))


PART_KEY = "Wq4Hn7Ks2Pd9Lx3Vb8Mz5Tc"


@pytest.mark.parametrize(
    ("name", "written"),
    [
        ("{part}.json", "{name}: not a report"),
        ("{part}.json", "./{name}: not a report"),
        ("{part}.json", "{root}/{name}: not a report"),
        ("{part}.json", "{root}/{name} not a report"),  # kept on main too, followed by a space
        ("runs/{part}.json", "{name}: not a report"),
        # Glued to other characters, the part is neither inside the key nor holds it (delta audit).
        ("report-{part}.json", "{root}/{name}: not a report"),
        ("{part}-v2.json", "{name}: not a report"),
        ("x{part}_old.json", "{root}/{name}. Not a report"),
        ("runs-{part}/r.json", "{name}: not a report"),
        ("runs-{part}/r.json", "{root}/{name}: not a report"),
        # Kept whole, the path's long low-entropy directories diluted the part below the
        # threshold; main judged `/r-<part>` alone. A whole path holding one is not kept.
        pytest.param(
            "/".join(c * 200 for c in "abc") + "/r-{part}.json",
            "{root}/{name}: not a report",
            id="diluted",
        ),
    ],
)
def test_an_existing_name_holding_part_of_a_registered_credential_is_masked(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, name: str, written: str
) -> None:
    monkeypatch.setattr(redactor_mod, "_KNOWN_SECRETS", set())
    register_known_secret(PART_KEY)
    part = PART_KEY[:16]  # masked outside a path too: 16 is the entropy rule's minimum
    path = tmp_path / name.format(part=part)
    path.parent.mkdir(parents=True, exist_ok=True)
    _complete_report(path)
    monkeypatch.chdir(tmp_path)
    text = "cannot read " + written.format(name=name.format(part=part), root=tmp_path)
    assert part not in _masked(ValueError(text))


def test_part_of_a_registered_credential_after_an_existing_directory_is_masked(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Kept up to `with space`, the part after it was judged alone from its `/` (pre-merge
    audit); only a whole path is kept beyond what main kept."""

    monkeypatch.setattr(redactor_mod, "_KNOWN_SECRETS", set())
    key = "U5XO+XIdlu/a+iCOoxvSQSNFnviw2Vue"
    register_known_secret(key)
    (tmp_path / "with space").mkdir()
    text = f"cannot write the report {tmp_path}/with space/{key[:16]}: denied"
    assert key[:16] not in _masked(ValueError(text))


def test_a_part_shorter_than_the_entropy_minimum_keeps_its_path_out(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """12 characters of a key in a whole path: main judged `/report-<12>` and masked it; a
    16-character window kept the path and printed them (delta audit of the rebuild)."""

    monkeypatch.setattr(redactor_mod, "_KNOWN_SECRETS", set())
    register_known_secret(PART_KEY)
    _complete_report(tmp_path / f"report-{PART_KEY[:12]}.json")
    text = f"cannot read {tmp_path}/report-{PART_KEY[:12]}.json: not a report"
    assert PART_KEY[:12] not in _masked(ValueError(text))


def test_the_window_is_eight_characters(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(redactor_mod, "_KNOWN_SECRETS", set())
    register_known_secret(PART_KEY)
    parts = redactor_mod.known_secret_parts()
    assert redactor_mod.holds_known_secret_part(f"x-{PART_KEY[5:13]}-y", parts)
    assert not redactor_mod.holds_known_secret_part(f"x-{PART_KEY[5:12]}-y", parts)


def test_two_kept_parts_that_touch_are_judged_apart(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A digest the error carries, glued to a long kept path: merged, the digest that is part of
    a registered key was judged with the path and diluted below the threshold (delta audit)."""

    import hashlib

    digest = hashlib.sha256(b"carried").hexdigest()
    monkeypatch.setattr(redactor_mod, "_KNOWN_SECRETS", set())
    register_known_secret(f"sk-{digest}")
    folder = tmp_path.joinpath(*(c * 250 for c in "abc"))
    folder.mkdir(parents=True)

    class Carrying(ValueError):
        digests = (digest,)

    assert digest not in _masked(Carrying(f"tampered: {digest}{folder} (see {folder})"))


def test_main_rule_stops_where_path_exists_raises(monkeypatch: pytest.MonkeyPatch) -> None:
    """Python 3.11 and 3.12 raise on a name too long, and main kept nothing for that token;
    `os.path.exists` went on to `/usr`, and the key's 14 characters were judged alone."""

    import errno

    real_exists = Path.exists

    def exists(self: Path, *args: object, **kwargs: object) -> bool:
        if any(len(part) > 255 for part in self.parts):
            raise OSError(errno.ENAMETOOLONG, "File name too long")
        return real_exists(self, *args, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(Path, "exists", exists)
    text = "upstream said: /usr/Zq8Xv3Lm9Pw2Rt." + "a" * 300
    assert "Zq8Xv3Lm9Pw2Rt" not in _masked(ValueError(text))


# --- the incomplete-report refusal goes through the redactor -----------------------------------


def _halted_report(path: Path, reason: str) -> Path:
    status = {"complete": False, "state": "halted", "reason": reason}
    path.write_text(json.dumps({"findings": [], "summary": {"status": status}}), encoding="utf-8")
    return path


def test_diff_masks_the_reason_of_an_incomplete_report_like_calibrate(tmp_path: Path) -> None:
    key = "sk-" + "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6"
    halted = _halted_report(tmp_path / "halted.json", f"transport said {key} then {SECRET}")
    ok = _complete_report(tmp_path / "ok.json")
    res = runner.invoke(app, ["diff", str(halted), str(ok)])
    assert res.exit_code == int(ExitCode.ERROR)
    assert "the baseline report describes a run that did not complete" in res.stderr
    assert "Re-run that scan, or diff two complete reports." in res.stderr
    assert key not in res.stderr and SECRET not in res.stderr
    labels = tmp_path / "labels.yaml"
    labels.write_text("{}\n", encoding="utf-8")
    calibrated = runner.invoke(app, ["calibrate", str(halted), str(labels)])
    reason = calibrated.stderr.split("(halted: ", 1)[1].split(")", 1)[0]
    assert f"(halted: {reason})" in res.stderr


# --- the filesystem lookups are bounded ----------------------------------------------------


@pytest.mark.parametrize(
    "build",
    [
        lambda base: " ".join(["/a" * 2047] * 256),  # 1 MiB: main made 524,032 lookups, 7 s
        lambda base: " ".join(f"{base}/x{i}" for i in range(50_000)),  # distinct names
        lambda base: " ".join([f"{base}/" + "a " * 127] * 400),  # a name at every space
        lambda base: " ".join(f"rel-{SHA}-{i}.json:" for i in range(20_000)),  # relative words
    ],
)
def test_one_error_makes_a_bounded_number_of_filesystem_lookups(
    build: Callable[[Path], str], tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    text = build(tmp_path)
    calls = 0
    real_stat = os.stat

    def counting(*args: object, **kwargs: object) -> os.stat_result:
        nonlocal calls
        calls += 1
        return real_stat(*args, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(os, "stat", counting)
    from ildottore.cli.app import _existing_prefixes

    _existing_prefixes(text)
    main_rule, calls = calls, 0
    _masked(ValueError(text))
    assert calls <= main_rule + 1024, "the whole-path walk's cap is `_MAX_LOOKUPS` in cli/app.py"


def test_an_error_that_names_no_path_costs_no_lookup(monkeypatch: pytest.MonkeyPatch) -> None:
    """A word with no run the entropy rule could mask is not worth a lookup."""

    calls = 0
    real_stat = os.stat

    def counting(*args: object, **kwargs: object) -> os.stat_result:
        nonlocal calls
        calls += 1
        return real_stat(*args, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(os, "stat", counting)
    text = "the baseline report describes a run that did not complete (halted: timed out) " * 20
    text += "budget: 3 / 4 of the battery ran, and / or a lone slash is no path. " * 20
    assert _masked(ValueError(text)) == text
    assert calls == 0


def test_a_walk_that_keeps_nothing_is_not_read_again_from_inside(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """`/./././...//x` keeps nothing; walked again from each `/`, it cost the square of its
    length (a 6,000-character path took minutes in a 1 MiB message)."""

    from ildottore.cli import app as app_mod

    calls = 0
    real_call = app_mod._Lookups.__call__

    def counting(self: object, path: str, *, directory: bool) -> bool:
        nonlocal calls
        calls += 1
        return real_call(self, path, directory=directory)  # type: ignore[arg-type]

    monkeypatch.setattr(app_mod._Lookups, "__call__", counting)
    text = "cannot read " + "/." * 3000 + "//x"
    _masked(ValueError(text))
    assert calls <= 2 * 3000, "one walk, a check per name"


def test_the_whole_path_walk_makes_a_bounded_number_of_checks(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Cached answers cost too: 600 paths through the same 200 directories make one new lookup
    and 200 cached answers each, 120,000 checks under the lookup cap."""

    from ildottore.cli import app as app_mod

    chain = tmp_path.joinpath(*(["d"] * 200))
    chain.mkdir(parents=True)
    calls = 0
    real_ask = app_mod._Lookups._ask

    def counting(self: object, *args: object) -> object:
        nonlocal calls
        calls += 1
        return real_ask(self, *args)  # type: ignore[arg-type]

    monkeypatch.setattr(app_mod._Lookups, "_ask", counting)
    text = " ".join(f"{chain}/x{i}" for i in range(600))
    app_mod._whole_path_spans(text, app_mod._Lookups())
    # A walk in progress when the cap is reached refuses at most one name's candidates more.
    assert calls <= 65_536 + 255, "the cap is `_MAX_CHECKS` in cli/app.py"
