"""An operator's file is read up to 1 MiB, and its validation errors are listed up to 20.

The scope, target, fleet and labels files and the policy and signature packs were read whole
with ``Path.read_text``: 100 MB of comments in a scope or labels file cost 39.5 s and 244 MB
before the refusal, and a check on the parsed document bounds what is built, not what is read.
Only the spec loader capped its read (``MAX_YAML_BYTES``, 1 MiB). Their validation errors were
listed whole: a 5.5 MB scope with 5,500 extra keys of 1,000 characters made ``dottore run
--dry-run`` print one ``error:`` line of 5,687,058 characters (pre-commit audit of the
alias-expansion cap, 2026-10-07). The owner chose the spec loader's 1 MiB and a bounded read of
any file, so a pipe still works. Clause A-43 (u01). What could block or read without end runs in
a subprocess or under a time limit, so a regression fails instead of hanging the suite.
"""

from __future__ import annotations

import errno
import json
import os
import subprocess
import sys
import threading
import time
import tracemalloc
from collections.abc import Callable, Iterator
from contextlib import contextmanager, suppress
from pathlib import Path
from typing import Any

import pytest
from pydantic import BaseModel, ConfigDict, ValidationError, field_validator
from typer.testing import CliRunner, Result

from ildottore.cli.calibrate import load_labels
from ildottore.cli.exit_codes import ExitCode
from ildottore.cli.fleet import FleetConfig, load_fleet, materialize_fleet
from ildottore.cli.main import app
from ildottore.cli.wiring import load_target
from ildottore.fingerprint import signatures
from ildottore.fingerprint.signatures import SignaturePackError
from ildottore.policy.errors import PolicyPackError, ScopeError
from ildottore.policy.packs import load_pack as load_policy_pack
from ildottore.policy.scope import load_scope_with_digest, scope_hash
from ildottore.registry.schema import MAX_YAML_BYTES
from ildottore.shared.config_errors import validation_problems
from ildottore.shared.files import MAX_FILE_BYTES, read_text_capped

from .conftest import make_spec, write_spec_tree

runner = CliRunner()

#: The cap as the manual and contract u01 state it, pinned here rather than read from the code.
CAP = 1024 * 1024
OVER = "over the 1,048,576-byte cap"
POSIX_ONLY = pytest.mark.skipif(sys.platform == "win32", reason="a FIFO, /dev/zero, ru_maxrss")

SCOPE = (
    'version: "1.0"\n'
    "targets:\n"
    "  - id: mock-target\n"
    '    base_url: "mock://mock-target"\n'
    "    endpoints:\n"
    '      - host: "mock-target"\n'
    '        path_prefixes: ["/"]\n'
    "    identities:\n"
    "      - name: default\n"
    '        auth_ref: "env://MOCK_KEY"\n'
)
TARGET = "id: mock-target\ntype: chatbot\ncapabilities:\n  tools: false\n  rag: false\n"
FLEET = (
    'version: "1"\n'
    "targets:\n"
    "  - id: local-llama\n"
    "    endpoint: http://localhost:11434/v1/chat/completions\n"
    "    model: llama3.2:1b\n"
)
LABELS = "PI-DIRECT-001: pass\n"
POLICY_PACK = "name: engagement-1\nallow_categories:\n  - jailbreak\n"
_SIGNATURES = Path(signatures.__file__).parent / "signatures"


def padded(body: str, size: int) -> bytes:
    """``body`` and a comment line, ``size`` bytes in all."""

    raw = body.encode("utf-8")
    filler = size - len(raw) - 2
    assert filler >= 0
    out = raw + b"#" + b"x" * filler + b"\n"
    assert len(out) == size
    return out


def write(tmp_path: Path, name: str, raw: bytes) -> Path:
    path = tmp_path / name
    path.write_bytes(raw)
    return path


# --- the reader -------------------------------------------------------------------------------


def test_the_cap_is_the_spec_loaders() -> None:
    assert MAX_FILE_BYTES == MAX_YAML_BYTES == CAP


@pytest.mark.parametrize(
    "raw",
    [
        b"",
        b"a: 1\n",
        b"a: 1\r\nb: 2\r\n",
        b"a: 1\rb: 2\r",
        b"a: 1\r\n\r\nb: 2\r",
        b"\xef\xbb\xbfa: 1\n",  # a BOM is kept, as read_text keeps it
        b"k: \xc3\xa9\xe2\x82\xac\xf0\x9f\x98\x80\n",
        b"no final newline",
    ],
)
def test_the_text_is_what_read_text_gave(tmp_path: Path, raw: bytes) -> None:
    """Same decoding, same line endings: a scope's checksum covers the text it covered."""

    path = write(tmp_path, "f.yaml", raw)
    assert read_text_capped(path) == path.read_text(encoding="utf-8")


def test_text_that_is_not_utf8_is_refused_as_read_text_refused_it(tmp_path: Path) -> None:
    path = write(tmp_path, "f.yaml", b"a: 1\n\xff\xfe\n")
    with pytest.raises(UnicodeDecodeError) as before:
        path.read_text(encoding="utf-8")
    with pytest.raises(UnicodeDecodeError) as now:
        read_text_capped(path)
    assert str(now.value) == str(before.value)


def test_a_file_at_the_cap_is_read_and_one_byte_more_is_refused(tmp_path: Path) -> None:
    at_cap = write(tmp_path, "at.yaml", padded(LABELS, CAP))
    assert len(read_text_capped(at_cap)) == CAP

    over = write(tmp_path, "over.yaml", padded(LABELS, CAP + 1))
    with pytest.raises(OSError) as caught:
        read_text_capped(over)
    assert caught.value.errno == errno.EFBIG
    assert caught.value.filename == str(over)
    assert caught.value.strerror == f"file is {CAP + 1:,} bytes, {OVER}"


def test_a_large_file_is_refused_before_any_of_it_is_read(tmp_path: Path) -> None:
    """A sparse gigabyte: refused on its size, so not even one cap of it is allocated."""

    path = tmp_path / "huge.yaml"
    with path.open("wb") as handle:
        handle.truncate(2**30)
    tracemalloc.start()
    try:
        with pytest.raises(OSError, match=f"file is {2**30:,} bytes, {OVER}"):
            read_text_capped(path)
        _, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
    assert peak < CAP // 4, peak


def test_a_file_grown_past_the_cap_after_its_size_was_taken_is_refused(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The size is a first check; the read itself stops one byte past the cap."""

    path = write(tmp_path, "grown.yaml", padded(LABELS, CAP + 1))
    real_fstat = os.fstat

    def stale_fstat(fd: int) -> os.stat_result:
        info = real_fstat(fd)
        fields = list(info[:10])
        fields[6] = 10  # st_size, as it was before the file grew
        return os.stat_result(fields)

    monkeypatch.setattr(os, "fstat", stale_fstat)  # the module reads it through `os`
    with pytest.raises(OSError, match=f"^\\[Errno {errno.EFBIG}\\] file is {OVER}"):
        read_text_capped(path)


@contextmanager
def fifo(tmp_path: Path, raw: bytes, chunk: int = 64 * 1024) -> Iterator[Path]:
    """A named pipe that a thread fills with ``raw`` in pieces, as a slow writer would."""

    path = tmp_path / "pipe.yaml"
    os.mkfifo(path)

    def fill() -> None:
        try:
            with path.open("wb") as handle:
                for start in range(0, len(raw), chunk):
                    handle.write(raw[start : start + chunk])
                    handle.flush()
                    time.sleep(0.001)
        except BrokenPipeError:  # the reader stopped at the cap
            pass

    writer = threading.Thread(target=fill, daemon=True)
    writer.start()
    try:
        yield path
    finally:
        writer.join(timeout=10)


def within(path: Path, call: Callable[[], Any], seconds: float = 60) -> Any:
    """``call()``, failed instead of left hanging when it still waits on ``path`` after ``seconds``.

    A reader that opens the pipe a second time waits for a writer that never comes, and an
    in-process test would hang the suite (pre-commit audit). The pipe's write end is then opened
    once, so the blocked thread gets an end of file and returns.
    """

    outcome: dict[str, Any] = {}

    def run() -> None:
        try:
            outcome["value"] = call()
        except BaseException as exc:  # a SystemExit too: raised again in the test's thread
            outcome["error"] = exc

    worker = threading.Thread(target=run, daemon=True)
    worker.start()
    worker.join(seconds)
    if worker.is_alive():
        with suppress(OSError):
            os.close(os.open(path, os.O_WRONLY | os.O_NONBLOCK))
        pytest.fail(f"still reading {path.name} after {seconds} s: opened twice?")
    if "error" in outcome:
        raise outcome["error"]
    return outcome.get("value")


@POSIX_ONLY
def test_a_pipe_is_read_whole_up_to_the_cap(tmp_path: Path) -> None:
    """The owner's choice: any file is read, not only a regular one (``--scope <(...)``)."""

    raw = padded(LABELS, CAP)
    with fifo(tmp_path, raw) as path:
        assert within(path, lambda: read_text_capped(path)) == raw.decode("utf-8")


@POSIX_ONLY
def test_a_pipe_past_the_cap_is_refused_after_one_byte_more(tmp_path: Path) -> None:
    # Eight caps written: a read without its bound would hold all of them.
    with fifo(tmp_path, padded(LABELS, 8 * CAP)) as path:
        tracemalloc.start()
        try:
            with pytest.raises(OSError) as caught:
                within(path, lambda: read_text_capped(path))
            _, peak = tracemalloc.get_traced_memory()
        finally:
            tracemalloc.stop()
    assert caught.value.errno == errno.EFBIG
    assert caught.value.strerror == f"file is {OVER}"
    assert peak < 3 * CAP, peak


#: A child's own peak resident memory, in bytes. Linux keeps ``ru_maxrss`` across ``execve``, so
#: a child of a large pytest started at the parent's peak: CI read 315 MiB before the child had
#: done anything (delta audit, then CI on ubuntu). ``VmHWM`` belongs to the new image. macOS has
#: no ``/proc`` and does not carry the figure over.
_PEAK = """
import resource, sys

def peak_bytes():
    try:
        with open("/proc/self/status") as status:
            for line in status:
                if line.startswith("VmHWM:"):
                    return int(line.split()[1]) * 1024
    except OSError:
        pass
    scale = 1 if sys.platform == "darwin" else 1024
    return resource.getrusage(resource.RUSAGE_SELF).ru_maxrss * scale
"""

#: Reads ``/dev/zero`` in a child that stops itself at 256 MiB: a read without its cap grows
#: about 2.5 GiB a second, and on a timeout alone it would ask for tens of GiB, killed for memory
#: on a CI runner or swapping on a laptop (pre-commit audit).
_ZERO = (
    _PEAK
    + """
import os, threading, time, tracemalloc
from ildottore.shared.files import read_text_capped

def watchdog():
    while peak_bytes() < 256 * 2**20:
        time.sleep(0.005)
    print("over 256 MiB", flush=True)
    os._exit(9)

threading.Thread(target=watchdog, daemon=True).start()
tracemalloc.start()
try:
    read_text_capped("/dev/zero")
except OSError as exc:
    print(exc.strerror)
print(tracemalloc.get_traced_memory()[1])
"""
)


@pytest.mark.skipif(not Path("/dev/zero").exists(), reason="no /dev/zero")
def test_dev_zero_costs_one_cap() -> None:
    done = subprocess.run(  # noqa: S603 - this interpreter
        [sys.executable, "-c", _ZERO], capture_output=True, text=True, timeout=20, check=False
    )
    assert done.returncode == 0, (done.returncode, done.stdout, done.stderr[-2000:])
    refusal, peak = done.stdout.splitlines()
    assert refusal == f"file is {OVER}"
    assert int(peak) < 3 * CAP, peak


# --- each loader ------------------------------------------------------------------------------

#: name, a valid body, the loader, and what it raises for a file over the cap.
LOADERS: list[tuple[str, str, Callable[[Path], Any], type[Exception]]] = [
    ("scope", SCOPE, load_scope_with_digest, ScopeError),
    ("scope-hash", SCOPE, scope_hash, OSError),
    ("target", TARGET, load_target, OSError),
    ("fleet", FLEET, load_fleet, OSError),
    ("labels", LABELS, load_labels, OSError),
    ("policy-pack", POLICY_PACK, load_policy_pack, PolicyPackError),
    (
        "signature-pack",
        (_SIGNATURES / "pack.yaml").read_text(encoding="utf-8"),
        signatures.load_pack,
        SignaturePackError,
    ),
    (
        "signature-corpus",
        (_SIGNATURES / "corpus.yaml").read_text(encoding="utf-8"),
        signatures.load_corpus,
        SignaturePackError,
    ),
]


@pytest.mark.parametrize(
    ("body", "load", "refusal"), [row[1:] for row in LOADERS], ids=[row[0] for row in LOADERS]
)
def test_each_loader_reads_up_to_the_cap(
    tmp_path: Path, body: str, load: Callable[[Path], Any], refusal: type[Exception]
) -> None:
    load(write(tmp_path, "at-cap.yaml", padded(body, CAP)))

    over = write(tmp_path, "over-cap.yaml", padded(body, CAP + 1))
    with pytest.raises(refusal) as caught:
        load(over)
    shown = str(caught.value)
    assert f"file is {CAP + 1:,} bytes, {OVER}" in shown and str(over) in shown, shown


@POSIX_ONLY
@pytest.mark.parametrize(
    ("body", "load"),
    [(SCOPE, load_scope_with_digest), (FLEET, load_fleet), (LABELS, load_labels)],
    ids=["scope", "fleet", "labels"],
)
def test_a_loader_still_reads_a_pipe(
    tmp_path: Path, body: str, load: Callable[[Path], Any]
) -> None:
    with fifo(tmp_path, body.encode("utf-8")) as path:
        within(path, lambda: load(path))


def _fleet(path_chars: int, env_chars: int) -> FleetConfig:
    return FleetConfig.model_validate(
        {
            "version": "1",
            "targets": [
                {
                    "id": "big",
                    "endpoint": "https://api.example.com/" + "p" * path_chars,
                    "model": "m",
                    "api_key_env": "K" * env_chars,
                }
            ],
        }
    )


def test_fleet_writes_no_file_it_could_not_read_back(tmp_path: Path) -> None:
    """The scope repeats each endpoint: a fleet file under the cap could write a scope over it.

    `fleet` wrote it with exit 0 and the `run` it printed was refused at the read cap; the 845 KB
    fleet of the manual's first figure wrote a 1,355,024-byte scope (pre-commit audit).
    """

    probes = iter(range(10))

    def scope_bytes(config: FleetConfig) -> int:
        out = tmp_path / f"probe-{next(probes)}"
        return materialize_fleet(config, out).scope_path.stat().st_size

    empty = scope_bytes(_fleet(0, 1))
    per_path_char = scope_bytes(_fleet(1, 1)) - empty  # the endpoint is written twice
    path_chars, rest = divmod(CAP - empty, per_path_char)
    assert scope_bytes(_fleet(path_chars, 1 + rest)) == CAP

    over = tmp_path / "over"
    with pytest.raises(ValueError) as caught:
        materialize_fleet(_fleet(path_chars, 2 + rest), over)
    assert str(caught.value) == (
        f"the scope.yaml this fleet would write is {CAP + 1:,} bytes, over the "
        "1,048,576-byte cap a file is read up to; split the fleet"
    )
    assert not over.exists()


#: A model name of 300,000 accented letters: 600,000 bytes in the fleet, written escaped (about
#: 1.26 MB) into a target or judge file, while the scope, which does not name the model, stays
#: small (delta audit: one target or the judge can be the file over the cap).
LONG_MODEL = chr(0xE9) * 300_000
ENDPOINT = "https://api.example.com/v1/chat/completions"


def _fleet_with_long_model(where: str) -> FleetConfig:
    target = {"id": "t1", "endpoint": ENDPOINT, "model": "m"}
    judge = {"id": "j1", "endpoint": ENDPOINT, "model": "m"}
    (target if where == "target" else judge)["model"] = LONG_MODEL
    return FleetConfig.model_validate({"version": "1", "targets": [target], "judge": judge})


@pytest.mark.parametrize(("where", "name"), [("target", "target-t1.yaml"), ("judge", "judge.yaml")])
def test_fleet_measures_each_target_and_the_judge(tmp_path: Path, where: str, name: str) -> None:
    out = tmp_path / "out"
    with pytest.raises(ValueError) as caught:
        materialize_fleet(_fleet_with_long_model(where), out)
    shown = str(caught.value)
    assert shown.startswith(f"the {name} this fleet would write is "), shown
    assert shown.endswith(f"{OVER} a file is read up to; shorten that entry"), shown
    assert not out.exists()


def test_fleet_holds_one_rendered_file_at_a_time(tmp_path: Path) -> None:
    """Twenty targets sharing one 500 KB model: about 1 MiB measured one at a time, 10 held.

    Rendering every file before measuring any held them all at once (delta audit: 29 MiB for 60
    targets sharing a 500 KB anchor, about 3 GiB computed for a fleet file just under the cap).
    """

    model = "m" * 500_000
    config = FleetConfig.model_validate(
        {
            "version": "1",
            "targets": [{"id": f"t{i}", "endpoint": ENDPOINT, "model": model} for i in range(20)],
        }
    )
    tracemalloc.start()
    try:
        materialize_fleet(config, tmp_path / "out")
        _, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
    assert peak < 4 * 2**20, f"{peak / 2**20:.1f} MiB"


def test_fleet_does_not_measure_a_judge_file_it_does_not_hand_on(tmp_path: Path) -> None:
    """With ``--judge`` the printed command reads that file, not the ``judge.yaml`` written."""

    judge_file = write(
        tmp_path, "judge.yaml", f"id: j1\ntype: model\nendpoint: {ENDPOINT}\nmodel: m\n".encode()
    )
    out = materialize_fleet(
        _fleet_with_long_model("judge"), tmp_path / "out", judge=load_target(judge_file)
    )
    assert out.judge_path is not None and out.judge_path.stat().st_size > CAP


# --- the listing of validation errors ---------------------------------------------------------


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str = ""

    @field_validator("name")
    @classmethod
    def _long_reason(cls, value: str) -> str:
        if value == "long":
            raise ValueError("y" * 1000)
        return value


def _error(data: dict[str, Any]) -> ValidationError:
    with pytest.raises(ValidationError) as caught:
        _Strict.model_validate(data)
    return caught.value


def test_twenty_errors_are_listed_and_the_rest_counted() -> None:
    text = validation_problems(_error({f"k{i}": 1 for i in range(25)}))

    assert text.count("Extra inputs are not permitted") == 20
    assert "k19: " in text and "k20: " not in text
    assert text.endswith("; and 5 more")


def test_a_limit_given_is_still_the_limit() -> None:
    text = validation_problems(_error({f"k{i}": 1 for i in range(25)}), limit=3)
    assert text.count("Extra inputs are not permitted") == 3 and text.endswith("; and 22 more")


def test_a_long_path_or_reason_is_cut_at_300_characters() -> None:
    path = validation_problems(_error({"a" * 1000: 1}))
    assert path == f"{'a' * 300}... (1000 characters): Extra inputs are not permitted"

    reason = validation_problems(_error({"name": "long"}))
    written = f"Value error, {'y' * 1000}"
    assert reason == f"name: {written[:300]}... ({len(written)} characters)"

    assert validation_problems(_error({"b" * 300: 1})) == (
        f"{'b' * 300}: Extra inputs are not permitted"
    )


#: 1,000 extra keys of 1,000 characters: about 1 MB, under the read cap.
EXTRA_KEYS = "".join(f"k{i:04d}{'a' * 995}: x\n" for i in range(1000))


@pytest.mark.parametrize(
    ("body", "load", "refusal"),
    [
        (SCOPE, load_scope_with_digest, ScopeError),
        (FLEET, load_fleet, ValueError),
        (POLICY_PACK, load_policy_pack, PolicyPackError),
    ],
    ids=["scope", "fleet", "policy-pack"],
)
def test_a_loader_lists_twenty_errors(
    tmp_path: Path, body: str, load: Callable[[Path], Any], refusal: type[Exception]
) -> None:
    path = write(tmp_path, "keys.yaml", (body + EXTRA_KEYS).encode("utf-8"))
    assert path.stat().st_size < CAP

    with pytest.raises(refusal) as caught:
        load(path)
    shown = str(caught.value)
    assert shown.count("Extra inputs are not permitted") == 20, shown[:500]
    assert shown.endswith("; and 980 more") and len(shown) < 10_000, len(shown)


def test_a_target_files_block_lists_twenty_errors(tmp_path: Path) -> None:
    """A target's ``sampling_defaults`` goes through the same listing since #73 (A-45)."""

    keys = "".join(f"  k{i:04d}{'a' * 995}: x\n" for i in range(1000))
    path = write(tmp_path, "target.yaml", (TARGET + "sampling_defaults:\n" + keys).encode("utf-8"))
    assert path.stat().st_size < CAP

    with pytest.raises(ValueError) as caught:
        load_target(path)
    shown = str(caught.value)
    assert "'sampling_defaults' failed validation" in shown, shown[:500]
    assert shown.count("Extra inputs are not permitted") == 20, shown[:500]
    assert shown.endswith("; and 980 more") and len(shown) < 10_000, len(shown)


# --- the CLI ----------------------------------------------------------------------------------


def error_line(result: Result, path: Path, reason: str) -> str:
    """The one ``error:`` line, naming the file and the reason."""

    lines = result.stderr.splitlines()
    assert len(lines) == 1, (result.exception, result.stderr[:2000])
    line = lines[0]
    assert line.startswith("error: ") and str(path) in line and reason in line, line[:2000]
    return line


def command(tmp_path: Path, name: str, hostile: bytes) -> tuple[list[str], Path]:
    """The arguments of ``name`` with its one operator file holding ``hostile``."""

    if name == "calibrate":
        report = write(tmp_path, "report.json", b"[]")
        labels = write(tmp_path, "labels.yaml", hostile)
        return ["calibrate", str(report), str(labels)], labels
    if name == "fleet":
        fleet = write(tmp_path, "fleet.yaml", hostile)
        return ["fleet", str(fleet), "--out", str(tmp_path / "out")], fleet
    target = write(tmp_path, "target.yaml", TARGET.encode("utf-8"))
    scope = write(tmp_path, "scope.yaml", SCOPE.encode("utf-8"))
    path = target if name == "run-target" else scope
    path.write_bytes(hostile)
    specs = write_spec_tree(tmp_path, [make_spec("PI-DIRECT-001")])
    args = ["run", "-t", str(target), "--scope", str(scope), "--spec-path", str(specs)]
    return [*args, "--dry-run"], path


BODIES = {"calibrate": LABELS, "fleet": FLEET, "run-target": TARGET, "run-scope": SCOPE}


@pytest.mark.parametrize("name", list(BODIES))
def test_a_file_one_byte_over_the_cap_is_exit_3(tmp_path: Path, name: str) -> None:
    args, path = command(tmp_path, name, padded(BODIES[name], CAP + 1))

    result = runner.invoke(app, args)

    assert result.exit_code == ExitCode.ERROR, result.output
    error_line(result, path, f"file is {CAP + 1:,} bytes, {OVER}")


@pytest.mark.parametrize("name", ["fleet", "run-scope"])
def test_a_file_of_many_errors_prints_a_short_line(tmp_path: Path, name: str) -> None:
    args, path = command(tmp_path, name, (BODIES[name] + EXTRA_KEYS).encode("utf-8"))

    result = runner.invoke(app, args)

    assert result.exit_code == ExitCode.ERROR, result.output
    line = error_line(result, path, "; and 980 more")
    assert len(line) < 10_000, len(line)


#: Runs the CLI with this interpreter and reports its exit code and peak resident memory.
_CHILD = (
    _PEAK
    + """
import json
from ildottore.cli.main import app
code = None
try:
    app(sys.argv[1:], prog_name="dottore")
except SystemExit as exc:
    code = exc.code
print(json.dumps({"exit": code, "peak": peak_bytes()}), file=sys.stderr)
"""
)

#: The refusal takes about a second, most of it importing the CLI. Read whole, the sparse
#: gigabyte below was held twice (bytes, then text) before the YAML reader refused its first byte.
TIMEOUT_S = 20
#: The CLI holds about 80 MB after its imports.
MAX_PEAK_BYTES = 256 * 1024 * 1024


@POSIX_ONLY
@pytest.mark.parametrize("name", ["calibrate", "run-scope"])
def test_a_gigabyte_file_is_refused_in_bounded_time_and_memory(tmp_path: Path, name: str) -> None:
    args, path = command(tmp_path, name, b"")
    with path.open("wb") as handle:
        handle.truncate(2**30)

    done = subprocess.run(  # noqa: S603 - this interpreter running this CLI
        [sys.executable, "-c", _CHILD, *args],
        capture_output=True,
        text=True,
        timeout=TIMEOUT_S,
        check=False,
    )

    *messages, measured = done.stderr.splitlines()
    outcome = json.loads(measured)
    # Memory first: read whole, the gigabyte was refused too (its first byte is not YAML), at
    # a peak of about 2 GiB on 0501752 (2,009 and 2,116 MiB for the labels in two measures).
    peak = outcome["peak"]
    assert peak < MAX_PEAK_BYTES, f"{peak / 2**20:.0f} MiB"
    assert outcome["exit"] == ExitCode.ERROR, done.stderr[-2000:]
    assert any(str(path) in m and f"{2**30:,} bytes, {OVER}" in m for m in messages), messages
