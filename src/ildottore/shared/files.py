"""Reading a file the operator names, never more than a fixed size of it.

The scope, target, fleet and labels files and the policy and signature packs were read whole
with ``Path.read_text``: 100 MB of comments in a scope or labels file cost 39.5 s and 244 MB
before the YAML loader refused it, and a gigabyte was read into memory before anything looked
at it. A check on the parsed document bounds what is built from the text, not the text
(pre-commit audit of the alias-expansion cap, 2026-10-07). The spec loader has its own read, at
most 1 MiB of a regular file inside its pack (``registry.schema.load_yaml_file``). This one
reads any file the operator points at, a pipe included (``--scope <(cat scope.yaml)`` worked
and still does), but never more than the cap: the owner's decision of 2026-10-07.
"""

from __future__ import annotations

import errno
import io
import os
import stat
from pathlib import Path
from typing import Final

__all__ = ["MAX_FILE_BYTES", "read_text_capped"]

#: The most of an operator's file that is read: 1 MiB, the spec loader's ``MAX_YAML_BYTES``. The
#: largest file shipped that goes through here, the signature corpus, is 8.7 KB; 1 MiB holds about
#: 22,000 labels, 2,000 scope targets with two identities each, or the scope ``dottore fleet``
#: writes for about 3,800 fleet entries (it repeats each endpoint, and refuses to write past this).
MAX_FILE_BYTES: Final = 1024 * 1024


def read_text_capped(path: str | Path, *, cap: int = MAX_FILE_BYTES) -> str:
    """The text of ``path`` as ``Path.read_text(encoding="utf-8")`` gives it, at most ``cap`` bytes.

    A regular file larger than ``cap`` is refused before any of it is read. Anything else (a
    pipe, a device) is read up to one byte past ``cap`` and refused if that byte came, so
    ``/dev/zero`` costs one cap of memory. The refusal is an ``OSError`` (``EFBIG``) with the
    path, which every caller already reports as a file it cannot read, exit 3 at the CLI. Its
    figures carry thousands separators: written bare, a size of nine digits or more was masked
    as a phone number by the CLI's redactor. The bytes are decoded and their line endings
    translated exactly as ``read_text`` does, so a scope's checksum covers the same text as
    before.

    Bytes that are not UTF-8 are refused the same way, an ``OSError`` (``EILSEQ``) with the path
    and the offset of the first bad byte in the file, as the spec loader words it. They raised
    ``read_text``'s own ``UnicodeDecodeError``, which names no file and reached the terminal as
    ``'utf-8' codec can't decode byte 0xff in position 15`` (clause A-51).
    """

    with open(path, "rb") as handle:
        info = os.fstat(handle.fileno())
        if stat.S_ISREG(info.st_mode) and info.st_size > cap:
            raise OSError(
                errno.EFBIG, f"file is {info.st_size:,} bytes, over the {cap:,}-byte cap", str(path)
            )
        # Bounded again: a regular file can grow between the size and the read.
        raw = handle.read(cap + 1)
    if len(raw) > cap:
        raise OSError(errno.EFBIG, f"file is over the {cap:,}-byte cap", str(path))
    with io.TextIOWrapper(io.BytesIO(raw), encoding="utf-8") as text:
        try:
            # One read decodes the whole buffer in one call, so the offset is the file's.
            return text.read()
        except UnicodeDecodeError as exc:
            raise OSError(errno.EILSEQ, f"not UTF-8 text (byte {exc.start})", str(path)) from exc
