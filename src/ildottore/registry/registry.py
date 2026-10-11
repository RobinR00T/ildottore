"""In-memory Attack Spec Registry + id-collision detection (contract §5.3, §3).

The registry merges packs **in load order**: the first pack to declare a spec id wins, and
any later pack re-declaring that id without an explicit ``extends`` is an
``ID_COLLISION`` error (contract §4 KEEP; ``docs/06 §2/§4``). It is a plain library object
(no protocol seam) injected at the composition root (u12).

API (contract §3):
    * ``list(filter=...)`` - ``category`` | ``owasp`` | ``tag`` | ``pack`` subset.
    * ``get(id)`` - a single spec by id (``KeyError`` if unknown).
    * ``resolve(suite_id)`` - the suite's specs in declared order.
    * ``packs()`` - the loaded packs.
"""

from __future__ import annotations

from ildottore.shared import AttackSpec, Suite

from .errors import LintCode, LintError
from .pack import LoadedPack


class SpecNotFoundError(KeyError):
    """Raised by ``get`` when a spec id is not registered."""


class SuiteNotFoundError(KeyError):
    """Raised by ``resolve`` when a suite id is not registered."""


class Registry:
    """Merged, queryable view over one or more loaded packs."""

    def __init__(self) -> None:
        self._packs: list[LoadedPack] = []
        self._specs: dict[str, AttackSpec] = {}
        self._spec_pack: dict[str, str] = {}  # spec id → owning pack id
        self._spec_file: dict[str, str | None] = {}  # spec id → the file it was read from
        self._suites: dict[str, Suite] = {}
        self._collisions: list[LintError] = []

    @classmethod
    def from_packs(cls, packs: list[LoadedPack]) -> Registry:
        """Build a registry by merging packs in order, recording id collisions."""
        reg = cls()
        for pack in packs:
            reg._add_pack(pack)
        return reg

    def _add_pack(self, pack: LoadedPack) -> None:
        self._packs.append(pack)
        for index, spec in enumerate(pack.specs):
            file = pack.spec_file(index)
            if spec.id in self._specs:
                first = self._spec_file[spec.id]
                # Both files, when the loader recorded them: two files of one directory share a
                # pack, and the pack's name said nothing about which two (u12 A-82).
                where = (
                    f"declared by {first} (pack {self._spec_pack[spec.id]!r}); {file} (pack "
                    f"{pack.id!r}) re-declares it"
                    if first is not None and file is not None
                    else f"declared by pack {self._spec_pack[spec.id]!r}; pack {pack.id!r} "
                    "re-declares it"
                )
                self._collisions.append(
                    LintError(
                        code=LintCode.ID_COLLISION,
                        message=(
                            f"spec id {spec.id!r} already {where} without an explicit 'extends'"
                        ),
                        spec_id=spec.id,
                        path=str(pack.root),
                    )
                )
                continue  # first declaration wins; do not silently override
            self._specs[spec.id] = spec
            self._spec_pack[spec.id] = pack.id
            self._spec_file[spec.id] = file
        for suite in pack.suites:
            # Later packs may add suites; a suite-id clash is not a spec collision but we
            # keep the first to preserve reproducibility.
            self._suites.setdefault(suite.id, suite)

    # --- collision surface -----------------------------------------------------------

    @property
    def collisions(self) -> list[LintError]:
        """The ``ID_COLLISION`` findings recorded while merging (read-only)."""
        return list(self._collisions)

    def spec_file(self, spec_id: str) -> str | None:
        """The file the registered spec ``spec_id`` was read from, when the loader recorded it."""

        return self._spec_file.get(spec_id)

    # --- API (contract §3) -----------------------------------------------------------

    def packs(self) -> list[LoadedPack]:
        """The loaded packs, in load order."""
        return list(self._packs)

    def get(self, spec_id: str) -> AttackSpec:
        """Return the spec with ``spec_id`` (raises :class:`SpecNotFoundError`)."""
        try:
            return self._specs[spec_id]
        except KeyError as exc:
            raise SpecNotFoundError(spec_id) from exc

    def resolve(self, suite_id: str) -> list[AttackSpec]:
        """Return a suite's specs in declared order (skips ids absent from the registry).

        Unknown/absent spec ids are reported separately by the linter
        (``UNKNOWN_SPEC_REF``); ``resolve`` returns only the specs it can satisfy so the
        engine never receives a dangling reference.
        """
        try:
            suite = self._suites[suite_id]
        except KeyError as exc:
            raise SuiteNotFoundError(suite_id) from exc
        out: list[AttackSpec] = []
        for entry in suite.specs:
            spec = self._specs.get(entry.spec_id)
            if spec is not None:
                out.append(spec)
        return out

    def suites(self) -> list[Suite]:
        """All registered suites."""
        return list(self._suites.values())

    def has_suite(self, suite_id: str) -> bool:
        """Whether a suite id is registered."""
        return suite_id in self._suites

    def list(
        self,
        *,
        category: str | None = None,
        owasp: str | None = None,
        tag: str | None = None,
        pack: str | None = None,
    ) -> list[AttackSpec]:
        """Return the registered specs matching every provided filter (AND semantics)."""
        out: list[AttackSpec] = []
        for spec_id, spec in self._specs.items():
            if category is not None and str(spec.category) != category:
                continue
            if owasp is not None and spec.owasp != owasp:
                continue
            if tag is not None and tag not in (spec.tags or []):
                continue
            if pack is not None and self._spec_pack.get(spec_id) != pack:
                continue
            out.append(spec)
        return out
