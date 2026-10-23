"""ATT&CK Navigator layers (layer format 4.5), built from specs alone or from a run.

A Navigator layer is the one ATT&CK artefact a security team already reads: a JSON document
the `MITRE ATT&CK Navigator <https://mitre-attack.github.io/attack-navigator/>`_ opens as a
coloured matrix. This module writes two:

* the **battery layer** (``dottore coverage --navigator-layer``): what the shipped specs can
  make a target do, before any run. Observed techniques in one colour, capability-only ones
  in another, every technique's comment naming the specs that declare it.
* the **run layer** (``dottore run -oN``): the same techniques coloured by what the run found,
  exploited, not exploited, inconclusive, with the not-exercised specs left out, as the
  coverage figures leave them out.

Both are pure and deterministic (no clock: the run's own timestamp is the only date that
appears, and only in the run layer's description). The format and field names follow the
Navigator's ``layerFormat 4.5`` and the layer a Feedly *Map ATT&CK Techniques* skill writes
(``versions.attack`` is the **major** release, ``"20"`` for 20.0; ``domain`` is
``enterprise-attack``; a technique appears once per tactic it is coloured under). Nothing in a
layer comes from a target's reply: spec ids, spec names, technique ids and verdict labels only,
so the layer carries no secret a redactor would have to find.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from typing import Any, Final

from ildottore.shared.attack import (
    ATTACK_LAYER_FORMAT,
    ATTACK_VERSION,
    attack_techniques,
    restrict_tactics,
    tactic_name,
)
from ildottore.shared.enums import AttackOccurrence
from ildottore.shared.models import AttackSpec

__all__ = [
    "NAVIGATOR_VERSION",
    "LayerEntry",
    "battery_layer",
    "fold_states",
    "layer_entries",
    "render_layer",
    "run_layer",
]

#: The Navigator release the layer format was checked against.
NAVIGATOR_VERSION: Final = "5.3.2"

#: Colours, one per legend item. Observed and exploited are the loud ones on purpose.
COLOR_OBSERVED: Final = "#e8710a"
COLOR_CAPABILITY_ONLY: Final = "#f5d78e"
COLOR_EXPLOITED: Final = "#c0392b"
COLOR_NOT_EXPLOITED: Final = "#27ae60"
COLOR_INCONCLUSIVE: Final = "#95a5a6"

#: Spec execution states a run layer colours by, worst first (``run_layer``).
STATE_FAIL: Final = "fail"
STATE_INCONCLUSIVE: Final = "inconclusive"
STATE_PASS: Final = "pass"  # noqa: S105  (a verdict status, not a credential)
_STATE_RANK: Final = {STATE_FAIL: 0, STATE_INCONCLUSIVE: 1, STATE_PASS: 2}


@dataclass(frozen=True)
class LayerEntry:
    """One technique as the specs declare it: which tactics, what occurrence, which specs."""

    technique_id: str
    name: str
    #: Tactic shortnames the entry is drawn under: the technique's own, narrowed by any spec
    #: restriction (the union of the restrictions when several specs declare it).
    tactics: tuple[str, ...]
    occurrence: str
    #: ``(spec_id, spec_name)`` sorted by id.
    specs: tuple[tuple[str, str], ...]


def layer_entries(specs: Iterable[AttackSpec]) -> tuple[LayerEntry, ...]:
    """Fold the specs' ``mitre_attack`` blocks into one entry per current technique.

    A retired or unknown ID is skipped here (the linter refuses it and coverage reports it);
    a layer that drew it would draw nothing, since the Navigator has no cell for it. Observed
    wins over capability-only when two specs disagree, as the coverage axis counts it. A
    technique whose every restriction is contradicted ends with no tactic and no cell.
    """

    current = attack_techniques()
    by_id: dict[str, tuple[str, set[str], dict[str, str]]] = {}
    for spec in {s.id: s for s in specs}.values():
        if spec.mitre_attack is None:
            continue
        for mapping in spec.mitre_attack.techniques:
            technique = current.get(mapping.id)
            if technique is None:
                continue
            occurrence, tactics, declared_by = by_id.setdefault(
                mapping.id, (str(mapping.occurrence), set(), {})
            )
            if mapping.occurrence is AttackOccurrence.OBSERVED:
                occurrence = str(AttackOccurrence.OBSERVED)
            # The same rule as the coverage fold: a restriction keeps only what it names and
            # the technique has, and a contradicted one keeps nothing (nothing is drawn).
            kept, _rejected = restrict_tactics(technique, mapping.tactics)
            tactics.update(kept)
            declared_by[spec.id] = spec.name
            by_id[mapping.id] = (occurrence, tactics, declared_by)
    return tuple(
        LayerEntry(
            technique_id=tid,
            name=current[tid].name,
            # Matrix order, not alphabetical: the Navigator draws the columns that way.
            tactics=tuple(t for t in current[tid].tactics if t in tactics),
            occurrence=occurrence,
            specs=tuple(sorted(declared_by.items())),
        )
        for tid, (occurrence, tactics, declared_by) in sorted(by_id.items())
        if tactics
    )


def fold_states(pairs: Iterable[tuple[str, str]]) -> dict[str, str]:
    """``spec_id -> state`` from ``(spec_id, state)`` pairs, the worst state per spec winning.

    A run against several targets yields one finding per spec and target; a spec exploited on
    one target and not on another is exploited (``run_layer`` colours a technique the same way
    across its specs). A state the ranking does not know counts as inconclusive.
    """

    folded: dict[str, str] = {}
    unknown = _STATE_RANK[STATE_INCONCLUSIVE]
    for spec_id, state in pairs:
        current = folded.get(spec_id)
        if current is None or _STATE_RANK.get(state, unknown) < _STATE_RANK.get(current, unknown):
            folded[spec_id] = state
    return folded


def render_layer(
    *,
    name: str,
    description: str,
    techniques: list[dict[str, Any]],
    legend: list[tuple[str, str]],
    metadata: list[tuple[str, str]],
) -> dict[str, Any]:
    """The layer document around an already-built technique list (format 4.5)."""

    return {
        "name": name,
        "versions": {
            "attack": ATTACK_VERSION.split(".")[0],
            "navigator": NAVIGATOR_VERSION,
            "layer": ATTACK_LAYER_FORMAT,
        },
        "domain": "enterprise-attack",
        "description": description,
        "filters": {"platforms": []},
        "sorting": 0,
        "layout": {"layout": "side", "aggregateFunction": "max", "showID": True, "showName": True},
        "hideDisabled": False,
        "techniques": techniques,
        "gradient": {"colors": ["#ffffff", COLOR_OBSERVED], "minValue": 0, "maxValue": 1},
        "legendItems": [{"label": label, "color": color} for label, color in legend],
        "metadata": [{"name": key, "value": value} for key, value in metadata],
        "showTacticRowBackground": False,
        "tacticRowBackground": "#dddddd",
        "selectTechniquesAcrossTactics": True,
        "selectSubtechniquesWithParent": False,
        "selectVisibleTechniques": False,
    }


def _cell(
    entry: LayerEntry, tactic: str, *, score: int, color: str, comment: str
) -> dict[str, Any]:
    return {
        "techniqueID": entry.technique_id,
        "tactic": tactic,
        "score": score,
        "color": color,
        "comment": comment,
        "enabled": True,
        "metadata": [
            {"name": "occurrence", "value": entry.occurrence},
            {"name": "specs", "value": ", ".join(spec_id for spec_id, _ in entry.specs)},
        ],
        "links": [],
        "showSubtechniques": False,
    }


def _declared_by(entry: LayerEntry) -> str:
    return "; ".join(f"{spec_id} ({spec_name})" for spec_id, spec_name in entry.specs)


def battery_layer(specs: Iterable[AttackSpec], *, unloaded: int = 0) -> dict[str, Any]:
    """What the battery can make a target do: observed vs capability-only, per technique.

    ``unloaded`` is how many spec files failed to load: they are absent from the layer, and the
    layer says so, as the coverage text lists them, so a matrix read alone is not taken for the
    whole battery.
    """

    entries = layer_entries(specs)
    cells: list[dict[str, Any]] = []
    for entry in entries:
        observed = entry.occurrence == str(AttackOccurrence.OBSERVED)
        for tactic in entry.tactics:
            cells.append(
                _cell(
                    entry,
                    tactic,
                    score=1 if observed else 0,
                    color=COLOR_OBSERVED if observed else COLOR_CAPABILITY_ONLY,
                    comment=(
                        f"{entry.occurrence}: declared by {_declared_by(entry)}"
                        + ("" if observed else "; listed, not counted toward tactic coverage")
                    ),
                )
            )
    observed_count = sum(1 for e in entries if e.occurrence == str(AttackOccurrence.OBSERVED))
    tactics = sorted(
        {t for e in entries if e.occurrence == str(AttackOccurrence.OBSERVED) for t in e.tactics}
    )
    return render_layer(
        name=f"Il Dottore battery, ATT&CK Enterprise v{ATTACK_VERSION}",
        description=(
            f"Techniques the shipped specs declare: {observed_count} observed (the target's own "
            f"actions or reply are the technique), {len(entries) - observed_count} "
            f"capability-only (an artefact that would enable it elsewhere; drawn, never counted). "
            f"Observed techniques sit under {len(tactics)} tactic(s): "
            + (", ".join(tactic_name(t) for t in tactics) or "none")
            + ". No scan performed."
            + (f" {unloaded} spec file(s) failed to load and are absent." if unloaded else "")
        ),
        techniques=cells,
        legend=[
            ("observed: counted toward tactic coverage", COLOR_OBSERVED),
            ("capability-only: listed, not counted", COLOR_CAPABILITY_ONLY),
        ],
        metadata=[
            ("generated_by", "il-dottore coverage --navigator-layer"),
            ("attack_version", ATTACK_VERSION),
            ("specs_with_mappings", str(len({s for e in entries for s, _ in e.specs}))),
            ("specs_unloaded", str(unloaded)),
        ],
    )


def run_layer(
    specs: Iterable[AttackSpec],
    state_of: Mapping[str, str],
    *,
    run_id: str,
    started_at: str,
    targets: Iterable[str],
) -> dict[str, Any]:
    """The battery layer coloured by one run's verdicts.

    ``state_of`` maps a spec id to ``fail`` (exploited), ``pass`` (not exploited) or
    ``inconclusive``; a spec absent from it was not exercised (nothing sent, or nothing that
    could be scored) and is left out of the layer, as it is left out of the coverage figure.
    A technique several specs declare takes the worst state among them: one exploit is enough
    to colour the cell. Only observed techniques carry a run state; a capability-only one is
    drawn as in the battery layer, since no run can turn an artefact into an action.
    """

    exercised = [spec for spec in {s.id: s for s in specs}.values() if spec.id in state_of]
    entries = layer_entries(exercised)
    cells: list[dict[str, Any]] = []
    counts = {STATE_FAIL: 0, STATE_INCONCLUSIVE: 0, STATE_PASS: 0}
    for entry in entries:
        if entry.occurrence != str(AttackOccurrence.OBSERVED):
            for tactic in entry.tactics:
                cells.append(
                    _cell(
                        entry,
                        tactic,
                        score=0,
                        color=COLOR_CAPABILITY_ONLY,
                        comment=f"capability-only: declared by {_declared_by(entry)}; not counted",
                    )
                )
            continue
        states = sorted(
            (state_of[spec_id] for spec_id, _ in entry.specs if spec_id in state_of),
            key=lambda s: _STATE_RANK.get(s, 1),
        )
        state = states[0] if states else STATE_INCONCLUSIVE
        counts[state if state in counts else STATE_INCONCLUSIVE] += 1
        color, label, score = {
            STATE_FAIL: (COLOR_EXPLOITED, "exploited", 2),
            STATE_PASS: (COLOR_NOT_EXPLOITED, "not exploited", 1),
        }.get(state, (COLOR_INCONCLUSIVE, "inconclusive", 0))
        by_spec = "; ".join(
            f"{spec_id} ({spec_name}): {state_of.get(spec_id, 'not exercised')}"
            for spec_id, spec_name in entry.specs
        )
        for tactic in entry.tactics:
            cells.append(
                _cell(entry, tactic, score=score, color=color, comment=f"{label}: {by_spec}")
            )
    target_list = ", ".join(sorted(set(targets)))
    return render_layer(
        name=f"Il Dottore run {run_id}, ATT&CK Enterprise v{ATTACK_VERSION}",
        description=(
            f"Run {run_id} started {started_at} against {target_list or 'no target'}: "
            f"{counts[STATE_FAIL]} technique(s) exploited, {counts[STATE_PASS]} not exploited, "
            f"{counts[STATE_INCONCLUSIVE]} inconclusive, among the observed techniques of the "
            f"specs that were exercised. Capability-only techniques are drawn, not counted; "
            f"specs that sent nothing scorable are absent."
        ),
        techniques=cells,
        legend=[
            ("exploited", COLOR_EXPLOITED),
            ("not exploited", COLOR_NOT_EXPLOITED),
            ("inconclusive", COLOR_INCONCLUSIVE),
            ("capability-only: drawn, not counted", COLOR_CAPABILITY_ONLY),
        ],
        metadata=[
            ("generated_by", "il-dottore run -oN"),
            ("attack_version", ATTACK_VERSION),
            ("run_id", run_id),
            ("targets", target_list),
        ],
    )
