"""Run-level obfuscation: the ``--obfuscate`` presets and the ``--fuzz`` draw (u05 A-99).

A spec declares the mutations its author chose. ``dottore run --obfuscate <list>`` adds more to
every selected spec, by name, chain or preset; ``--fuzz N`` adds ``N`` chains per spec drawn at
random from a pool, in the spirit of Best-of-N (Hughes et al., arXiv 2412.03556): many cheap,
varied carriers of one request, since the chance that one of them gets through grows with the
number tried. Both only add mutation strings to the specs; the runner, the estimate, the
dry-run, the evidence and ``--resume`` then treat them as if the spec had declared them, so a
fuzzed attempt is replayed byte for byte from the mutation string its evidence records.

Pure functions: no I/O, no clock, and the draw is seeded by ``(fuzz seed, spec id)``.
"""

from __future__ import annotations

from collections.abc import Iterable, Sequence

from ildottore.mutators.base import seeded_rng
from ildottore.mutators.bon import MAX_SAMPLES
from ildottore.mutators.image import VARIANTS as IMAGE_VARIANTS
from ildottore.mutators.registry import MutatorRegistry
from ildottore.shared.mutation_chain import (
    CHAIN_SEPARATOR,
    IMAGE_LINK,
    MAX_CHAIN_LINKS,
    chain_links,
    chain_problem,
    link_base,
)

__all__ = [
    "FUZZ_POOL",
    "MAX_FUZZ",
    "PRESETS",
    "UNDRAWABLE",
    "ObfuscationError",
    "expand_obfuscation",
    "fuzz_chains",
    "mutation_problem",
]

#: Named sets ``--obfuscate`` accepts; each expands to the mutation strings listed.
PRESETS: dict[str, tuple[str, ...]] = {
    "encodings": (
        "base64_wrap",
        "rot13",
        "encode:hex",
        "encode:base32",
        "encode:base85",
        "encode:uu",
        "encode:qp",
        "encode:url",
        "encode:morse",
        "encode:braille",
        "encode:nato",
        "encode:binary",
    ),
    "ciphers": (
        "cipher:caesar",
        "cipher:atbash",
        "cipher:reverse",
        "cipher:word_reverse",
        "bijection:letters",
        "bijection:digits",
    ),
    "unicode": (
        "unicode_confusable",
        "zero_width_inject",
        "smuggle:tags",
        "smuggle:variation",
        "glyph:fullwidth",
        "glyph:bold",
        "glyph:circled",
        "glyph:zalgo",
        "glyph:spaced",
    ),
    "structured": (
        "structured:json",
        "structured:yaml",
        "structured:xml",
        "structured:ini",
        "structured:csv",
        "structured:markdown",
        "structured:policy",
        "structured:js",
        "structured:python",
    ),
    "evasion": (
        "evade:double_url",
        "evade:overlong",
        "evade:html_entity",
        "evade:js_escape",
        "evade:fromcharcode",
        "evade:concat",
        "evade:comment_split",
        "evade:fragment",
        "evade:soft_hyphen",
    ),
    "art": ("ascii_art",),
    "framing": (
        "roleplay_wrap",
        "nested_instruction",
        "refusal_suppression_prefix",
        "html_comment_carrier",
        "markdown_comment_carrier",
        "payload_splitting",
        "leetspeak",
        "adversarial_suffix",
        "math_problem",
    ),
    "bon": tuple(f"bon:{n}" for n in range(8)),
    # The carrier drawn into a PNG (needs a target that declares multimodal input).
    "image": (
        "image:plain",
        "image:figstep",
        "structured:js+image:plain",
        "encode:uu+image:decode",
        "base64_wrap+image:decode",
        "evade:fromcharcode+image:plain",
    ),
}
#: Presets ``all`` leaves out: Best-of-N samples are many of one kind, and an image needs a
#: target that reads images; both are asked for on their own.
_APART = frozenset({"bon", "image"})
PRESETS["all"] = tuple(
    dict.fromkeys(m for name, ms in PRESETS.items() if name not in _APART for m in ms)
)

#: The links ``--fuzz`` draws from: every text carrier of ``all`` (a ``bon`` sample is added to a
#: chain on its own draw, and ``--fuzz-image`` ends every chain with an image link).
FUZZ_POOL: tuple[str, ...] = PRESETS["all"]

#: Links whose output is not printable ASCII: the image font draws them as solid blocks, so
#: ``--fuzz-image`` leaves them out of the draw.
UNDRAWABLE: frozenset[str] = frozenset(
    {
        "encode:braille",
        "evade:soft_hyphen",
        "glyph:bold",
        "glyph:circled",
        "glyph:fullwidth",
        "glyph:zalgo",
        "smuggle:tags",
        "smuggle:variation",
        "unicode_confusable",
        "zero_width_inject",
    }
)

#: The most chains ``--fuzz`` adds per spec; each one is ``runs`` attempts on the wire.
MAX_FUZZ = 1000


class ObfuscationError(ValueError):
    """An ``--obfuscate`` token or a ``--fuzz`` setting the run cannot use."""


def mutation_problem(mutation: str, registry: MutatorRegistry) -> str | None:
    """Why ``mutation`` (a plain mutation or a chain) cannot be sent, or ``None``.

    The same checks the linter and the runner apply to a declared mutation, link by link: a
    registered mutator, a parameter it accepts, and a sound chain.
    """

    shape = chain_problem(mutation)
    if shape is not None:
        return shape
    for link in chain_links(mutation):
        base, _, param = link.partition(":")
        if base == "identity" and not param:
            continue
        if not registry.has(base):
            return f"{link!r} names no registered mutator"
        accepted = getattr(registry.get(base), "accepted_params", None)
        if param and accepted is not None and param.strip().lower() not in accepted:
            return (
                f"{link!r}: {base} takes no parameter"
                if not accepted
                else f"{link!r}: {param!r} is not a parameter {base} accepts"
            )
    return None


def expand_obfuscation(tokens: Iterable[str], registry: MutatorRegistry) -> list[str]:
    """The mutation strings ``--obfuscate`` names, presets expanded, in order, de-duplicated.

    A token is a preset (:data:`PRESETS`), a mutation (``encode:hex``) or a chain
    (``structured:json+encode:base32``). Commas separate several in one flag. An unknown or
    malformed one is refused with what was wrong, never sent as something else.
    """

    out: dict[str, None] = {}
    for raw in tokens:
        for item in (part.strip() for part in raw.split(",")):
            if not item:
                continue
            if item in PRESETS:
                out.update(dict.fromkeys(PRESETS[item]))
                continue
            problem = mutation_problem(item, registry)
            if problem is not None:
                raise ObfuscationError(
                    f"--obfuscate {item!r}: {problem}. Presets: {', '.join(sorted(PRESETS))}; "
                    "mutators: `dottore registry mutators`."
                )
            if item != "identity":
                out[item] = None
    return list(out)


def fuzz_chains(
    spec_id: str,
    count: int,
    *,
    depth: int = 2,
    seed: int = 0,
    image: bool = False,
    pool: Sequence[str] = FUZZ_POOL,
) -> list[str]:
    """``count`` distinct chains for ``spec_id``, each of 1 to ``depth`` links from ``pool``.

    Half the chains, drawn at random, start with a Best-of-N sample (``bon:<n>``) so the request
    is also scrambled before it is wrapped. With ``image``, every chain ends in an image link
    whose variant is drawn too. The draw is a pure function of the arguments: the same seed gives
    the same chains, a different spec gets its own. Fewer than ``count`` come back only when the
    pool cannot make that many distinct chains.
    """

    if count < 0 or count > MAX_FUZZ:
        raise ObfuscationError(f"--fuzz {count}: give 0 to {MAX_FUZZ} chains per spec")
    widest = MAX_CHAIN_LINKS - 1 - (1 if image else 0)
    if not 1 <= depth <= widest:
        raise ObfuscationError(
            f"--fuzz-depth {depth}: give 1 to {widest} links (a chain also takes one Best-of-N "
            "link on half the draws" + (", and the image link" if image else "") + ")"
        )
    pool = [
        link
        for link in dict.fromkeys(pool)
        if link_base(link) not in {"identity", "bon", IMAGE_LINK}
        and not (image and link in UNDRAWABLE)
    ]
    if not pool or count == 0:
        return []
    rng = seeded_rng(f"{seed}::{spec_id}", salt="fuzz")
    chains: dict[str, None] = {}
    attempts = 0
    while len(chains) < count and attempts < count * 50:
        attempts += 1
        links = rng.sample(pool, rng.randint(1, min(depth, len(pool))))
        if rng.random() < 0.5:
            links.insert(0, f"bon:{rng.randrange(MAX_SAMPLES)}")
        if image:
            links.append(f"{IMAGE_LINK}:{rng.choice(IMAGE_VARIANTS)}")
        chains.setdefault(CHAIN_SEPARATOR.join(links), None)
    return list(chains)
