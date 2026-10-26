"""``bon:<n>`` - sample ``n`` of the Best-of-N text augmentations of the payload.

Hughes et al., "Best-of-N Jailbreaking" (arXiv 2412.03556, NeurIPS 2025): sample many randomly
augmented versions of one request until one gets through. Attack success grows with the number
of samples following a power law (89% on GPT-4o and 78% on Claude 3.5 Sonnet at 10,000 samples in
the paper). The three text augmentations and their rates are the paper's (Appendix A.1):

* scrambling: the inner letters of every word longer than three characters are shuffled, first
  and last kept, with probability 0.6 per word;
* random capitalization: each letter's case is flipped with probability 0.6;
* noising: each printable ASCII character is moved one code point up or down with probability
  0.06, staying printable.

The sample index is the parameter, so ``bon:0`` to ``bon:99`` are a hundred different, replayable
samples of the same request; a run sends as many as it lists (``--obfuscate bon`` lists eight,
``--fuzz`` draws more). Not reversible.
"""

from __future__ import annotations

from random import Random

from ildottore.mutators.base import BaseMutator, seeded_rng

__all__ = ["CAPS_P", "MAX_SAMPLES", "NOISE_P", "SCRAMBLE_P", "BestOfNMutator", "augment"]

#: Sample indices ``bon`` accepts (``bon:0`` .. ``bon:99``).
MAX_SAMPLES = 100
SCRAMBLE_P = 0.6
CAPS_P = 0.6
NOISE_P = 0.06


def _scramble(word: str, rng: Random) -> str:
    if len(word) <= 3 or rng.random() >= SCRAMBLE_P:
        return word
    inner = list(word[1:-1])
    rng.shuffle(inner)
    return word[0] + "".join(inner) + word[-1]


def _noise(char: str, rng: Random) -> str:
    point = ord(char)
    if not 0x20 <= point <= 0x7E or rng.random() >= NOISE_P:
        return char
    moved = point + rng.choice((-1, 1))
    return chr(moved) if 0x20 <= moved <= 0x7E else char


def augment(text: str, rng: Random) -> str:
    """One Best-of-N sample of ``text``: scramble, then flip case, then noise."""

    scrambled = " ".join(_scramble(word, rng) for word in text.split(" "))
    flipped = "".join(
        char.swapcase() if char.isalpha() and rng.random() < CAPS_P else char for char in scrambled
    )
    return "".join(_noise(char, rng) for char in flipped)


class BestOfNMutator(BaseMutator):
    """One seeded Best-of-N augmentation sample (scramble, capitalization, noise)."""

    name = "bon"
    fingerprint_probe = False  # run on request only (--obfuscate, --fuzz)
    reversible = False
    accepted_params: frozenset[str] = frozenset(str(n) for n in range(MAX_SAMPLES))

    def _transform(self, text: str, seed: str) -> tuple[str, dict[str, object]]:
        tail = seed.rsplit(":", 1)[-1].strip()
        sample = int(tail) if tail in self.accepted_params else 0  # ASCII 0 to 99 only
        rng = seeded_rng(seed, salt=f"bon:{sample}")
        return augment(text, rng), {
            "sample": sample,
            "scramble_p": SCRAMBLE_P,
            "caps_p": CAPS_P,
            "noise_p": NOISE_P,
        }
