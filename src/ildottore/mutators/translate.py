"""``translate`` - offline, deterministic phrase-map translation (OD-8, contract §9).

**Decision (OD-8, index ledger):** ship a small **static offline phrase-map** subset for
MVP-1 across a fixed language set ``{es, fr, de, zh}``; a pluggable dictionary provider is
deferred to L3 (``docs/06 §3``). This mutator makes **no network/LLM call** (contract §8):
translation is a table lookup of whole phrases plus a fixed per-language keyword map, so it
is deterministic and offline.

The strategy ``name`` is the bare ``translate``; the target language is read from the
``(spec.id, mutation.name)`` seed so a spec declaring ``translate:es`` vs ``translate:fr``
routes deterministically. When the seed does not name a language, the default is ``es`` and
the language is otherwise picked deterministically from the seed hash. Untranslated words
pass through unchanged (intent-preserving best-effort gloss), so ``reversible=False`` and
the chosen language is recorded in provenance.
"""

from __future__ import annotations

from ildottore.mutators.base import BaseMutator, derive_int_seed

__all__ = ["DEFAULT_LANG", "LANGUAGES", "PHRASE_MAP", "TranslateMutator"]

LANGUAGES: tuple[str, ...] = ("es", "fr", "de", "zh")
DEFAULT_LANG = "es"

# Static offline keyword gloss per language (bounded, documented). Whole-word, case-folded.
PHRASE_MAP: dict[str, dict[str, str]] = {
    "es": {
        "ignore": "ignora",
        "previous": "anteriores",
        "instructions": "instrucciones",
        "reveal": "revela",
        "system": "sistema",
        "prompt": "indicación",
        "password": "contraseña",
        "secret": "secreto",
        "tell": "dime",
        "me": "me",
        "the": "el",
        "your": "tu",
        "and": "y",
        "all": "todo",
    },
    "fr": {
        "ignore": "ignore",
        "previous": "précédentes",
        "instructions": "instructions",
        "reveal": "révèle",
        "system": "système",
        "prompt": "invite",
        "password": "mot de passe",
        "secret": "secret",
        "tell": "dis",
        "me": "moi",
        "the": "le",
        "your": "ton",
        "and": "et",
        "all": "tout",
    },
    "de": {
        "ignore": "ignoriere",
        "previous": "vorherigen",
        "instructions": "Anweisungen",
        "reveal": "enthülle",
        "system": "System",
        "prompt": "Eingabeaufforderung",
        "password": "Passwort",
        "secret": "Geheimnis",
        "tell": "sag",
        "me": "mir",
        "the": "das",
        "your": "dein",
        "and": "und",
        "all": "alles",
    },
    "zh": {
        "ignore": "忽略",
        "previous": "先前的",
        "instructions": "指令",
        "reveal": "透露",
        "system": "系统",
        "prompt": "提示",
        "password": "密码",
        "secret": "秘密",
        "tell": "告诉",
        "me": "我",
        "the": "",
        "your": "你的",
        "and": "和",
        "all": "所有",
    },
}


def _resolve_lang(seed: str) -> str:
    """Pick the target language from the seed (``translate:<lang>`` suffix, else hashed)."""
    tail = seed.rsplit(":", 1)[-1].strip().lower()
    if tail in LANGUAGES:
        return tail
    return LANGUAGES[derive_int_seed(seed, salt="translate") % len(LANGUAGES)]


class TranslateMutator(BaseMutator):
    """Glosses known keywords into the seed-selected language; unknown words pass through."""

    name = "translate"
    reversible = False

    def _transform(self, text: str, seed: str) -> tuple[str, dict[str, object]]:
        lang = _resolve_lang(seed)
        table = PHRASE_MAP[lang]
        out: list[str] = []
        translated = 0
        for token in text.split(" "):
            key = token.lower().strip(".,!?;:\"'()[]")
            if table.get(key):
                # Preserve trailing punctuation crudely: append the mapped word + original tail.
                out.append(table[key])
                translated += 1
            else:
                out.append(token)
        provenance: dict[str, object] = {
            "language": lang,
            "translated_tokens": translated,
            "note": "offline static gloss; unknown tokens unchanged",
        }
        return " ".join(out), provenance
