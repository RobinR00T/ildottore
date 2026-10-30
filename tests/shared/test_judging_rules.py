"""The code that judges is bound to a run, and its version is bumped when it changes (u12 A-81).

``shared.judging_rules`` binds a resume to the rules that judged its halted half twice: the
version a person names (``JUDGING_RULES_VERSION``) and a digest computed at run time from the
installed package (``judging_digest``). The digest is deny by default: every file of the package is
in it but the test harness, the one module ``JUDGING_EXEMPT`` names, with its reason. It
replaced an allow-list of verdict code with a reference walk, which two audits found blind to code
that decides verdicts: the CLI audit's H2 (a run halted before five changes to the rules resumed
after them into a report that contradicted itself), then four one-line edits the first list missed
(pre-merge audit of ``22269e0c``), then a default of the REST template, a subclass's override, the
offline judge and a decorator (second audit of ``6de5780b``).

What is checked here: the digest of the current code is the one pinned to its version (a change to
covered code fails until the version is bumped, or re-pinned with a reason); the pins are an
append-only history, which a frozen record of them keeps from being edited in place; each
exemption is presentation or input only by a test, not by a word; and the normalization keeps code
and drops comments and docstrings, the same on every Python version (checked equal on 3.9, 3.12
and 3.14; CI runs 3.11).
"""

from __future__ import annotations

import ast
import shutil
import time
from pathlib import Path

import pytest

from ildottore.shared import judging_rules
from ildottore.shared.judging_rules import (
    JUDGING_EXEMPT,
    JUDGING_RULES_VERSION,
    covered_files,
    judging_digest,
    normalized_source,
)

#: Every pin ever made, in order: ``(version, digest, reason)``. Append-only: a line is never edited
#: or removed, which ``judging_pins.frozen`` beside this file enforces. A new version is a new
#: line; a version is re-pinned only by a new line whose reason says ``re-pin`` and why (the
#: landing re-pin on the final tree, or a change that cannot alter a stored verdict). One line was
#: replaced instead, once: the provisional pin of 2026-10-14 (``b644c56b``, the tree merged with
#: main before the last branch landed), which never reached ``main``, by the landing pin, here and
#: in the frozen file at the same place, while version 1 was unreleased.
PIN_HISTORY: tuple[tuple[int, str, str], ...] = (
    (
        1,
        "cdf2cacd2d7f432c3fde978470a44cf87f3516e4d04aba0c2de1a75739b26bf4",
        "2026-10-12: the first list (evaluators, eight shared modules, twenty runner and execute "
        "functions)",
    ),
    (
        1,
        "c4627211d80fdf0913d74546006e89494d2e1a73fb50a60527512cdb3c345710",
        "re-pin 2026-10-12: the list the closure test requires (pre-merge audit of 22269e0c, H-1); "
        "version 1 is not released",
    ),
    (
        1,
        "c0c0f23b83a4e2c063d31f660a841a976cfdb9b049155a4b0d67085dd5370919",
        "re-pin 2026-10-12: the runner's _run_spec, _sweep_identities and the reproduction "
        "functions they call, which the scoring branch's audit named, and the class attributes "
        "the walk follows now (sends_sampling, logprobs_enabled, max_frame_bytes); version 1 is "
        "not released",
    ),
    (
        1,
        "d22739274adb405de5ca37f206962771e042b36ed426809968c914ffa990a809",
        "re-pin 2026-10-13: deny by default, the whole package but JUDGING_EXEMPT (second audit of "
        "6de5780b); version 1 is not released",
    ),
    (
        1,
        "094105ecb30f4edb5fc32504951510538dd590f151679b42ec64201f9e0c56a5",
        "re-pin 2026-10-13: the renderers, commands, cli.app and cli.main covered, data files by "
        "suffix only (third audit of 1d3d65c7); version 1 is not released",
    ),
    (
        1,
        "308311955bfec13158d1aff961d977e13dd4e1556ec9ebc091eab702791494c9",
        "re-pin 2026-10-15: the rules as of the merge that introduced the version, on main at "
        "a906cea9 (#111 to #116); replaces the provisional pin of 2026-10-14; version 1 is not "
        "released",
    ),
    (
        1,
        "dbfbedd793b731ab385a0c2bae7e9bc9e85c795a1230eeaf0814c83038335d0c",
        "re-pin 2026-10-15: help and docstring text only (cli.app's --help texts and docstrings, "
        "a docstring of cli.run), from docs/audit-2026-10-12 stacked on e92a7541; no verdict can "
        "change; version 1 is not released",
    ),
    (
        1,
        "a5133e824e05f286f6375a00439721cd64a9a5e4f99b76e92d1cfbab3afed230",
        "re-pin 2026-10-16: the built-in battery and the attack-spec schema moved into the "
        "package (u12 A-84), byte for byte, now covered as data files (.wav added), the lookup "
        "through shared.package_data, the default spec path, the moved-path notes and help text; "
        "no verdict can change; from fix/packaging-dependency-floors on 7d01521f; version 1 is "
        "not released",
    ),
    (
        1,
        "63e2465e2c59dc5db9c2a3a29bcf10fb16070af065b890f353fe74b3bd9808a9",
        "re-pin 2026-10-16: the pre-merge audit of 0f556628 (u12 A-84): the default spec path "
        "fails closed (specs/ read whenever it is a directory, the battery where there is none "
        "and in the own checkout, a GitHub warning), the moved-path notes name the change, a "
        "resume refusal keeps battery file names readable; spec selection and messages only, no "
        "verdict can change; version 1 is not released",
    ),
    (
        1,
        "c8f50e0615fb1fd0a95752c37a88631fc8f2612a62bd9b6bc1b69d34edf1bc88",
        "re-pin 2026-10-17: round 2 of the pre-merge audit of u12 A-84: the own checkout told by "
        "its shape (src/ildottore/battery, the root, a pyproject.toml naming ildottore), a "
        "record-only label kept readable only where the package has files; which specs a "
        "default reads and what a refusal shows, no verdict can change; version 1 is not "
        "released",
    ),
    (
        1,
        "5b95a2b4c8bf9fb8c5e5c99d9c0b43d0434655515dc1a31d2377ccd5e1128e44",
        "re-pin 2026-10-17: the floors job of #119 (WebSocketResponse protects only model_validate "
        "and model_dump, so pydantic 2.6 does not warn about model_path) and round 3 of the "
        "audit (is_own_checkout reads pyproject.toml only when it is a regular file); a model "
        "config and a file check, no verdict can change; version 1 is not released",
    ),
    (
        1,
        "ce74f59ffe475a510cabae443bc2980dd199342d238138d7bc74ab4a7ebb064f",
        "re-pin 2026-10-16: masking only (u01/u12 A-83, fix/masking-followups on 7d01521f): the "
        "redactor's reading of U+0000 and U+0001, the CLI's error masking and exit statuses, an "
        "endpoint URL's user registered; the redactor decides what is stored and printed, the "
        "evaluators judge the raw reply, so no verdict can change; version 1 is not released",
    ),
    (
        1,
        "8c14612b7877025ed3350055d51dbcf0c239b4185ee224ede6e29825f66a18e3",
        "re-pin 2026-10-17: the fixes of the pre-merge audit of 4f1b28db (an ordered set for a "
        "merged stretch's masks and A-77's pieces, a text exit code masked as itself, late typed "
        "a frozenset), masking and speed only; no verdict can change; version 1 is not released",
    ),
    (
        1,
        "eea242b76899ce22c68bc80c4c6b51a92c22cd39d4763bc373f3cd8a612e9dec",
        "re-pin 2026-10-17: the merge of fix/packaging-dependency-floors (#119, 1fb6d485) into "
        "fix/masking-followups, with A-83's round-2 fixes (A-77's pieces share their stretch's "
        "mask tuple, an exit code holding text masked as that text); masking, speed and "
        "packaging only, no verdict can change; version 1 is not released",
    ),
    (
        2,
        "69d8b855dc421934ba2d003d32f28900e837700ce6eca9379804425f48bd268e",
        "2026-10-16: u08 A-85 (fix/scoring-followups on 7d01521f): a crossing of a canary the "
        "identity sweep's request carries is needs-review, a sweep's crossing counts once, "
        "secret_shape reads the redactor's key formats; the stacked landing re-pins it",
    ),
    (
        2,
        "4c5168fd528e31dc7cd65a59bdd094bf60bad1360ad9887d794e4f9a05a9d204",
        "re-pin 2026-10-16: the sweep's stamp, numbering and notes moved from core.runner to "
        "shared.identity_sweep after the first pin; no verdict changes; version 2 is not "
        "released",
    ),
    (
        2,
        "fbbeaeb07e7ef5a8c5c8e46559308705495a68acc544185de9458464bf258442",
        "re-pin 2026-10-16: a crossing of a canary the request carries is a fail that needs "
        "review (echo_only, never confirmed) rather than inconclusive, amended by the "
        "coordinator before the audit; version 2 is not released",
    ),
    (
        2,
        "0ade18400ad1421207d796522b453d3f59ed507b37db24e7b868bf7aa52ad729",
        "re-pin 2026-10-16: a finding's line counts the fails resting on an identity sweep "
        "alone (report text only, no verdict changes); version 2 is not released",
    ),
    (
        2,
        "4e5605bbc29a776978a30c4bbfa4c60266a89379180ac15f4ba0a73fde28d334",
        "re-pin 2026-10-17: the sweep's own count dropped (pre-merge audit of 8a42d08f, HIGH 1), "
        "the canary rule by label, class and entropy, the echo read case-folded; version 2 is "
        "not released",
    ),
    (
        2,
        "923035a7357858c11b6294e98de9e22c8c5815d1fcf3d3941d7f200a13559461",
        "re-pin 2026-10-17: round 2 of the branch's audit, the canary floor at 16 characters and "
        "a label taken out before the rest is judged (LOW 2, LOW 4), every crossing canary "
        "listed (LOW 6); version 2 is not released",
    ),
    (
        2,
        "06c484bf2ab4a62cd519d8981920682bf121b5372701c14675e08cf1506b9b66",
        "re-pin 2026-10-17: fix/scoring-followups stacked on fix/masking-followups (#120, "
        "388c6c18, which holds main 5edeb0a7, #119): the digest now covers the built-in battery "
        "(.yaml and .wav under src/ildottore/battery) and A-83's masking; version 2 is not "
        "released",
    ),
    (
        2,
        "8ef344979b038047c1c6e78120685c7c88cebe8b80dfbeeb9c9b2aec27546dc0",
        "re-pin 2026-10-17: u01 A-86 (fix/stream-bounds on fef4963e): an alternative of a token "
        "past four masks shows one fragment, a dict or a set exit code is masked as its items' "
        "texts; masking only, the evaluators judge the raw reply, no verdict can change; version "
        "2 is not released",
    ),
    (
        2,
        "06bb22a2c83345c8cea8c238e6b2b642e8ef5236ba9d5879193899d1741c6082",
        "re-pin 2026-10-17: u01 A-86 pre-merge audit (fix/stream-bounds on 620095b5): a deque, an "
        "exception with arguments and a memoryview exit code are masked as their items' texts "
        "(bytes for a memoryview); masking only, no verdict can change; version 2 is not released",
    ),
    (
        2,
        "8d0f56fb1a5237de51492dea812a213f4ed39c8ea5a2b5edaff1812e0300c372",
        "re-pin 2026-10-19: u06 A-88 (feat/tool-argument-values on d8b43561): tool_call reads an "
        "opt-in forbidden_arg_values, and three test_only specs use it; a spec without the key "
        "judges as before, no existing verdict changes; version 2 is not released",
    ),
    (
        3,
        "bedc37ed4b3f66fd60f755711a9911094ad64e456056e09f708ff09928c00f26",
        "u06 A-89 (fix/long-integer-arguments on d6236c7d): a call's JSON-string arguments "
        "holding an integer longer than int converts are read, the integer kept as its digits, "
        "where they read as {} and tool_call passed; a stored pass can become a fail",
    ),
    (
        3,
        "ee44c0fc64ebbda4663040f0c4246f342b398e7290de53f71fb48024642414b7",
        "re-pin 2026-10-19: u06 A-88 audit 2 LOW-3 (u06-argval-hash-whole, merged with 4e4fa2f1): "
        "a map or an empty list read whole under a pinned argument is hashed whole in matched; "
        "masking only, no status changes",
    ),
    (
        4,
        "2099ec3dce34a24b9ae8cb98500c38a58089ea65a907cb2a7f36e50200a809df",
        "u06 A-90 (fix/long-integer-object-arguments on fix/long-integer-arguments): arguments a "
        "reply carries as a JSON object holding such an integer are read too, where the reply "
        "was unreadable and the attempt not evaluated; an inconclusive can become a verdict",
    ),
    (
        4,
        "7589807e9974bc2c0977706d3d05c418042d69c73ae58bb0cbf9cc3f8bba5f68",
        "re-pin, the pre-merge audit of A-90: the check reads the integers the parsed reply holds "
        "(a duplicate key's dropped value is not refused), and a WebSocket text, model or id path "
        "into a call's arguments reads no digits; version 4 is not released",
    ),
    (
        4,
        "a1609118af05b8a942c1982916c99c707552ac8324d804d3248aecac0bd67dc1",
        "re-pin, the second audit of A-90: a WebSocket final_path into a call's arguments reads "
        "no stop there either; version 4 is not released",
    ),
    (
        4,
        "86d4391094d167c454d0e05ec076a36ca10c585c57b1d00574a7e86e87c0fe40",
        "re-pin, merge of main after #126 (u06 A-88, a map read whole hashed whole): version 4 "
        "takes rules 3's masking change too; version 4 is not released",
    ),
    (
        5,
        "c352e9bd55c8e3b0629e4164411b64667327a5c3cd533e003a7cb84475ecf9c4",
        "u08 A-87, every reply received under an identity read against the owner map, the "
        "identity sweep one trial counted once, a canary read case-folded without format "
        "characters; version 5 is not released",
    ),
    (
        6,
        "47293b7afb2a5409bff93319a9fa384621c3ecbe8b9a261be8bb428e05d0f4f7",
        "u08 A-92 (fix/fold-default-ignorables on 01d6bdc5): a canary is read without the default "
        "ignorable code points too (a variation selector, the combining grapheme joiner, a Hangul "
        "filler hid a crossing), both sets pinned to Unicode 16.0; an inconclusive or a pass can "
        "become a fail",
    ),
    (
        7,
        "42267c76083955ff723878c0db06d412e9bccf0a2fd206dc0016bc8b6459e11f",
        "u08 A-93 (fix/canary-floors-folded on 65203f18): the canary floors measure the folded "
        "canary, so a short word padded with invisible characters is read exactly, not folded to "
        "the word; a fail can become a pass",
    ),
    (
        7,
        "68120a3be571b6039312da6090141deac6fb13316717f8c72ae75f408aa3d9b4",
        "re-pin 2026-10-21: u01 A-91 (fix/shared-identity-credentials, merged with 4673bb54), two "
        "identities sharing a credential (one auth_ref, or two variables holding one key) are "
        "refused before anything is sent; no stored verdict changes",
    ),
    (
        7,
        "c5650a08150487badb91d9d35bf571dbdcb93530dfe47cf58c104c9f809cee77",
        "re-pin 2026-10-21: u10 A-94 (fix/evidence-folded-canary, merged with 30cc2d6a): the "
        "evidence store masks a canary as the evaluators read it (re-cased, split by an invisible "
        "character) and gets every identity canary of the scope; what is stored changes, no "
        "verdict does",
    ),
    (
        7,
        "4f8fbe8f723615a7779ff005fcb16d636c33c624b29acb24527584afa3804d30",
        "re-pin 2026-10-24: u02 A-95 (feat/mitre-attack-axis): MITRE ATT&CK Enterprise v20.0 "
        "pinned as data, the mitre_attack spec field, the linter rule, the coverage axis, the "
        "report block and the Navigator layers; mapping and reporting only, no verdict path "
        "touched",
    ),
    (
        7,
        "7cbd07d44c567f778f0fd66763d60df51c336321467ca274d0f6c3092b18c86e",
        "re-pin 2026-10-24: feat/banner: the logo above the root help on a terminal "
        "(cli/banner.py, the format_help hook in cli/app.py, DATA_EXEMPT for the two art files); "
        "help output only, no verdict path touched",
    ),
    (
        7,
        "54cf9d2751a6a7f8ca9dfd4d4fb157e4977bc24e8d548d2d18f686a8bf18d076",
        "re-pin 2026-10-24: u04 A-96 (the WebSocket guard): websocket.guard in the model, the "
        "loader and the adapter (adapters/agent_guard.py), the dry-run's guard line and the "
        "guard left out of the target digest; it decides whether and when a query goes out, "
        "never how a reply read is judged, and a target without the block reads every frame as "
        "before, so no stored verdict changes",
    ),
    (
        7,
        "6764e7c12a1c64266369fffbf2779c99d8a0ecab782efefbc47a4f02f984a32d",
        "re-pin 2026-10-26: u01 A-97 (a scope's validity window): valid_from and valid_until in "
        "the scope model and its loader, checked first by authorize_target, and the dry-run's "
        "window note; it decides whether an attempt is sent at all, never how a reply read is "
        "judged, and a scope without the fields authorizes as before, so no stored verdict "
        "changes",
    ),
    (
        7,
        "a2f4408dd9b856d77ce853e09558e695fc695ab9b34d17f56f2e16866af2760a",
        "re-pin 2026-10-26: u08 A-100 (OD-58, no constant canary stem): the battery's canaries "
        "written {{canary_prefix}}{{run_id}}, shared/canary.py, the runner, setup_delivery, "
        "the evidence store and the fixture stub binding both, seeded_setup.canary_prefix, the "
        "scope refusing the placeholder in an identity canary and the redactor masking the old "
        "stem; it changes which string a reply is searched for, never how a reply holding it is "
        "judged, and a stored verdict is not judged again",
    ),
    (
        7,
        "58a65f6a3e096b3c6ab6229a14a6e32126f98cbe60ba836e3c73eed7889a2d9e",
        "re-pin 2026-10-26: u08 A-100 again, the derived prefix a fixed 12 capital letters and "
        "'_' (the old stem's length) instead of 6 to 11, so a request, and the tokens reserved "
        "for it, are as long in every run; it changes which string a reply is searched for, "
        "never how a reply holding it is judged",
    ),
    (
        7,
        "1cfc6a3eaf8457b8451dbb66c374ea62133a15d4e62fcaa873ad3eecaf8b3931",
        "re-pin 2026-10-26: u08 A-100's body, {{canary_body}} derived from the binding in "
        "place of {{run_id}} in the battery's canaries, so neither the run id nor the spec id "
        "is in a canary, and the attack-spec schema's $id on ildottore.dev; it changes which "
        "string a reply is searched for, never how a reply holding it is judged",
    ),
    (
        7,
        "f34bd72254c380863707baff87328f367998dfab20e6167f6abe0572810add2b",
        "re-pin 2026-10-26: u05 A-99 (obfuscation and fuzzing): ten mutator families, chains "
        "(shared/mutation_chain.py), the image link's PNG part in the runner, the linter's chain "
        "checks and the run flags; they change what is sent when a spec or the operator names "
        "them, never how a reply is judged, and a spec without them is sent and judged as "
        "before, so no stored verdict changes",
    ),
    (
        7,
        "7197208eba4188d2372bb39f05b5144e1d4f6c17b5167645a80a55877b4b96c8",
        "re-pin 2026-10-26: u05 A-99 merged with main after u08 A-100 (the derived canary): the "
        "two changes' code together, neither changed; what is sent and how a reply is judged "
        "are each as their own pin says",
    ),
    (
        7,
        "9095f2f009b16a8d3cddb98255a8d22c1917a96e7634ff4a3a7d63bbdaa0fcac",
        "re-pin 2026-10-26: u04 A-98 (feat/guard-window-http): guard.window, rest.guard through "
        "the shared GuardKeeper (a pacing hook before each HTTP attempt, a guard-lowered reply "
        "cap), get_path moved to adapters/paths.py, and profiles by name in the CLI; they decide "
        "whether and when a request goes out, never how a reply read is judged, and a target "
        "without the blocks behaves as before, so no stored verdict changes",
    ),
    (
        7,
        "dd9cf562d9df8dc94a0c6c20c6ea2be93ad0202f73eebaa86a9853cba40706c0",
        "re-pin 2026-10-26: u04 A-98 merged with main after u01 A-97 and u08 A-100 (the scope's "
        "validity window, the derived canary): the changes' code together, none changed; what "
        "is sent and how a reply is judged are each as their own pin says",
    ),
    (
        7,
        "d9f2d827e5b636ef9d008350ee362662eb5046a0cb30a4478e68e785d10af1aa",
        "re-pin 2026-10-26: u04 A-98 merged with main after u05 A-99 (obfuscation and "
        "fuzzing): the two changes' code together, neither changed; what is sent and how a "
        "reply is judged are each as their own pin says",
    ),
    (
        7,
        "09544f8e10fea1587b7489647880fef04149ee080313002c3578ceea07d01f78",
        "re-pin 2026-10-27: u12 A-103 (fix/repeated-option): the root group refuses an option "
        "that keeps one value given two (a usage error, exit 3), before any command runs; "
        "no evaluator and no combination changed, so a reply is judged as before",
    ),
    (
        7,
        "a85ba0628dd72e4cd4de2adabfb71bd52e67cfa35e5a25dfb9bb919441db58ee",
        "re-pin 2026-10-27: u04 A-101 (feat/mcp-rug-pull): the MCP adapter renders each tool's "
        "described parameters and compares a pinned catalogue, and the loader reads mcp.pins; "
        "no evaluator and no combination changed, so a reply is judged as before",
    ),
    (
        7,
        "05ea2ba9d629a531733da8057a18474598ae9e8131edb54c0c77fa0007e9c4a0",
        "re-pin 2026-10-27: u13 A-102 (feat/mcp-rug-pull): MCP-TOOLPOISON-001's markers widened "
        "to a hidden block, 'you must first access' and 'do not mention that'; it changes which "
        "listing the spec fails, never how an evaluator judges, and the spec digest moved with "
        "it, so a stored verdict is not judged again",
    ),
    (
        7,
        "456035ff52b22341b916fc42ef8395fb2fe595bbe8cd4d2b94cb2f4ca2764045",
        "re-pin 2026-10-27: u04 A-104 (a stdio MCP server may run in a container): the "
        "adapter's launch and the target file's isolation block; no verdict path touched",
    ),
    (
        7,
        "2d7136000bc58c0478160f318ff87937be1907c1075696e0e03648e7912cac3a",
        "re-pin 2026-10-27: u08 A-105 (the false-positive breaker): the runner takes the specs "
        "a labels ledger holds and never confirms a fail of one; without --fp-ledger nothing is "
        "held, and no evaluator and no combination changed, so a reply is judged as before",
    ),
    (
        7,
        "1e1da38788d86beaa08683cdf4457820afe536d045df97ae3eab73db5eef1fb8",
        "re-pin 2026-10-28: u05 A-99 follow-up: encode:qp writes a payload's line breaks as =0D "
        "and =0A, so the blob decodes to the same bytes; it changes what one carrier sends, not "
        "how a reply is judged",
    ),
    (
        7,
        "dc6913b6f6973ad1e01158455a106292b4532526f2016cdbd2010bf3f36937a0",
        "re-pin 2026-10-30: u08 A-106 (run --control): a failing spec may send its "
        "attack.control once, kept apart from its trials; without the flag nothing is sent, and "
        "no evaluator and no combination changed, so a reply is judged as before",
    ),
)

#: The digest each version is pinned to now: the last line of :data:`PIN_HISTORY` for it.
PINNED: dict[int, str] = {
    1: "eea242b76899ce22c68bc80c4c6b51a92c22cd39d4763bc373f3cd8a612e9dec",
    2: "8d0f56fb1a5237de51492dea812a213f4ed39c8ea5a2b5edaff1812e0300c372",
    3: "ee44c0fc64ebbda4663040f0c4246f342b398e7290de53f71fb48024642414b7",
    4: "86d4391094d167c454d0e05ec076a36ca10c585c57b1d00574a7e86e87c0fe40",
    5: "c352e9bd55c8e3b0629e4164411b64667327a5c3cd533e003a7cb84475ecf9c4",
    6: "47293b7afb2a5409bff93319a9fa384621c3ecbe8b9a261be8bb428e05d0f4f7",
    7: "dc6913b6f6973ad1e01158455a106292b4532526f2016cdbd2010bf3f36937a0",
}

#: One ``<version> <digest>`` line per pin, appended to and never edited: the history must start
#: with these lines, and may hold at most one more (the pin being made, frozen when it is
#: committed). An edit in place of a pin, its line and ``PINNED`` together, fails here.
FROZEN = Path(__file__).with_name("judging_pins.frozen")

_SRC = Path(judging_rules.__file__).resolve().parents[2]


# --- the import graph, for the exemptions ----------------------------------------------------


def _module_file(name: str) -> Path | None:
    base = _SRC.joinpath(*name.split("."))
    if (base / "__init__.py").is_file():
        return base / "__init__.py"
    return base.with_suffix(".py") if base.with_suffix(".py").is_file() else None


def _absolute(module: str, level: int, target: str | None) -> str:
    if level == 0:
        return target or ""
    path = _module_file(module)
    package = (
        module if path is not None and path.name == "__init__.py" else module.rpartition(".")[0]
    )
    for _ in range(level - 1):
        package = package.rpartition(".")[0]
    return f"{package}.{target}" if target else package


def _imports(module: str) -> set[str]:
    """The ``ildottore`` modules ``module`` imports, anywhere in it, with their parents."""

    path = _module_file(module)
    assert path is not None, module
    found: set[str] = set()
    for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
        if isinstance(node, ast.ImportFrom):
            source = _absolute(module, node.level, node.module)
            if source.startswith("ildottore"):
                found.add(source)
                found.update(
                    f"{source}.{a.name}" for a in node.names if _module_file(f"{source}.{a.name}")
                )
        elif isinstance(node, ast.Import):
            found.update(a.name for a in node.names if a.name.startswith("ildottore"))
    out: set[str] = set()
    for name in found:
        parts = name.split(".")
        out.update(
            ".".join(parts[:i])
            for i in range(1, len(parts) + 1)
            if _module_file(".".join(parts[:i]))
        )
    return out


def _closure(start: str) -> set[str]:
    seen: set[str] = set()
    pending = [start]
    while pending:
        module = pending.pop()
        if module in seen or _module_file(module) is None:
            continue
        seen.add(module)
        pending.extend(_imports(module))
    return seen


def _all_modules() -> list[str]:
    return sorted(
        ".".join(p.relative_to(_SRC).with_suffix("").parts).removesuffix(".__init__")
        for p in (_SRC / "ildottore").rglob("*.py")
    )


def _under(module: str, name: str) -> bool:
    return module == name or module.startswith(f"{name}.")


# --- the pin -----------------------------------------------------------------------------------


def test_the_judging_code_is_the_code_its_version_was_pinned_for() -> None:
    current = judging_digest()
    pinned = PINNED.get(JUDGING_RULES_VERSION)
    assert pinned == current, (
        "the code that judges (shared.judging_rules.judging_digest: the whole package but "
        f"JUDGING_EXEMPT) is not the code JUDGING_RULES_VERSION {JUDGING_RULES_VERSION} was "
        "pinned for. If this change can alter the verdict stored for an attempt, bump "
        f"JUDGING_RULES_VERSION to {JUDGING_RULES_VERSION + 1}, write its CHANGELOG line (with "
        "its date: JUDGING_RULES_SINCE is the day runs began to record their rules and stays) "
        f"and append ({JUDGING_RULES_VERSION + 1}, {current!r}, '<why>') to "
        "PIN_HISTORY, judging_pins.frozen and PINNED. If it cannot (a message, a refactor), "
        f"append ({JUDGING_RULES_VERSION}, {current!r}, 're-pin <date>: <why>') instead. Never "
        "edit an existing line. A run halted on other code is refused by its resume either way, "
        "by the digest it recorded (u12 A-81)."
    )


def test_the_pins_are_an_append_only_history_that_ends_at_the_current_version() -> None:
    """No bump without a pin, no pin without a line, no line without a reason or edited."""

    versions = [version for version, _, _ in PIN_HISTORY]
    assert versions == sorted(versions), "the history is in order"
    assert sorted(set(versions)) == list(range(1, JUDGING_RULES_VERSION + 1))
    assert sorted(PINNED) == list(range(1, JUDGING_RULES_VERSION + 1))
    last = {version: digest for version, digest, _ in PIN_HISTORY}
    assert last == PINNED, "a pin differs from the last PIN_HISTORY line for its version"
    seen: set[int] = set()
    for version, digest, reason in PIN_HISTORY:
        assert reason.strip(), f"version {version}'s line gives no reason"
        assert len(digest) == 64, f"version {version}'s line holds no digest"
        if version in seen:
            assert "re-pin" in reason, f"a second line for version {version} must say re-pin"
        seen.add(version)
    owners: dict[str, int] = {}
    for version, digest, _ in PIN_HISTORY:
        assert owners.setdefault(digest, version) == version, "one code pinned to two versions"


def test_the_history_starts_with_the_frozen_pins_so_none_is_edited_in_place() -> None:
    """The second audit edited the last line's digest and PINNED together, and passed: the
    frozen record is a third place, never edited, that such an edit does not match."""

    frozen = [
        (int(version), digest)
        for version, digest in (line.split() for line in FROZEN.read_text().splitlines() if line)
    ]
    history = [(version, digest) for version, digest, _ in PIN_HISTORY]
    assert history[: len(frozen)] == frozen, (
        "a pin of PIN_HISTORY differs from judging_pins.frozen: a pin is never edited; append a "
        "new line to both instead"
    )
    assert len(history) - len(frozen) <= 1, "freeze each pin in judging_pins.frozen"


# --- what the digest covers ------------------------------------------------------------------


def test_every_exemption_names_a_module_and_gives_its_reason() -> None:
    for name, reason in JUDGING_EXEMPT.items():
        assert reason.strip(), f"{name} is exempt with no reason"
        assert _module_file(name) is not None, f"{name} is not a module of the package"


#: The functions of the standard library that import a module named by a string.
_DYNAMIC_IMPORTS = frozenset({"import_module", "__import__"})


def test_no_part_of_a_run_can_import_an_exempt_module() -> None:
    """An exemption is checked, not taken on its word. A module the ``dottore`` entry point loads
    runs its top-level code in the process of every run, so an exempt one must be outside the
    import closure of ``ildottore.cli.main`` (the third audit: an exempt renderer emptied
    ``FILTER_STOPS`` at import time and a resume mixed verdicts)."""

    loaded = _closure("ildottore.cli.main")
    for name in JUDGING_EXEMPT:
        inside = sorted(m for m in loaded if _under(m, name))
        assert not inside, (
            f"{name} is exempt and the dottore entry point imports {inside}: cover it (it runs in "
            "every run's process)"
        )


def test_no_covered_code_imports_an_exempt_module_by_name() -> None:
    """A dynamic import is outside the static closure (the third audit's dyn-x reached an exempt
    command's constant through ``importlib.import_module``). One that names an ``ildottore``
    module must name a covered one, by a literal string; an argument that is not a literal is
    allowed only where no literal of its function names an ``ildottore`` module."""

    covered = {label for label, _ in covered_files()}
    for module in _all_modules():
        if module not in covered:
            continue
        path = _module_file(module)
        assert path is not None
        tree = ast.parse(path.read_text(encoding="utf-8"))
        scopes: list[ast.AST] = [tree] + [
            n for n in ast.walk(tree) if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))
        ]
        for scope in scopes:
            literals = [
                n.value
                for n in ast.walk(scope)
                if isinstance(n, ast.Constant) and isinstance(n.value, str)
            ]
            for call in (n for n in ast.walk(scope) if isinstance(n, ast.Call)):
                func = call.func
                called = func.attr if isinstance(func, ast.Attribute) else getattr(func, "id", "")
                if called not in _DYNAMIC_IMPORTS or not call.args:
                    continue
                first = call.args[0]
                if isinstance(first, ast.Constant) and isinstance(first.value, str):
                    assert not any(_under(first.value, n) for n in JUDGING_EXEMPT), (
                        f"{module} imports the exempt module {first.value} by name"
                    )
                else:
                    assert not any(v.startswith("ildottore") for v in literals), (
                        f"{module} imports a module by a computed name beside a literal naming an "
                        "ildottore module: cover what it can reach, or import it statically"
                    )


def test_every_other_file_of_the_package_is_covered() -> None:
    labels = {label for label, _ in covered_files()}
    for module in _all_modules():
        if not any(_under(module, name) for name in JUDGING_EXEMPT):
            assert module in labels, f"{module} is neither covered nor exempt"
    assert {
        "store/schema.sql",
        "fingerprint/signatures/pack.yaml",
        "reporting/schemas/report-1.0.schema.json",
        "reporting/templates/report.html.j2",
        # The built-in battery and the attack-spec schema, inside the package since u12 A-84.
        "battery/pack.yaml",
        "battery/attacks/PI-DIRECT-001.yaml",
        "battery/attacks/assets/mm-audio-override-pineapple.wav",
        "battery/suites/quick.yaml",
        "registry/schemas/attack-spec.schema.json",
        "ildottore.reporting.json_reporter",
        "ildottore.cli.render",
        "ildottore.cli.app",
    } <= labels
    assert not any(label.startswith("ildottore.testing") for label in labels)


def test_only_the_suffixes_the_package_reads_are_data() -> None:
    """Every non-Python file of the package has a suffix of DATA_SUFFIXES, so none it reads is
    left out; a stray file (the third audit's evaluators/.DS_Store) is not one of them."""

    package = Path(judging_rules.__file__).resolve().parents[1]
    for path in package.rglob("*"):
        relative = path.relative_to(package)
        if (
            path.is_file()
            and path.suffix not in {".py", ".pyc"}
            and not any(part.startswith(".") or part == "__pycache__" for part in relative.parts)
        ):
            assert (
                path.suffix in judging_rules.DATA_SUFFIXES
                or relative.as_posix() in judging_rules.DATA_EXEMPT
            ), f"{relative} is read? classify it"


def _package_copy(tmp_path: Path) -> Path:
    copy = tmp_path / "ildottore"
    shutil.copytree(
        Path(judging_rules.__file__).resolve().parents[1],
        copy,
        ignore=shutil.ignore_patterns("__pycache__"),
    )
    return copy


@pytest.mark.parametrize(
    ("relative", "old", "new"),
    [
        # The second audit's HIGH 1: a default of the REST template no target file carries.
        (
            "adapters/rest.py",
            "    finish_path: str | None = None",
            '    finish_path: str | None = "finish_reason"',
        ),
        # The offline judge (its mut-g2).
        ("cli/wiring.py", 'verdict = "exploited"', 'verdict = "secure"'),
        # A decorator (its mut-h).
        ("adapters/rest.py", "    @property\n    def reads_array_body", "    def reads_array_body"),
        # The first audit's mut-a: a constant the runner reads.
        (
            "core/runner.py",
            "        EvaluatorType.REFUSAL,\n        EvaluatorType.SECRET_LEAKAGE,",
            "        EvaluatorType.SECRET_LEAKAGE,",
        ),
        # A data file.
        ("store/schema.sql", "CREATE TABLE", "CREATE  TABLE"),
    ],
)
def test_a_change_to_covered_code_changes_the_digest(
    tmp_path: Path, relative: str, old: str, new: str
) -> None:
    copy = _package_copy(tmp_path)
    before = judging_rules._digest(copy)
    target = copy / relative
    text = target.read_text(encoding="utf-8")
    assert old in text, (relative, old)
    target.write_text(text.replace(old, new, 1), encoding="utf-8")
    assert judging_rules._digest(copy) != before


def test_a_comment_a_docstring_or_a_stray_file_is_not_a_change(tmp_path: Path) -> None:
    copy = _package_copy(tmp_path)
    before = judging_rules._digest(copy)
    runner = copy / "core" / "runner.py"
    runner.write_text(runner.read_text(encoding="utf-8") + "\n# a note, and nothing else\n")
    (copy / "evaluators" / ".DS_Store").write_bytes(b"\x00\x01 Finder")
    (copy / "evaluators" / "notes.txt").write_text("nothing the package reads")
    (copy / "testing" / "golden.py").write_text("X = 1\n")
    assert judging_rules._digest(copy) == before


def test_a_side_effect_in_a_renderer_changes_the_digest(tmp_path: Path) -> None:
    """The third audit's mut-sidefx2, which an exemption of the renderer let through."""

    copy = _package_copy(tmp_path)
    before = judging_rules._digest(copy)
    render = copy / "cli" / "render.py"
    render.write_text(
        render.read_text(encoding="utf-8")
        + "\nimport ildottore.shared.provider_filter as _pf\n\n_pf.FILTER_STOPS = frozenset()\n"
    )
    assert judging_rules._digest(copy) != before


def test_a_package_with_no_source_is_refused_not_digested(tmp_path: Path) -> None:
    """A zip or frozen install has no file under the package directory: a digest of nothing would
    pass every resume (third audit, LOW). It is refused, a ValueError, which the CLI exits 3 on."""

    empty = tmp_path / "ildottore"
    empty.mkdir()
    (empty / "data.yaml").write_text("x: 1\n")
    with pytest.raises(judging_rules.JudgingCodeUnreadable, match="cannot read Il Dottore's own"):
        judging_rules._digest(empty)
    assert issubclass(judging_rules.JudgingCodeUnreadable, ValueError)


def test_each_covered_file_has_a_short_digest_for_the_refusal(tmp_path: Path) -> None:
    files = judging_rules.judging_files()
    assert set(files) == {label for label, _ in covered_files()}
    assert all(len(d) == judging_rules.FILE_DIGEST_LENGTH for d in files.values())
    copy = _package_copy(tmp_path)
    _, before = judging_rules._scan(copy)
    rest = copy / "adapters" / "rest.py"
    text = rest.read_text(encoding="utf-8")
    rest.write_text(
        text.replace("finish_path: str | None = None", 'finish_path: str | None = "x"', 1)
    )
    _, after = judging_rules._scan(copy)
    assert [k for k in before if before[k] != after[k]] == ["ildottore.adapters.rest"]


def test_the_digest_costs_well_under_a_second() -> None:
    """Taken once per process, at run start and by a resume: 0.35 to 0.38 s measured for the 171
    files at landing."""

    started = time.perf_counter()
    judging_rules._digest(Path(judging_rules.__file__).resolve().parents[1])
    assert time.perf_counter() - started < 3.0, "a regression past the measured 0.38 s"


def test_a_comment_or_a_docstring_is_not_a_change_and_a_token_or_a_decorator_is() -> None:
    base = 'def f(x):\n    """Doc."""\n    return x + 1  # one\n'
    commented = (
        'def f(x):\n    """Another doc,\n    on two lines."""\n\n    # a note\n    return x + 1\n'
    )
    changed = 'def f(x):\n    """Doc."""\n    return x + 2\n'
    assert normalized_source(base) == normalized_source(commented)
    assert normalized_source(base) != normalized_source(changed)
    assert "@property" in normalized_source(
        "class A:\n    @property\n    def p(self):\n        return 1\n"
    )
    # A string that is not a docstring is code, and a `#` inside a string is not a comment.
    assert "'#'" in normalized_source("def g():\n    return '#'\n")


@pytest.mark.parametrize(
    "name",
    [
        "JUDGING_EXEMPT",
        "JUDGING_RULES_SINCE",
        "JUDGING_RULES_VERSION",
        "covered_files",
        "judging_digest",
    ],
)
def test_the_module_exports_what_it_documents(name: str) -> None:
    assert name in judging_rules.__all__
