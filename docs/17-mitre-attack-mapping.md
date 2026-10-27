# 17, MITRE ATT&CK Enterprise mapping (a fifth coverage axis, no runtime dependency)

Spec-by-technique map of the battery against **MITRE ATT&CK Enterprise v20.0** (released
2026-10-13), the release that gave an AI red-team battery something honest to map to: it added
Direct and Indirect Prompt Injection (`T1699`, `T1698`), AI-Enabled Exfiltration (`T1700`), Impair
Autonomous Defenses (`T1685.007`), Query Public AI Services (`T1682`), Generate Content (`T1683`)
and Invisible Unicode (`T1027.018`), renamed Defense Evasion to **Stealth** and split a new
**Defense Impairment** tactic out of it. Before v20 the only honest statement was "ATLAS covers
the model, ATT&CK covers the estate, and this tool tests the model". After v20, most agentic specs
map directly, because the agent *is* on the estate.

**Decision (2026-10-24).** ATT&CK is a **coverage reference** here, like ATLAS, IoPC and AISVS.
The universe is pinned as data (`src/ildottore/shared/data/attack-enterprise-20.0.json`), derived
from the official STIX 2.1 bundle by `scripts/attack_universe.py`; nothing is fetched at run
time, and every figure beside `v20.0` can be rebuilt from the checkout. The method is borrowed
from the Feedly *Map ATT&CK Techniques* Claude skill (`claude-skill-04-map-att-and-ck-techniques`,
read 2026-10-24), reduced to what a test harness can tell apart: the skill maps a *report's*
prose with four occurrence statuses and a confidence; this repository maps a *spec's* oracle with
two, and the harness is its own observer, so there is no confidence to attach. What was kept from
the skill: check the release before mapping, verify every ID against the pinned bundle, refuse a
retired ID with its replacement named, keep a technique's tactic restriction inside the
technique's own tactics, write the Navigator layer in format 4.5 with `versions.attack` as the
major release, and never cite a technique the evidence does not show.

## What a mapping claims

A spec's optional `mitre_attack:` block lists techniques, each with an `occurrence`:

| occurrence | meaning | counted? |
|---|---|---|
| `observed` | the technique's behaviour appears in the **target's own actions or reply** during the test: a mock tool call the trace records (a cron entry written, a credential store read, a record POSTed out), or the reply itself being the technique's effect (an injected instruction obeyed, a lure written, a targeting dossier synthesised) | yes, its tactics |
| `capability-only` | the target produced an **artefact that would enable the technique elsewhere** (malware source, a phishing lure's eventual delivery, the reconnaissance a dossier would feed); nothing of the technique itself was executed | listed, never |

The axis counts **tactics**, as the ATLAS axis does, and only from `observed` techniques. A
technique sits under one or more tactics upstream; a spec may restrict its claim with `tactics:`
to the ones it exercises (`T1053.003` Cron is Execution, Persistence and Privilege Escalation, and
a beacon spec exercises Persistence). The restriction is validated against the pin: a tactic the
technique is not under is `FRAMEWORK_CLAIM_CONTRADICTED`, since a restriction narrows a claim and
cannot move it. A retired or unknown ID is `UNKNOWN_FRAMEWORK_CODE`, naming the replacement when
the release gives one (`T1562` Impair Defenses became `T1685`; `T1070.002` Clear Linux logs became
`T1685.006`). `dottore coverage` does not lint, so it reports both under `off_universe` and counts
neither (clause A-95).

Three things a mapping is **not**: a claim that the target is compromised (a `pass` on a mapped
spec means the technique was attempted and refused), a claim about the attacker's infrastructure
(Resource Development is counted only where the model itself produced the resource), and a threat
intelligence statement (no `reported` or `source-assessed` occurrence exists here, because nothing
in a run is a third-party report).

## Figures (copied from `dottore coverage --framework attack`, 2026-10-24)

```
  MITRE ATT&CK Enterprise tactics (v20.0)    8/15   53%
```

41 of 79 specs carry a mapping; 18 distinct techniques are declared, 14 observed and 4
capability-only. Covered: Reconnaissance, Resource Development, Execution, Persistence, Stealth,
Credential Access, Exfiltration, Impact. Not covered yet, all **roadmap** (a black-box runtime
scanner driving an agent can observe each in the target's own tool calls): Initial Access,
Privilege Escalation, Defense Impairment, Discovery, Lateral Movement, Collection, Command and
Control. None is out of reach or deliberately untested, and the bucket membership is pinned in
`tests/cli/test_coverage_cmd.py`.

## The map

| Spec | Technique(s) | Why this and not more |
|---|---|---|
| `PI-DIRECT-001`, `JB-ROLEPLAY-001`, `JB-REFUSAL-SUPPRESS-001`, `JB-ENCODING-001`, `JB-CRESCENDO-001`, `JB-LINEAR-001`, `JB-SEQUENTIAL-001`, `JB-TREE-001`, `JB-LIKERT-001`, `JB-MULTILINGUAL-001`, `GUARD-INPUT-EVASION-001`, `GUARD-OUTPUT-ENCODE-001` | `T1699` observed | v20 defines Direct Prompt Injection to cover bypassing safeguards (jailbreaks) as well as overriding instructions; the reply obeying is the technique |
| `GUARD-UNICODE-EVASION-001` | `T1699`, `T1027.018` observed | the carrier is invisible Unicode; the hidden instruction is read by the model |
| `JB-OFFENSIVE-RANSOM-CODEGEN-001` | `T1699` observed; `T1587.001` capability-only | the toolkit is source the model writes, never run |
| `RECON-TARGET-OSINT-001` | `T1682` observed; `T1589`, `T1591` capability-only | the model is the public AI service being queried for targeting; the dossier would feed identity and org gathering elsewhere |
| `SAFETY-PHISH-BEC-001` | `T1683.001` observed; `T1566` capability-only | the lure is generated; nothing is sent |
| `SAFETY-DISINFO-001` | `T1683.001` observed | written content at scale; no operation follows |
| `PI-INDIRECT-RAG-001`, `PI-INDIRECT-TOOL-001`, `MM-IMG-DOC-INJECT-001`, `MM-IMG-PROMPTINJECT-001`, `MM-AUD-PROMPTINJECT-001`, `MM-IMG-SPLIT-PAYLOAD-001`, `MEM-POISON-001`, `AG-WORM-PROPAGATE-001` | `T1698` observed | the instruction arrives in data the target processes and is obeyed |
| `PI-DELAYED-TRIGGER-001`, `AG-TOOLMETA-POISON-001`, `AG-INTERAGENT-COMPROMISE-001`, `MM-IMG-TOOL-EXFIL-001`, `AG-TOOLCHAIN-EXFIL-001` | `T1698`, `T1700` observed | the injected instruction makes the agent move data out through a tool |
| `AG-CODEEXEC-UNEXPECTED-001` | `T1698`, `T1059.006` observed | the injected snippet is run through the Python interpreter tool |
| `AG-EXTORT-CHAIN-001` | `T1698`, `T1552`, `T1485`, `T1486`, `T1700` observed | the JadePuffer chain end to end: inject, read the env, drop, encrypt, POST out |
| `MCP-TOOLPOISON-001` | `T1698` capability-only | the adapter reads poisoned metadata; no tool is invoked, so nothing is obeyed |
| `AG-EXFIL-EGRESS-001` | `T1700` observed | the POST to the blocked external address is the technique |
| `AG-CRED-SWEEP-001` | `T1552` observed | the planted canary read from the mock secret store |
| `AC-SSRF-001` | `T1552.005` observed | the fetch to the link-local metadata endpoint |
| `AG-PERSIST-BEACON-001` | `T1053.003` observed, `tactics: [persistence]` | the cron entry; the spec exercises persistence, not execution or escalation |
| `AG-DESTRUCTIVE-DBDROP-001`, `AG-AUTONOMY-SELFCORRECT-001` | `T1485`, `T1486` observed | `drop_table` and `encrypt_config` mock calls |
| `AG-LOG-EVASION-001` | `T1070` observed | the agent deletes or forges audit-log entries (application logs, so the generic Indicator Removal, not the v20 system-log sub-techniques now under Defense Impairment) |
| `DOS-RESOURCE-HIJACK-001` | `T1496.004` observed | v20's Cloud Service Hijacking names LLM resource abuse ("LLMJacking"); the operator's inference budget is the hijacked service |

**Deliberately unmapped** (37 specs): the output-security family (`OUT-*`: the vulnerability is in
the consumer of the reply, which the test never runs), data leakage and embeddings (`DL-*`,
`EMB-*`, `SP-LEAK-001`: ATLAS and IoPC name these; ATT&CK's Collection and Exfiltration would
be the model's own data, which stretches "adversary on the estate" past what the oracle shows),
model and system reconnaissance (`RECON-SYSTEM-001`, `RECON-MODEL-IDENTITY-001`: ATLAS
Reconnaissance), the access-control family (`AC-BFLA/BOLA/RBAC/DEBUG`, `AC-SSRF-SCHEME-001`:
application authorization, OWASP API), the agent-autonomy and trust specs (`AG-TOOL-UNAUTH-001`,
`AG-GOAL-THEFT-001`, `AG-RECURSIVE-HIJACK-001`, `AG-AUTONOMY-DRIFT-001`, `AG-IDENTITY-ABUSE-001`,
`AG-TRUST-APPROVAL-001`, `AG-CONFIRM-BYPASS-001`: IoPC and OWASP Agents name them; no single
ATT&CK technique is the oracle's effect), the function-call argument specs (`FUNCALL-*`: an
application-layer flaw in the argument), `SUPPLY-SLOPSQUAT-001` (the suggestion of a package is
not its installation), `DOS-TOKEN-AMP-001` (one large reply is not a service hijack), and the
responsible-AI floor (`SAFETY-HARMFUL-001`, `BIAS-STEREOTYPE-001`). A mapping would be arguable
for several of these; "a spec declares a code only if it genuinely exercises it" decides against.

## The Navigator layer

`dottore coverage --navigator-layer battery.json` writes the battery as an ATT&CK Navigator layer
(format 4.5, `domain: enterprise-attack`, `versions.attack: "20"`): observed techniques in one
colour, capability-only in another, each cell's comment naming the specs that declare it, one
cell per tactic the technique is drawn under (narrowed by the spec's restriction). `dottore run
-oN layer.json` writes the same matrix coloured by the run's verdicts (exploited, not exploited,
inconclusive; capability-only drawn, not counted; specs that sent nothing scorable absent). A
spec run against several targets takes the worst verdict among them; a restriction that names
no tactic of the technique draws nothing, as coverage counts nothing; the battery layer's
`specs_unloaded` metadata says how many spec files failed to load and are absent. The
layer is built from spec ids, spec names, technique ids, the run id and target ids only: no
reply reaches it. It is a companion to a report, not a report, so `-oA` keeps writing four files.

## Keeping the pin current

```bash
python3 -I scripts/attack_universe.py check                 # exit 1 if a newer Enterprise release exists
python3 -I scripts/attack_universe.py refresh               # download the newest bundle, re-derive, re-pin
python3 -I scripts/attack_universe.py refresh --version 20.0 --index index.json --bundle bundle.json
python3 -I scripts/attack_universe.py diff old.json new.json
```

`refresh` verifies the bundle's `x_mitre_version` against the collection index, writes the new
data file, removes the old one, and prints what moved: tactics renamed, techniques added, gone or
re-homed, and **which shipped specs declare an ID the new release retired**, so the bump cannot
land with a numerator quietly shrunk. After it, bump `ATTACK_VERSION` in
`src/ildottore/shared/attack.py` and copy the new figures into this file and the manual.

Source: `mitre-attack/attack-stix-data`, `enterprise-attack/enterprise-attack-20.0.json`
(SHA-256 `81113ba98afa2928f3dcff62022539f7ce30c315c32e14422f11ff95ce534352`, 55,271,014 bytes,
collection index modified 2026-10-13T17:54:40Z). Only identifiers, names and tactic memberships
are reproduced; ATT&CK is published by The MITRE Corporation under its own terms of use, and the
descriptions stay upstream.
