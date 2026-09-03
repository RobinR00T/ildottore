# References (state of the art, as of 2026-07)

## Frameworks
- OWASP Top 10 for LLM Applications 2025: https://genai.owasp.org/resource/owasp-top-10-for-llm-applications-2025/
- OWASP GenAI Red Teaming Guide (Jan 2025): https://genai.owasp.org/resource/genai-red-teaming-guide/
- MITRE ATLAS: https://atlas.mitre.org/
- NIST AI 600-1 (GenAI Profile) / AI RMF: https://www.nist.gov/itl/ai-risk-management-framework

## Tools (design references)
- NVIDIA garak (LLM vuln scanner; 50+ probe modules, run-all default, "buffs"=mutators): https://github.com/NVIDIA/garak · https://garak.ai/
- Microsoft PyRIT (automated red team; multi-turn Crescendo/TAP/Skeleton-Key, XPIA orchestrator): https://github.com/Azure/PyRIT · https://www.microsoft.com/en-us/security/blog/2024/02/22/announcing-microsofts-open-automation-framework-to-red-team-generative-ai-systems/
- promptfoo (157 plugins; framework presets owasp:llm/mitre:atlas/nist/eu:ai-act/gdpr/iso:42001): https://www.promptfoo.dev/docs/red-team/plugins/
- Giskard LLM scan (traditional + LLM-assisted detectors): https://docs.giskard.ai/en/latest/knowledge/llm_vulnerabilities/index.html
- AgentDojo (97 tasks / 629 security cases; utility+security jointly): https://www.emergentmind.com/topics/agentdojo-benchmark

## Vendor guidance
- Anthropic: how we contain Claude (defense-in-depth, RL against injection, automated red-team agent): https://www.anthropic.com/engineering/how-we-contain-claude
- OpenAI: approach to external red teaming: https://arxiv.org/html/2503.16431v1
- OpenAI: understanding prompt injections / hardening Atlas: https://openai.com/index/prompt-injections/ · https://openai.com/index/hardening-atlas-against-prompt-injection/

## Datasets (for dataset-backed specs)
HarmBench · BeaverTails · CyberSecEval · DoNotAnswer · ToxicChat · XSTest (false-refusal) ·
NVIDIA Aegis.

## Development methodology (how we build Il Dottore)
Primary: **Zynap: Specs-Driven Development with AI** (internal methodology brief, 2026). The
six-stage method, PITV harness, contract anatomy and operating discipline in `AGENTS.md` +
`docs/00` derive from it. It in turn grounds on:

- Anthropic: Claude Code best practices: https://code.claude.com/docs/en/best-practices
- Anthropic: Building effective agents: https://www.anthropic.com/engineering/building-effective-agents
- Anthropic: Multi-agent research system: https://www.anthropic.com/engineering/multi-agent-research-system
- Anthropic: Effective context engineering: https://www.anthropic.com/engineering/effective-context-engineering-for-ai-agents
- Anthropic: Writing effective tools for agents: https://www.anthropic.com/engineering/writing-tools-for-agents
- Anthropic: Statistical approach to evals: https://www.anthropic.com/research/statistical-approach-to-model-evals
- Anthropic: Claude Code sandboxing: https://www.anthropic.com/engineering/claude-code-sandboxing
- Vercel: Eval-driven development: https://vercel.com/blog/eval-driven-development-build-better-ai-faster
- Vercel: Agent responsibly: https://vercel.com/blog/agent-responsibly
- AGENTS.md open standard: https://agents.md
- GitHub spec-kit: https://github.com/github/spec-kit
- AWS Kiro (spec-driven IDE): https://kiro.dev
- OpenAI: Practical guide to building agents: https://openai.com/business/guides-and-resources
- Sean Grove (OpenAI): The New Code: https://youtube.com/watch?v=8rABwKRsec4
- Karpathy: Software Is Changing (Again); Simon Willison: vibe coding / lethal trifecta (https://simonwillison.net)
- Cognition: Don't Build Multi-Agents: https://cognition.com/blog/dont-build-multi-agents
- Thoughtworks: Exploring Generative AI: https://martinfowler.com/articles/exploring-gen-ai.html
- Addy Osmani: The 70% Problem (https://addyo.substack.com) · Chip Huyen: AI Engineering / EDD (https://huyenchip.com)

## Agentic-abuse / LLM-driven threats (docs/13)
- Sysdig: JADEPUFFER: agentic ransomware for automated database extortion (2026): https://www.sysdig.com/blog/jadepuffer-agentic-ransomware-for-automated-database-extortion
- The Register: first end-to-end agentic ransomware attack (2026-07): https://www.theregister.com/security/2026/07/02/smooth-ai-criminal-drives-first-end-to-end-agentic-ransomware-attack/
- Anthropic: Detecting and countering misuse of AI, Aug 2025 ("vibe hacking" extortion): https://www.anthropic.com/news/detecting-countering-misuse-aug-2025
- Anthropic: Disrupting the first reported AI-orchestrated cyber-espionage campaign (Nov 2025): https://www.anthropic.com/news/disrupting-AI-espionage
- ESET / NYU: PromptLock (AI ransomware PoC); PROMPTFLUX / PROMPTSTEAL LLM-embedded malware
- CVE-2025-3248 (Langflow unauth RCE): JadePuffer initial access
