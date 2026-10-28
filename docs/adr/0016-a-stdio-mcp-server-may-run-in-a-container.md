# ADR-0016: a stdio MCP server may run in a container (u04 A-104)

* **Status:** accepted on 2026-10-27 by the owner ("do it all"), as built (OD-60): opt-in per
  target, no network, `isolation:` a top-level key that stays there when A-101's `mcp:` block
  lands, and a mount holding the home directory (or one above it) refused
* **Date:** 2026-10-27
* **Context:** clause u04 A-104 in `specs/contracts/u04-target-adapters.md` with its halves in u00
  and u12; `docs/02` (S3, the safety charter), the stdio transport of the MCP adapter, the bench
  run on 2026-10-27 against the public Damn Vulnerable MCP Server labs.

## The problem, measured

A `provider: mcp`, `transport: stdio` target is a program the scanner starts on the operator's
machine. The scope authorizes its exact command line, so nothing unlisted is launched, and the
adapter only lists what the server advertises, never `tools/call`. That is the whole of what keeps
the scanned code in check. On `9dda026b` the server runs as the operator's user, with the
operator's files, network and processes within reach; since SEC-08 (2026-10-03) it inherits only
`PATH`, `HOME`, the locale and the temporary directory, not the credentials of other targets.

Discovery alone runs the server's code: its start-up, its `initialize` handler, its listing
handlers. The servers this tool is pointed at are, by the nature of the work, the ones nobody
trusts yet. On the 2026-10-27 bench, the lab servers wrote files under `/tmp` at start-up (the
sandboxed run failed for that reason), and a server that does more than that at start-up would do
it with the operator's rights. "Authorized command" says who chose to run it; it says nothing about
what it can reach.

## The decision

A stdio MCP target may declare `isolation:`, and then the server runs in a container, never on
the host:

* **Opt-in, one block.** `image` (required, pinned by digest: `name@sha256:<64 hex>`), `runtime`
  (`docker`, the default, or `podman`), `memory` (default `512m`), `cpus` (default `1`), `pids`
  (default `128`), `mounts` (each a `source` directory on the host and a `target` path inside,
  always read-only) and `workdir`. Only `provider: mcp` with `transport: stdio` takes it. Absent,
  nothing changes: the server runs as before.
* **The scope authorizes the same thing.** The scope's `commands` entry still names the command
  run inside the container, exactly as now. The isolation can only take rights away, so it needs
  no authorization of its own; the image is pinned in the target file, which the operator wrote.
* **What the container gets, fixed:** no network (`--network none`), a read-only root file system
  with a small `noexec` `/tmp`, every capability dropped, `no-new-privileges`, the user
  `65534:65534`, an init process, the resource limits above, no variable from the host, and
  `--pull never`, so the scanner never fetches an image from a registry. The operator pulls the
  pinned image first; the scan does not reach the network to start a local server.
* **No fallback to the host.** A runtime that is not on `PATH`, or an image that is not present
  locally, stops the run before anything is spawned (`IsolationUnavailable`, a product error: the
  configuration cannot be carried out, as a placeholder with no value cannot), naming what to do.
  A target that asked for isolation never runs unisolated.
* **Cleanup.** The container has a random name (`dottore-mcp-<12 hex>`) and the label
  `dottore.mcp=1`; after the session the runtime's `rm -f` removes it, whether the server exited,
  hung or was killed.
* **What it changes in the evidence.** Nothing in the reply: the catalogue is the same rendering.
  The block enters the target digest (the image is part of what answers), without `runtime`,
  `memory`, `cpus` and `pids`, which change where and how fast, not what answers. Absent, it is
  left out, so a run stored before the field existed still resumes.
* **Where the argv is built.** `adapters/isolation.py`, a pure function of the block, the command
  and a name, so the flags are tested without a container runtime. One test, opt-in by
  `DOTTORE_TEST_DOCKER_IMAGE`, starts a real container.

## Not taken

* **Isolation on by default.** It would need a runtime on every machine that scans a stdio server,
  and an image for each; today the tool works with neither. Default-on is a policy decision with a
  cost (OD-60).
* **Network allowed on request.** A server that needs its upstream API cannot be listed in this
  container. Allowing a declared egress means an allowlist inside the container (a proxy, or a
  network the runtime does not filter by host), a larger piece of work; until then such a server
  runs unisolated, as before, and the operator chooses that (OD-60).
* **A sandbox without containers** (`sandbox-exec`, `bwrap`, seccomp). Different per platform and,
  on macOS, deprecated; a container behaves the same on Linux and macOS, where the tool is used.
* **Pulling the image.** It would make the scan reach a registry, outside the scope's allowlist.
* **Mounts that write.** A server that must write keeps its writes in `/tmp`, which is discarded.

## Consequences

* A stdio server can be scanned with no access to the operator's files, network or processes,
  and a server that misbehaves at start-up does it inside a container that is removed after.
* The scan of an isolated server needs Docker or Podman and the image pulled beforehand; the
  error says both.
* Reversal: drop `isolation` from `Target` and the loader (`cli/wiring.py` `_isolation_spec`),
  and the two branches in `adapters/mcp.py` that read it; `adapters/isolation.py` goes whole.
