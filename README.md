# Purinina

> A multi-agent **cybersecurity / pentesting** framework that runs on top of
> [opencode](https://opencode.ai) inside a hardened, host-networked Docker
> sandbox. Its multi-agent architecture is inspired 1:1 by
> [CAI (Cybersecurity AI)](https://github.com/aliasrobotics/cai) — re-implemented
> from scratch in **TypeScript**, with a consistent **Human-In-The-Loop (HITL)**
> policy.

> [!WARNING]
> Offensive-security tool. Use **only** against systems you own or are explicitly
> authorized to test. Read [`DISCLAIMER`](./DISCLAIMER) before use.

---

## Why this design

opencode already provides what is genuinely hard to build well: a polished
terminal/UI experience, model & provider management, agent/subagent execution,
tool calling, bash integration and a permission system. Purinina does **not**
reinvent any of that. Instead it treats opencode as the **runtime and interface**
and layers the CAI-style multi-agent *architecture* on top:

| CAI (Python) | Purinina (TypeScript on opencode) |
| --- | --- |
| `Agent` personas (red team, recon, …) | opencode **agents** (`runtime/agent/*.md`) |
| `handoff` / `transfer_to_X` | opencode **`task`** tool (orchestrator → subagent) |
| Orchestration patterns (swarm / parallel / sequential) | **orchestrator agent** + the **purinina plugin** |
| Per-category tools (recon, exploitation, web, …) | custom **tools** in the purinina plugin |
| Human-In-The-Loop | central **HITL policy** in the plugin (`permission.ask` + `tool.execute.before`) |
| Containerized virtualization (`--network host`, `NET_RAW`) | the **Docker sandbox** (`docker/`) |

See [`docs/architecture.md`](./docs/architecture.md) for the full mapping.

## How it works

```
 host ──► purinina (launcher CLI)
            │  1. checks Docker is installed
            │  2. builds the sandbox image if missing (Kali + tools + opencode + purinina, baked in)
            │  3. starts the container:  --network host  --cap-add NET_ADMIN,NET_RAW  seccomp=unconfined
            │  4. mounts host opencode auth (read-only) + your engagement workspace
            ▼
 sandbox container ──► opencode TUI
            │   loads purinina global config (~/.config/opencode):
            │     • opencode.json   — providers, agents, permissions, plugin
            │     • plugin/         — HITL policy, sandbox guard, pentest tools
            │     • agent/          — orchestrator + recon + web-exploit + reporter
            ▼
        you ⇄ orchestrator ⇄ specialist subagents ⇄ tools  (every dangerous step gated by HITL)
```

opencode for Purinina is **only ever launched inside the sandbox**. The plugin
additionally refuses to arm its offensive tooling unless it detects the sandbox
marker (defense in depth — see [`docs/sandbox.md`](./docs/sandbox.md)).

## Requirements

- **Docker** (required — the launcher refuses to run without it)
- **Node.js ≥ 20** (to run the host launcher)
- A model provider configured in opencode on your host (e.g. `opencode auth login`)

## Quick start

```bash
# 1. Build the launcher
npm install
npm run build

# 2. Launch — builds the sandbox image on first run, then drops you into opencode
node dist/launcher/index.js
#   (or `npm link` once, then just: purinina)
```

On first launch the framework starts in **strict HITL** mode: every potentially
intrusive action pauses for your approval.

## Project status

Early development. **v1 (vertical slice)** wires the full pipeline end-to-end
(sandbox → opencode → plugin → agents → HITL → tools) with four agents:
`orchestrator`, `recon`, `web-exploit`, `reporter`. The remaining CAI specialist
agents and the custom orchestration patterns are added incrementally
(see [`docs/architecture.md`](./docs/architecture.md) → *Roadmap*).

## Repository layout

```
purinina/
├── src/launcher/          # host-side CLI (TypeScript) — the `purinina` command
├── runtime/               # baked into the sandbox image as opencode global config
│   ├── opencode.json      #   providers, agents, permissions, plugin registration
│   ├── plugin/            #   the purinina plugin: HITL, sandbox guard, tools
│   ├── agent/             #   agent personas (markdown)
│   └── workspace-skeleton # ready-made engagement folder structure
├── docker/                # Dockerfile + entrypoint + compose for the sandbox
└── docs/                  # architecture, HITL, sandbox & agent documentation
```

## License

[MIT](./LICENSE). Inspired by CAI's architecture; contains no CAI source code.
