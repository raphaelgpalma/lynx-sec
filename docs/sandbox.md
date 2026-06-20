# The sandbox

Purinina runs entirely inside a Docker container. This is both a safety boundary
(the model operates on the container's filesystem, not the host's) and a ready
pentesting environment (Kali + tools + opencode + the Purinina architecture,
baked in).

## What the image contains (`docker/Dockerfile`)

- **Base:** `kalilinux/kali-rolling`.
- **Tooling (v1 vertical slice — recon + web):** `nmap`, `masscan`, `whatweb`,
  `gobuster`, `ffuf`, `wfuzz`, `dirb`, `nikto`, `sqlmap`, `dnsutils`,
  `seclists`, `netcat`, plus the usual shell/network utilities. (More land as
  new agents do.)
- **Node.js 22** — to install the plugin's runtime dependency.
- **opencode** — installed via the official installer, **pinned** to
  `OPENCODE_VERSION` (default 1.17.8) so builds are reproducible.
- **Purinina global config** baked into `~/.config/opencode/`:
  `opencode.json`, `plugin/purinina.ts`, `agent/*.md`. Plugin deps are
  pre-installed so the first launch is fast and offline-reproducible.
- **Engagement skeleton** at `/opt/purinina/workspace-skeleton`, used to seed an
  empty workspace on first run (`scope/`, `recon/`, `web/`, `exploitation/`,
  `loot/`, `evidence/`, `reports/`, `notes/`, `AGENTS.md`).

> opencode is installed as part of bringing the sandbox up — Docker is a hard
> requirement, and the `purinina` launcher refuses to run without it.

## How it runs (`src/launcher` / `docker/docker-compose.yml`)

```
docker run -d --name purinina-sandbox \
  --network host \                  # full host network access (pentesting)
  --cap-add NET_ADMIN \             # routing / iptables / tunnels
  --cap-add NET_RAW \               # raw sockets: nmap SYN scans, ping, crafting
  --security-opt seccomp=unconfined \  # broad tool compatibility
  -e PURININA_SANDBOX=1 -e PURININA_HITL=strict \
  -v <your-workspace>:/root/engagement \
  -v ~/.local/share/opencode/auth.json:/root/.local/share/opencode/auth.json:ro \
  purinina:latest
# then: docker exec -it purinina-sandbox opencode --agent orchestrator
```

The container stays alive (`sleep infinity`) so the launcher can `exec` opencode
into it; this matches CAI's "persistent container, exec in" model.

## Security model — read this carefully

Purinina makes a deliberate trade-off that is standard for pentesting tooling:

- **Network is shared with the host (`--network host`) — by design.** Pentesting
  requires reaching targets exactly as the host can, and opencode needs outbound
  access to model-provider APIs. There is no network isolation between the
  container and the host. **Run Purinina only from a machine and network
  position from which you are authorized to operate.**
- **Filesystem and processes ARE isolated.** The container only sees its own
  filesystem plus two mounts: your engagement workspace, and your opencode
  `auth.json` (read-only). The host filesystem is otherwise invisible.
- **Raw-socket capabilities + seccomp unconfined** are granted for tool
  compatibility. This is powerful; it is scoped to the container.

### Defense in depth: "opencode for Purinina only runs in the sandbox"

Three independent mechanisms enforce this:

1. The **launcher** only ever execs opencode _inside_ the container.
2. The image sets `PURININA_SANDBOX=1`; the **entrypoint** refuses to start if it
   is missing.
3. The **plugin** disables `bash` (throws in `tool.execute.before`) whenever the
   `PURININA_SANDBOX` marker is absent — so even if the config is copied to a
   host, the offensive shell will not run there.

### Host file protection

`external_directory: "deny"` in `opencode.json` prevents opencode's file tools
from reading or writing anything outside the workspace, and the only host path
mounted writable is the workspace itself. `auth.json` is mounted read-only and
is never written from inside.

## Authentication into the sandbox

All of opencode's default providers stay available — Purinina restricts nothing.

By default (`PURININA_AUTH_MODE=mount`) the launcher mounts your host opencode
credentials read-only, so every provider you've already logged into on the host
works immediately — including **Ollama Cloud** (`ollama-cloud/*`), which opencode
supports natively. Pick a model with `PURININA_MODEL`, e.g.
`PURININA_MODEL=ollama-cloud/qwen3-coder:480b`; list options inside the sandbox
with `opencode models | grep ollama-cloud`.

Alternatively set `PURININA_AUTH_MODE=env` and provide one or more of
`OLLAMA_API_KEY` / `ANTHROPIC_API_KEY` / `OPENAI_API_KEY` / `OPENROUTER_API_KEY`
/ `GOOGLE_GENERATIVE_AI_API_KEY` in the environment.
