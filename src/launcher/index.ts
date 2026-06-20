#!/usr/bin/env node
/**
 * purinina — host launcher.
 *
 * Brings up the hardened sandbox and drops you into opencode inside it. opencode
 * for Purinina is ONLY ever launched through this container; it is never run
 * directly on the host.
 *
 *   purinina            build (if needed) + start sandbox + open opencode
 *   purinina build      (re)build the sandbox image
 *   purinina shell      open a bash shell inside the sandbox
 *   purinina status     show docker / image / container state
 *   purinina stop       stop the sandbox container
 *   purinina down       stop and remove the sandbox container
 *   purinina --help
 */
import { existsSync, mkdirSync, readFileSync } from "node:fs"
import { resolve } from "node:path"
import { loadConfig, type PurininaConfig } from "./config.js"
import * as docker from "./docker.js"

const RESET = "\x1b[0m"
const BOLD = "\x1b[1m"
const DIM = "\x1b[2m"
const RED = "\x1b[31m"
const GREEN = "\x1b[32m"
const YELLOW = "\x1b[33m"
const CYAN = "\x1b[36m"

const log = (m: string) => console.log(m)
const info = (m: string) => console.log(`${CYAN}›${RESET} ${m}`)
const ok = (m: string) => console.log(`${GREEN}✓${RESET} ${m}`)
const warn = (m: string) => console.log(`${YELLOW}!${RESET} ${m}`)
const fail = (m: string) => console.error(`${RED}✗ ${m}${RESET}`)

function version(cfg: PurininaConfig): string {
  try {
    const pkg = JSON.parse(readFileSync(resolve(cfg.repoRoot, "package.json"), "utf8"))
    return String(pkg.version ?? "0.0.0")
  } catch {
    return "0.0.0"
  }
}

function printHelp(cfg: PurininaConfig): void {
  log(`${BOLD}purinina${RESET} ${DIM}v${version(cfg)}${RESET} — multi-agent pentesting on opencode

${BOLD}Usage${RESET}
  purinina [command]

${BOLD}Commands${RESET}
  ${CYAN}(default)${RESET}   build if needed, start the sandbox, open opencode (orchestrator)
  ${CYAN}build${RESET}       (re)build the sandbox image
  ${CYAN}shell${RESET}       open a bash shell inside the running sandbox
  ${CYAN}status${RESET}      show docker / image / container state
  ${CYAN}stop${RESET}        stop the sandbox container
  ${CYAN}down${RESET}        stop and remove the sandbox container
  ${CYAN}help${RESET}        show this help

${BOLD}Key settings${RESET} ${DIM}(env or .env)${RESET}
  PURININA_WORKSPACE  host dir mounted as the engagement workspace (default ./engagement)
  PURININA_HITL       strict | guided | auto   (default strict)
  PURININA_MODEL      default model, e.g. anthropic/claude-opus-4-8
  PURININA_IMAGE      image tag   (default purinina:latest)
  PURININA_CONTAINER  container name (default purinina-sandbox)

${DIM}Offensive-security tool — authorized testing only. See DISCLAIMER.${RESET}`)
}

/** Verify Docker is present and the daemon is up; exit otherwise. */
function requireDocker(): void {
  if (!docker.isDockerInstalled()) {
    fail("Docker is required but was not found on PATH.")
    log(
      `${DIM}Install Docker, then re-run. Purinina runs entirely inside a Docker sandbox.${RESET}`,
    )
    process.exit(1)
  }
  if (!docker.isDockerRunning()) {
    fail("Docker is installed but the daemon is not running (or you lack permission).")
    log(`${DIM}Start Docker (e.g. 'sudo systemctl start docker') and try again.${RESET}`)
    process.exit(1)
  }
}

function ensureImage(cfg: PurininaConfig, force = false): void {
  if (!force && docker.imageExists(cfg.image)) {
    ok(`Image ${cfg.image} present.`)
    return
  }
  info(
    `Building sandbox image ${cfg.image} (opencode ${cfg.opencodeVersion}) — first build takes a few minutes…`,
  )
  const code = docker.buildImage({
    image: cfg.image,
    context: cfg.repoRoot,
    dockerfile: resolve(cfg.repoRoot, "docker", "Dockerfile"),
    opencodeVersion: cfg.opencodeVersion,
  })
  if (code !== 0) {
    fail("Image build failed.")
    process.exit(code)
  }
  ok(`Built ${cfg.image}.`)
}

/** Build the mount list + env for the container based on auth mode. */
function authWiring(cfg: PurininaConfig): {
  mounts: Array<[string, string, boolean?]>
  env: Record<string, string>
} {
  const mounts: Array<[string, string, boolean?]> = []
  const env: Record<string, string> = {}
  if (cfg.authMode === "mount") {
    if (existsSync(cfg.hostAuthFile)) {
      mounts.push([cfg.hostAuthFile, "/root/.local/share/opencode/auth.json", true])
    } else {
      warn(
        `No host opencode auth found at ${cfg.hostAuthFile}. ` +
          `Run 'opencode auth login' on the host, or set PURININA_AUTH_MODE=env.`,
      )
    }
  } else {
    for (const key of [
      "OLLAMA_API_KEY",
      "ANTHROPIC_API_KEY",
      "OPENAI_API_KEY",
      "OPENROUTER_API_KEY",
      "GOOGLE_GENERATIVE_AI_API_KEY",
    ]) {
      const v = process.env[key]
      if (v) env[key] = v
    }
    if (Object.keys(env).length === 0) {
      warn("PURININA_AUTH_MODE=env but no provider API keys found in the environment.")
    }
  }
  return { mounts, env }
}

function ensureContainer(cfg: PurininaConfig): void {
  const state = docker.containerState(cfg.container)
  if (state === "running") {
    ok(`Sandbox ${cfg.container} is running.`)
    return
  }
  if (state === "stopped") {
    info(`Starting existing sandbox ${cfg.container}…`)
    if (docker.startContainer(cfg.container) !== 0) {
      fail("Failed to start the existing container. Try 'purinina down' then retry.")
      process.exit(1)
    }
    return
  }
  // absent -> create
  mkdirSync(cfg.workspace, { recursive: true })
  info(`Creating sandbox ${cfg.container} (host network, NET_ADMIN/NET_RAW)…`)
  const { mounts, env } = authWiring(cfg)
  if (
    docker.runContainer({
      image: cfg.image,
      container: cfg.container,
      workspace: cfg.workspace,
      hitl: cfg.hitl,
      mounts,
      env,
    }) !== 0
  ) {
    fail("Failed to start the sandbox container.")
    process.exit(1)
  }
  ok(`Sandbox up. Workspace: ${cfg.workspace} -> /root/engagement`)
}

function openOpencode(cfg: PurininaConfig): never {
  const command = ["opencode", "--agent", "orchestrator"]
  if (cfg.model) command.push("--model", cfg.model)
  info(`Opening opencode (HITL=${cfg.hitl}${cfg.model ? `, model=${cfg.model}` : ""})…`)
  log(DIM + "─".repeat(60) + RESET)
  const code = docker.execInteractive({
    container: cfg.container,
    env: { PURININA_HITL: cfg.hitl },
    command,
  })
  process.exit(code)
}

function cmdLaunch(cfg: PurininaConfig): void {
  requireDocker()
  ensureImage(cfg)
  ensureContainer(cfg)
  openOpencode(cfg)
}

function cmdBuild(cfg: PurininaConfig): void {
  requireDocker()
  ensureImage(cfg, true)
}

function cmdShell(cfg: PurininaConfig): void {
  requireDocker()
  ensureImage(cfg)
  ensureContainer(cfg)
  info("Opening a shell inside the sandbox…")
  const code = docker.execInteractive({
    container: cfg.container,
    env: { PURININA_HITL: cfg.hitl },
    command: ["/bin/bash"],
  })
  process.exit(code)
}

function cmdStatus(cfg: PurininaConfig): void {
  log(`${BOLD}purinina status${RESET}`)
  log(`  docker installed : ${docker.isDockerInstalled() ? GREEN + "yes" : RED + "no"}${RESET}`)
  log(`  docker running   : ${docker.isDockerRunning() ? GREEN + "yes" : RED + "no"}${RESET}`)
  log(
    `  image (${cfg.image}) : ${docker.imageExists(cfg.image) ? GREEN + "built" : YELLOW + "missing"}${RESET}`,
  )
  log(`  container        : ${cfg.container} -> ${docker.containerState(cfg.container)}`)
  log(`  workspace        : ${cfg.workspace}`)
  log(`  HITL mode        : ${cfg.hitl}`)
  log(`  auth mode        : ${cfg.authMode}`)
}

function cmdStop(cfg: PurininaConfig): void {
  requireDocker()
  if (docker.containerState(cfg.container) === "absent") {
    warn("No sandbox container to stop.")
    return
  }
  docker.stopContainer(cfg.container)
  ok("Sandbox stopped.")
}

function cmdDown(cfg: PurininaConfig): void {
  requireDocker()
  if (docker.containerState(cfg.container) === "absent") {
    warn("No sandbox container to remove.")
    return
  }
  docker.removeContainer(cfg.container)
  ok("Sandbox removed.")
}

function main(): void {
  const cfg = loadConfig()
  const arg = (process.argv[2] ?? "").toLowerCase()

  switch (arg) {
    case "":
    case "start":
    case "launch":
    case "up":
      cmdLaunch(cfg)
      break
    case "build":
      cmdBuild(cfg)
      break
    case "shell":
    case "sh":
      cmdShell(cfg)
      break
    case "status":
    case "ps":
      cmdStatus(cfg)
      break
    case "stop":
      cmdStop(cfg)
      break
    case "down":
    case "rm":
      cmdDown(cfg)
      break
    case "help":
    case "-h":
    case "--help":
      printHelp(cfg)
      break
    case "version":
    case "-v":
    case "--version":
      log(version(cfg))
      break
    default:
      fail(`Unknown command: ${arg}`)
      printHelp(cfg)
      process.exit(1)
  }
}

main()
