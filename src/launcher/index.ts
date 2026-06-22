#!/usr/bin/env node
/**
 * lynx-sec — host launcher.
 *
 * Brings up the hardened sandbox and drops you into opencode inside it. opencode
 * for Lynx is ONLY ever launched through this container; it is never run
 * directly on the host.
 *
 *   lynx-sec               build (if needed) + start sandbox + open opencode (active target)
 *   lynx-sec target [name] show / create+select the active target (engagement)
 *   lynx-sec targets       list saved targets
 *   lynx-sec build         (re)build the sandbox image
 *   lynx-sec shell         open a bash shell inside the sandbox
 *   lynx-sec status        show docker / image / container / target state
 *   lynx-sec reset [name]  wipe a target's session/context (keeps its files)
 *   lynx-sec stop          stop the sandbox container
 *   lynx-sec down          stop and remove the sandbox container
 *   lynx-sec --help
 */
import { existsSync, mkdirSync, readFileSync, rmSync } from "node:fs"
import { resolve } from "node:path"
import { loadConfig, type LynxConfig } from "./config.js"
import * as docker from "./docker.js"
import * as targets from "./targets.js"
import {
  discoverAgentNames,
  listAccessibleModels,
  loadSelection,
  resolveModels,
  runInteractiveSelector,
  selectionPath,
  writeWorkspaceModelConfig,
} from "./models.js"

/** Last-resort default model if none is configured (user runs Ollama Cloud). */
const FALLBACK_MODEL = "ollama-cloud/qwen3-coder:480b"

const RESET = "\x1b[0m"
const BOLD = "\x1b[1m"
const DIM = "\x1b[2m"
const RED = "\x1b[31m"
const GREEN = "\x1b[32m"
const YELLOW = "\x1b[33m"
const CYAN = "\x1b[36m"
const DARKRED = "\x1b[38;5;88m" // deep blood-red (256-color) for the banner

const log = (m: string) => console.log(m)
const info = (m: string) => console.log(`${CYAN}›${RESET} ${m}`)
const ok = (m: string) => console.log(`${GREEN}✓${RESET} ${m}`)
const warn = (m: string) => console.log(`${YELLOW}!${RESET} ${m}`)
const fail = (m: string) => console.error(`${RED}✗ ${m}${RESET}`)

/** Print the Lynx ASCII banner (best-effort; never fatal). */
function printBanner(cfg: LynxConfig): void {
  try {
    const art = readFileSync(resolve(cfg.repoRoot, "assets", "lynx-banner.txt"), "utf8")
    log(BOLD + DARKRED + art + RESET)
  } catch {
    // Banner is cosmetic — ignore if the asset is missing.
    log(`${BOLD}${DARKRED}LYNX${RESET} — multi-agent offensive security, under control`)
  }
}

function version(cfg: LynxConfig): string {
  try {
    const pkg = JSON.parse(readFileSync(resolve(cfg.repoRoot, "package.json"), "utf8"))
    return String(pkg.version ?? "0.0.0")
  } catch {
    return "0.0.0"
  }
}

function printHelp(cfg: LynxConfig): void {
  log(`${BOLD}lynx-sec${RESET} ${DIM}v${version(cfg)}${RESET} — multi-agent pentesting on opencode

${BOLD}Usage${RESET}
  lynx-sec [command]

${BOLD}Commands${RESET}
  ${CYAN}(default)${RESET}      build if needed, start the sandbox, open opencode on the active target
  ${CYAN}target${RESET} [name]  show, or create+select, the active target (engagement)
  ${CYAN}targets${RESET}        list saved targets
  ${CYAN}build${RESET}          (re)build the sandbox image
  ${CYAN}models${RESET}         assign a model to each agent (interactive); 'models list' prints all
  ${CYAN}shell${RESET}          open a bash shell inside the running sandbox
  ${CYAN}status${RESET}         show docker / image / container / target state
  ${CYAN}reset${RESET} [name]   wipe a target's opencode session/context (keeps engagement files)
  ${CYAN}stop${RESET}           stop the sandbox container
  ${CYAN}down${RESET}           stop and remove the sandbox container
  ${CYAN}help${RESET}           show this help

${BOLD}Targets${RESET} ${DIM}(each is a persistent, separate engagement)${RESET}
  Files + opencode session live per target under ${DIM}~/.lynx-sec/targets/<name>/${RESET}.
  Switching targets recreates a clean sandbox; resuming one restores files + context.
    lynx-sec target acme   # create/select 'acme'
    lynx-sec               # launch it
    lynx-sec target old    # switch back to a previous target (restores its session)

${BOLD}Key settings${RESET} ${DIM}(env or .env)${RESET}
  LYNX_HOME       lynx state dir: targets, active pointer, model selection (default ~/.lynx-sec)
  LYNX_WORKSPACE  pin a raw workspace dir (advanced; bypasses targets, ephemeral sessions)
  LYNX_HITL       strict | guided | auto   (default strict)
  LYNX_MODEL      default model, e.g. ollama-cloud/qwen3-coder:480b
                      ${DIM}(per-agent models: 'lynx-sec models')${RESET}
  LYNX_IMAGE      image tag   (default lynx:latest)
  LYNX_CONTAINER  container name (default lynx-sandbox)

${DIM}Offensive-security tool — authorized testing only. See DISCLAIMER.${RESET}`)
}

/** Verify Docker is present and the daemon is up; exit otherwise. */
function requireDocker(): void {
  if (!docker.isDockerInstalled()) {
    fail("Docker is required but was not found on PATH.")
    log(`${DIM}Install Docker, then re-run. Lynx runs entirely inside a Docker sandbox.${RESET}`)
    process.exit(1)
  }
  if (!docker.isDockerRunning()) {
    fail("Docker is installed but the daemon is not running (or you lack permission).")
    log(`${DIM}Start Docker (e.g. 'sudo systemctl start docker') and try again.${RESET}`)
    process.exit(1)
  }
}

function ensureImage(cfg: LynxConfig, force = false): void {
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
function authWiring(cfg: LynxConfig): {
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
          `Run 'opencode auth login' on the host, or set LYNX_AUTH_MODE=env.`,
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
      warn("LYNX_AUTH_MODE=env but no provider API keys found in the environment.")
    }
  }
  return { mounts, env }
}

function ensureContainer(cfg: LynxConfig): void {
  const desired = resolve(cfg.workspace)
  const state = docker.containerState(cfg.container)
  if (state !== "absent") {
    const bound = docker.containerWorkspace(cfg.container)
    if (bound && resolve(bound) !== desired) {
      // The existing sandbox belongs to a different target — recreate it so each
      // target gets a clean container bound to its own files + opencode session.
      info(`Switching target — recreating sandbox (was bound to ${bound}).`)
      docker.removeContainer(cfg.container)
    } else if (state === "running") {
      ok(`Sandbox ${cfg.container} is running.`)
      return
    } else {
      info(`Starting existing sandbox ${cfg.container}…`)
      if (docker.startContainer(cfg.container) !== 0) {
        fail("Failed to start the existing container. Try 'lynx-sec down' then retry.")
        process.exit(1)
      }
      return
    }
  }
  // absent or just-removed -> create
  mkdirSync(cfg.workspace, { recursive: true })
  if (cfg.dataDir) mkdirSync(cfg.dataDir, { recursive: true })
  info(`Creating sandbox ${cfg.container} (host network, NET_ADMIN/NET_RAW)…`)
  const { mounts, env } = authWiring(cfg)
  if (
    docker.runContainer({
      image: cfg.image,
      container: cfg.container,
      workspace: cfg.workspace,
      dataDir: cfg.dataDir,
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

/**
 * Resolve per-agent models and write them into the workspace opencode.json.
 * We do NOT pass `--model` to opencode (it would override every agent); the
 * merged workspace config drives both the default and per-agent models.
 */
function applyModels(cfg: LynxConfig): { default: string; agents: Record<string, string> } {
  mkdirSync(cfg.workspace, { recursive: true })
  const agents = discoverAgentNames(cfg.repoRoot)
  const sel = loadSelection(targets.lynxHome(), cfg.model ?? FALLBACK_MODEL)
  const agentModels = resolveModels(agents, sel)
  writeWorkspaceModelConfig(cfg.workspace, sel.default, agentModels)
  return { default: sel.default, agents: agentModels }
}

function openOpencode(
  cfg: LynxConfig,
  models: { default: string; agents: Record<string, string> },
): never {
  const orchestrator = models.agents["orchestrator"] ?? models.default
  info(`Opening opencode (HITL=${cfg.hitl}, orchestrator=${orchestrator})…`)
  log(
    DIM +
      "models per agent are set in <workspace>/opencode.json — edit with 'lynx-sec models'" +
      RESET,
  )
  log(DIM + "─".repeat(60) + RESET)
  // Start on the orchestrator. No --model: per-agent models come from config.
  const code = docker.execInteractive({
    container: cfg.container,
    env: { LYNX_HITL: cfg.hitl },
    command: ["opencode", "--agent", "orchestrator"],
  })
  process.exit(code)
}

function cmdLaunch(cfg: LynxConfig): void {
  printBanner(cfg)
  if (cfg.target) {
    targets.ensureTarget(cfg.target)
    info(`Target: ${BOLD}${cfg.target}${RESET} ${DIM}(${targets.targetDir(cfg.target)})${RESET}`)
  }
  requireDocker()
  ensureImage(cfg)
  const models = applyModels(cfg)
  ensureContainer(cfg)
  openOpencode(cfg, models)
}

function cmdBuild(cfg: LynxConfig): void {
  requireDocker()
  ensureImage(cfg, true)
}

function cmdShell(cfg: LynxConfig): void {
  requireDocker()
  ensureImage(cfg)
  applyModels(cfg)
  ensureContainer(cfg)
  info("Opening a shell inside the sandbox…")
  const code = docker.execInteractive({
    container: cfg.container,
    env: { LYNX_HITL: cfg.hitl },
    command: ["/bin/bash"],
  })
  process.exit(code)
}

function cmdStatus(cfg: LynxConfig): void {
  log(`${BOLD}lynx-sec status${RESET}`)
  log(`  docker installed : ${docker.isDockerInstalled() ? GREEN + "yes" : RED + "no"}${RESET}`)
  log(`  docker running   : ${docker.isDockerRunning() ? GREEN + "yes" : RED + "no"}${RESET}`)
  log(
    `  image (${cfg.image}) : ${docker.imageExists(cfg.image) ? GREEN + "built" : YELLOW + "missing"}${RESET}`,
  )
  log(`  container        : ${cfg.container} -> ${docker.containerState(cfg.container)}`)
  log(`  target           : ${cfg.target ?? `${DIM}(LYNX_WORKSPACE override)${RESET}`}`)
  log(`  workspace        : ${cfg.workspace}`)
  if (cfg.dataDir) log(`  session data     : ${cfg.dataDir}`)
  log(`  HITL mode        : ${cfg.hitl}`)
  log(`  auth mode        : ${cfg.authMode}`)

  const agents = discoverAgentNames(cfg.repoRoot)
  const sel = loadSelection(targets.lynxHome(), cfg.model ?? FALLBACK_MODEL)
  const models = resolveModels(agents, sel)
  log(`  models           : ${DIM}(default ${sel.default}; edit with 'lynx-sec models')${RESET}`)
  for (const a of agents) {
    const overridden = sel.agents[a] ? "" : `${DIM} (default)${RESET}`
    log(`    ${a.padEnd(14)} ${models[a]}${overridden}`)
  }
}

function cmdModels(cfg: LynxConfig): void {
  const agents = discoverAgentNames(cfg.repoRoot)
  if (agents.length === 0) {
    fail("No agents found under runtime/agent/. Run from the lynx-sec repo.")
    process.exit(1)
  }
  // `lynx-sec models list` -> just print accessible model ids.
  if ((process.argv[3] ?? "").toLowerCase() === "list") {
    const models = listAccessibleModels()
    if (models.length === 0) {
      warn("Could not list models. Is opencode installed and authenticated on the host?")
      return
    }
    for (const m of models) log(m)
    return
  }
  mkdirSync(targets.lynxHome(), { recursive: true })
  void runInteractiveSelector(targets.lynxHome(), agents, cfg.model ?? FALLBACK_MODEL).then(
    (sel) => {
      ok(`Saved model selection to ${selectionPath(targets.lynxHome())}`)
      log(`${DIM}Applied on next launch (written into <workspace>/opencode.json).${RESET}`)
      const resolved = resolveModels(agents, sel)
      for (const a of agents) log(`  ${a.padEnd(14)} ${resolved[a]}`)
    },
  )
}

/** Show, or create+select, the active target (engagement). */
function cmdTarget(): void {
  const name = process.argv[3]
  if (!name) {
    const active = targets.getActiveTarget() ?? targets.DEFAULT_TARGET
    log(`${BOLD}active target${RESET}: ${active}`)
    log(`  dir       : ${targets.targetDir(active)}`)
    log(`  workspace : ${targets.targetWorkspace(active)}`)
    log(`${DIM}select/create: lynx-sec target <name>  ·  list: lynx-sec targets${RESET}`)
    return
  }
  if (!targets.isValidTargetName(name)) {
    fail(`Invalid target name '${name}'. Use letters, digits, . _ - (max 64 chars).`)
    process.exit(1)
  }
  const fresh = !targets.targetExists(name)
  targets.ensureTarget(name)
  targets.setActiveTarget(name)
  ok(`${fresh ? "Created and selected" : "Selected"} target '${name}'.`)
  log(`  ${targets.targetDir(name)}`)
  log(`${DIM}run 'lynx-sec' to launch it.${RESET}`)
}

/** List saved targets, marking the active one. */
function cmdTargets(): void {
  const active = targets.getActiveTarget() ?? targets.DEFAULT_TARGET
  const all = targets.listTargets()
  if (all.length === 0) {
    warn("No targets yet. Create one with: lynx-sec target <name>")
    return
  }
  log(`${BOLD}targets${RESET} ${DIM}(${targets.targetsRoot()})${RESET}`)
  for (const t of all) {
    const mark = t === active ? `${GREEN}●${RESET}` : " "
    const tag = t === active ? `${DIM} (active)${RESET}` : ""
    log(`  ${mark} ${t}${tag}`)
  }
}

/** Wipe a target's opencode session/context, keeping its engagement files. */
function cmdReset(cfg: LynxConfig): void {
  const name = process.argv[3] ?? targets.getActiveTarget() ?? targets.DEFAULT_TARGET
  if (!targets.targetExists(name)) {
    warn(`Target '${name}' does not exist — nothing to reset.`)
    return
  }
  // If the sandbox is currently bound to this target, remove it so the wiped
  // session is recreated clean on next launch.
  if (
    docker.isDockerInstalled() &&
    docker.containerState(cfg.container) !== "absent" &&
    resolve(docker.containerWorkspace(cfg.container) || "/") ===
      resolve(targets.targetWorkspace(name))
  ) {
    docker.removeContainer(cfg.container)
    info("Removed the sandbox bound to this target.")
  }
  rmSync(targets.targetDataDir(name), { recursive: true, force: true })
  mkdirSync(targets.targetDataDir(name), { recursive: true })
  ok(`Reset session/context for target '${name}'. Engagement files kept.`)
  log(`${DIM}Files: ${targets.targetWorkspace(name)}${RESET}`)
}

function cmdStop(cfg: LynxConfig): void {
  requireDocker()
  if (docker.containerState(cfg.container) === "absent") {
    warn("No sandbox container to stop.")
    return
  }
  docker.stopContainer(cfg.container)
  ok("Sandbox stopped.")
}

function cmdDown(cfg: LynxConfig): void {
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
    case "target":
    case "use":
      cmdTarget()
      break
    case "targets":
    case "ls":
      cmdTargets()
      break
    case "reset":
      cmdReset(cfg)
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
    case "models":
    case "model":
      cmdModels(cfg)
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
