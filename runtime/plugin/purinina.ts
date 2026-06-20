/**
 * Purinina — opencode plugin
 * ==========================
 *
 * This single plugin file is the heart of Purinina's safety + tooling layer. It
 * is loaded by opencode as GLOBAL config inside the sandbox container
 * (~/.config/opencode/plugin/purinina.ts) and provides three things:
 *
 *   1. A consistent Human-In-The-Loop (HITL) policy, mirroring CAI's philosophy
 *      that a human stays in control of dangerous actions. Implemented on top of
 *      opencode's native permission machinery (`permission.ask`).
 *
 *   2. A hard safety floor + sandbox guard (`tool.execute.before`): destructive
 *      and host-escape commands are blocked in *every* mode, and offensive
 *      tooling refuses to run outside the Purinina sandbox.
 *
 *   3. Engagement helper tools (`tool`): structured note-taking and scope
 *      reading, so agents keep findings organized in the workspace.
 *
 * NOTE: opencode loads *every* file in the plugin directory as a plugin, so this
 * stays a single self-contained file. Helper functions are module-private (not
 * exported); only `PurininaPlugin` is exported.
 */

import { tool, type Plugin } from "@opencode-ai/plugin"
import { appendFile, mkdir, readFile } from "node:fs/promises"
import { join } from "node:path"

// ---------------------------------------------------------------------------
// HITL modes
// ---------------------------------------------------------------------------

/** strict = ask before anything intrusive · guided = ask before high-impact · auto = no prompts (lab only). */
type HitlMode = "strict" | "guided" | "auto"

function hitlMode(): HitlMode {
  const v = (process.env.PURININA_HITL ?? "strict").toLowerCase()
  return v === "guided" || v === "auto" ? v : "strict"
}

function inSandbox(): boolean {
  return process.env.PURININA_SANDBOX === "1"
}

// ---------------------------------------------------------------------------
// Command risk classification
// ---------------------------------------------------------------------------
//
// This is the Purinina analogue of CAI's per-category tools. Instead of wrapping
// every binary as its own tool, we let agents use opencode's robust `bash` tool
// and classify each command into a risk tier. The tier drives the HITL decision.

type RiskTier =
  | "destructive" // irreversible damage — always denied
  | "escape" // attempts to break out of the sandbox / reach the host — always denied
  | "exploit" // active exploitation / credential attacks / shells — high impact
  | "recon" // active scanning / enumeration against targets — intrusive
  | "script" // arbitrary interpreters (python/sh -c ...) — intent unknown
  | "readonly" // local, non-intrusive inspection — safe
  | "unknown" // unrecognized — treated cautiously

/** Patterns that must NEVER run, regardless of HITL mode. Irreversible / catastrophic. */
const DESTRUCTIVE_PATTERNS: RegExp[] = [
  /\brm\s+(-[a-z]*\s+)*-[a-z]*r[a-z]*f|\brm\s+(-[a-z]*\s+)*-[a-z]*f[a-z]*r/i, // rm -rf style...
  /\brm\s+(-[a-zA-Z]+\s+)*(\/|\/\*|~|\$HOME)(\s|$)/i, // ...targeting / ~ $HOME
  /:\s*\(\s*\)\s*\{\s*:\s*\|\s*:\s*&\s*\}\s*;\s*:/, // fork bomb
  /\bmkfs(\.\w+)?\b/i,
  /\bwipefs\b/i,
  /\bdd\b[^\n]*\bof=\/dev\/(sd|nvme|vd|hd|xvd|disk)/i,
  /[>]\s*\/dev\/(sd|nvme|vd|hd|xvd)/i,
  /\b(shutdown|reboot|halt|poweroff)\b/i,
  /\binit\s+[06]\b/i,
  /\bchmod\s+-R\s+0*777\s+\//,
  /\bchown\s+-R\s+[^\s]+\s+\/(\s|$)/,
]

/** Patterns that try to escape the container or reach the host. Always denied. */
const ESCAPE_PATTERNS: RegExp[] = [
  /\bnsenter\b/i,
  /\b\/var\/run\/docker\.sock\b/i,
  /\bdocker\s+(run|exec|-H|--host)\b/i,
  /\bchroot\b/i,
  /\/proc\/1\/root\b/i,
  /\/proc\/sysrq-trigger\b/i,
  /\/dev\/(mem|kmem|kcore)\b/i,
  /\bmount\s+[^\n]*\/host\b/i,
]

/** Active exploitation / credential attacks / shells. */
const EXPLOIT_BINARIES = [
  "sqlmap",
  "msfconsole",
  "msfvenom",
  "metasploit",
  "hydra",
  "medusa",
  "ncrack",
  "crackmapexec",
  "cme",
  "netexec",
  "nxc",
  "evil-winrm",
  "responder",
  "john",
  "hashcat",
  "patator",
]
/** Reverse/bind-shell tells that are exploit-grade regardless of binary. */
const EXPLOIT_PATTERNS: RegExp[] = [
  /\/dev\/tcp\//i, // bash reverse shell
  /\bnc\b[^\n]*\s-[a-z]*e\b/i, // nc -e
  /\bncat\b[^\n]*--exec\b/i,
  /\bbash\s+-i\b/i,
  /\bpython3?\b[^\n]*socket\b[^\n]*(connect|bind)/i,
]

/** Active reconnaissance / enumeration — intrusive but standard pentest recon. */
const RECON_BINARIES = [
  "nmap",
  "masscan",
  "rustscan",
  "gobuster",
  "ffuf",
  "feroxbuster",
  "dirb",
  "dirbuster",
  "wfuzz",
  "nikto",
  "whatweb",
  "wpscan",
  "nuclei",
  "enum4linux",
  "enum4linux-ng",
  "dnsenum",
  "dnsrecon",
  "fierce",
  "sublist3r",
  "amass",
  "testssl.sh",
  "onesixtyone",
  "snmpwalk",
]

/** Local, non-intrusive inspection. Safe to auto-allow. */
const READONLY_BINARIES = [
  "ls",
  "cat",
  "head",
  "tail",
  "less",
  "more",
  "pwd",
  "cd",
  "echo",
  "printf",
  "whoami",
  "id",
  "uname",
  "hostname",
  "date",
  "env",
  "which",
  "type",
  "file",
  "stat",
  "wc",
  "sort",
  "uniq",
  "cut",
  "tr",
  "find",
  "grep",
  "egrep",
  "rg",
  "awk",
  "jq",
  "strings",
  "xxd",
  "md5sum",
  "sha1sum",
  "sha256sum",
  "dig",
  "nslookup",
  "host",
  "whois",
]

/** Interpreters whose intent we cannot infer from the command alone. */
const SCRIPT_BINARIES = ["python", "python3", "perl", "ruby", "php", "node", "bash", "sh", "zsh", "lua"]

/** Split a command line into segments across shell operators, returning the leading binary of each. */
function leadingBinaries(command: string): string[] {
  const segments = command.split(/\||;|&&|\|\||\n|`|\$\(/)
  const bins: string[] = []
  for (const seg of segments) {
    const trimmed = seg.trim().replace(/^[({]+/, "").trim()
    if (!trimmed) continue
    // strip leading env assignments like FOO=bar cmd
    const withoutEnv = trimmed.replace(/^(\w+=\S+\s+)+/, "")
    const token = withoutEnv.split(/\s+/)[0] ?? ""
    const bin = token.split("/").pop() ?? token // basename of /usr/bin/nmap -> nmap
    if (bin) bins.push(bin.toLowerCase())
  }
  return bins
}

function classifyCommand(command: string): RiskTier {
  const cmd = command.trim()
  if (!cmd) return "readonly"

  // Hard-deny tiers first (whole-string regex).
  if (ESCAPE_PATTERNS.some((re) => re.test(cmd))) return "escape"
  if (DESTRUCTIVE_PATTERNS.some((re) => re.test(cmd))) return "destructive"
  if (EXPLOIT_PATTERNS.some((re) => re.test(cmd))) return "exploit"

  const bins = leadingBinaries(cmd)
  if (bins.length === 0) return "unknown"

  const has = (list: string[]) => bins.some((b) => list.includes(b))

  if (has(EXPLOIT_BINARIES)) return "exploit"
  if (has(RECON_BINARIES)) return "recon"

  // If every segment is a known readonly binary, it's safe. A single unknown
  // segment downgrades the whole pipeline to a more cautious tier.
  const allReadonly = bins.every((b) => READONLY_BINARIES.includes(b))
  if (allReadonly) return "readonly"

  if (has(SCRIPT_BINARIES)) return "script"
  return "unknown"
}

// ---------------------------------------------------------------------------
// HITL decision matrix
// ---------------------------------------------------------------------------

type Decision = "allow" | "ask" | "deny"

function decideForBash(tier: RiskTier, mode: HitlMode): { decision: Decision; reason: string } {
  if (tier === "destructive") return { decision: "deny", reason: "destructive / irreversible command" }
  if (tier === "escape") return { decision: "deny", reason: "sandbox-escape / host-access attempt" }

  if (mode === "auto") return { decision: "allow", reason: "auto mode (lab use)" }

  switch (tier) {
    case "readonly":
      return { decision: "allow", reason: "read-only inspection" }
    case "recon":
      return mode === "strict"
        ? { decision: "ask", reason: "active reconnaissance against a target" }
        : { decision: "allow", reason: "recon allowed in guided mode" }
    case "exploit":
      return { decision: "ask", reason: "active exploitation / high impact" }
    case "script":
      return { decision: "ask", reason: "arbitrary interpreter — intent unknown" }
    default:
      return { decision: "ask", reason: "unrecognized command — review before running" }
  }
}

function decideForEdit(mode: HitlMode): { decision: Decision; reason: string } {
  // Writes outside the workspace are already blocked by opencode's
  // `external_directory: deny`. Inside the workspace, edits are low risk.
  if (mode === "auto" || mode === "guided")
    return { decision: "allow", reason: "edit within engagement workspace" }
  return { decision: "ask", reason: "file write (strict mode)" }
}

/** Best-effort extraction of the shell command from a Permission object. */
function commandFromPermission(p: { title?: string; pattern?: string | string[]; metadata?: Record<string, unknown> }): string {
  const meta = p.metadata ?? {}
  const fromMeta = typeof meta["command"] === "string" ? (meta["command"] as string) : ""
  if (fromMeta) return fromMeta
  if (typeof p.title === "string" && p.title) return p.title
  if (typeof p.pattern === "string") return p.pattern
  if (Array.isArray(p.pattern)) return p.pattern.join(" ")
  return ""
}

function log(msg: string): void {
  // opencode captures plugin stderr into its logs.
  console.error(`[purinina] ${msg}`)
}

// ---------------------------------------------------------------------------
// Plugin
// ---------------------------------------------------------------------------

export const PurininaPlugin: Plugin = async ({ directory }) => {
  if (!inSandbox()) {
    log(
      "WARNING: PURININA_SANDBOX marker not found. Offensive tooling is disabled outside the sandbox.",
    )
  } else {
    log(`active · HITL=${hitlMode()} · workspace=${directory}`)
  }

  return {
    /**
     * Central HITL gate. opencode routes intrusive tools to "ask" (see
     * opencode.json); here we refine that into allow / ask / deny based on the
     * action's risk tier and the configured mode.
     */
    "permission.ask": async (input, output) => {
      const mode = hitlMode()

      if (input.type === "bash") {
        const command = commandFromPermission(input)
        const tier = classifyCommand(command)
        const { decision, reason } = decideForBash(tier, mode)
        output.status = decision
        log(`bash [${tier}] -> ${decision} (${reason}) :: ${command.slice(0, 160)}`)
        return
      }

      if (input.type === "edit" || input.type === "write" || input.type === "patch") {
        const { decision, reason } = decideForEdit(mode)
        output.status = decision
        log(`${input.type} -> ${decision} (${reason})`)
        return
      }

      // Everything else: in auto mode allow; otherwise leave opencode's prompt.
      if (mode === "auto") output.status = "allow"
    },

    /**
     * Hard safety floor — runs immediately before any tool executes and CANNOT
     * be bypassed by HITL mode. Throwing here aborts the tool call.
     */
    "tool.execute.before": async (input, output) => {
      if (input.tool !== "bash") return
      const command: string = String((output.args as { command?: unknown })?.command ?? "")

      // Offensive shell only runs inside the sandbox.
      if (!inSandbox()) {
        throw new Error(
          "[purinina] bash is disabled outside the Purinina sandbox. Launch via the `purinina` command.",
        )
      }

      const tier = classifyCommand(command)
      if (tier === "destructive" || tier === "escape") {
        log(`BLOCKED [${tier}] :: ${command.slice(0, 200)}`)
        throw new Error(
          `[purinina] blocked ${tier} command by safety policy. This action is never permitted.`,
        )
      }
    },

    /**
     * Engagement helper tools — keep findings structured in the workspace.
     */
    tool: {
      purinina_note: tool({
        description:
          "Append a timestamped entry to the engagement log (notes/engagement-log.md). Use this to record findings, decisions, and next steps as you work.",
        args: {
          entry: tool.schema.string().describe("The note to append. Be concise and factual."),
          phase: tool.schema
            .enum(["recon", "web", "exploitation", "loot", "report", "general"])
            .default("general")
            .describe("Engagement phase this note belongs to."),
        },
        async execute(args, ctx) {
          const dir = join(ctx.directory, "notes")
          await mkdir(dir, { recursive: true })
          const file = join(dir, "engagement-log.md")
          const stamp = new Date().toISOString()
          const line = `\n## ${stamp} · [${args.phase}]\n\n${args.entry}\n`
          await appendFile(file, line, "utf8")
          return `Logged to notes/engagement-log.md under [${args.phase}].`
        },
      }),

      purinina_scope: tool({
        description:
          "Read the engagement scope/authorization (scope/SCOPE.md). ALWAYS call this before any intrusive action to confirm the target is in scope and authorized.",
        args: {},
        async execute(_args, ctx) {
          const file = join(ctx.directory, "scope", "SCOPE.md")
          try {
            const content = await readFile(file, "utf8")
            return content.trim().length > 0
              ? content
              : "scope/SCOPE.md is empty. Ask the operator to define the authorized scope before proceeding."
          } catch {
            return "No scope/SCOPE.md found. Ask the operator to define the authorized scope before proceeding."
          }
        },
      }),
    },
  }
}
