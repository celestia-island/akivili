/**
 * @celestia-island/akivili — the TypeScript side of the Celestia Plugin
 * Fabric plugin contract.
 *
 * This module mirrors the Rust `akivili_registry` manifest schema v2
 * (akivili #33): the same field gating, the same closed capability
 * vocabulary, the same form spellings. The Rust side stays the
 * authority; this port exists so webui-side tooling (manifest pickers,
 * catalog validation, plugin authoring aids) validates exactly what the
 * store will accept — no drift.
 */

/** The plugin form — how a host loads and runs the plugin (schema 2). */
export type FormKind =
  | "wasm.component"
  | "process.rpc"
  | "script.ts"
  | "web.vue-module"
  | "web.resource";

/** The canonical form spellings (open in TS, but pinned by tests). */
export const FORM_KINDS: readonly FormKind[] = [
  "wasm.component",
  "process.rpc",
  "script.ts",
  "web.vue-module",
  "web.resource",
];

/** The closed capability vocabulary, v1 (mirrors capabilities.rs). */
export const CAPABILITY_WORDS: readonly string[] = [
  "log",
  "kv.read",
  "kv.write",
  "config.read",
  // parameterized words — base spellings; hosts accept `word:param`
  "http.egress",
  "event.forward",
  "tool.register",
  "mcp.register",
  "state.read",
  "state.write",
  "db.contract",
  "db.query",
  "db.sql",
  "db.direct",
  "mesh.call",
  "mesh.send",
  "mesh.subscribe",
];

const PARAMETERIZED = new Set([
  "http.egress",
  "db.contract",
  "db.query",
  "mesh.call",
  "mesh.send",
  "mesh.subscribe",
]);

/** A parsed `akivili.plugin.toml` manifest (schema 1 or 2). */
export interface PluginManifest {
  schema: number;
  id: string;
  version: string;
  provider: string;
  description?: string;
  form?: FormKind;
  capabilities?: string[];
  /** Wire key: `requires-contract` in TOML. */
  requiresContract?: string[];
  trust?: {
    signature?: string;
    minTrust?: "unsigned" | "signed" | "verified-publisher";
  };
}

/** A validation failure with a human-actionable message. */
export interface ManifestIssue {
  field: string;
  message: string;
}

const ID_V1 = /^[a-z0-9]+$/;
const ID_V2 = /^[a-z0-9][a-z0-9-]*$/;
const SEMVER =
  /^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-((?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*)(?:\.(?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*))*))?(?:\+([0-9a-zA-Z-]+(?:\.[0-9a-zA-Z-]+)*))?$/;
const CONTRACT_REF = /^celestia:[a-z0-9-]+(\.[a-z0-9-]+)*\/[a-z0-9-]+@(0|[1-9]\d*)\.(0|[1-9]\d*)$/;
const HOST = /^[a-z0-9.-]+$/;
const KEBAB = /^[a-z0-9-]+$/;
const TARGET = /^[a-z0-9][a-z0-9-]*$/;

/** Validate a capability word against the closed v1 vocabulary. */
export function validateCapability(word: string): ManifestIssue | null {
  const [base, param] = word.split(":", 2) as [string, string | undefined];
  const known = CAPABILITY_WORDS.includes(base);
  if (param === undefined) {
    // A plain word: must be a parameter-less entry.
    return known && !PARAMETERIZED.has(base)
      ? null
      : { field: "capabilities", message: `'${word}' is outside the closed vocabulary` };
  }
  if (!PARAMETERIZED.has(base) || param.length === 0) {
    return { field: "capabilities", message: `'${word}' is not a valid parameterized word` };
  }
  if (base === "http.egress" && !HOST.test(param)) {
    return { field: "capabilities", message: `'${param}' is not a lowercase hostname` };
  }
  if (base === "db.contract") {
    const parts = param.split(".");
    if (parts.length !== 2 || !parts.every((p) => KEBAB.test(p))) {
      return { field: "capabilities", message: `'${param}' must be domain.op` };
    }
  }
  if (base === "db.query" && !KEBAB.test(param)) {
    return { field: "capabilities", message: `'${param}' must be a kebab domain` };
  }
  if ((base === "mesh.call" || base === "mesh.send") && !TARGET.test(param)) {
    return { field: "capabilities", message: `'${param}' must be a plugin id shape` };
  }
  if (base === "mesh.subscribe") {
    const parts = param.split(".");
    if (parts.some((p) => !KEBAB.test(p))) {
      return { field: "capabilities", message: `'${param}' must be dotted kebab topics` };
    }
  }
  return null;
}

/**
 * Validate a manifest. Returns every issue (never throws) — callers
 * surface them all at once.
 */
export function validateManifest(m: PluginManifest): ManifestIssue[] {
  const issues: ManifestIssue[] = [];
  const push = (field: string, message: string) => issues.push({ field, message });

  if (m.schema !== 1 && m.schema !== 2) {
    push("schema", `unsupported schema version ${m.schema} (expected 1 or 2)`);
    return issues; // gating fields depend on the schema; stop here.
  }

  const idRule = m.schema === 1 ? ID_V1 : ID_V2;
  if (!idRule.test(m.id)) {
    push("id", `'${m.id}' fails the schema ${m.schema} id rule`);
  }
  if (m.schema === 1) {
    if (!/^\d+(\.\d+)*$/.test(m.version)) {
      push("version", `'${m.version}' must be dot-separated numeric segments`);
    }
    for (const v2Field of ["form", "capabilities", "requiresContract", "trust"] as const) {
      if (m[v2Field] !== undefined) {
        const wire = v2Field === "requiresContract" ? "requires-contract" : v2Field;
        push(v2Field, `field '${wire}' requires schema = 2`);
      }
    }
  } else {
    if (!SEMVER.test(m.version)) {
      push("version", `'${m.version}' must be SemVer`);
    }
    if (m.form === undefined) {
      push("form", "schema 2 requires a 'form' field");
    } else if (!FORM_KINDS.includes(m.form)) {
      push("form", `'${m.form}' is not a known form spelling`);
    }
    for (const word of m.capabilities ?? []) {
      const issue = validateCapability(word);
      if (issue) issues.push(issue);
    }
    for (const ref of m.requiresContract ?? []) {
      if (!CONTRACT_REF.test(ref)) {
        push("requires-contract", `'${ref}' must be celestia:<domain>/<world>@<major>.<minor>`);
      }
    }
  }
  return issues;
}

/** Parse a TOML manifest text (a minimal TOML subset reader — the wire
 * shape the store writes) and validate it. */
export function parseManifest(text: string): { manifest: PluginManifest } | { issues: ManifestIssue[] } {
  const issues: ManifestIssue[] = [];
  // Minimal subset: `key = value` lines, `[[resources]]` skipped, quoted
  // strings, arrays of strings (single-line). The store's writer emits
  // this exact shape; a full TOML parser is out of scope for the TS
  // mirror (the Rust side owns full parsing).
  const out: Record<string, unknown> = {};
  let section = "";
  for (const rawLine of text.split("\n")) {
    const line = rawLine.trim();
    if (line.length === 0 || line.startsWith("#")) continue;
    if (line.startsWith("[[")) continue; // resource tables — not mirrored
    if (line.startsWith("[")) {
      section = line.slice(1, -1);
      continue;
    }
    const eq = line.indexOf("=");
    if (eq < 0) continue;
    const key = line.slice(0, eq).trim();
    const valueRaw = line.slice(eq + 1).trim();
    const target = section.length === 0 ? out : ((out[section] ??= {}) as Record<string, unknown>);
    if (valueRaw.startsWith("[")) {
      // single-line string array
      const inner = valueRaw.slice(1, valueRaw.lastIndexOf("]"));
      target[key] = inner
        .split(",")
        .map((s) => s.trim())
        .filter((s) => s.length > 0)
        .map((s) => stripQuotes(s));
    } else if (valueRaw === "true" || valueRaw === "false") {
      target[key] = valueRaw === "true";
    } else {
      target[key] = stripQuotes(valueRaw);
    }
  }
  const root = out as Partial<PluginManifest> & Record<string, unknown>;
  // TOML integers arrive as strings from the minimal reader — coerce.
  if (typeof root.schema === "string" && /^\d+$/.test(root.schema)) {
    root.schema = Number(root.schema);
  }
  if (typeof root.schema !== "number") root.schema = 1;
  if (typeof root.id !== "string") issues.push({ field: "id", message: "missing id" });
  if (typeof root.version !== "string") issues.push({ field: "version", message: "missing version" });
  if (typeof root.provider !== "string") issues.push({ field: "provider", message: "missing provider" });
  if (issues.length > 0) return { issues };
  const manifest: PluginManifest = {
    schema: root.schema,
    id: root.id as string,
    version: root.version as string,
    provider: root.provider as string,
  };
  if (typeof root.description === "string") manifest.description = root.description;
  if (typeof root.form === "string") manifest.form = root.form as FormKind;
  if (Array.isArray(root.capabilities)) manifest.capabilities = root.capabilities as string[];
  if (Array.isArray(root["requires-contract"] ?? root.requiresContract)) {
    manifest.requiresContract = (root["requires-contract"] ?? root.requiresContract) as string[];
  }
  if (root.trust && typeof root.trust === "object") {
    const t = root.trust as Record<string, unknown>;
    manifest.trust = {};
    if (typeof t.signature === "string") manifest.trust.signature = t.signature;
    if (typeof t["min-trust"] === "string") {
      manifest.trust.minTrust = t["min-trust"] as PluginManifest["trust"] extends undefined
        ? never
        : NonNullable<PluginManifest["trust"]>["minTrust"];
    }
  }
  return { manifest };
}
function stripQuotes(s: string): string {
  if (s.length >= 2 && s.startsWith('"') && s.endsWith('"')) return s.slice(1, -1);
  return s;
}
