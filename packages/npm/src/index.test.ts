import { describe, expect, it } from "vitest";
import {
  FORM_KINDS,
  parseManifest,
  validateCapability,
  validateManifest,
  type PluginManifest,
} from "./index";

const v2 = (over: Partial<PluginManifest> = {}): PluginManifest => ({
  schema: 2,
  id: "celestia-kanban",
  version: "1.2.0",
  provider: "official",
  form: "web.vue-module",
  ...over,
});

describe("validateManifest", () => {
  it("accepts a full schema 2 manifest", () => {
    const m = v2({
      capabilities: ["kv.read", "http.egress:api.github.com", "mesh.call:celestia-reports"],
      requiresContract: ["celestia:host/guest@0.1"],
    });
    expect(validateManifest(m)).toEqual([]);
  });

  it("gates v2 fields under schema 1", () => {
    const issues = validateManifest(
      v2({ schema: 1, capabilities: ["kv.read"] } as Partial<PluginManifest>),
    );
    expect(issues.some((i) => i.field === "capabilities")).toBe(true);
  });

  it("requires semver under schema 2", () => {
    expect(validateManifest(v2({ version: "1.2" })).some((i) => i.field === "version")).toBe(true);
    expect(validateManifest(v2({ version: "1.2.3-rc.1" }))).toEqual([]);
  });

  it("requires a form under schema 2 and rejects unknown spellings", () => {
    const noForm = { ...v2() } as Partial<PluginManifest>;
    delete noForm.form;
    expect(validateManifest(noForm as PluginManifest).some((i) => i.field === "form")).toBe(true);
    expect(
      validateManifest(v2({ form: "web.esmodule" as PluginManifest["form"] })).some(
        (i) => i.field === "form",
      ),
    ).toBe(true);
  });

  it("relaxes the id rule for schema 2 only", () => {
    expect(validateManifest(v2({ id: "celestia-kanban" }))).toEqual([]);
    expect(validateManifest(v2({ schema: 1, id: "hyphen-not-allowed" } as Partial<PluginManifest>)).length).toBeGreaterThan(0);
  });
});

describe("validateCapability", () => {
  it("accepts plain and parameterized vocabulary words", () => {
    for (const word of ["log", "kv.read", "db.sql"]) {
      expect(validateCapability(word)).toBeNull();
    }
    for (const word of [
      "http.egress:api.github.com",
      "db.contract:usage.read",
      "mesh.subscribe:telemetry.usage",
    ]) {
      expect(validateCapability(word)).toBeNull();
    }
  });

  it("rejects unknown bases and malformed params", () => {
    expect(validateCapability("fs.read")).not.toBeNull();
    expect(validateCapability("kv.read:")).not.toBeNull();
    expect(validateCapability("mesh.call:-leading")).not.toBeNull();
  });
});

describe("parseManifest", () => {
  it("parses and validates a store-shaped TOML text", () => {
    const text = [
      "schema = 2",
      'id = "celestia-kanban"',
      'version = "1.2.0"',
      'provider = "official"',
      'form = "web.vue-module"',
      "capabilities = [\"kv.read\", \"mesh.call:celestia-reports\"]",
      'requires-contract = ["celestia:host/guest@0.1"]',
    ].join("\n");
    const result = parseManifest(text);
    expect("manifest" in result).toBe(true);
    if ("manifest" in result) {
      expect(validateManifest(result.manifest)).toEqual([]);
      expect(result.manifest.capabilities).toHaveLength(2);
    }
  });

  it("pin every form spelling against the Rust enum", () => {
    // The five Rust FormKind spellings — any drift here is a test red.
    expect(FORM_KINDS).toEqual([
      "wasm.component",
      "process.rpc",
      "script.ts",
      "web.vue-module",
      "web.resource",
    ]);
  });
});
