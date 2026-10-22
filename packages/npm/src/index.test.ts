import { describe, expect, it } from "vitest";
import {
  FORM_KINDS,
  SURFACES,
  parseManifest,
  validateCapability,
  validateManifest,
  type PluginManifest,
} from "./index";

const base = (over: Partial<PluginManifest> = {}): PluginManifest => ({
  schema: 1,
  id: "celestia-kanban",
  version: "1.2.0",
  provider: "official",
  form: "web.vue-module",
  ...over,
});

describe("validateManifest", () => {
  it("accepts a full fabric manifest", () => {
    const m = base({
      capabilities: ["kv.read", "http.egress:api.github.com", "mesh.call:celestia-reports"],
      requiresContract: ["celestia:host/guest@0.1"],
    });
    expect(validateManifest(m)).toEqual([]);
  });

  it("rejects schema values other than 1", () => {
    expect(validateManifest(base({ schema: 2 } as Partial<PluginManifest>)).some((i) => i.field === "schema")).toBe(true);
    expect(validateManifest(base({ schema: 3 } as Partial<PluginManifest>)).some((i) => i.field === "schema")).toBe(true);
  });

  it("requires semver", () => {
    expect(validateManifest(base({ version: "1.2" })).some((i) => i.field === "version")).toBe(true);
    expect(validateManifest(base({ version: "1" })).some((i) => i.field === "version")).toBe(true);
    expect(validateManifest(base({ version: "1.2.3-rc.1" }))).toEqual([]);
    expect(validateManifest(base({ version: "1.2.3+build.5" }))).toEqual([]);
  });

  it("requires a form and rejects unknown spellings", () => {
    const noForm = { ...base() } as Partial<PluginManifest>;
    delete noForm.form;
    expect(validateManifest(noForm as PluginManifest).some((i) => i.field === "form")).toBe(true);
    expect(
      validateManifest(base({ form: "web.esmodule" as PluginManifest["form"] })).some(
        (i) => i.field === "form",
      ),
    ).toBe(true);
  });

  it("accepts hyphenated ids (the unified rule)", () => {
    expect(validateManifest(base({ id: "celestia-kanban" }))).toEqual([]);
    expect(validateManifest(base({ id: "acme-plugin" }))).toEqual([]);
    expect(validateManifest(base({ id: "-leading" })).some((i) => i.field === "id")).toBe(true);
    expect(validateManifest(base({ id: "UpperCase" })).some((i) => i.field === "id")).toBe(true);
  });

  it("enforces the class ⇔ system.host binding", () => {
    expect(validateManifest(base({ form: "system.host" })).some((i) => i.field === "class")).toBe(true);
    expect(validateManifest(base({ class: "system" })).some((i) => i.field === "class")).toBe(true);
    expect(validateManifest(base({ form: "system.host", class: "system" }))).toEqual([]);
    expect(validateManifest(base({ form: "system.host", class: "panel" })).some((i) => i.field === "class")).toBe(true);
  });
});

describe("validateCapability", () => {
  it("accepts plain and parameterized vocabulary words", () => {
    for (const word of ["log", "kv.read", "db.sql", "host.tool"]) {
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

  it("keeps host.tool a plain word (no capability parameter)", () => {
    expect(validateCapability("host.tool:plugin_resource_push")).not.toBeNull();
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
      "schema = 1",
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
    // The six Rust FormKind spellings — any drift here is a test red.
    expect(FORM_KINDS).toEqual([
      "wasm.component",
      "process.rpc",
      "script.ts",
      "web.vue-module",
      "web.resource",
      "system.host",
    ]);
  });
});

describe("attachments", () => {
  it("accepts a multi-surface manifest and pins the surface vocabulary", () => {
    expect(SURFACES).toEqual(["engine", "webui", "edge"]);
    const m = base({
      capabilities: ["kv.read", "mesh.call:evernight"],
      attachments: [
        {
          surface: "engine",
          form: "process.rpc",
          kind: "engine.agent",
          name: "industrial_iot",
          capabilities: ["mesh.call:evernight"],
          payload: { Inline: { folder: "industrial_iot" } },
        },
        { surface: "edge", form: "wasm.component", kind: "edge.deploy" },
      ],
    });
    expect(validateManifest(m)).toEqual([]);
  });

  it("rejects duplicate surfaces and the system.host attachment form", () => {
    const dup = base({
      attachments: [
        { surface: "engine", form: "process.rpc" },
        { surface: "engine", form: "script.ts" },
      ],
    });
    expect(
      validateManifest(dup).some((i) => i.field === "attachments[1].surface"),
    ).toBe(true);

    const hostForm = base({
      attachments: [{ surface: "engine", form: "system.host" }],
    });
    expect(
      validateManifest(hostForm).some((i) => i.field === "attachments[0].form"),
    ).toBe(true);
  });

  it("rejects attachments on system.host manifests", () => {
    const m = base({
      form: "system.host",
      class: "system",
      attachments: [{ surface: "engine", form: "process.rpc" }],
    });
    expect(validateManifest(m).some((i) => i.field === "attachments")).toBe(true);
  });

  it("requires attachment capabilities to narrow the plugin-level grant", () => {
    const widening = base({
      capabilities: ["kv.read"],
      attachments: [
        { surface: "engine", form: "process.rpc", capabilities: ["mesh.call:evernight"] },
      ],
    });
    expect(
      validateManifest(widening).some(
        (i) =>
          i.field === "attachments[0].capabilities" &&
          i.message.includes("not granted at plugin level"),
      ),
    ).toBe(true);

    const narrowing = base({
      capabilities: ["kv.read"],
      attachments: [
        { surface: "engine", form: "process.rpc", capabilities: ["kv.read"] },
      ],
    });
    expect(validateManifest(narrowing)).toEqual([]);
  });

  it("validates attachment kind syntax and contract refs", () => {
    const badKind = base({
      attachments: [{ surface: "engine", form: "process.rpc", kind: "engine" }],
    });
    expect(
      validateManifest(badKind).some(
        (i) => i.field === "attachments[0].kind" && i.message.includes("dotted kind"),
      ),
    ).toBe(true);

    const badRef = base({
      attachments: [
        {
          surface: "engine",
          form: "process.rpc",
          requiresContract: ["celestia:host/guest"],
        },
      ],
    });
    expect(
      validateManifest(badRef).some((i) => i.field === "attachments[0].requires-contract"),
    ).toBe(true);

    const good = base({
      attachments: [
        {
          surface: "engine",
          form: "process.rpc",
          kind: "engine.agent",
          requiresContract: ["celestia:host/guest@0.1"],
        },
      ],
    });
    expect(validateManifest(good)).toEqual([]);
  });
});
