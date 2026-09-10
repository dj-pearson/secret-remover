import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import path from "node:path";

const PLUGIN = path.dirname(path.dirname(fileURLToPath(import.meta.url)));
const ROOT = path.dirname(path.dirname(PLUGIN));

const read = (p) => JSON.parse(readFileSync(p, "utf8"));

test("the three version strings agree", () => {
  const pkg = read(path.join(PLUGIN, "package.json"));
  const manifest = read(path.join(PLUGIN, ".claude-plugin", "plugin.json"));
  const market = read(path.join(ROOT, ".claude-plugin", "marketplace.json"));

  const entry = market.plugins.find((p) => p.name === "secret-redactor");
  assert.ok(entry, "secret-redactor is missing from marketplace.json");

  assert.equal(manifest.version, pkg.version);
  assert.equal(entry.version, pkg.version);
});

test("the marketplace is named pearson-media and points at the plugin", () => {
  const market = read(path.join(ROOT, ".claude-plugin", "marketplace.json"));
  assert.equal(market.name, "pearson-media");
  const entry = market.plugins.find((p) => p.name === "secret-redactor");
  assert.equal(entry.source, "./plugins/secret-redactor");
});

test("the plugin declares zero dependencies", () => {
  const pkg = read(path.join(PLUGIN, "package.json"));
  assert.equal(pkg.dependencies, undefined);
  assert.equal(pkg.devDependencies, undefined);
});
