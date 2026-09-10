import test from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { loadAllowlist, isAllowed, staleEntries, fingerprintOf, ALLOWLIST_FILE } from "../lib/allowlist.mjs";

function repoWith(config) {
  const dir = mkdtempSync(path.join(tmpdir(), "secret-gate-allow-"));
  if (config !== null) writeFileSync(path.join(dir, ALLOWLIST_FILE), JSON.stringify(config));
  return dir;
}

// The value only needs to be shaped like a real stripe-key finding (it is
// never a real credential): sk_live_ followed by 20+ alphanumerics, starting
// with "0123" so the "value pattern" test below can match a prefix of it.
const hit = { label: "stripe-key", line: 14, value: "sk_live_0123" + "a".repeat(20) };

test("an absent file yields an empty allowlist that allows nothing", () => {
  const list = loadAllowlist(repoWith(null));
  assert.equal(isAllowed(list, "docs/setup.md", hit), false);
});

test("a path pattern allows every finding in that file", () => {
  const list = loadAllowlist(repoWith({ version: 1, paths: ["^test/fixtures/"] }));
  assert.equal(isAllowed(list, "test/fixtures/corpus.txt", hit), true);
  assert.equal(isAllowed(list, "src/app.ts", hit), false);
});

test("a value pattern allows a matching value anywhere", () => {
  const list = loadAllowlist(repoWith({ version: 1, regexes: ["^sk_live_0123"] }));
  assert.equal(isAllowed(list, "anywhere.md", hit), true);
});

test("a fingerprint allows exactly one finding", () => {
  const fp = fingerprintOf("docs/setup.md", hit);
  assert.equal(fp, "docs/setup.md:stripe-key:14");
  const list = loadAllowlist(repoWith({ version: 1, fingerprints: [fp] }));
  assert.equal(isAllowed(list, "docs/setup.md", hit), true);
  assert.equal(isAllowed(list, "docs/setup.md", { ...hit, line: 15 }), false);
  assert.equal(isAllowed(list, "docs/other.md", hit), false);
});

test("an entry that matched nothing is reported as stale", () => {
  const list = loadAllowlist(repoWith({ version: 1, paths: ["^used/"], regexes: ["never-matches-this"] }));
  isAllowed(list, "used/file.md", hit);
  assert.deepEqual(staleEntries(list), ["never-matches-this"]);
});

test("invalid JSON throws with the file named and no secret in the message", () => {
  const dir = mkdtempSync(path.join(tmpdir(), "secret-gate-allow-"));
  writeFileSync(path.join(dir, ALLOWLIST_FILE), "{ not json");
  assert.throws(() => loadAllowlist(dir), /\.secretgate\.json is not valid JSON/);
});

test("an invalid regex throws with the pattern named", () => {
  const dir = repoWith({ version: 1, paths: ["["] });
  assert.throws(() => loadAllowlist(dir), /\[/);
});
