import test from "node:test";
import assert from "node:assert/strict";
import { writeFileSync, mkdirSync } from "node:fs";
import path from "node:path";
import { loadAllowlist, isAllowed, staleEntries, fingerprintOf, ALLOWLIST_FILE } from "../lib/allowlist.mjs";
import { makeRepo } from "./helpers/temp-repo.mjs";

// loadAllowlist now checks whether .secretgate.json is itself git-tracked
// (Finding 3), so every fixture needs a real repo, not a bare temp dir - a
// plain directory reports "git could not answer" for every path, which
// loadAllowlist treats the same as "ignored" (fail toward no exemptions).
function repoWith(config) {
  const dir = makeRepo({});
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
  const dir = makeRepo({});
  writeFileSync(path.join(dir, ALLOWLIST_FILE), "{ not json");
  assert.throws(() => loadAllowlist(dir), /\.secretgate\.json is not valid JSON/);
});

test("an invalid regex throws with the pattern named", () => {
  const dir = repoWith({ version: 1, paths: ["["] });
  assert.throws(() => loadAllowlist(dir), /\[/);
});

// --- Review round 1, Finding 3 (important): a gitignored allowlist must
// not be honored --------------------------------------------------------
//
// Any allowlist is self-service to something that can already write files,
// so the one guarantee worth keeping is that USING it leaves a reviewable
// artifact - a change that actually shows up in a diff someone looks at. A
// .secretgate.json that git itself ignores can be written and consulted
// without ever appearing in a commit, which defeats that guarantee
// entirely. `paths: [""]` (an empty pattern) matches every path, so this is
// the most permissive allowlist that can be written, deliberately, to make
// the failure obvious rather than borderline.
test("a gitignored .secretgate.json is treated as absent, not as a grant (Finding 3)", () => {
  const dir = makeRepo({ ".gitignore": ALLOWLIST_FILE + "\n" });
  writeFileSync(path.join(dir, ALLOWLIST_FILE), JSON.stringify({ version: 1, paths: [""] }));
  const list = loadAllowlist(dir);
  assert.equal(isAllowed(list, "src/app.ts", hit), false, "a gitignored allowlist must not grant any exemption");
});

// --- Review round 1, Finding 4: an unknown version is honored under v1
// semantics instead of being rejected ------------------------------------
//
// If a future v2 changes what `paths` (or any field) means, a guard that
// still speaks v1 reading a v2 file would silently misinterpret it under
// the wrong rules - an allow-direction failure that is invisible when it
// happens, since nothing errors. Reject an unknown version the same way
// malformed JSON is rejected, rather than defaulting past it.
test("an unrecognized version is rejected rather than honored under v1 rules", () => {
  const dir = repoWith({ version: 999, paths: ["^test/fixtures/"] });
  assert.throws(() => loadAllowlist(dir), /version/i);
});

// --- Review round 2, Finding B (minor): a read failure was mislabeled as
// invalid JSON ------------------------------------------------------------
//
// readFileSync sat inside the same try as JSON.parse, so an EACCES or a
// locked file reported ".secretgate.json is not valid JSON: Error" - wrong
// direction (it still denies either way) but wrong wording, sending an
// operator hunting for a syntax error in a file they simply cannot open. A
// directory in the file's place is a reliable, cross-platform way to force
// a read failure (readFileSync throws EISDIR) without touching permissions.
test("a .secretgate.json that cannot be read is reported as unreadable, not as invalid JSON", () => {
  const dir = makeRepo({});
  mkdirSync(path.join(dir, ALLOWLIST_FILE));
  assert.throws(() => loadAllowlist(dir), /\.secretgate\.json could not be read/);
});
