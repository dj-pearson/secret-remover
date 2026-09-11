import test from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, mkdirSync, writeFileSync, symlinkSync, linkSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { canonicalize, canonicalizeParent, isSameFile, samePath } from "../lib/paths.mjs";

// lib/paths.mjs exists because every path comparison in this plugin has one
// side that came from git and one that came from Node, and those two disagree
// about how to spell the same file on macOS (symlinks) and Windows (8.3 short
// names, casing). Getting it wrong does not throw - it makes the gate report
// clean - so each behaviour it depends on is pinned here directly rather than
// only through the end-to-end tests that happen to exercise it.

function scratch() {
  const dir = mkdtempSync(path.join(tmpdir(), "secret-gate-paths-"));
  return { dir, cleanup: () => rmSync(dir, { recursive: true, force: true }) };
}

test("canonicalize resolves a symlinked directory in the middle of a path", (t) => {
  const { dir, cleanup } = scratch();
  try {
    const real = path.join(dir, "real");
    mkdirSync(real);
    writeFileSync(path.join(real, "f.txt"), "x");
    const link = path.join(dir, "link");
    try {
      symlinkSync(real, link, "junction");
    } catch {
      return t.skip("this machine will not create a symlink");
    }
    assert.equal(canonicalize(path.join(link, "f.txt")), canonicalize(path.join(real, "f.txt")));
  } finally {
    cleanup();
  }
});

test("canonicalize works on a path whose deepest parts do not exist yet", () => {
  const { dir, cleanup } = scratch();
  try {
    // Write routinely names a file in a folder that does not exist yet. A
    // bare realpathSync throws there; this must climb, canonicalize what does
    // exist, and re-attach the rest.
    const target = path.join(dir, "not", "there", "yet.txt");
    const result = canonicalize(target);
    assert.equal(path.basename(result), "yet.txt");
    assert.ok(result.endsWith(path.join("not", "there", "yet.txt")));
    assert.ok(path.isAbsolute(result));
  } finally {
    cleanup();
  }
});

test("canonicalizeParent does NOT follow a symlink in the final component", (t) => {
  const { dir, cleanup } = scratch();
  try {
    const real = path.join(dir, "real.txt");
    writeFileSync(real, "x");
    const link = path.join(dir, "link.txt");
    try {
      symlinkSync(real, link);
    } catch {
      return t.skip("this machine will not create a symlink");
    }
    // git tracks a symlink as a symlink. Following the last component here
    // would silently scan - or allowlist - the link's target under the wrong
    // repo-relative name.
    assert.equal(path.basename(canonicalizeParent(link)), "link.txt");
  } finally {
    cleanup();
  }
});

test("isSameFile recognizes one file reached through a symlinked directory", (t) => {
  const { dir, cleanup } = scratch();
  try {
    const real = path.join(dir, "real");
    mkdirSync(real);
    const file = path.join(real, "cli.mjs");
    writeFileSync(file, "x");
    const link = path.join(dir, "link");
    try {
      symlinkSync(real, link, "junction");
    } catch {
      return t.skip("this machine will not create a symlink");
    }
    assert.equal(isSameFile(path.join(link, "cli.mjs"), file), true);
  } finally {
    cleanup();
  }
});

// The branch that keeps Windows working. Two hard links are one file under
// two names that NO amount of canonicalizing will reconcile into each other -
// the same shape as Windows handing argv[1] an 8.3 short path while Node
// records the long one in import.meta.url. Only the st_dev/st_ino identity
// check answers this correctly, so if that check is ever dropped in favour of
// "just canonicalize both sides", this test goes red instead of the entry
// point silently deciding it was imported and scanning nothing.
test("isSameFile recognizes two hard links to one file, which no canonical spelling reconciles", (t) => {
  const { dir, cleanup } = scratch();
  try {
    const a = path.join(dir, "a.mjs");
    const b = path.join(dir, "b.mjs");
    writeFileSync(a, "x");
    try {
      linkSync(a, b);
    } catch {
      return t.skip("this machine will not create a hard link");
    }
    assert.notEqual(canonicalize(a), canonicalize(b), "the fixture is wrong: these should be two distinct names");
    assert.equal(isSameFile(a, b), true);
  } finally {
    cleanup();
  }
});

test("isSameFile says no for two genuinely different files, and for junk input", () => {
  const { dir, cleanup } = scratch();
  try {
    const a = path.join(dir, "a.mjs");
    const b = path.join(dir, "b.mjs");
    writeFileSync(a, "x");
    writeFileSync(b, "x"); // identical CONTENT, different file
    assert.equal(isSameFile(a, b), false);
    assert.equal(isSameFile(a, path.join(dir, "missing.mjs")), false);
    assert.equal(isSameFile("", a), false);
    assert.equal(isSameFile(undefined, a), false);
  } finally {
    cleanup();
  }
});

test("samePath is case-sensitive off Windows and case-insensitive on it", () => {
  assert.equal(samePath("/a/b", "/a/b"), true);
  assert.equal(samePath("/a/b", "/a/B"), process.platform === "win32");
  assert.equal(samePath("/a/b", "/a/c"), false);
});
