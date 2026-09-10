import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync, writeFileSync } from "node:fs";
import { execFileSync } from "node:child_process";
import path from "node:path";
import { makeRepo, runCli } from "./helpers/temp-repo.mjs";
import { MAX_SCAN_BYTES } from "../lib/detect.mjs";

// A synthetic value shaped like a live Stripe secret key (the stripe-key
// detector: sk_live_ or rk_live_ followed by 20+ alphanumerics). Not a real
// key - generated for this test suite only.
const LIVE = "sk_live_" + "a1b2c3d4e5f6g7h8i9j0k1l2";

test("fix --staged rewrites the file and leaves the label alone", () => {
  const dir = makeRepo({ "docs/setup.md": "# Setup\n\nSTRIPE_KEY=" + LIVE + "\n" });
  const { code } = runCli(dir, ["fix", "--staged"]);
  assert.equal(code, 0);
  const after = readFileSync(path.join(dir, "docs", "setup.md"), "utf8");
  assert.equal(after, "# Setup\n\nSTRIPE_KEY=[REDACTED stripe-key #1]\n");
});

test("fix --staged restages the rewritten file", () => {
  const dir = makeRepo({ "docs/setup.md": "STRIPE_KEY=" + LIVE + "\n" });
  runCli(dir, ["fix", "--staged"]);
  const stagedNow = execFileSync("git", ["show", ":docs/setup.md"], { cwd: dir, encoding: "utf8" });
  assert.ok(!stagedNow.includes(LIVE));
  assert.match(stagedNow, /\[REDACTED stripe-key #1\]/);
});

test("scan is clean immediately after fix", () => {
  const dir = makeRepo({ "docs/setup.md": "STRIPE_KEY=" + LIVE + "\n" });
  runCli(dir, ["fix", "--staged"]);
  assert.equal(runCli(dir, ["scan", "--staged"]).code, 0);
});

test("fix respects the allowlist and leaves an allowed fixture alone", () => {
  const original = "STRIPE_KEY=" + LIVE + "\n";
  const dir = makeRepo({
    "test/fixtures/keys.txt": original,
    ".secretgate.json": JSON.stringify({ version: 1, paths: ["^test/fixtures/"] }),
  });
  runCli(dir, ["fix", "--staged"]);
  assert.equal(readFileSync(path.join(dir, "test", "fixtures", "keys.txt"), "utf8"), original);
});

test("fix is a no-op on a clean tree and says so", () => {
  const dir = makeRepo({ "a.md": "clean\n" });
  const { code, stdout } = runCli(dir, ["fix", "--staged"]);
  assert.equal(code, 0);
  assert.match(stdout, /nothing to fix/i);
});

test("fix without --staged exits 2 rather than touching the whole tree", () => {
  const dir = makeRepo({ "a.md": "STRIPE_KEY=" + LIVE + "\n" });
  const { code, stderr } = runCli(dir, ["fix"]);
  assert.equal(code, 2);
  assert.match(stderr, /--staged/);
  assert.match(readFileSync(path.join(dir, "a.md"), "utf8"), /sk_live/);
});

test("fix never prints the value it replaced", () => {
  const dir = makeRepo({ "a.md": "STRIPE_KEY=" + LIVE + "\n" });
  const { stdout, stderr } = runCli(dir, ["fix", "--staged"]);
  assert.ok(!(stdout + stderr).includes(LIVE));
});

// --- Task 10 review corrections: fix must be safe on the paths scan learned
// about the hard way ----------------------------------------------------

// fix shares scan's file-reading machinery (readTarget/isBinary/
// MAX_SCAN_BYTES), so it must inherit the same "never partially rewrite"
// guarantee. A partial rewrite of a binary file is data loss, not a fix.
test("fix leaves a binary staged file byte-for-byte untouched and does not restage it", () => {
  const dir = makeRepo({});
  const binary = Buffer.concat([Buffer.from([0, 1, 2]), Buffer.from("PNG" + LIVE), Buffer.from([0])]);
  writeFileSync(path.join(dir, "logo.png"), binary);
  execFileSync("git", ["add", "-A"], { cwd: dir, stdio: "ignore" });

  const { code, stdout } = runCli(dir, ["fix", "--staged"]);
  assert.equal(code, 0);
  assert.match(stdout, /nothing to fix/i, "a binary file has nothing fix() is allowed to touch");
  assert.ok(readFileSync(path.join(dir, "logo.png")).equals(binary), "the binary file's bytes must be unchanged");
});

// Mirrors the "binary and oversize" skip scan already applies in collect() -
// fix must skip an oversize file rather than rewrite it. Sized just over
// MAX_SCAN_BYTES (2 MiB), matching the margin this plugin's own test suite
// already uses for its 8 MiB hook cap (see test/hooks.test.mjs) rather than
// building a payload far larger than the cap requires.
test("fix leaves an oversize staged file byte-for-byte untouched and does not restage it", () => {
  const dir = makeRepo({});
  const filler = "x".repeat(MAX_SCAN_BYTES - 40);
  const oversize = Buffer.from(filler + "STRIPE_KEY=" + LIVE + "\n", "utf8");
  assert.ok(oversize.length > MAX_SCAN_BYTES, "fixture must actually exceed MAX_SCAN_BYTES");
  writeFileSync(path.join(dir, "big.txt"), oversize);
  execFileSync("git", ["add", "-A"], { cwd: dir, stdio: "ignore" });

  const { code, stdout } = runCli(dir, ["fix", "--staged"]);
  assert.equal(code, 0);
  assert.match(stdout, /nothing to fix/i);
  assert.ok(readFileSync(path.join(dir, "big.txt")).equals(oversize), "the oversize file's bytes must be unchanged");
});

// Stronger than the "content is unchanged" check above: this compares the
// staged blob before and after, so a rewrite-then-restage-identical-content
// pass (touched, not just correct) would still be caught.
test("fix does not restage a file whose only hits are allowlisted", () => {
  const original = "STRIPE_KEY=" + LIVE + "\n";
  const dir = makeRepo({
    "test/fixtures/keys.txt": original,
    ".secretgate.json": JSON.stringify({ version: 1, paths: ["^test/fixtures/"] }),
  });
  const before = execFileSync("git", ["rev-parse", ":test/fixtures/keys.txt"], { cwd: dir, encoding: "utf8" }).trim();

  const { stdout } = runCli(dir, ["fix", "--staged"]);
  assert.match(stdout, /nothing to fix/i);

  const after = execFileSync("git", ["rev-parse", ":test/fixtures/keys.txt"], { cwd: dir, encoding: "utf8" }).trim();
  assert.equal(after, before, "an allowlisted-only file must not be restaged, even with identical content");
});

// A malformed allowlist must fail CLOSED. loadAllowlist() throws on invalid
// JSON; fix must let that propagate to exit 2 and must not have written
// anything by the time it does - rewriting files under a broken allowlist
// is the worst possible combination this tool could produce.
test("a malformed .secretgate.json makes fix exit 2 and rewrite nothing", () => {
  const original = "STRIPE_KEY=" + LIVE + "\n";
  const dir = makeRepo({
    "a.md": original,
    ".secretgate.json": "{ this is not valid json",
  });
  const { code, stderr } = runCli(dir, ["fix", "--staged"]);
  assert.equal(code, 2);
  assert.match(stderr, /not valid JSON/i);
  assert.equal(readFileSync(path.join(dir, "a.md"), "utf8"), original, "fix must not rewrite anything when the allowlist itself is broken");
});

// Everything outside the hit ranges must survive byte-for-byte: a BOM, CRLF
// line endings, and a missing trailing newline. Comparing raw Buffers, not
// decoded strings, so a re-encoding difference (e.g. the BOM being dropped
// or CRLF being normalized to LF) would fail this test even if it "reads"
// the same.
test("fix preserves a BOM, CRLF line endings and a missing trailing newline exactly", () => {
  const dir = makeRepo({});
  // Built with String.fromCharCode rather than an embedded literal - the
  // UTF-8 BOM character (U+FEFF) is the deliberate subject of this test,
  // not incidental source content, and it must not sit invisibly in this
  // file as a raw character.
  const bom = String.fromCharCode(0xfeff);
  const before = Buffer.from(bom + "line one\r\nSTRIPE_KEY=" + LIVE + "\r\nlast line, no newline", "utf8");
  writeFileSync(path.join(dir, "notes.txt"), before);
  execFileSync("git", ["add", "-A"], { cwd: dir, stdio: "ignore" });

  const { code } = runCli(dir, ["fix", "--staged"]);
  assert.equal(code, 0);

  const after = readFileSync(path.join(dir, "notes.txt"));
  const expected = Buffer.from(bom + "line one\r\nSTRIPE_KEY=[REDACTED stripe-key #1]\r\nlast line, no newline", "utf8");
  assert.ok(after.equals(expected), "bytes outside the redacted range must be byte-identical, including the BOM, CRLF and the missing trailing newline");
});
