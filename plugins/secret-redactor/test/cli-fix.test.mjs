import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync, writeFileSync, rmSync, chmodSync, symlinkSync } from "node:fs";
import { execFileSync } from "node:child_process";
import path from "node:path";
import { makeRepo, runCli, runGit } from "./helpers/temp-repo.mjs";
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
// Review round 2, Finding 5: a skip must be VISIBLE, so "nothing to fix" is
// no longer the right assertion once something was in fact skipped - it
// must instead show up in the skip list, the same way scan's report() does.
test("fix leaves a binary staged file byte-for-byte untouched, does not restage it, and reports the skip", () => {
  const dir = makeRepo({});
  const binary = Buffer.concat([Buffer.from([0, 1, 2]), Buffer.from("PNG" + LIVE), Buffer.from([0])]);
  writeFileSync(path.join(dir, "logo.png"), binary);
  runGit(dir, "add", "-A");

  const { code, stdout } = runCli(dir, ["fix", "--staged"]);
  assert.equal(code, 0, "a binary skip alone is advisory, same as scan's default - it does not fail the command");
  assert.match(stdout, /skipped/i);
  assert.match(stdout, /logo\.png/);
  assert.ok(readFileSync(path.join(dir, "logo.png")).equals(binary), "the binary file's bytes must be unchanged");
});

// Mirrors the "binary and oversize" skip scan already applies in collect() -
// fix must skip an oversize file rather than rewrite it. Sized just over
// MAX_SCAN_BYTES (2 MiB), matching the margin this plugin's own test suite
// already uses for its 8 MiB hook cap (see test/hooks.test.mjs) rather than
// building a payload far larger than the cap requires.
test("fix leaves an oversize staged file byte-for-byte untouched, does not restage it, and reports the skip", () => {
  const dir = makeRepo({});
  const filler = "x".repeat(MAX_SCAN_BYTES - 40);
  const oversize = Buffer.from(filler + "STRIPE_KEY=" + LIVE + "\n", "utf8");
  assert.ok(oversize.length > MAX_SCAN_BYTES, "fixture must actually exceed MAX_SCAN_BYTES");
  writeFileSync(path.join(dir, "big.txt"), oversize);
  runGit(dir, "add", "-A");

  const { code, stdout } = runCli(dir, ["fix", "--staged"]);
  assert.equal(code, 0);
  assert.match(stdout, /skipped/i);
  assert.match(stdout, /big\.txt/);
  assert.ok(readFileSync(path.join(dir, "big.txt")).equals(oversize), "the oversize file's bytes must be unchanged");
});

// Review round 2, Finding 5's own reproduction: an oversize file staged
// ALONGSIDE a file fix can safely rewrite must not make the oversize file
// vanish from the report just because something else succeeded.
test("a fixed file and a skipped oversize file are both reported in the same run", () => {
  const dir = makeRepo({ "small.md": "STRIPE_KEY=" + LIVE + "\n" });
  const filler = "x".repeat(MAX_SCAN_BYTES - 40);
  writeFileSync(path.join(dir, "big.txt"), filler + "STRIPE_KEY=" + LIVE + "\n");
  runGit(dir, "add", "-A");

  const { code, stdout } = runCli(dir, ["fix", "--staged"]);
  assert.equal(code, 0);
  assert.match(stdout, /small\.md/, "the file that WAS fixed must still be reported");
  assert.match(stdout, /big\.txt/, "the file that was skipped must not vanish from the report");
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
//
// core.autocrlf=true is set EXPLICITLY on this fixture (Finding B, review
// round 4): without it, the staged blob and the worktree file are
// byte-identical from the moment they're staged, and this test would still
// pass even if fix wrote the STAGED (not worktree) text back out - which is
// exactly the bug Finding B found. With autocrlf on, `git add` normalizes
// this file's CRLFs to LF going into the index while the worktree keeps
// CRLF, so a fix that spliced staged offsets into (or wrote staged text
// over) the worktree file would silently convert every line ending in the
// file to LF, not just redact the finding - this assertion is the one that
// catches that.
test("fix preserves a BOM, CRLF line endings and a missing trailing newline exactly, even when core.autocrlf normalizes the staged copy (Finding B)", () => {
  const dir = makeRepo({});
  runGit(dir, "config", "core.autocrlf", "true");
  // Built with String.fromCharCode rather than an embedded literal - the
  // UTF-8 BOM character (U+FEFF) is the deliberate subject of this test,
  // not incidental source content, and it must not sit invisibly in this
  // file as a raw character.
  const bom = String.fromCharCode(0xfeff);
  const before = Buffer.from(bom + "line one\r\nSTRIPE_KEY=" + LIVE + "\r\nlast line, no newline", "utf8");
  writeFileSync(path.join(dir, "notes.txt"), before);
  runGit(dir, "add", "-A");

  // Sanity-check the fixture: it must actually reproduce the autocrlf
  // normalization, or this test proves nothing about Finding B.
  const stagedText = execFileSync("git", ["show", ":notes.txt"], { cwd: dir, encoding: "utf8" });
  assert.ok(!stagedText.includes("\r"), "staged blob must be LF-normalized under autocrlf=true, or the fixture is not exercising Finding B");

  const { code } = runCli(dir, ["fix", "--staged"]);
  assert.equal(code, 0);

  const after = readFileSync(path.join(dir, "notes.txt"));
  const expected = Buffer.from(bom + "line one\r\nSTRIPE_KEY=[REDACTED stripe-key #1]\r\nlast line, no newline", "utf8");
  assert.ok(
    after.equals(expected),
    "bytes outside the redacted range must be byte-identical, including the BOM, CRLF and the missing trailing newline - not silently reformatted to the index's LF-normalized form",
  );
  assert.equal(runCli(dir, ["scan", "--staged"]).code, 0, "the credential must actually be gone from the index");
});

// A hit at byte offset 0 - the very first bytes of the file - exercises the
// `text.slice(last, hit.start)` branch where `last` and `hit.start` are
// both 0, an easy off-by-one to get wrong.
test("fix redacts a hit at the very start of the file", () => {
  const dir = makeRepo({ "a.md": LIVE + "\ntrailing text\n" });
  const { code } = runCli(dir, ["fix", "--staged"]);
  assert.equal(code, 0);
  assert.equal(readFileSync(path.join(dir, "a.md"), "utf8"), "[REDACTED stripe-key #1]\ntrailing text\n");
});

// A hit ending exactly at end-of-file (no trailing newline, no trailing
// text at all after the hit) exercises `text.slice(last)` where `last`
// equals `text.length`.
test("fix redacts a hit that ends exactly at end-of-file", () => {
  const dir = makeRepo({ "a.md": "leading text\n" + LIVE });
  const { code } = runCli(dir, ["fix", "--staged"]);
  assert.equal(code, 0);
  assert.equal(readFileSync(path.join(dir, "a.md"), "utf8"), "leading text\n[REDACTED stripe-key #1]");
});

// The reviewer ran this by hand and it behaved correctly; pinning it here.
// Two distinct secrets in one file, only one of them allowlisted by a
// `regexes` entry that matches its exact value - the OTHER one must still
// be found and replaced, and the allowlisted one must survive untouched.
test("fix replaces only the non-allowlisted hit when a file has a mix of both", () => {
  const ALLOWED = LIVE; // "sk_TEST_live_a1b2c3d4e5f6g7h8i9j0k1l2"
  const NOT_ALLOWED = "sk_live_" + "z9y8x7w6v5u4t3s2r1q0p9o8";
  const dir = makeRepo({
    "a.md": "ALLOWED=" + ALLOWED + "\nNOT_ALLOWED=" + NOT_ALLOWED + "\n",
    ".secretgate.json": JSON.stringify({ version: 1, regexes: ["^sk_TEST_live_a1b2c3d4"] }),
  });
  const { code, stdout } = runCli(dir, ["fix", "--staged"]);
  assert.equal(code, 0);
  const after = readFileSync(path.join(dir, "a.md"), "utf8");
  assert.equal(after, "ALLOWED=" + ALLOWED + "\nNOT_ALLOWED=[REDACTED stripe-key #1]\n");
  assert.match(stdout, /1 replaced/);
  assert.equal(runCli(dir, ["scan", "--staged"]).code, 0, "the remaining value is allowlisted, so scan must be clean too");
});

// --- Task 10 review round 2 --------------------------------------------
//
// FINDING 1 (CRITICAL): fix decoded a staged buffer with
// buffer.toString("utf8") and wrote the decoded STRING back. For a file
// that is not valid UTF-8, every invalid byte becomes U+FFFD on the way in
// and the 3-byte UTF-8 encoding of U+FFFD on the way out - a silent,
// unannounced corruption of content that was never part of any finding.
// Fixture mirrors the reviewer's own byte-level reproduction: a Latin-1/
// CP1252 'e with an accent' (0xE9, not valid standalone UTF-8) before the
// key, and a bare continuation byte (0x80, also not valid standalone
// UTF-8) after it - built with raw byte arrays, not embedded literals, so
// the invalid bytes are visible in the source rather than hidden in it.
test("fix refuses to rewrite a file that is not valid UTF-8, leaving it byte-for-byte untouched (Finding 1)", () => {
  const dir = makeRepo({});
  const before = Buffer.concat([
    Buffer.from("# caf", "ascii"),
    Buffer.from([0xe9]),
    Buffer.from(" notes\nSTRIPE_KEY=" + LIVE + "\ntail ", "ascii"),
    Buffer.from([0x80]),
    Buffer.from("\n", "ascii"),
  ]);
  // Sanity-check the fixture: it must actually be invalid UTF-8, or this
  // test proves nothing about the refusal path.
  assert.ok(
    !Buffer.from(before.toString("utf8"), "utf8").equals(before),
    "fixture must not round-trip through UTF-8 cleanly",
  );
  writeFileSync(path.join(dir, "notes.txt"), before);
  runGit(dir, "add", "-A");

  const { code, stdout } = runCli(dir, ["fix", "--staged"]);
  assert.equal(code, 1, "an unresolved finding (refused, not fixed) must not report success as exit 0");
  assert.match(stdout, /notes\.txt/);
  assert.match(stdout, /utf-8/i);
  assert.ok(readFileSync(path.join(dir, "notes.txt")).equals(before), "not one byte may change - the file is invalid UTF-8 outside the finding too");
  assert.equal(runCli(dir, ["scan", "--staged"]).code, 1, "the credential is still staged - scan must still catch it");
});

// FINDING 2 (CRITICAL): fix decided from the WORKTREE while scan (and the
// finding it acts on) is about the STAGED blob. Three ways they can
// disagree, all of which must be refused rather than guessed at.

// Case A: staged with the key, then hand-edited afterward. The worktree no
// longer matches what's actually in the index.
test("fix refuses a file hand-edited after staging rather than reporting a false 'nothing to fix' (Finding 2, case A)", () => {
  const dir = makeRepo({ "a.md": "STRIPE_KEY=" + LIVE + "\n" });
  const stagedBefore = execFileSync("git", ["rev-parse", ":a.md"], { cwd: dir, encoding: "utf8" }).trim();
  assert.equal(runCli(dir, ["scan", "--staged"]).code, 1, "fixture must actually have a staged finding");

  writeFileSync(path.join(dir, "a.md"), "STRIPE_KEY=" + LIVE + "\nEDITED BY HAND AFTER STAGING\n");

  const { code, stdout } = runCli(dir, ["fix", "--staged"]);
  assert.equal(code, 1, "a real, unfixed finding must not exit 0");
  assert.ok(!/nothing to fix/i.test(stdout), "must never claim success while the credential is still staged");
  assert.match(stdout, /a\.md/);
  assert.match(stdout, /differs from the worktree/i);

  const stagedAfter = execFileSync("git", ["rev-parse", ":a.md"], { cwd: dir, encoding: "utf8" }).trim();
  assert.equal(stagedAfter, stagedBefore, "the staged blob must be completely untouched");
  assert.equal(runCli(dir, ["scan", "--staged"]).code, 1, "the credential must still be reported as staged");
});

// Case B: only part of the file was staged (git add -p style). Rewriting
// the worktree and restaging it would promote the deliberately-unstaged
// tail into the commit along with the fix - fix must refuse instead.
test("fix does not promote unstaged worktree content into the commit on a partially staged file (Finding 2, case B)", () => {
  const dir = makeRepo({ "a.md": "line1\n" }, { commit: true });
  writeFileSync(path.join(dir, "a.md"), "line1\nSTAGED EDIT " + LIVE + "\n");
  runGit(dir, "add", "a.md");
  const stagedBefore = execFileSync("git", ["rev-parse", ":a.md"], { cwd: dir, encoding: "utf8" }).trim();

  // Further, unstaged edit - never passed to `git add` again.
  writeFileSync(path.join(dir, "a.md"), "line1\nSTAGED EDIT " + LIVE + "\nUNSTAGED WORK IN PROGRESS\n");

  const { code, stdout } = runCli(dir, ["fix", "--staged"]);
  assert.equal(code, 1);
  assert.match(stdout, /differs from the worktree/i);

  const stagedAfter = execFileSync("git", ["rev-parse", ":a.md"], { cwd: dir, encoding: "utf8" }).trim();
  assert.equal(stagedAfter, stagedBefore, "the staged blob must not gain the unstaged tail");
  const worktreeAfter = readFileSync(path.join(dir, "a.md"), "utf8");
  assert.match(worktreeAfter, /UNSTAGED WORK IN PROGRESS/, "fix must not have touched the worktree file either");
});

// Case C: staged with the key, then the worktree copy is deleted entirely.
// readFileSync on the worktree path fails; that must read as "the two
// copies disagree" (there IS a staged finding, and now nothing to compare
// it against), not as "nothing here, move on."
test("fix refuses a file deleted from the worktree after staging (Finding 2, case C)", () => {
  const dir = makeRepo({ "a.md": "STRIPE_KEY=" + LIVE + "\n" });
  const stagedBefore = execFileSync("git", ["rev-parse", ":a.md"], { cwd: dir, encoding: "utf8" }).trim();

  rmSync(path.join(dir, "a.md")); // only the worktree copy - the index still has the staged blob

  const { code, stdout } = runCli(dir, ["fix", "--staged"]);
  assert.equal(code, 1);
  assert.match(stdout, /a\.md/);

  const stagedAfter = execFileSync("git", ["rev-parse", ":a.md"], { cwd: dir, encoding: "utf8" }).trim();
  assert.equal(stagedAfter, stagedBefore, "the staged blob must be untouched even though the worktree file is gone");
});

// FINDING 3: a tracked symlink's worktree entry is the link itself; reading
// or writing `path.join(root, rel)` with plain fs calls follows it to the
// TARGET, which the staged blob (just link text) never represents. This
// sandbox cannot create real symlinks (confirmed: fs.symlinkSync raises
// EPERM here, the same result the reviewer got) - the test detects that at
// runtime and skips itself with a clear reason rather than faking a pass.
test("fix does not follow a symlink to rewrite a file outside the repo (Finding 3)", (t) => {
  const dir = makeRepo({});
  const outside = execFileSync("git", ["rev-parse", "--show-toplevel"], { cwd: dir, encoding: "utf8" }).trim() + "-outside-secret.txt";
  writeFileSync(outside, "STRIPE_KEY=" + LIVE + "\n");
  try {
    symlinkSync(outside, path.join(dir, "link.txt"), "file");
  } catch (err) {
    rmSync(outside, { force: true });
    t.skip(`cannot create a real symlink on this machine (${err.code}) - the write-through-symlink path is unverified here, matching the reviewer's own environment`);
    return;
  }

  runGit(dir, "add", "-A");
  runCli(dir, ["fix", "--staged"]);

  const outsideAfter = readFileSync(outside, "utf8");
  rmSync(outside, { force: true });
  assert.equal(outsideAfter, "STRIPE_KEY=" + LIVE + "\n", "fix must never write through a symlink to a file outside the repo");
});

// FINDING 4: `args.includes("--staged")` was the only inspection fix did of
// its own argv, so an unrecognized flag or a stray path argument was
// silently ignored rather than rejected - the one command that writes to
// files must treat an argument it doesn't understand as a usage error.
test("an unrecognized flag makes fix exit 2 instead of rewriting the whole staged tree (Finding 4)", () => {
  const dir = makeRepo({ "a.md": "STRIPE_KEY=" + LIVE + "\n" });
  const { code, stderr } = runCli(dir, ["fix", "--staged", "--dry-run"]);
  assert.equal(code, 2);
  assert.match(stderr, /--dry-run/);
  assert.match(readFileSync(path.join(dir, "a.md"), "utf8"), /sk_live/, "must not have rewritten anything");
});

test("a stray path argument makes fix exit 2 rather than silently scoping (or failing to scope) the rewrite (Finding 4)", () => {
  const dir = makeRepo({ "a.md": "STRIPE_KEY=" + LIVE + "\n" });
  const { code, stderr } = runCli(dir, ["fix", "--staged", "a.md"]);
  assert.equal(code, 2);
  assert.match(stderr, /a\.md/);
});

// FINDING 6: a mid-loop write/restage failure used to throw straight out of
// the loop, discarding the report of files already handled. Made read-only
// via the Windows file attribute (chmodSync 0o444), which really does make
// writeFileSync fail with EPERM here (verified separately) - unlike POSIX
// permission bits, this does not depend on which user owns the file.
test("a write failure on one file does not swallow the report of another file already fixed in the same run (Finding 6)", () => {
  const dir = makeRepo({
    "ok.md": "STRIPE_KEY=" + LIVE + "\n",
    "readonly.md": "STRIPE_KEY=" + LIVE + "\n",
  });
  const roPath = path.join(dir, "readonly.md");
  chmodSync(roPath, 0o444);
  try {
    const { code, stdout } = runCli(dir, ["fix", "--staged"]);
    assert.equal(code, 1, "the unresolved file must make the overall run report non-zero");
    assert.match(stdout, /ok\.md/, "the file that succeeded must still be reported");
    assert.match(stdout, /1 replaced/);
    assert.match(stdout, /readonly\.md/, "the file that failed must be named, not silently dropped");
    assert.equal(readFileSync(path.join(dir, "ok.md"), "utf8"), "STRIPE_KEY=[REDACTED stripe-key #1]\n");
    const okStaged = execFileSync("git", ["show", ":ok.md"], { cwd: dir, encoding: "utf8" });
    assert.match(okStaged, /\[REDACTED stripe-key #1\]/, "ok.md must have been restaged despite readonly.md's failure");
  } finally {
    chmodSync(roPath, 0o666);
  }
});

// --- Task 10 review round 3 --------------------------------------------
//
// FINDING A: the byte-equality divergence check from round 2 refuses every
// file affected by git's own EOL normalization. On a default
// Git-for-Windows install, core.autocrlf=true (set in the machine's SYSTEM
// gitconfig, not this repo) means `git add` writes LF to the index while
// the worktree legitimately keeps CRLF for a file nobody hand-edited - a
// byte comparison calls that "diverged" and fix becomes a dead end for
// most of a user's text files. The fixture sets core.autocrlf=true
// EXPLICITLY on this one repo (a local, not global/system, git config
// value) so the test exercises the same behavior deterministically on any
// machine, regardless of that machine's own ambient git config - this is
// exactly the isolation temp-repo.mjs's isolatedGitEnv already gives every
// other fixture in this suite, just set for a value this one test actually
// wants turned on.
test("fix rewrites a CRLF file under core.autocrlf=true even though the index legitimately differs from the worktree (Finding A)", () => {
  const dir = makeRepo({});
  runGit(dir, "config", "core.autocrlf", "true");
  writeFileSync(path.join(dir, "cfg.txt"), "line one\r\nSTRIPE_KEY=" + LIVE + "\r\nline three\r\n");
  runGit(dir, "add", "-A");

  // Sanity-check the fixture: it must actually reproduce the autocrlf
  // divergence, or this test proves nothing about Finding A.
  const stagedText = execFileSync("git", ["show", ":cfg.txt"], { cwd: dir, encoding: "utf8" });
  const worktreeText = readFileSync(path.join(dir, "cfg.txt"), "utf8");
  assert.ok(!stagedText.includes("\r"), "staged blob must be LF-normalized under autocrlf=true, or the fixture is not exercising it");
  assert.ok(worktreeText.includes("\r\n"), "worktree copy must keep CRLF, or the fixture is not exercising it");
  assert.notEqual(stagedText, worktreeText, "fixture must produce a real byte-level difference between staged and worktree");

  const { code, stdout } = runCli(dir, ["fix", "--staged"]);
  assert.equal(code, 0, "an autocrlf-only difference is not a real divergence and must not be refused");
  assert.match(stdout, /cfg\.txt/);
  assert.match(stdout, /1 replaced/);
  assert.equal(runCli(dir, ["scan", "--staged"]).code, 0, "the credential must actually be gone from the index, not just reported as fixed");
});

// The three real-divergence cases from Finding 2 must still refuse under
// the new git-diff-based check, not just under the old byte comparison.
test("fix still refuses a hand-edited file under the git-diff-based divergence check (Finding 2 case A, re-verified for Finding A)", () => {
  const dir = makeRepo({ "a.md": "STRIPE_KEY=" + LIVE + "\n" });
  writeFileSync(path.join(dir, "a.md"), "STRIPE_KEY=" + LIVE + "\nEDITED BY HAND AFTER STAGING\n");
  const { code, stdout } = runCli(dir, ["fix", "--staged"]);
  assert.equal(code, 1);
  assert.match(stdout, /differs from the worktree/i);
});
