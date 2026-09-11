import test from "node:test";
import assert from "node:assert/strict";
import { writeFileSync, mkdtempSync, existsSync, rmSync } from "node:fs";
import { execFileSync, spawnSync } from "node:child_process";
import { tmpdir } from "node:os";
import path from "node:path";
import { makeRepo, runCli, runGit, isolatedGitEnv } from "./helpers/temp-repo.mjs";

// Same class as runGit() below (review Finding 5): this needs stdin piping
// and stdout capture, which runGit() doesn't do, but it's still a `git`
// child process that would otherwise inherit whatever GIT_* the caller
// carries - GIT_DIR included. `hash-object -w` writes a loose object into
// whichever repo GIT_DIR names, so an inherited one here writes into the
// wrong repo's object database the same way an unprotected update-index or
// commit writes into its index or history.
function gitPlumbing(cwd, args, input) {
  return execFileSync("git", args, { cwd, input, encoding: "utf8", env: isolatedGitEnv(cwd) }).trim();
}

// A synthetic value shaped like a live Stripe secret key (the stripe-key
// detector: sk_live_ or rk_live_ followed by 20+ alphanumerics). Not a real
// key - generated for this test suite only.
const LIVE = "sk_live_A1b2C3d4E5f6G7h8I9j0";

test("scan --staged exits 1 and names the file, line and label", () => {
  const dir = makeRepo({ "docs/setup.md": "# Setup\n\nSTRIPE_KEY=" + LIVE + "\n" });
  const { code, stdout } = runCli(dir, ["scan", "--staged"]);
  assert.equal(code, 1);
  assert.match(stdout, /docs\/setup\.md:3/);
  assert.match(stdout, /stripe-key/);
  assert.ok(!stdout.includes(LIVE), "the report printed the secret value");
});

test("scan --staged exits 0 on a clean tree", () => {
  const dir = makeRepo({ "docs/setup.md": "# Setup\n\nnothing here\n" });
  const { code } = runCli(dir, ["scan", "--staged"]);
  assert.equal(code, 0);
});

test("scan --staged reads the STAGED content, not the worktree", () => {
  const dir = makeRepo({ "a.md": "clean\n" });
  writeFileSync(path.join(dir, "a.md"), "STRIPE_KEY=" + LIVE + "\n");
  const { code } = runCli(dir, ["scan", "--staged"]);
  assert.equal(code, 0, "an unstaged edit must not block the commit");
});

test("scan with no --staged walks tracked files", () => {
  const dir = makeRepo({ "docs/setup.md": "STRIPE_KEY=" + LIVE + "\n" }, { commit: true });
  const { code, stdout } = runCli(dir, ["scan"]);
  assert.equal(code, 1);
  assert.match(stdout, /docs\/setup\.md/);
});

test("the allowlist suppresses a finding and the exit code goes to 0", () => {
  const dir = makeRepo({
    "test/fixtures/keys.txt": "STRIPE_KEY=" + LIVE + "\n",
    ".secretgate.json": JSON.stringify({ version: 1, paths: ["^test/fixtures/"] }),
  });
  const { code } = runCli(dir, ["scan", "--staged"]);
  assert.equal(code, 0);
});

test("a stale allowlist entry is reported but does not change the exit code", () => {
  const dir = makeRepo({
    "a.md": "clean\n",
    ".secretgate.json": JSON.stringify({ version: 1, regexes: ["matches-nothing-at-all"] }),
  });
  const { code, stdout } = runCli(dir, ["scan", "--staged"]);
  assert.equal(code, 0);
  assert.match(stdout, /stale/i);
  assert.match(stdout, /matches-nothing-at-all/);
});

test("binary and oversize files are skipped and the skip is reported", () => {
  const dir = makeRepo({
    "logo.png": String.fromCharCode(0, 1) + "PNG" + LIVE,
    "a.md": "clean\n",
  });
  const { code, stdout } = runCli(dir, ["scan", "--staged"]);
  assert.equal(code, 0);
  assert.match(stdout, /skipped/i);
  assert.match(stdout, /logo\.png/);
});

test("--version prints the version and exits 0", () => {
  const dir = makeRepo({ "a.md": "clean\n" });
  const { code, stdout } = runCli(dir, ["--version"]);
  assert.equal(code, 0);
  assert.match(stdout.trim(), /^\d+\.\d+\.\d+$/);
});

test("an unknown command exits 2 and prints usage", () => {
  const dir = makeRepo({ "a.md": "clean\n" });
  const { code, stderr } = runCli(dir, ["frobnicate"]);
  assert.equal(code, 2);
  assert.match(stderr, /usage/i);
});

test("running outside a git repo exits 2 with a clear message", () => {
  const { code, stderr } = runCli(tmpdir(), ["scan", "--staged"]);
  assert.equal(code, 2);
  assert.match(stderr, /not a git repository/i);
});

// Correction 2: git sets GIT_DIR, GIT_INDEX_FILE and often
// GIT_CONFIG_PARAMETERS for every hook it invokes, so a poisoned git
// environment is the normal case when this CLI runs as a pre-commit hook,
// not an edge case. An inherited GIT_DIR pointing at a different repo, or
// GIT_CONFIG_PARAMETERS overriding core.excludesFile, must not change what
// this scan finds. The lowercase git_config_parameters checks the
// case-insensitive half of that same requirement (Windows resolves env
// names case-insensitively).
test("an inherited GIT_DIR and lowercase git_config_parameters must not stop --staged from finding the secret", () => {
  const dir = makeRepo({ "docs/setup.md": "# Setup\n\nSTRIPE_KEY=" + LIVE + "\n" });
  const otherRepo = makeRepo({});

  const poisonedEnv = {
    ...process.env,
    GIT_DIR: path.join(otherRepo, ".git"),
    git_config_parameters: "'core.excludesFile=/dev/null'",
  };

  const { code, stdout } = runCli(dir, ["scan", "--staged"], { env: poisonedEnv });
  assert.equal(code, 1, "poisoned GIT_* env must not turn a real finding into a clean scan");
  assert.match(stdout, /docs\/setup\.md:3/);
});

// --- Task 9 review round 1 -------------------------------------------------

// FINDING B: explicit-path arguments were joined straight onto the repo
// root, so anything but a root-relative path (typed from a subdirectory, an
// absolute path, or a plain typo) reported the repo clean instead of
// scanning the right file or refusing to guess.
test("scan with an explicit path typed from a subdirectory finds the secret", () => {
  const dir = makeRepo({ "docs/setup.md": "STRIPE_KEY=" + LIVE + "\n" }, { commit: true });
  const { code, stdout } = runCli(dir, ["scan", "setup.md"], { cwd: path.join(dir, "docs") });
  assert.equal(code, 1, "a path typed relative to the caller's cwd must still be found");
  assert.match(stdout, /docs\/setup\.md/);
});

test("scan with an absolute explicit path finds the secret", () => {
  const dir = makeRepo({ "docs/setup.md": "STRIPE_KEY=" + LIVE + "\n" }, { commit: true });
  const { code, stdout } = runCli(dir, ["scan", path.join(dir, "docs", "setup.md")]);
  assert.equal(code, 1);
  assert.match(stdout, /docs\/setup\.md/);
});

test("scan with a nonexistent explicit path exits 2, not 0", () => {
  const dir = makeRepo({ "docs/setup.md": "STRIPE_KEY=" + LIVE + "\n" }, { commit: true });
  const { code, stderr } = runCli(dir, ["scan", "does-not-exist.md"]);
  assert.equal(code, 2, 'a typo in an explicit path must never read back as "repo is clean"');
  assert.match(stderr, /does-not-exist\.md/);
});

// FINDING C: --diff-filter=ACMR silently drops type changes (T) - e.g. a
// tracked symlink replaced in the index by a regular file holding a
// credential, an ordinary move on POSIX. Built via plumbing (hash-object +
// update-index --cacheinfo) rather than a real OS symlink, so this
// reproduces identically on Windows.
test("a staged type-change (symlink -> regular file) is scanned, not dropped by the diff filter", () => {
  const dir = makeRepo({});
  const symlinkBlob = gitPlumbing(dir, ["hash-object", "-w", "--stdin"], "somewhere");
  runGit(dir, "update-index", "--add", "--cacheinfo", `120000,${symlinkBlob},cfg`);
  runGit(dir, "commit", "-qm", "cfg as symlink");

  const secretBlob = gitPlumbing(dir, ["hash-object", "-w", "--stdin"], "STRIPE_KEY=" + LIVE + "\n");
  runGit(dir, "update-index", "--cacheinfo", `100644,${secretBlob},cfg`);

  // Confirm the fixture actually produces a T status before trusting the
  // scan result either way.
  const status = gitPlumbing(dir, ["diff", "--cached", "--name-status"]);
  assert.match(status, /^T\s+cfg/m, "fixture did not produce a type-change - test is not exercising Finding C");

  const { code, stdout } = runCli(dir, ["scan", "--staged"]);
  assert.equal(code, 1, "a type-changed staged file must still be scanned");
  assert.match(stdout, /cfg/);
});

// FINDING D: a `git show` failure (a gitlink with no blob to print, a spawn
// failure) was indistinguishable from "nothing to do" - collect() treated a
// bare `null` as absent rather than unreadable, so the file vanished from
// both the findings and the skip list.
test("a staged gitlink (submodule reference) is reported as skipped, not silently dropped", () => {
  const dir = makeRepo({});
  const fakeSha = "a".repeat(40);
  runGit(dir, "update-index", "--add", "--cacheinfo", `160000,${fakeSha},vendor/lib`);

  const { code, stdout } = runCli(dir, ["scan", "--staged"]);
  assert.equal(code, 0, "a gitlink alone is not a credential finding");
  assert.match(stdout, /skipped/i, "an unreadable staged path must be reported, not silently dropped");
  assert.match(stdout, /vendor\/lib/);
});

// FINDING E (coordinator's ruling): the default exit code stays 0 for a
// skip alone (a pre-commit hook must not brick every commit that touches an
// image), but --strict exists for CI, where a skip should fail the build.
test("a skipped file does not fail the scan by default, but --strict makes it fail", () => {
  const dir = makeRepo({
    "logo.png": String.fromCharCode(0, 1) + "PNG",
    "a.md": "clean\n",
  });
  const plain = runCli(dir, ["scan", "--staged"]);
  assert.equal(plain.code, 0, "a skip alone must not block a commit by default");

  const strict = runCli(dir, ["scan", "--staged", "--strict"]);
  assert.equal(strict.code, 1, "--strict must fail the scan when anything was skipped");
  assert.match(strict.stdout, /skipped/i);
});

test("the skip output mentions --strict so the option is discoverable", () => {
  const dir = makeRepo({
    "logo.png": String.fromCharCode(0, 1) + "PNG",
    "a.md": "clean\n",
  });
  const { stdout } = runCli(dir, ["scan", "--staged"]);
  assert.match(stdout, /--strict/);
});

// Small fix: the remediation text pointed at "lib/cli.mjs", which is wrong
// both from the repo root and in a repo where install (Task 11) has
// vendored this file to scripts/secret-gate/cli.mjs - name the location a
// caller can actually run.
test("the remediation text names the vendored fix command", () => {
  const dir = makeRepo({ "docs/setup.md": "STRIPE_KEY=" + LIVE + "\n" });
  const { stdout } = runCli(dir, ["scan", "--staged"]);
  assert.match(stdout, /scripts\/secret-gate\/cli\.mjs fix --staged/);
});

// FINDING F: makeRepo()'s own git calls must be as immune to a poisoned git
// environment as the CLI itself is (Correction 2) - this is the identical
// hole, just in the test infrastructure instead of the product. A fixture
// built while GIT_DIR or an excludesFile override is inherited must still
// behave like an ordinary repo: not stage nothing (a vacuous "expect exit 0"
// pass) and not throw outright (breaking every fixture if this suite is
// ever run from inside a git hook, this plugin's own pre-commit included).
test("makeRepo stages files correctly even when the process has a poisoned excludesFile override", () => {
  const excludesDir = mkdtempSync(path.join(tmpdir(), "poison-excludes-"));
  const excludesFile = path.join(excludesDir, "ignore-md");
  writeFileSync(excludesFile, "*.md\n");

  const saved = {
    GIT_CONFIG_COUNT: process.env.GIT_CONFIG_COUNT,
    GIT_CONFIG_KEY_0: process.env.GIT_CONFIG_KEY_0,
    GIT_CONFIG_VALUE_0: process.env.GIT_CONFIG_VALUE_0,
  };
  process.env.GIT_CONFIG_COUNT = "1";
  process.env.GIT_CONFIG_KEY_0 = "core.excludesFile";
  process.env.GIT_CONFIG_VALUE_0 = excludesFile;
  try {
    const dir = makeRepo({ "docs/setup.md": "STRIPE_KEY=" + LIVE + "\n" });
    const { code, stdout } = runCli(dir, ["scan", "--staged"]);
    // If the poisoned excludesFile leaked into makeRepo()'s own `git add
    // -A`, docs/setup.md would never be staged at all, and this would
    // report clean for the wrong reason entirely - a vacuous pass, not a
    // real one.
    assert.equal(code, 1, "docs/setup.md must actually be staged, not silently excluded");
    assert.match(stdout, /docs\/setup\.md/);
  } finally {
    for (const [key, value] of Object.entries(saved)) {
      if (value === undefined) delete process.env[key];
      else process.env[key] = value;
    }
  }
});

test("makeRepo works even when the outer process has GIT_DIR set (e.g. running under a hook)", () => {
  const saved = process.env.GIT_DIR;
  process.env.GIT_DIR = path.join(tmpdir(), "not-a-real-gitdir-" + Date.now());
  try {
    const dir = makeRepo({ "a.md": "clean\n" });
    const { code } = runCli(dir, ["scan", "--staged"]);
    assert.equal(code, 0);
  } finally {
    if (saved === undefined) delete process.env.GIT_DIR;
    else process.env.GIT_DIR = saved;
  }
});

// --- Task 10 review corrections ---------------------------------------------

// Correction 1a: a directory explicit argument used to sail through
// existsSync (true for a directory) and fail later inside readFileSync as an
// unlabeled EISDIR skip - which reports plain exit 0. `scan .` in someone's
// CI would then be a permanently green gate that scanned nothing. A
// directory argument must be rejected outright (exit 2) rather than
// expanded or silently skipped - see cli.mjs for the "why reject rather
// than expand" note.
test("scan with a directory argument exits 2, not 0 (a bare 'docs' path)", () => {
  const dir = makeRepo({ "docs/setup.md": "STRIPE_KEY=" + LIVE + "\n" }, { commit: true });
  const { code, stderr } = runCli(dir, ["scan", "docs"]);
  assert.equal(code, 2, "a directory argument must never read back as a clean scan");
  assert.match(stderr, /docs/);
});

test("scan with a trailing-slash directory argument exits 2, not 0 ('docs/')", () => {
  const dir = makeRepo({ "docs/setup.md": "STRIPE_KEY=" + LIVE + "\n" }, { commit: true });
  const { code, stderr } = runCli(dir, ["scan", "docs/"]);
  assert.equal(code, 2);
  assert.match(stderr, /docs/);
});

test("scan '.' exits 2, not a silently-clean 0", () => {
  const dir = makeRepo({ "docs/setup.md": "STRIPE_KEY=" + LIVE + "\n" }, { commit: true });
  const { code, stderr } = runCli(dir, ["scan", "."]);
  assert.equal(code, 2, "'scan .' must not become a permanently green gate that scanned nothing");
  assert.match(stderr, /\./);
});

// Correction 1b: path.win32.relative("C:/repo", "D:/secrets/keys.env") returns
// the absolute path unchanged (no leading ".."), so the existing
// dotdot-only outside-the-repo guard let a cross-drive path through, where
// it degraded to an ENOENT skip and a plain exit 0. Reproduced with `subst`
// (no admin rights required) rather than assuming a second physical drive
// exists on the machine running this suite.
test(
  "an absolute path on a different drive letter is rejected as outside the repo, not silently skipped",
  { skip: process.platform !== "win32" ? "cross-drive paths are a Windows-only concept" : false },
  () => {
    const letter = ["Z", "Y", "X", "W", "V", "U"].find((l) => !existsSync(`${l}:\\`));
    assert.ok(letter, "no free drive letter available to subst for this test");

    const target = mkdtempSync(path.join(tmpdir(), "cross-drive-"));
    writeFileSync(path.join(target, "keys.env"), "STRIPE_KEY=" + LIVE + "\n");

    const substResult = spawnSync("subst", [`${letter}:`, target]);
    assert.equal(substResult.status, 0, "subst failed to create the virtual drive - cannot exercise this guard");

    try {
      const dir = makeRepo({ "a.md": "clean\n" }, { commit: true });
      const { code, stderr } = runCli(dir, ["scan", `${letter}:\\keys.env`]);
      assert.equal(code, 2, "a cross-drive path must be rejected, not degrade into an ENOENT skip (exit 0)");
      assert.match(stderr, /outside the repository/i);
    } finally {
      spawnSync("subst", [`${letter}:`, "/D"]);
      rmSync(target, { recursive: true, force: true });
    }
  },
);

// Correction 2: --diff-filter=ACMR (later ACMRT) is an allowlist of status
// letters closed by NAME rather than by CLASS - the same mistake this
// plugin has now made three times (T had to be added after a symlink-swap
// slipped through). --diff-filter=d (lowercase - exclude deletions) is
// deny-by-default: it survives any status letter git adds later. This
// fixture stages a type-change (T), a deletion (D) and a plain add (A)
// together and checks all three are handled correctly in one pass.
test("--diff-filter=d scans an added file and a type-change but excludes a deletion, all staged together", () => {
  // gone.md's content is deliberately unrelated to new.md's - identical
  // content would let git's rename detection report this pair as R100
  // instead of a plain D + A, which would not exercise the deletion branch
  // at all.
  const dir = makeRepo({ "keep.md": "clean\n", "gone.md": "nothing secret about this file at all\n" }, { commit: true });

  const symlinkBlob = gitPlumbing(dir, ["hash-object", "-w", "--stdin"], "somewhere");
  runGit(dir, "update-index", "--add", "--cacheinfo", `120000,${symlinkBlob},cfg`);
  runGit(dir, "commit", "-qm", "cfg as symlink");

  const secretBlob = gitPlumbing(dir, ["hash-object", "-w", "--stdin"], "STRIPE_KEY=" + LIVE + "\n");
  runGit(dir, "update-index", "--cacheinfo", `100644,${secretBlob},cfg`);
  runGit(dir, "rm", "--cached", "-q", "gone.md");
  writeFileSync(path.join(dir, "new.md"), "STRIPE_KEY=" + LIVE + "\n");
  runGit(dir, "add", "new.md");

  const status = gitPlumbing(dir, ["diff", "--cached", "--name-status"]);
  assert.match(status, /^T\s+cfg/m, "fixture did not produce a type-change (T)");
  assert.match(status, /^D\s+gone\.md/m, "fixture did not produce a deletion (D)");
  assert.match(status, /^A\s+new\.md/m, "fixture did not produce an add (A)");

  const { code, stdout } = runCli(dir, ["scan", "--staged"]);
  assert.equal(code, 1, "the type-change and the new file must both be scanned");
  assert.match(stdout, /cfg/);
  assert.match(stdout, /new\.md/);
  assert.ok(!stdout.includes("gone.md"), "a deleted path has nothing staged to scan and must not be reported");
});
