import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync, mkdtempSync, writeFileSync, copyFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import path from "node:path";
import { tmpdir } from "node:os";
import { execFileSync } from "node:child_process";
import { runHook } from "./helpers/run-hook.mjs";
import { makeRepo, runGit } from "./helpers/temp-repo.mjs";
import { gitIgnores } from "../lib/gitignore.mjs";
import { MAX_BYTES } from "../hooks/io.mjs";

const PLUGIN = path.dirname(path.dirname(fileURLToPath(import.meta.url)));
const TOKEN = "ghp_" + "f".repeat(36);
const STRIPE_KEY = "sk_live_" + "a".repeat(20);

test("PostToolUse: rewrites the result and reports the count", async () => {
  const { code, stdout, stderr } = await runHook("redact-tool-output.mjs", {
    hook_event_name: "PostToolUse",
    tool_name: "Bash",
    tool_response: { stdout: "GITHUB_TOKEN=" + TOKEN, stderr: "", interrupted: false },
  });
  assert.equal(code, 0);
  assert.equal(stderr, "");
  assert.ok(!stdout.includes(TOKEN), "the hook leaked the secret into its own output");
  const out = JSON.parse(stdout);
  assert.equal(out.hookSpecificOutput.hookEventName, "PostToolUse");
  assert.equal(out.hookSpecificOutput.updatedToolOutput.interrupted, false);
  assert.match(out.hookSpecificOutput.additionalContext, /replaced 1 secret/);
});

test("PostToolUse: prints nothing at all for a clean payload", async () => {
  const { code, stdout } = await runHook("redact-tool-output.mjs", {
    hook_event_name: "PostToolUse",
    tool_name: "Bash",
    tool_response: { stdout: "246 tests, 246 passing", exitCode: 0 },
  });
  assert.equal(code, 0);
  assert.equal(stdout, "");
});

test("PostToolUse: fails open on malformed and on empty stdin", async () => {
  for (const payload of ["this is not json{{{", ""]) {
    const { code, stdout } = await runHook("redact-tool-output.mjs", payload);
    assert.equal(code, 0);
    assert.equal(stdout, "");
  }
});

test("PostToolUse: ignores an event that is not its own", async () => {
  const { code, stdout } = await runHook("redact-tool-output.mjs", {
    hook_event_name: "PreToolUse",
    tool_name: "Bash",
    tool_response: { stdout: "GITHUB_TOKEN=" + TOKEN },
  });
  assert.equal(code, 0);
  assert.equal(stdout, "");
});

test("UserPromptSubmit: rewrites a pasted secret out of the prompt", async () => {
  const { code, stdout } = await runHook("redact-prompt.mjs", {
    hook_event_name: "UserPromptSubmit",
    prompt: "put this in the env file: STRIPE_KEY=" + STRIPE_KEY,
  });
  assert.equal(code, 0);
  assert.ok(!stdout.includes(STRIPE_KEY), "the hook leaked the secret into its own output");
  const out = JSON.parse(stdout);
  assert.equal(out.hookSpecificOutput.hookEventName, "UserPromptSubmit");
  assert.match(out.hookSpecificOutput.updatedPrompt, /\[REDACTED stripe-key #1\]/);
  assert.match(out.hookSpecificOutput.updatedPrompt, /^put this in the env file: /);
  assert.match(out.systemMessage, /1 secret redacted from your prompt/);
});

test("UserPromptSubmit: says nothing for a clean prompt", async () => {
  const { code, stdout } = await runHook("redact-prompt.mjs", {
    hook_event_name: "UserPromptSubmit",
    prompt: "run the tests and tell me what broke",
  });
  assert.equal(code, 0);
  assert.equal(stdout, "");
});

test("UserPromptSubmit: #allow-secret is an escape hatch", async () => {
  const { code, stdout } = await runHook("redact-prompt.mjs", {
    hook_event_name: "UserPromptSubmit",
    prompt: "#allow-secret STRIPE_KEY=" + STRIPE_KEY,
  });
  assert.equal(code, 0);
  assert.equal(stdout, "");
});

test("UserPromptSubmit: fails open on malformed stdin", async () => {
  const { code, stdout } = await runHook("redact-prompt.mjs", "}}}not json");
  assert.equal(code, 0);
  assert.equal(stdout, "");
});

test("io.mjs MAX_BYTES cap: oversized input exits 0 with no output", async () => {
  // MAX_BYTES is 8388608. Payload 8388700 bytes exceeds limit by 92 bytes.
  // Cap present: read aborts when size exceeds MAX_BYTES, returns null, hook exits 0.
  // Cap removed: secret at end would be found and redacted (test would fail).
  // The 92-byte cushion avoids pipe buffer issues while proving the cap works.
  const filler = "x".repeat(8388700 - 80 - 28);
  const largePayload =
    '{"hook_event_name":"PostToolUse","tool_name":"Test","tool_response":{"stdout":"' +
    filler +
    STRIPE_KEY +
    '"}}';
  const { code, stdout } = await runHook("redact-tool-output.mjs", largePayload);
  assert.equal(code, 0);
  assert.equal(stdout, "");
});

test("hooks.json registers all three hooks against the right events", () => {
  const cfg = JSON.parse(readFileSync(path.join(PLUGIN, "hooks", "hooks.json"), "utf8"));
  assert.ok(cfg.hooks.PostToolUse, "PostToolUse is not registered");
  assert.ok(cfg.hooks.UserPromptSubmit, "UserPromptSubmit is not registered");
  assert.ok(cfg.hooks.PreToolUse, "PreToolUse is not registered");
  assert.equal(cfg.hooks.PreToolUse[0].matcher, "Write|Edit|NotebookEdit");
  const commands = JSON.stringify(cfg);
  for (const script of ["redact-tool-output.mjs", "redact-prompt.mjs", "guard-write.mjs"]) {
    assert.ok(commands.includes(script), script + " is not wired in hooks.json");
  }
});

// --- Task 7: the PreToolUse write guard ------------------------------------

const LIVE = "sk_live_" + "b".repeat(20);

// True when `git check-ignore` says `relPath` (relative to `cwd`) is
// ignored. Used to assert a fixture's premise before we rely on it - e.g.
// "this .gitignore pattern really does match this path" - so a future edit
// that breaks the pattern fails loudly instead of leaving a regression test
// that passes without pinning anything.
function isIgnoredByGit(cwd, relPath) {
  try {
    execFileSync("git", ["check-ignore", "--quiet", "--", relPath], { cwd, stdio: "ignore" });
    return true;
  } catch {
    return false;
  }
}

test("PreToolUse: denies writing a secret into a tracked file", async () => {
  // Finding B (round 2): `docs/` must actually exist on disk before this
  // write. `makeRepo` only mkdirs for files it's given, so without an entry
  // under `docs/` the target's parent directory would not exist yet, the
  // guard would take the ENOENT fallback ("git could not answer"), and this
  // test would keep passing for the wrong reason - a non-.env name denies
  // either way, so it would pin nothing about the git-answered path it
  // claims to cover. Asserting on the reason, not just the outcome, is what
  // catches that.
  const cwd = makeRepo({
    ".gitignore": ".env\n.env.local\n",
    "docs/.gitkeep": "",
  });
  const { code, stdout } = await runHook(
    "guard-write.mjs",
    {
      hook_event_name: "PreToolUse",
      tool_name: "Write",
      tool_input: { file_path: path.join(cwd, "docs", "setup.md"), content: "STRIPE_KEY=" + LIVE },
    },
    { cwd },
  );
  assert.equal(code, 0);
  assert.ok(!stdout.includes(LIVE), "the deny reason leaked the value");
  const out = JSON.parse(stdout);
  assert.equal(out.hookSpecificOutput.permissionDecision, "deny");
  assert.match(out.hookSpecificOutput.permissionDecisionReason, /stripe-key/);
  assert.match(out.hookSpecificOutput.permissionDecisionReason, /setup\.md/);
  assert.match(
    out.hookSpecificOutput.permissionDecisionReason,
    /git tracks this path/,
    "this test claims to cover the git-answered (not ENOENT-fallback) path",
  );
});

test("PreToolUse: allows writing a secret into a gitignored .env", async () => {
  const cwd = makeRepo({
    ".gitignore": ".env\n.env.local\n",
  });
  const { code, stdout } = await runHook(
    "guard-write.mjs",
    {
      hook_event_name: "PreToolUse",
      tool_name: "Write",
      tool_input: { file_path: path.join(cwd, ".env.local"), content: "STRIPE_KEY=" + LIVE },
    },
    { cwd },
  );
  assert.equal(code, 0);
  assert.equal(stdout, "");
});

// Regression test for the --no-index bug described in the task brief.
//
// `git check-ignore --quiet --no-index -- <path>` answers from the ignore
// patterns alone, so it reports a TRACKED .env.production as "ignored" even
// though git is already carrying it. That flips the exemption backwards and
// lets a real key sail through into the one file nobody double-checks.
// Without --no-index, git's default behaviour already does the right thing:
// a tracked path is never "ignored", so it gets scanned like anything else.
//
// This repo's .gitignore covers .env.* (which would normally catch
// .env.production too), but the file is force-added and committed, so it is
// tracked. The guard MUST deny here. With --no-index this test fails; without
// it, it passes.
test("PreToolUse: denies a secret in a TRACKED .env.production (regression: --no-index inverts this)", async () => {
  const cwd = makeRepo({
    ".gitignore": ".env.*\n",
    ".env.production": "VITE_PUBLIC=1\n",
  });
  // Assert the fixture's own premise before relying on it: if a future edit
  // changed the pattern to something that no longer matches .env.production,
  // this force-add below would become a no-op and the test would pass while
  // pinning nothing.
  assert.ok(
    isIgnoredByGit(cwd, ".env.production"),
    "fixture premise broken: .gitignore does not match .env.production before it is force-tracked",
  );
  // makeRepo's own `git add -A` skipped .env.production because .gitignore
  // covers it. Force-add it and commit so it is genuinely tracked.
  runGit(cwd, "add", "-f", ".env.production");
  runGit(cwd, "commit", "-qm", "track env.production");

  const { code, stdout } = await runHook(
    "guard-write.mjs",
    {
      hook_event_name: "PreToolUse",
      tool_name: "Write",
      tool_input: { file_path: path.join(cwd, ".env.production"), content: "STRIPE_KEY=" + LIVE },
    },
    { cwd },
  );
  assert.equal(code, 0);
  assert.ok(!stdout.includes(LIVE), "the deny reason leaked the value");
  const out = JSON.parse(stdout);
  assert.equal(
    out.hookSpecificOutput.permissionDecision,
    "deny",
    "a tracked .env.production must be scanned like any other tracked file",
  );
});

test("PreToolUse: reads Edit new_string and NotebookEdit new_source", async () => {
  const cwd = makeRepo({
    ".gitignore": ".env\n.env.local\n",
  });
  for (const [tool, key] of [
    ["Edit", "new_string"],
    ["NotebookEdit", "new_source"],
  ]) {
    const { stdout } = await runHook(
      "guard-write.mjs",
      {
        hook_event_name: "PreToolUse",
        tool_name: tool,
        tool_input: { file_path: path.join(cwd, "notes.md"), [key]: "STRIPE_KEY=" + LIVE },
      },
      { cwd },
    );
    const out = JSON.parse(stdout);
    assert.equal(out.hookSpecificOutput.permissionDecision, "deny", tool + " was not blocked");
  }
});

test("PreToolUse: stays silent for clean content", async () => {
  const cwd = makeRepo({
    ".gitignore": ".env\n.env.local\n",
  });
  const { code, stdout } = await runHook(
    "guard-write.mjs",
    {
      hook_event_name: "PreToolUse",
      tool_name: "Write",
      tool_input: { file_path: path.join(cwd, "notes.md"), content: "# Notes\n\nnothing here\n" },
    },
    { cwd },
  );
  assert.equal(code, 0);
  assert.equal(stdout, "");
});

test("PreToolUse: outside a git repo, falls back to the .env name rule and says so", async () => {
  const cwd = mkdtempSync(path.join(tmpdir(), "secret-gate-nogit-"));
  const { stdout } = await runHook(
    "guard-write.mjs",
    {
      hook_event_name: "PreToolUse",
      tool_name: "Write",
      tool_input: { file_path: path.join(cwd, "notes.md"), content: "STRIPE_KEY=" + LIVE },
    },
    { cwd },
  );
  const out = JSON.parse(stdout);
  assert.equal(out.hookSpecificOutput.permissionDecision, "deny");
  // Wording fix (review Finding 6): "not a git repo" was flatly wrong for the
  // cross-repo case (Finding 1) where git DOES exist, it just can't answer
  // for this particular path. "could not answer" covers both truthfully.
  assert.match(out.hookSpecificOutput.permissionDecisionReason, /git could not answer/i);
});

test("PreToolUse: outside a git repo, an actual .env file is exempt by name and stays silent", async () => {
  const cwd = mkdtempSync(path.join(tmpdir(), "secret-gate-nogit-"));
  const { code, stdout } = await runHook(
    "guard-write.mjs",
    {
      hook_event_name: "PreToolUse",
      tool_name: "Write",
      tool_input: { file_path: path.join(cwd, ".env.local"), content: "STRIPE_KEY=" + LIVE },
    },
    { cwd },
  );
  assert.equal(code, 0);
  assert.equal(stdout, "");
});

test("PreToolUse: ignores an event that is not its own", async () => {
  const cwd = makeRepo({});
  const { code, stdout } = await runHook(
    "guard-write.mjs",
    {
      hook_event_name: "PostToolUse",
      tool_name: "Write",
      tool_input: { file_path: path.join(cwd, "notes.md"), content: "STRIPE_KEY=" + LIVE },
    },
    { cwd },
  );
  assert.equal(code, 0);
  assert.equal(stdout, "");
});

test("PreToolUse: fails open on malformed stdin", async () => {
  const cwd = makeRepo({});
  const { code, stdout } = await runHook("guard-write.mjs", "}}}not json", { cwd });
  assert.equal(code, 0);
  assert.equal(stdout, "");
});

// --- Task 7 fix round: review findings ---------------------------------

// Finding 1 (critical): the session's cwd is not the target file's repo.
//
// A session working in repo A can still Write into a path in repo B (ten
// projects share this machine, and cross-repo writes are routine). Asking
// git from repo A's cwd about a path in repo B fails with "outside
// repository" -> available:false -> the old code fell through to the
// name-based exemption and silently allowed a tracked .env.production in
// repo B through. The fix resolves git's cwd from the file's own directory
// instead of the caller's.
test("PreToolUse: denies a secret written into a DIFFERENT repo's tracked .env.production (Finding 1)", async () => {
  const targetRepo = makeRepo({
    ".gitignore": ".env.*\n",
    ".env.production": "VITE_PUBLIC=1\n",
  });
  assert.ok(
    isIgnoredByGit(targetRepo, ".env.production"),
    "fixture premise broken: .gitignore does not match .env.production before it is force-tracked",
  );
  runGit(targetRepo, "add", "-f", ".env.production");
  runGit(targetRepo, "commit", "-qm", "track env.production");

  // The session's own cwd is a completely unrelated repo.
  const sessionRepo = makeRepo({});

  const { code, stdout } = await runHook(
    "guard-write.mjs",
    {
      hook_event_name: "PreToolUse",
      tool_name: "Write",
      tool_input: { file_path: path.join(targetRepo, ".env.production"), content: "STRIPE_KEY=" + LIVE },
    },
    { cwd: sessionRepo },
  );
  assert.equal(code, 0);
  assert.ok(!stdout.includes(LIVE), "the deny reason leaked the value");
  const out = JSON.parse(stdout);
  assert.equal(
    out.hookSpecificOutput.permissionDecision,
    "deny",
    "a tracked .env.production in a different repo than the session's cwd must still be scanned",
  );
});

// Finding 2 (important): a non-string file_path must not disarm the guard.
//
// tool_input.file_path is attacker/tool-controlled shape, not guaranteed to
// be a string. Before the fix, a non-string value reached
// filePath.replaceAll() inside envExemption, threw a TypeError, and io.mjs's
// uncaughtException/unhandledRejection handler turned that into a silent
// exit 0 - even though findSecrets had already found a real credential in
// the content.
test("PreToolUse: denies when file_path is not a string, rather than silently allowing (Finding 2)", async () => {
  const cwd = makeRepo({});
  const { code, stdout } = await runHook(
    "guard-write.mjs",
    {
      hook_event_name: "PreToolUse",
      tool_name: "Write",
      tool_input: { file_path: 12345, content: "STRIPE_KEY=" + LIVE },
    },
    { cwd },
  );
  assert.equal(code, 0);
  assert.ok(!stdout.includes(LIVE), "the deny reason leaked the value");
  const out = JSON.parse(stdout);
  assert.equal(out.hookSpecificOutput.permissionDecision, "deny");
});

// Finding 3 (important): a hung git must not become an allow.
//
// hooks.json gives this hook a 15-second budget. Without its own timeout, a
// git that blocks (index.lock contention, a stalled network filesystem, a
// slow AV scan) burns that budget, the harness kills the hook, and a killed
// PreToolUse hook does not deny. gitIgnores already handled
// `result.status === null` (spawnSync's own timeout signature) - the bug was
// only that the `timeout` option was never set, so that branch never fired
// on its own.
//
// This calls gitIgnores() directly rather than going through the hook
// subprocess: it needs to fake out `git` itself on PATH, which is simplest
// to do in-process for the duration of one call.
//
// The fake has to be a genuine .exe: Node's spawnSync (no shell) resolves an
// extension-less command by appending ".exe" the way CreateProcess does, NOT
// by trying PATHEXT the way cmd.exe would - a same-named "git.cmd" earlier on
// PATH is silently skipped in favour of the real git.exe found later. A copy
// of the current node binary IS a real .exe, so it resolves.
//
// It also has to hang via a synchronous busy-loop, not `setTimeout`: Node
// runs a `NODE_OPTIONS=--require` hook synchronously but then immediately
// moves on to load argv[1] ("check-ignore") as its main module, which throws
// "Cannot find module" and exits almost instantly - an async timer scheduled
// in the hook never gets the chance to fire. A busy-loop blocks that startup
// sequence for real.
function makeHangingGit(hangMs) {
  const dir = mkdtempSync(path.join(tmpdir(), "fake-hanging-git-"));
  const gitExe = path.join(dir, "git.exe");
  copyFileSync(process.execPath, gitExe);
  const sleeper = path.join(dir, "sleeper.js");
  writeFileSync(sleeper, `const end = Date.now() + ${hangMs}; while (Date.now() < end) {} process.exit(0);`);
  return { dir, sleeper };
}

test("gitIgnores: times out rather than hanging forever when git itself hangs (Finding 3)", () => {
  const cwd = makeRepo({});
  const { dir: fakeGitDir, sleeper } = makeHangingGit(7000); // hangs ~7s; the guard's own timeout is 5s
  const originalPath = process.env.PATH;
  const originalNodeOptions = process.env.NODE_OPTIONS;
  process.env.PATH = fakeGitDir + path.delimiter + originalPath;
  process.env.NODE_OPTIONS = "--require " + sleeper;
  try {
    const start = Date.now();
    const result = gitIgnores(path.join(cwd, "notes.md"), cwd);
    const elapsed = Date.now() - start;
    assert.ok(
      elapsed < 6000,
      `gitIgnores took ${elapsed}ms against a hanging git; expected it to be killed well under 6000ms`,
    );
    assert.deepEqual(result, { available: false, ignored: false });
  } finally {
    process.env.PATH = originalPath;
    if (originalNodeOptions === undefined) delete process.env.NODE_OPTIONS;
    else process.env.NODE_OPTIONS = originalNodeOptions;
  }
});

// Finding 4: oversized input in the WRITE GUARD must deny, not fail open.
//
// This hook is being asked to certify content it did not get to examine, so
// silence (= allow) is the dangerous answer here, unlike the two redactor
// hooks where the alternative on oversize is corrupting output. Filler is
// cheap repeated "x" - the point is that the payload is too big to read at
// all, not that it contains anything the detector needs to work on.
test("PreToolUse: denies rather than allowing when the input is too large to scan (Finding 4)", async () => {
  const cwd = makeRepo({});
  const filePathJson = JSON.stringify(path.join(cwd, "notes.md"));
  const prefix = `{"hook_event_name":"PreToolUse","tool_name":"Write","tool_input":{"file_path":${filePathJson},"content":"`;
  const suffix = `"}}`;
  const overBy = 200;
  const fillerLength = MAX_BYTES - prefix.length - suffix.length + overBy;
  const payload = prefix + "x".repeat(fillerLength) + suffix;
  assert.ok(payload.length > MAX_BYTES, "test payload must actually exceed MAX_BYTES");

  const { code, stdout } = await runHook("guard-write.mjs", payload, { cwd });
  assert.equal(code, 0);
  const out = JSON.parse(stdout);
  assert.equal(out.hookSpecificOutput.permissionDecision, "deny");
  assert.match(out.hookSpecificOutput.permissionDecisionReason, /too large|cannot be checked/i);
});

// Finding 5: the file's basename can itself be credential-shaped (a pasted
// key used as a filename). "Never print a secret value" has no carve-out for
// the name field.
test("PreToolUse: redacts a credential-shaped file name out of the deny message (Finding 5)", async () => {
  const cwd = makeRepo({});
  const secretName = "sk_live_" + "c".repeat(20);
  const contentToken = "ghp_" + "e".repeat(36);
  const { code, stdout } = await runHook(
    "guard-write.mjs",
    {
      hook_event_name: "PreToolUse",
      tool_name: "Write",
      tool_input: {
        file_path: path.join(cwd, "docs", secretName),
        content: "a token lives here: " + contentToken,
      },
    },
    { cwd },
  );
  assert.equal(code, 0);
  assert.ok(!stdout.includes(secretName), "the deny message leaked the credential-shaped file name");
  assert.ok(!stdout.includes(contentToken), "the deny message leaked the content credential");
  const out = JSON.parse(stdout);
  assert.equal(out.hookSpecificOutput.permissionDecision, "deny");
  assert.match(out.hookSpecificOutput.permissionDecisionReason, /\[REDACTED stripe-key #\d+\]/);
  assert.match(out.systemMessage, /\[REDACTED stripe-key #\d+\]/);
});

// --- Task 7 fix round 2: a sibling hole in the round-1 Critical fix --------

// Finding A (critical, round 2): resolving git's cwd from the file's own
// directory (round 1's Finding 1 fix) broke the moment that directory does
// not exist yet. Write routinely creates a brand new folder, and Claude Code
// always sends an absolute file_path, so this was not a corner case: it fired
// on every real Write into a new folder. spawnSync ENOENTs, gitIgnores
// reports available:false, and control fell through to the SAME name-based
// exemption round 1's Finding 1 closed - through a different door.
//
// The two Criticals are in tension: a fix for "wrong repo" (round 1) can
// silently reintroduce "wrong repo" (round 2) by falling back to the
// session's cwd whenever the immediate parent is missing. This is tested as
// a matrix rather than a single case for exactly that reason - each case
// below isolates one axis (which repo, does the folder exist, is the path
// actually ignored) so a fix that breaks one does not hide behind the others
// passing.
test("PreToolUse: a not-yet-existing folder does not disable the git answer (Finding A matrix)", async () => {
  // .gitignore covers .env and .env.local by NAME only - not .env.production
  // - and both patterns are depth-agnostic (no leading slash), so they also
  // cover a nested path once that path is evaluated, even before the folder
  // holding it exists on disk.
  const repoA = makeRepo({ ".gitignore": ".env\n.env.local\n" });
  const repoB = makeRepo({}); // a second, wholly unrelated repo used as "session cwd"
  const secretContent = "STRIPE_KEY=" + LIVE;

  const deny = async (filePath, cwd) => {
    const { stdout } = await runHook(
      "guard-write.mjs",
      {
        hook_event_name: "PreToolUse",
        tool_name: "Write",
        tool_input: { file_path: filePath, content: secretContent },
      },
      { cwd },
    );
    return stdout;
  };

  // Case 1: new folder, SAME repo as the session cwd. .env.production is not
  // covered by the .gitignore, so this must deny regardless of whether the
  // folder exists yet.
  const case1 = await deny(path.join(repoA, "new-folder-1", ".env.production"), repoA);
  assert.equal(
    JSON.parse(case1).hookSpecificOutput.permissionDecision,
    "deny",
    "case 1 (new folder, same repo as session cwd) must deny",
  );

  // Case 2: new folder, DIFFERENT repo than the session cwd. The walk-up must
  // land inside repoA (where the file actually lives, and whose nearest
  // EXISTING ancestor is its own root), not fall back to repoB just because
  // the immediate parent is missing.
  const case2 = await deny(path.join(repoA, "new-folder-2", ".env.production"), repoB);
  assert.equal(
    JSON.parse(case2).hookSpecificOutput.permissionDecision,
    "deny",
    "case 2 (new folder, different repo than session cwd) must deny",
  );

  // Case 3: EXISTING folder, different repo than the session cwd. This is
  // round 1's Finding 1 case, repeated here so the matrix stands on its own
  // without depending on another test elsewhere in the file.
  const case3 = await deny(path.join(repoA, ".env.production"), repoB);
  assert.equal(
    JSON.parse(case3).hookSpecificOutput.permissionDecision,
    "deny",
    "case 3 (existing folder, different repo than session cwd) must deny",
  );

  // Case 4: a genuinely gitignored .env file in a NEW folder must still be
  // ALLOWED. This is the case a naive "when in doubt, deny" fix would break -
  // the walk-up must not turn every .env* write into a deny regardless of
  // whether it is actually ignored.
  const case4 = await deny(path.join(repoA, "new-folder-3", ".env.local"), repoA);
  assert.equal(case4, "", "case 4 (gitignored .env in a new folder) must stay silent");
});

