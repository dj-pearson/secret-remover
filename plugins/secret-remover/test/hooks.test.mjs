import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync, mkdtempSync, writeFileSync, copyFileSync, chmodSync, symlinkSync, rmSync } from "node:fs";
import { fileURLToPath } from "node:url";
import path from "node:path";
import { tmpdir } from "node:os";
import { execFileSync } from "node:child_process";
import { runHook } from "./helpers/run-hook.mjs";
import { makeRepo, runGit } from "./helpers/temp-repo.mjs";
import { gitIgnores } from "../lib/gitignore.mjs";
import { MAX_BYTES } from "../hooks/io.mjs";
import { ALLOWLIST_FILE } from "../lib/allowlist.mjs";

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
// The fake is built differently per platform, because "put a fake `git`
// earlier on PATH" means two different things:
//
// WINDOWS: it has to be a genuine .exe. Node's spawnSync (no shell) resolves
// an extension-less command by appending ".exe" the way CreateProcess does,
// NOT by trying PATHEXT the way cmd.exe would - a same-named "git.cmd"
// earlier on PATH is silently skipped in favour of the real git.exe found
// later. A copy of the current node binary IS a real .exe, so it resolves,
// and NODE_OPTIONS=--require makes that copy hang before it does anything.
// It hangs via a synchronous busy-loop, not `setTimeout`: Node runs a
// --require hook synchronously but then immediately moves on to load argv[1]
// ("check-ignore") as its main module, which throws "Cannot find module" and
// exits almost instantly - an async timer scheduled in the hook never gets
// the chance to fire.
//
// POSIX: there is no ".exe" to append, so the Windows trick resolves nothing
// and the REAL git answers in a few milliseconds - which is exactly how this
// test passed on Windows while asserting nothing on Ubuntu and macOS, where
// it failed with available:true (a real, fast, correct answer) rather than
// the timeout it was written to prove. An executable file simply named `git`
// is what PATH lookup finds here. It `exec`s sleep so the process spawnSync
// signals on timeout IS the sleeping process - a plain `sleep 7` would leave
// a grandchild alive after the shell was killed.
function makeHangingGit(hangMs) {
  const dir = mkdtempSync(path.join(tmpdir(), "fake-hanging-git-"));
  if (process.platform === "win32") {
    copyFileSync(process.execPath, path.join(dir, "git.exe"));
    const sleeper = path.join(dir, "sleeper.js");
    writeFileSync(sleeper, `const end = Date.now() + ${hangMs}; while (Date.now() < end) {} process.exit(0);`);
    return { dir, env: { NODE_OPTIONS: "--require " + sleeper } };
  }
  const fakeGit = path.join(dir, "git");
  writeFileSync(fakeGit, `#!/bin/sh\nexec sleep ${Math.ceil(hangMs / 1000)}\n`);
  chmodSync(fakeGit, 0o755);
  return { dir, env: {} };
}

test("gitIgnores: times out rather than hanging forever when git itself hangs (Finding 3)", () => {
  const cwd = makeRepo({});
  const { dir: fakeGitDir, env: fakeEnv } = makeHangingGit(7000); // hangs ~7s; the guard's own timeout is 5s
  const originalPath = process.env.PATH;
  const originalEnv = Object.fromEntries(Object.keys(fakeEnv).map((k) => [k, process.env[k]]));
  process.env.PATH = fakeGitDir + path.delimiter + originalPath;
  Object.assign(process.env, fakeEnv);
  try {
    const start = Date.now();
    const result = gitIgnores(path.join(cwd, "notes.md"), cwd);
    const elapsed = Date.now() - start;
    assert.ok(
      elapsed < 6000,
      `gitIgnores took ${elapsed}ms against a hanging git; expected it to be killed well under 6000ms`,
    );
    assert.ok(
      elapsed > 1000,
      `gitIgnores returned in ${elapsed}ms - the fake hanging git was not the one that answered, so this test proved nothing`,
    );
    assert.deepEqual(result, { available: false, ignored: false });
  } finally {
    process.env.PATH = originalPath;
    for (const [key, value] of Object.entries(originalEnv)) {
      if (value === undefined) delete process.env[key];
      else process.env[key] = value;
    }
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


// --- Task 8: wire the allowlist into the write guard -----------------------

// The brief's own prose required the guard to consult .secretgate.json; the
// code that shipped never read one. These four cases pin the fix: an
// allowlisted path allows, a non-allowlisted path in the same repo still
// denies, no file behaves as before, and a broken file denies rather than
// allowing.

test("PreToolUse: an allowlisted path allows a write that would otherwise deny", async () => {
  const cwd = makeRepo({
    [ALLOWLIST_FILE]: JSON.stringify({ version: 1, paths: ["^test/fixtures/"] }),
    "test/fixtures/.gitkeep": "",
  });
  const { code, stdout } = await runHook(
    "guard-write.mjs",
    {
      hook_event_name: "PreToolUse",
      tool_name: "Write",
      tool_input: { file_path: path.join(cwd, "test", "fixtures", "corpus.txt"), content: "STRIPE_KEY=" + LIVE },
    },
    { cwd },
  );
  assert.equal(code, 0);
  assert.equal(stdout, "", "an allowlisted path must allow silently, just like a clean write");
});

// The same symlink/short-path mismatch that made the vendored CLI a no-op
// (see cli-install.test.mjs) also silently broke the allowlist here: repoRoot
// comes from git and file_path comes from the tool call, so path.relative()
// between the two spellings produced "../../../../var/folders/.../corpus.txt"
// instead of "test/fixtures/corpus.txt", matched no `paths` entry, and the
// guard denied a write the repo had explicitly allowed. That failed on the
// macOS and Windows legs of CI and passed on Ubuntu purely because Ubuntu's
// /tmp is not a symlink. Constructing the symlink pins it everywhere.
test("PreToolUse: an allowlisted path still allows when the repo is reached through a symlink", async (t) => {
  const real = makeRepo({
    [ALLOWLIST_FILE]: JSON.stringify({ version: 1, paths: ["^test/fixtures/"] }),
    "test/fixtures/.gitkeep": "",
  });
  const parent = mkdtempSync(path.join(tmpdir(), "secret-gate-link-"));
  const cwd = path.join(parent, "linked-repo");
  try {
    // "junction" needs no elevation or developer mode on Windows and is
    // ignored on POSIX, where a plain symlink is made instead.
    symlinkSync(real, cwd, "junction");
  } catch {
    rmSync(parent, { recursive: true, force: true });
    return t.skip("this machine will not create a symlink");
  }
  try {
    const { code, stdout } = await runHook(
      "guard-write.mjs",
      {
        hook_event_name: "PreToolUse",
        tool_name: "Write",
        tool_input: { file_path: path.join(cwd, "test", "fixtures", "corpus.txt"), content: "STRIPE_KEY=" + LIVE },
      },
      { cwd },
    );
    assert.equal(code, 0);
    assert.equal(stdout, "", "an allowlisted path reached through a symlink must allow, same as through the real path");
  } finally {
    // Removes the link, not the repo it points at - rmSync does not follow
    // a symlink or junction when deleting it.
    rmSync(parent, { recursive: true, force: true });
  }
});

test("PreToolUse: a non-allowlisted path in the same repo still denies", async () => {
  const cwd = makeRepo({
    [ALLOWLIST_FILE]: JSON.stringify({ version: 1, paths: ["^test/fixtures/"] }),
    "src/.gitkeep": "",
  });
  const { code, stdout } = await runHook(
    "guard-write.mjs",
    {
      hook_event_name: "PreToolUse",
      tool_name: "Write",
      tool_input: { file_path: path.join(cwd, "src", "app.ts"), content: "STRIPE_KEY=" + LIVE },
    },
    { cwd },
  );
  assert.equal(code, 0);
  assert.ok(!stdout.includes(LIVE), "the deny reason leaked the value");
  const out = JSON.parse(stdout);
  assert.equal(
    out.hookSpecificOutput.permissionDecision,
    "deny",
    "the allowlist must not exempt a path it does not cover",
  );
});

test("PreToolUse: a repo with no .secretgate.json behaves exactly as before", async () => {
  const cwd = makeRepo({ "docs/.gitkeep": "" });
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
});

test("PreToolUse: a malformed .secretgate.json denies rather than allowing", async () => {
  const cwd = makeRepo({
    [ALLOWLIST_FILE]: "{ not json",
    "test/fixtures/.gitkeep": "",
  });
  const { code, stdout } = await runHook(
    "guard-write.mjs",
    {
      hook_event_name: "PreToolUse",
      tool_name: "Write",
      // This path WOULD have been allowlisted by a well-formed file with the
      // same paths rule - proving the broken file fails closed rather than
      // simply skipping allowlist logic and denying for the ordinary reason.
      tool_input: { file_path: path.join(cwd, "test", "fixtures", "corpus.txt"), content: "STRIPE_KEY=" + LIVE },
    },
    { cwd },
  );
  assert.equal(code, 0);
  assert.ok(!stdout.includes(LIVE), "the deny reason leaked the value");
  const out = JSON.parse(stdout);
  assert.equal(
    out.hookSpecificOutput.permissionDecision,
    "deny",
    "a broken .secretgate.json is not permission to write a credential",
  );
  // Tighter than "mentions .secretgate.json somewhere" - the ordinary deny
  // message already says that much as generic advice ("add it to
  // .secretgate.json first"), which would make this assertion pass even if
  // the allowlist were never consulted at all. Pin the file-is-the-problem
  // wording specifically so a missing wiring shows up as a failure here.
  assert.match(
    out.hookSpecificOutput.permissionDecisionReason,
    /\.secretgate\.json (?:is unreadable|could not be read)/,
    "the deny reason should name the allowlist file itself as unreadable, not just mention it as advice",
  );
});

// --- Review round 1, Finding 2 (important): the unreadable-allowlist deny
// message printed the allowlist file's OWN content verbatim -------------
//
// lib/allowlist.mjs's compile() interpolates the raw pattern source into its
// thrown Error's message, and a `regexes` entry is credential-adjacent by
// design (the brief's own example is a key prefix). A bad regex or bad JSON
// in .secretgate.json must not become a channel for the very kind of value
// this plugin exists to keep out of a transcript.
const ALLOWLIST_SECRET = "sk_live_" + "d".repeat(20);

test("PreToolUse: an invalid regex in .secretgate.json regexes must not leak the pattern (Finding 2a)", async () => {
  const cwd = makeRepo({
    [ALLOWLIST_FILE]: JSON.stringify({ version: 1, regexes: [ALLOWLIST_SECRET + "("] }),
  });
  const { code, stdout } = await runHook(
    "guard-write.mjs",
    {
      hook_event_name: "PreToolUse",
      tool_name: "Write",
      tool_input: { file_path: path.join(cwd, "notes.md"), content: "STRIPE_KEY=" + LIVE },
    },
    { cwd },
  );
  assert.equal(code, 0);
  assert.ok(!stdout.includes(ALLOWLIST_SECRET), "the deny reason leaked the .secretgate.json regexes value");
  const out = JSON.parse(stdout);
  assert.equal(out.hookSpecificOutput.permissionDecision, "deny");
});

test("PreToolUse: an invalid regex in .secretgate.json paths must not leak the pattern (Finding 2b)", async () => {
  const cwd = makeRepo({
    [ALLOWLIST_FILE]: JSON.stringify({ version: 1, paths: [ALLOWLIST_SECRET + "["] }),
  });
  const { code, stdout } = await runHook(
    "guard-write.mjs",
    {
      hook_event_name: "PreToolUse",
      tool_name: "Write",
      tool_input: { file_path: path.join(cwd, "notes.md"), content: "STRIPE_KEY=" + LIVE },
    },
    { cwd },
  );
  assert.equal(code, 0);
  assert.ok(!stdout.includes(ALLOWLIST_SECRET), "the deny reason leaked the .secretgate.json paths value");
  const out = JSON.parse(stdout);
  assert.equal(out.hookSpecificOutput.permissionDecision, "deny");
});

test("PreToolUse: invalid JSON starting with a secret-shaped value must not leak it via the parser's own snippet (Finding 2c)", async () => {
  const cwd = makeRepo({
    [ALLOWLIST_FILE]: ALLOWLIST_SECRET + " this is not json",
  });
  const { code, stdout } = await runHook(
    "guard-write.mjs",
    {
      hook_event_name: "PreToolUse",
      tool_name: "Write",
      tool_input: { file_path: path.join(cwd, "notes.md"), content: "STRIPE_KEY=" + LIVE },
    },
    { cwd },
  );
  assert.equal(code, 0);
  // V8's own JSON.parse SyntaxError truncates to a short prefix rather than
  // the full value - checking the FULL string never fails, since only the
  // first 10 characters ever appear ("sk_live_dd..." for this fixture). That
  // prefix is still a real leak, so pin the actual truncated snippet rather
  // than the full value, which is distinct enough from every other
  // sk_live_-prefixed fixture in this file (they all use a different
  // repeated letter) not to false-match something unrelated.
  const leakedPrefix = ALLOWLIST_SECRET.slice(0, 10);
  assert.ok(
    !stdout.includes(leakedPrefix),
    "the deny reason leaked a snippet of the malformed JSON via the parser's own error message",
  );
  const out = JSON.parse(stdout);
  assert.equal(out.hookSpecificOutput.permissionDecision, "deny");
});

// --- Review round 1, Finding 3 (important): a gitignored allowlist grants
// exemptions it should not, end to end through the write guard -----------
//
// Reproduces the reviewer's own repro: a repo whose .gitignore lists
// .secretgate.json, with that file present holding the most permissive
// allowlist that can be written (`paths: [""]`, matching every path). It
// must not silently allow a credential into an ordinary source file just
// because nobody would ever see the allowlist that permitted it in a diff.
test("PreToolUse: a gitignored .secretgate.json must not grant an exemption (Finding 3)", async () => {
  const cwd = makeRepo({
    ".gitignore": ALLOWLIST_FILE + "\n",
    [ALLOWLIST_FILE]: JSON.stringify({ version: 1, paths: [""] }),
    "src/.gitkeep": "",
  });
  const { code, stdout } = await runHook(
    "guard-write.mjs",
    {
      hook_event_name: "PreToolUse",
      tool_name: "Write",
      tool_input: { file_path: path.join(cwd, "src", "app.ts"), content: "STRIPE_KEY=" + LIVE },
    },
    { cwd },
  );
  assert.equal(code, 0);
  assert.ok(!stdout.includes(LIVE), "the deny reason leaked the value");
  assert.notEqual(
    stdout,
    "",
    "a gitignored .secretgate.json silently granted an exemption nobody would see in a diff",
  );
  const out = JSON.parse(stdout);
  assert.equal(out.hookSpecificOutput.permissionDecision, "deny");
});

// --- Task 8: harden every git call against inherited GIT_* env vars --------

// Git sets GIT_DIR/GIT_WORK_TREE/GIT_INDEX_FILE for every hook it runs, and
// this code is meant to be vendored into a pre-commit hook by later tasks -
// so an inherited GIT_DIR pointing at some other repository is the normal
// case there, not an edge case. Without stripping those vars before calling
// git, they override `cwd` entirely: git answers about the WRONG repo, the
// path looks "outside the repository", envExemption's git-unavailable
// fallback kicks in, and a tracked .env.production is allowed through by
// name alone.
test("PreToolUse: inherited GIT_DIR/GIT_WORK_TREE must not hijack which repo git answers about (Requirement 2)", async () => {
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

  // A wholly unrelated repo, injected via the environment the way git itself
  // injects it into every hook it invokes.
  const poisonRepo = makeRepo({});

  const { code, stdout } = await runHook(
    "guard-write.mjs",
    {
      hook_event_name: "PreToolUse",
      tool_name: "Write",
      tool_input: { file_path: path.join(targetRepo, ".env.production"), content: "STRIPE_KEY=" + LIVE },
    },
    {
      cwd: targetRepo,
      env: {
        ...process.env,
        GIT_DIR: path.join(poisonRepo, ".git"),
        GIT_WORK_TREE: poisonRepo,
        GIT_INDEX_FILE: path.join(poisonRepo, ".git", "index"),
      },
    },
  );
  assert.equal(code, 0);
  assert.ok(!stdout.includes(LIVE), "the deny reason leaked the value");
  assert.notEqual(
    stdout,
    "",
    "the write was allowed silently - inherited GIT_DIR/GIT_WORK_TREE hijacked which repo git answered about",
  );
  const out = JSON.parse(stdout);
  assert.equal(
    out.hookSpecificOutput.permissionDecision,
    "deny",
    "inherited GIT_DIR/GIT_WORK_TREE/GIT_INDEX_FILE must not flip a tracked .env.production to an allow",
  );
});

// --- Review round 1, Finding 1 (critical): closed by NAME, not by CLASS ---
//
// Naming exactly GIT_DIR/GIT_WORK_TREE/GIT_INDEX_FILE closed those three and
// left every other GIT_* variable git itself sets for a hook open. Each case
// below is measured against its own control on the identical fixture: the
// control denies, the poisoned env allows silently, and after stripping the
// whole GIT_* prefix (rather than a list) both must deny.

// Vector A: GIT_CONFIG_COUNT/KEY_0/VALUE_0 point core.excludesFile at a file
// that ignores everything. check-ignore then reports an ordinary untracked
// file as ignored, and envExemption treats "ignored" as exempt.
test("PreToolUse: GIT_CONFIG_COUNT/KEY_0/VALUE_0 excludesFile override must not manufacture an exemption (Finding 1a)", async () => {
  const cwd = makeRepo({});
  const excludesFile = path.join(mkdtempSync(path.join(tmpdir(), "secret-gate-excludes-")), "exclude-all");
  writeFileSync(excludesFile, "*\n");

  const { code, stdout } = await runHook(
    "guard-write.mjs",
    {
      hook_event_name: "PreToolUse",
      tool_name: "Write",
      tool_input: { file_path: path.join(cwd, "src", "app.ts"), content: "STRIPE_KEY=" + LIVE },
    },
    {
      cwd,
      env: {
        ...process.env,
        GIT_CONFIG_COUNT: "1",
        GIT_CONFIG_KEY_0: "core.excludesFile",
        GIT_CONFIG_VALUE_0: excludesFile.replaceAll("\\", "/"),
      },
    },
  );
  assert.equal(code, 0);
  assert.ok(!stdout.includes(LIVE), "the deny reason leaked the value");
  assert.notEqual(stdout, "", "GIT_CONFIG_COUNT/KEY_0/VALUE_0 manufactured a silent exemption");
  const out = JSON.parse(stdout);
  assert.equal(out.hookSpecificOutput.permissionDecision, "deny");
});

// Vector B: GIT_CONFIG_PARAMETERS is the single-variable encoding git itself
// exports to every hook it invokes when the invoking command ran as
// `git -c key=value ...` - not exotic, the normal shape of a hook's own
// environment. Same excludesFile trick, different variable.
test("PreToolUse: GIT_CONFIG_PARAMETERS excludesFile override must not manufacture an exemption (Finding 1b)", async () => {
  const cwd = makeRepo({});
  const excludesFile = path.join(mkdtempSync(path.join(tmpdir(), "secret-gate-excludes-")), "exclude-all");
  writeFileSync(excludesFile, "*\n");

  const { code, stdout } = await runHook(
    "guard-write.mjs",
    {
      hook_event_name: "PreToolUse",
      tool_name: "Write",
      tool_input: { file_path: path.join(cwd, "src", "app.ts"), content: "STRIPE_KEY=" + LIVE },
    },
    {
      cwd,
      env: {
        ...process.env,
        GIT_CONFIG_PARAMETERS: `'core.excludesFile'='${excludesFile.replaceAll("\\", "/")}'`,
      },
    },
  );
  assert.equal(code, 0);
  assert.ok(!stdout.includes(LIVE), "the deny reason leaked the value");
  assert.notEqual(stdout, "", "GIT_CONFIG_PARAMETERS manufactured a silent exemption");
  const out = JSON.parse(stdout);
  assert.equal(out.hookSpecificOutput.permissionDecision, "deny");
});

// Vector C: GIT_CEILING_DIRECTORIES set to the repo root itself stops git
// from ascending INTO that directory while discovering the repo from a
// nested subdirectory - repo discovery fails, both git calls report
// "not a git repository", and envExemption's git-unavailable fallback
// exempts a tracked .env.production by name alone.
test("PreToolUse: GIT_CEILING_DIRECTORIES must not break repo discovery into a false exemption (Finding 1c)", async () => {
  const targetRepo = makeRepo({
    ".gitignore": ".env.*\n",
    "sub/.gitkeep": "",
    "sub/.env.production": "VITE_PUBLIC=1\n",
  });
  assert.ok(
    isIgnoredByGit(targetRepo, "sub/.env.production"),
    "fixture premise broken: .gitignore does not match sub/.env.production before it is force-tracked",
  );
  runGit(targetRepo, "add", "-f", "sub/.env.production");
  runGit(targetRepo, "commit", "-qm", "track nested env.production");

  const { code, stdout } = await runHook(
    "guard-write.mjs",
    {
      hook_event_name: "PreToolUse",
      tool_name: "Write",
      tool_input: { file_path: path.join(targetRepo, "sub", ".env.production"), content: "STRIPE_KEY=" + LIVE },
    },
    {
      cwd: targetRepo,
      env: {
        ...process.env,
        GIT_CEILING_DIRECTORIES: targetRepo,
      },
    },
  );
  assert.equal(code, 0);
  assert.ok(!stdout.includes(LIVE), "the deny reason leaked the value");
  assert.notEqual(stdout, "", "GIT_CEILING_DIRECTORIES broke repo discovery into a silent exemption");
  const out = JSON.parse(stdout);
  assert.equal(out.hookSpecificOutput.permissionDecision, "deny");
});

// --- Review round 2, Finding A (critical): the GIT_ prefix check was
// case-sensitive; Windows environment lookup is not ----------------------
//
// gitEnv() stripped keys with `key.startsWith("GIT_")`. Object.keys()
// returns environment variable names in whatever casing the process holds
// them under, but the git.exe child resolves GIT_DIR (and friends) through
// the Win32 environment block, which is case-insensitive - so a lowercase
// or mixed-case name survives the strip untouched and git still reads it.
// Same construction as the GIT_DIR/GIT_WORK_TREE hijack test above, just
// with the env var names cased differently.
function gitDirHijackEnv(targetRepo, poisonRepo, caseVariant) {
  const names =
    caseVariant === "lowercase"
      ? { dir: "git_dir", workTree: "git_work_tree", indexFile: "git_index_file" }
      : { dir: "Git_Dir", workTree: "Git_Work_Tree", indexFile: "Git_Index_File" };
  return {
    ...process.env,
    [names.dir]: path.join(poisonRepo, ".git"),
    [names.workTree]: poisonRepo,
    [names.indexFile]: path.join(poisonRepo, ".git", "index"),
  };
}

for (const caseVariant of ["lowercase", "mixed-case"]) {
  test(`PreToolUse: ${caseVariant} git_dir/git_work_tree must not hijack which repo git answers about (Finding A)`, async () => {
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

    const poisonRepo = makeRepo({});

    const { code, stdout } = await runHook(
      "guard-write.mjs",
      {
        hook_event_name: "PreToolUse",
        tool_name: "Write",
        tool_input: { file_path: path.join(targetRepo, ".env.production"), content: "STRIPE_KEY=" + LIVE },
      },
      {
        cwd: targetRepo,
        env: gitDirHijackEnv(targetRepo, poisonRepo, caseVariant),
      },
    );
    assert.equal(code, 0);
    assert.ok(!stdout.includes(LIVE), "the deny reason leaked the value");
    assert.notEqual(
      stdout,
      "",
      `the write was allowed silently - ${caseVariant} GIT_DIR/GIT_WORK_TREE hijacked which repo git answered about`,
    );
    const out = JSON.parse(stdout);
    assert.equal(
      out.hookSpecificOutput.permissionDecision,
      "deny",
      `${caseVariant} GIT_DIR/GIT_WORK_TREE/GIT_INDEX_FILE must not flip a tracked .env.production to an allow`,
    );
  });
}
