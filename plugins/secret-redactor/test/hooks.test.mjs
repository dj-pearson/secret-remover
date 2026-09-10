import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import path from "node:path";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { runHook } from "./helpers/run-hook.mjs";
import { makeRepo, runGit } from "./helpers/temp-repo.mjs";

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

test("PreToolUse: denies writing a secret into a tracked file", async () => {
  const cwd = makeRepo({
    ".gitignore": ".env\n.env.local\n",
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
  assert.match(out.hookSpecificOutput.permissionDecisionReason, /not a git repo/i);
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

