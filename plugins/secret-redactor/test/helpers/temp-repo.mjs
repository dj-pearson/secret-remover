// Shared git-repo fixture builder for tests that need a real repo on disk.
//
// Task 7 (the write guard) and Task 9 both need a throwaway git repo with a
// known set of files and commit history. Keep this self-contained and
// generally useful rather than shaped around one task's fixtures.
import { mkdtempSync, mkdirSync, writeFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { execFileSync, spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";

// Every makeRepo() leaks its temp directory unless something removes it -
// one earlier fixture copied a ~100 MB node binary into one, and repeated
// test runs otherwise fill the disk over time. Register each dir once and
// remove them all on process exit; exit listeners must run synchronously,
// which is exactly what rmSync gives us.
const pendingCleanup = new Set();
let cleanupRegistered = false;

function registerCleanup(dir) {
  pendingCleanup.add(dir);
  if (cleanupRegistered) return;
  cleanupRegistered = true;
  process.on("exit", () => {
    for (const d of pendingCleanup) {
      try {
        rmSync(d, { recursive: true, force: true });
      } catch {
        // best-effort: a locked file on the way out must not crash the
        // test process during exit.
      }
    }
  });
}

// A developer's global `core.hooksPath` (this very project's own `prepare`
// script sets one locally) or global `core.excludesFile` would otherwise
// change fixture behaviour machine to machine. Pointing GIT_CONFIG_GLOBAL
// and GIT_CONFIG_SYSTEM at paths that do not exist makes every fixture repo
// see only the config it is given here, and passing --initial-branch
// explicitly removes init.defaultBranch as another such variable.
function isolatedGitEnv(dir) {
  return {
    ...process.env,
    GIT_CONFIG_GLOBAL: path.join(dir, ".unused-global-gitconfig"),
    GIT_CONFIG_SYSTEM: path.join(dir, ".unused-system-gitconfig"),
  };
}

// Creates a temp dir, `git init`s it, makes an initial commit so HEAD exists,
// then writes `files` (repo-relative path -> content, parent dirs created as
// needed). Stages everything with `git add -A` when `stage` is true, and
// commits that stage when `commit` is also true. Returns the repo's absolute
// path.
export function makeRepo(files = {}, { stage = true, commit = false } = {}) {
  const dir = mkdtempSync(path.join(tmpdir(), "secret-gate-"));
  registerCleanup(dir);

  const env = isolatedGitEnv(dir);
  const git = (...args) => execFileSync("git", args, { cwd: dir, stdio: "ignore", env });

  git("init", "-q", "--initial-branch=main");
  git("config", "user.email", "test@example.com");
  git("config", "user.name", "test");
  git("config", "commit.gpgsign", "false");

  // An initial commit so HEAD exists before any fixture-specific history.
  writeFileSync(path.join(dir, ".gitkeep"), "");
  git("add", ".gitkeep");
  git("commit", "-qm", "init");

  for (const [relPath, content] of Object.entries(files)) {
    const fullPath = path.join(dir, relPath);
    mkdirSync(path.dirname(fullPath), { recursive: true });
    writeFileSync(fullPath, content);
  }

  if (stage) git("add", "-A");

  if (commit) {
    // `git commit` on an empty stage exits 1 with a message this helper's
    // callers never see (execFileSync just throws "Command failed"), which
    // reads as a broken fixture rather than the actual mistake: asking for
    // a commit with nothing staged (stage: false, or no files given at
    // all). Check first and say exactly that instead.
    const staged = spawnSync("git", ["diff", "--cached", "--quiet"], { cwd: dir, env });
    if (staged.status === 0) {
      throw new Error(
        "makeRepo: commit requested but nothing is staged - pass files with stage left at its default (true), or omit commit",
      );
    }
    git("commit", "-qm", "fixture");
  }

  return dir;
}

export function runGit(cwd, ...args) {
  execFileSync("git", args, { cwd, stdio: "ignore" });
}

// Runs the CLI (lib/cli.mjs) as a real child process against a fixture repo,
// the same way the pre-commit hook and a developer's terminal would. `env`,
// when supplied, replaces the child's environment entirely - tests use this
// to simulate the poisoned GIT_* environment git sets for every hook it
// invokes (see Correction 2 in the task-9 brief).
export function runCli(dir, args, { env } = {}) {
  const cliPath = path.join(
    path.dirname(path.dirname(fileURLToPath(import.meta.url))),
    "..",
    "lib",
    "cli.mjs",
  );
  try {
    const stdout = execFileSync(process.execPath, [cliPath, ...args], {
      cwd: dir,
      encoding: "utf8",
      stdio: ["ignore", "pipe", "pipe"],
      env: env ?? process.env,
    });
    return { code: 0, stdout, stderr: "" };
  } catch (err) {
    return { code: err.status ?? 2, stdout: err.stdout ?? "", stderr: err.stderr ?? "" };
  }
}
