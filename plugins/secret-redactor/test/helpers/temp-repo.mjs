// Shared git-repo fixture builder for tests that need a real repo on disk.
//
// Task 7 (the write guard) and Task 9 both need a throwaway git repo with a
// known set of files and commit history. Keep this self-contained and
// generally useful rather than shaped around one task's fixtures.
import { mkdtempSync, mkdirSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { execFileSync } from "node:child_process";

// Creates a temp dir, `git init`s it, makes an initial commit so HEAD exists,
// then writes `files` (repo-relative path -> content, parent dirs created as
// needed). Stages everything with `git add -A` when `stage` is true, and
// commits that stage when `commitFirst` is also true. Returns the repo's
// absolute path.
export function makeRepo(files = {}, { stage = true, commitFirst = false } = {}) {
  const dir = mkdtempSync(path.join(tmpdir(), "secret-gate-"));
  const git = (...args) => execFileSync("git", args, { cwd: dir, stdio: "ignore" });

  git("init", "-q");
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
  if (commitFirst) git("commit", "-qm", "fixture");

  return dir;
}

export function runGit(cwd, ...args) {
  execFileSync("git", args, { cwd, stdio: "ignore" });
}
