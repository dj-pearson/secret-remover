// lib/gitignore.mjs
//
// The .env exemption is "git ignores this file", not "this file is called .env".
// GradeThread tracks .env.production and .env.example, so a name-only rule would
// let a real key reach GitHub in the one place nobody would look for it.
import { spawnSync } from "node:child_process";
import { existsSync } from "node:fs";
import path from "node:path";
import { canonicalize, canonicalizeParent } from "./paths.mjs";

const ENV_NAME = /(^|[/\\])\.env(\.|$)/;
const GIT_TIMEOUT_MS = 5000;

// Git sets a family of GIT_* variables for every hook it runs, and Tasks
// 9-11 vendor this code into repos where it runs FROM a pre-commit hook - so
// a process environment that already carries some of them is the normal
// case there, not an edge case. Left alone, several of them override `cwd`
// or repo discovery entirely, and each was measured to flip a DENY to a
// silent ALLOW on its own:
//   - GIT_DIR/GIT_WORK_TREE/GIT_INDEX_FILE point git at a different repo
//     than `cwd` names.
//   - GIT_CONFIG_COUNT/GIT_CONFIG_KEY_n/GIT_CONFIG_VALUE_n and the single
//     -c-equivalent GIT_CONFIG_PARAMETERS can set core.excludesFile to a
//     file that ignores everything, so check-ignore reports an ordinary
//     untracked file as ignored.
//   - GIT_CEILING_DIRECTORIES set to the repo root stops git ascending INTO
//     that root while discovering the repo from a nested subdirectory, so
//     both check-ignore and rev-parse fail with "not a git repository" and
//     envExemption's git-unavailable fallback exempts a tracked
//     .env.production by name alone.
// An earlier version of this function deleted exactly those first three by
// name. That closed the vars the original report named and left every other
// GIT_* variable open - GIT_CONFIG_PARAMETERS among them, which is not
// exotic: git exports it to every hook invoked as `git -c key=value ...`,
// precisely the vendored pre-commit case this code targets. Neither
// check-ignore nor rev-parse --show-toplevel needs any GIT_* input, so
// stripping the whole prefix costs nothing and closes the class rather than
// a list - including GIT_COMMON_DIR, GIT_OBJECT_DIRECTORY, and whatever git
// adds next. process.env itself is never mutated, only the copy handed to
// the child.
// Exported so lib/cli.mjs (Task 9) can reuse the exact same stripping for
// every git call it makes, rather than carrying a second copy of this list.
// This hole has been closed three times in this plugin now; one function is
// one thing to keep correct.
export function gitEnv() {
  const env = { ...process.env };
  for (const key of Object.keys(env)) {
    // Case-INSENSITIVE on purpose: Object.keys() returns each variable in
    // whatever casing the process happens to hold it under, but the git.exe
    // child resolves GIT_DIR (and every other GIT_* var) case-insensitively
    // through the Win32 environment block - so a `git_dir` or `Git_Dir`
    // survived a `startsWith("GIT_")` check untouched and git still read
    // it. The earlier three-name `delete env.GIT_DIR` had the identical
    // gap; switching to a prefix check closed it for the class of variable
    // names but not for the class of casings.
    if (key.toUpperCase().startsWith("GIT_")) delete env[key];
  }
  return env;
}

// Write routinely creates a brand new folder, and Claude Code always sends an
// absolute file_path - so `path.dirname(filePath)` frequently names a
// directory that does not exist YET. Handing that straight to spawnSync's
// `cwd` makes it ENOENT (available:false), which used to fall through to the
// same name-based exemption the cross-repo fix above was about, allowing a
// real key into a not-yet-created .env.production. Climb to the nearest
// directory that actually exists - that is still inside the target file's
// own repo (the repo root itself always exists), so the cross-repo fix stays
// intact; it just stops assuming the immediate parent exists too.
function nearestExistingAncestor(dir) {
  let current = dir;
  while (!existsSync(current)) {
    const parent = path.dirname(current);
    if (parent === current) return current; // hit the filesystem root; give up climbing
    current = parent;
  }
  return current;
}

// exit 0 = ignored, exit 1 = not ignored, anything else = git could not answer.
//
// Deliberately no --no-index here. `--no-index` answers from the ignore
// patterns alone, so it reports a TRACKED file as "ignored" even when git is
// already carrying it (e.g. .env.production tracked despite a `.env.*` rule
// in .gitignore). Git's default behaviour already encodes what this guard
// needs: a tracked path is never "ignored", so it falls through to be
// scanned like anything else.
//
// The child process's cwd follows the FILE, not the caller's cwd. A session
// working in one repo can still Write into a path that lives in a different
// repo (ten projects share this machine, and cross-repo writes are
// routine). Asking git from the session's cwd about a path outside it fails
// with "outside repository at ..." -> available:false -> the name-based
// fallback used to exempt a tracked .env.production in the OTHER repo,
// silently allowing the exact write this guard exists to stop. Resolving
// from the file's own directory lets git walk up to the repo that actually
// owns the path.
//
// `timeout` matters for the same reason `result.status === null` was already
// handled below: a git that blocks (index.lock contention, a stalled
// network filesystem, a slow AV scan) would otherwise burn the hook's whole
// PreToolUse budget, get killed by the harness, and a killed hook does not
// deny. Timing the child out ourselves turns that into a fast, honest
// "git could not answer" instead.
export function gitIgnores(filePath, cwd) {
  const dir = canonicalize(path.isAbsolute(filePath) ? nearestExistingAncestor(path.dirname(filePath)) : cwd);
  const result = spawnSync("git", ["check-ignore", "--quiet", "--", filePath], {
    cwd: dir,
    timeout: GIT_TIMEOUT_MS,
    stdio: "ignore",
    env: gitEnv(),
  });
  if (result.error || result.status === null) return { available: false, ignored: false };
  if (result.status === 0) return { available: true, ignored: true };
  if (result.status === 1) return { available: true, ignored: false };
  return { available: false, ignored: false };
}

// Resolves the repo root that owns `filePath`, for callers (the write guard,
// loading .secretgate.json) that need to ask git something beyond
// check-ignore. Reuses the same cwd-resolution as gitIgnores above rather
// than inventing a second way to find the right directory to ask git about:
// climb to the nearest existing ancestor first, since Write routinely
// targets a not-yet-created folder, then ask git from there. Returns null
// (not a throw) when git can't answer - no repo, a timeout, git missing -
// so a caller can fall back to "no allowlist" the same way envExemption
// falls back to the .env name rule.
export function repoRootFor(filePath, cwd) {
  const dir = canonicalize(path.isAbsolute(filePath) ? nearestExistingAncestor(path.dirname(filePath)) : cwd);
  const result = spawnSync("git", ["rev-parse", "--show-toplevel"], {
    cwd: dir,
    timeout: GIT_TIMEOUT_MS,
    encoding: "utf8",
    env: gitEnv(),
  });
  if (result.error || result.status !== 0 || typeof result.stdout !== "string") return null;
  const root = result.stdout.trim();
  // Canonicalized before it leaves this function: the write guard
  // path.relative()s a Node-built absolute file path against this root to
  // get the repo-relative path it matches .secretgate.json `paths` entries
  // against, and git and Node spell the same directory differently on macOS
  // (/private/var vs /var) and Windows (long vs 8.3, casing). Uncanonicalized,
  // that relative path came out as "../../../../var/folders/.../fixture.txt",
  // matched no allowlist entry, and the guard denied a write the repo had
  // explicitly allowed. See lib/paths.mjs.
  return root.length > 0 ? canonicalize(root) : null;
}

// `rawFilePath` may not be a string at all (a malformed tool_input can hand
// us anything). Coerce to "" rather than letting .replaceAll() throw -
// an empty path is not .env-shaped and gitIgnores("") reports unavailable,
// so it lands on the deny side, same as any other unrecognized path.
export function envExemption(rawFilePath, cwd = process.cwd()) {
  const filePath = typeof rawFilePath === "string" ? rawFilePath : "";
  const looksLikeEnv = ENV_NAME.test(filePath.replaceAll("\\", "/"));
  const { available, ignored } = gitIgnores(filePath, cwd);

  if (available && ignored) {
    return { exempt: true, reason: "git ignores this path" };
  }
  if (available) {
    return { exempt: false, reason: "git tracks this path" };
  }
  if (looksLikeEnv) {
    return { exempt: true, reason: "git could not answer for this path, falling back to the .env name rule" };
  }
  return { exempt: false, reason: "git could not answer for this path, and this is not a .env file" };
}
