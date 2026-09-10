// lib/gitignore.mjs
//
// The .env exemption is "git ignores this file", not "this file is called .env".
// GradeThread tracks .env.production and .env.example, so a name-only rule would
// let a real key reach GitHub in the one place nobody would look for it.
import { spawnSync } from "node:child_process";
import { existsSync } from "node:fs";
import path from "node:path";

const ENV_NAME = /(^|[/\\])\.env(\.|$)/;
const GIT_TIMEOUT_MS = 5000;

// Git sets GIT_DIR, GIT_WORK_TREE and GIT_INDEX_FILE for every hook it runs,
// and Tasks 9-11 vendor this code into repos where it runs FROM a pre-commit
// hook - so a process environment that already carries those vars is the
// normal case there, not an edge case. Left alone they override `cwd`
// entirely: git answers about whatever repo GIT_DIR names, not the one this
// module resolved and passed as `cwd`. Measured consequence: a secret
// written into another repo's tracked .env.production reads as "outside the
// repository" under the poisoned GIT_DIR, envExemption's git-unavailable
// fallback exempts it by name alone, and a DENY silently becomes an ALLOW.
// Stripping them before every spawnSync call is the fix; process.env itself
// is never mutated, only the copy handed to the child.
function gitEnv() {
  const env = { ...process.env };
  delete env.GIT_DIR;
  delete env.GIT_WORK_TREE;
  delete env.GIT_INDEX_FILE;
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
  const dir = path.isAbsolute(filePath) ? nearestExistingAncestor(path.dirname(filePath)) : cwd;
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
  const dir = path.isAbsolute(filePath) ? nearestExistingAncestor(path.dirname(filePath)) : cwd;
  const result = spawnSync("git", ["rev-parse", "--show-toplevel"], {
    cwd: dir,
    timeout: GIT_TIMEOUT_MS,
    encoding: "utf8",
    env: gitEnv(),
  });
  if (result.error || result.status !== 0 || typeof result.stdout !== "string") return null;
  const root = result.stdout.trim();
  return root.length > 0 ? root : null;
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
