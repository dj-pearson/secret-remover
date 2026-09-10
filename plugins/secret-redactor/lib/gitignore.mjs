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
  });
  if (result.error || result.status === null) return { available: false, ignored: false };
  if (result.status === 0) return { available: true, ignored: true };
  if (result.status === 1) return { available: true, ignored: false };
  return { available: false, ignored: false };
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
