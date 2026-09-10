// lib/gitignore.mjs
//
// The .env exemption is "git ignores this file", not "this file is called .env".
// GradeThread tracks .env.production and .env.example, so a name-only rule would
// let a real key reach GitHub in the one place nobody would look for it.
import { spawnSync } from "node:child_process";

const ENV_NAME = /(^|[/\\])\.env(\.|$)/;

// exit 0 = ignored, exit 1 = not ignored, anything else = git could not answer.
//
// Deliberately no --no-index here. `--no-index` answers from the ignore
// patterns alone, so it reports a TRACKED file as "ignored" even when git is
// already carrying it (e.g. .env.production tracked despite a `.env.*` rule
// in .gitignore). Git's default behaviour already encodes what this guard
// needs: a tracked path is never "ignored", so it falls through to be
// scanned like anything else.
export function gitIgnores(filePath, cwd) {
  const result = spawnSync("git", ["check-ignore", "--quiet", "--", filePath], {
    cwd,
    stdio: "ignore",
  });
  if (result.error || result.status === null) return { available: false, ignored: false };
  if (result.status === 0) return { available: true, ignored: true };
  if (result.status === 1) return { available: true, ignored: false };
  return { available: false, ignored: false };
}

export function envExemption(filePath, cwd = process.cwd()) {
  const looksLikeEnv = ENV_NAME.test(filePath.replaceAll("\\", "/"));
  const { available, ignored } = gitIgnores(filePath, cwd);

  if (available && ignored) {
    return { exempt: true, reason: "git ignores this path" };
  }
  if (available) {
    return { exempt: false, reason: "git tracks this path" };
  }
  if (looksLikeEnv) {
    return { exempt: true, reason: "not a git repo, falling back to the .env name rule" };
  }
  return { exempt: false, reason: "not a git repo, and this is not a .env file" };
}
