// lib/allowlist.mjs
//
// JSON rather than TOML because Node has no built-in TOML parser and this
// plugin takes no dependencies.
//
// An entry that stops matching anything is reported as stale on every scan.
// That is what keeps the list shrinking rather than growing: a silenced rule
// nobody re-checks is how a live key ends up allowlisted forever.
import { existsSync, readFileSync } from "node:fs";
import path from "node:path";
import { gitIgnores } from "./gitignore.mjs";

export const ALLOWLIST_FILE = ".secretgate.json";

function compile(patterns, field) {
  return (patterns ?? []).map((src) => {
    if (typeof src !== "string") {
      throw new Error(`${ALLOWLIST_FILE}: ${field} entries must be strings`);
    }
    try {
      return { src, re: new RegExp(src) };
    } catch (err) {
      throw new Error(`${ALLOWLIST_FILE}: ${field} entry ${src} is not a valid regex: ${err.message}`);
    }
  });
}

export function loadAllowlist(repoRoot) {
  const file = path.join(repoRoot, ALLOWLIST_FILE);
  const empty = { version: 1, paths: [], regexes: [], fingerprints: [], used: new Set() };
  if (!existsSync(file)) return empty;

  // Any allowlist is self-service to something that can already write
  // files, so the one guarantee worth keeping is that USING it leaves a
  // reviewable artifact: a change git will actually carry, visible in a
  // diff someone can look at. A .secretgate.json git itself ignores can be
  // written and consulted without ever appearing in a commit anyone
  // reviews, which defeats that guarantee - so it is treated exactly like
  // an absent file, silently, without even validating its syntax. The same
  // applies when git can't answer at all (timeout, race): the safe
  // direction here is "no exemptions," not "trust an unverified file."
  const { available, ignored } = gitIgnores(file, repoRoot);
  if (!available || ignored) return empty;

  let parsed;
  try {
    parsed = JSON.parse(readFileSync(file, "utf8"));
  } catch (err) {
    // Deliberately not interpolating err.message: V8's own JSON.parse
    // SyntaxError echoes a snippet of the file's actual content for some
    // parse failures (e.g. `Unexpected token 's', "sk_live_dd"... is not
    // valid JSON`), truncated but still long enough to identify a
    // credential. Name the file and the failure class only - never content
    // this call did not get to validate.
    throw new Error(`${ALLOWLIST_FILE} is not valid JSON: ${err.constructor.name}`);
  }

  // A future v2 is free to change what any field means. A guard that only
  // ever speaks v1 semantics and silently accepts an unrecognized version
  // number would misinterpret a v2 file under the wrong rules with nothing
  // erroring - an allow-direction failure invisible at the moment it
  // happens. Reject it now, the same way malformed JSON is rejected, rather
  // than defaulting an unknown version past this check.
  const version = parsed.version ?? 1;
  if (version !== 1) {
    throw new Error(`${ALLOWLIST_FILE}: unsupported version ${JSON.stringify(version)} (this tool only understands version 1)`);
  }

  return {
    version,
    paths: compile(parsed.paths, "paths"),
    regexes: compile(parsed.regexes, "regexes"),
    fingerprints: (parsed.fingerprints ?? []).map((src) => ({ src })),
    used: new Set(),
  };
}

export function fingerprintOf(relPath, hit) {
  return `${relPath.replaceAll("\\", "/")}:${hit.label}:${hit.line}`;
}

export function isAllowed(allowlist, relPath, hit) {
  const rel = relPath.replaceAll("\\", "/");
  for (const entry of allowlist.paths) {
    if (entry.re.test(rel)) {
      allowlist.used.add(entry.src);
      return true;
    }
  }
  for (const entry of allowlist.regexes) {
    if (entry.re.test(hit.value)) {
      allowlist.used.add(entry.src);
      return true;
    }
  }
  const fp = fingerprintOf(rel, hit);
  for (const entry of allowlist.fingerprints) {
    if (entry.src === fp) {
      allowlist.used.add(entry.src);
      return true;
    }
  }
  return false;
}

export function staleEntries(allowlist) {
  return [...allowlist.paths, ...allowlist.regexes, ...allowlist.fingerprints]
    .map((entry) => entry.src)
    .filter((src) => !allowlist.used.has(src));
}
