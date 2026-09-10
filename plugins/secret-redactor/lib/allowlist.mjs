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

  let parsed;
  try {
    parsed = JSON.parse(readFileSync(file, "utf8"));
  } catch (err) {
    throw new Error(`${ALLOWLIST_FILE} is not valid JSON: ${err.message}`);
  }

  return {
    version: parsed.version ?? 1,
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
