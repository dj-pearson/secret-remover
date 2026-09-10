#!/usr/bin/env node
// lib/cli.mjs
//
// scan / fix / install. This file plus detect.mjs and allowlist.mjs are what
// `install` vendors into a repo, so the three of them import each other with
// plain relative paths and nothing else.
//
// Exit codes:
//   0  clean
//   1  findings (or, with --strict, a skip)
//   2  internal error or bad usage
//
// The failure asymmetry is deliberate. The generated pre-commit hook treats 2
// as a warning and lets the commit through, because a crashing scanner must not
// brick committing in twenty repos. CI treats 2 as a failure, because there the
// right response to a broken scanner is a red build.
import { existsSync, readFileSync, writeFileSync, statSync } from "node:fs";
import { spawnSync } from "node:child_process";
import path from "node:path";
import { pathToFileURL } from "node:url";
import { findSecrets, newState, tokenFor, MAX_SCAN_BYTES } from "./detect.mjs";
import { loadAllowlist, isAllowed, staleEntries, ALLOWLIST_FILE } from "./allowlist.mjs";
import { gitEnv } from "./gitignore.mjs";

export const VERSION = "2.0.0";

const USAGE = `usage: secret-gate <command>

  scan [--staged] [--strict] [paths...]
                                exit 1 if a credential is present;
                                --strict also exits 1 if anything was skipped
  fix --staged                 rewrite staged findings to [REDACTED] markers
  install [--force]            wire this repo up with the commit gate
  --version                    print ${VERSION}
`;

// --- git helpers -----------------------------------------------------------
//
// Every git call this file makes goes through this one function, and every
// one of them uses gitEnv() - git sets GIT_DIR, GIT_INDEX_FILE and often
// GIT_CONFIG_PARAMETERS for every hook it invokes, so this CLI running from a
// pre-commit hook sees a poisoned git environment as the normal case, not an
// edge case. Reusing gitignore.mjs's gitEnv() rather than writing a second
// copy is deliberate: this exact hole has been closed three times already in
// this plugin.

function git(args, cwd, encoding = "utf8") {
  return spawnSync("git", args, { cwd, encoding, env: gitEnv(), maxBuffer: MAX_SCAN_BYTES * 4 });
}

export function repoRoot(cwd = process.cwd()) {
  const result = git(["rev-parse", "--show-toplevel"], cwd);
  if (result.status !== 0) throw new Error("not a git repository");
  return result.stdout.trim();
}

function stagedPaths(root) {
  // An explicit allowlist of status letters (first ACMR, then ACMRT once a
  // symlink-replaced-by-a-regular-file slipped through as a type change) is
  // closed by NAME, not by CLASS - the same mistake fixed twice already.
  // --diff-filter=d (lowercase: EXCLUDE deletions) is deny-by-default - it
  // keeps every status letter git has today or adds tomorrow except the one
  // that never has content to scan, so a future status letter can't repeat
  // this hole a fourth time.
  const result = git(["diff", "--cached", "--name-only", "--diff-filter=d", "-z"], root);
  if (result.status !== 0) throw new Error("could not list staged files");
  return result.stdout.split(String.fromCharCode(0)).filter(Boolean);
}

function trackedPaths(root) {
  const result = git(["ls-files", "-z"], root);
  if (result.status !== 0) throw new Error("could not list tracked files");
  return result.stdout.split(String.fromCharCode(0)).filter(Boolean);
}

// Resolves each CLI-supplied path argument against the caller's cwd (not the
// repo root - `cd docs && secret-gate scan setup.md` must find docs/setup.md,
// not root/setup.md) and relativizes it back to the repo root, because every
// downstream consumer (findings, the allowlist fingerprint) expects a
// root-relative path. Throws - rather than quietly producing nothing to scan
// - on a path that doesn't exist or that resolves outside the repository: a
// typo in an explicit path argument must never read back as "repo is clean."
//
// A directory argument is REJECTED rather than expanded to the tracked files
// beneath it. `scan` already has two well-defined ways to mean "more than
// one file" - no path arguments (every tracked file) and --staged (every
// staged file) - and silently reinterpreting "scan docs" as "scan every
// tracked file under docs" would add a third set of semantics that
// interacts with gitignored files, untracked files and the staged filter in
// ways a caller can't see from the command line. Before this fix,
// `existsSync(abs)` was true for a directory, `readFileSync` inside
// readTarget() then failed with an unlabeled EISDIR, and that came back as
// an ordinary skip - exit 0 by default. `scan .` in someone's CI was a
// permanently green gate that scanned nothing.
function resolveExplicitPaths(root, cwd, args) {
  return args.map((arg) => {
    const abs = path.resolve(cwd, arg);
    if (!existsSync(abs)) {
      throw new Error(`${arg}: no such file`);
    }
    if (statSync(abs).isDirectory()) {
      throw new Error(`${arg}: is a directory - pass individual file paths, or omit paths to scan every tracked file`);
    }
    // path.relative computed BEFORE the "\\" -> "/" normalization, and
    // checked for path.isAbsolute, not just a leading "..": on Windows,
    // path.relative("C:\\repo", "D:\\secrets\\keys.env") returns the second
    // path unchanged (absolute, no leading ".."), because there is no
    // relative path between two drives. The dotdot-only check let that
    // through, and it degraded further downstream into a plain ENOENT skip
    // (path.join glues an absolute Windows path onto the repo root, which
    // resolves nowhere) - exit 0 instead of exit 2.
    const relRaw = path.relative(root, abs);
    if (path.isAbsolute(relRaw)) {
      throw new Error(`${arg}: outside the repository`);
    }
    const rel = relRaw.replaceAll("\\", "/");
    if (rel === ".." || rel.startsWith("../")) {
      throw new Error(`${arg}: outside the repository`);
    }
    return rel;
  });
}

export function isBinary(buffer) {
  return buffer.subarray(0, 8192).includes(0);
}

// Reads one target's bytes, or explains why it couldn't. Returns
// `{ buffer }` on success or `{ skip: "<reason>" }` on failure - never
// silently nothing. A file this couldn't read must show up in the skip list,
// not vanish: `git show` can fail on a gitlink (a submodule reference has no
// blob to print), on a spawn-level failure (a huge staged file can overrun
// the subprocess's maxBuffer), or on a race where a tracked file disappeared
// from disk between listing it and reading it - all three used to come back
// as a bare `null` that `collect()` treated as "nothing to do here."
function readTarget(root, rel, staged) {
  if (staged) {
    const result = git(["show", `:${rel}`], root, "buffer");
    if (result.status === 0 && Buffer.isBuffer(result.stdout)) {
      return { buffer: result.stdout };
    }
    if (result.error) {
      return { skip: `${rel} (git could not read the staged content: ${result.error.code ?? result.error.message})` };
    }
    return { skip: `${rel} (git show :${rel} failed - not a regular staged file, e.g. a gitlink)` };
  }
  const abs = path.join(root, rel);
  try {
    return { buffer: readFileSync(abs) };
  } catch (err) {
    return { skip: `${rel} (could not be read: ${err.code ?? err.constructor.name})` };
  }
}

// --- scan --------------------------------------------------------------

function collect(rel, target, allowlist, findings, skipped) {
  if (target.skip) {
    skipped.push(target.skip);
    return;
  }
  const { buffer } = target;
  if (buffer.length > MAX_SCAN_BYTES) {
    skipped.push(`${rel} (${buffer.length} bytes, over the ${MAX_SCAN_BYTES} byte limit)`);
    return;
  }
  if (isBinary(buffer)) {
    skipped.push(`${rel} (binary)`);
    return;
  }
  for (const hit of findSecrets(buffer.toString("utf8"))) {
    if (isAllowed(allowlist, rel, hit)) continue;
    findings.push({ file: rel, line: hit.line, column: hit.column, label: hit.label });
  }
}

function report(findings, skipped, stale, staged) {
  const out = [];
  if (findings.length > 0) {
    const where = staged ? "staged files" : "tracked files";
    const plural = findings.length === 1 ? "secret" : "secrets";
    out.push(`[secret-gate] BLOCKED - ${findings.length} ${plural} in ${where}`, "");
    // A reduce rather than Math.max(...findings.map(...)): spreading the
    // whole array onto Math.max's argument list overflows the engine's
    // argument-count limit on a large enough findings array, turning a
    // report into a crash (exit 2) instead of a report.
    const width = findings.reduce((max, f) => Math.max(max, `${f.file}:${f.line}:${f.column}`.length), 0);
    for (const f of findings) {
      out.push(`  ${`${f.file}:${f.line}:${f.column}`.padEnd(width)}  ${f.label}`);
    }
    out.push(
      "",
      "Fix one of these ways:",
      "  1. Remove the value and read it from a gitignored .env file instead, or",
      "  2. node scripts/secret-gate/cli.mjs fix --staged",
      `  3. If it is a fixture, pin it in ${ALLOWLIST_FILE}:`,
      `       { "fingerprints": ["${findings[0].file}:${findings[0].label}:${findings[0].line}"] }`,
      "",
    );
  }
  if (skipped.length > 0) {
    out.push(`[secret-gate] skipped ${skipped.length} file(s):`);
    for (const s of skipped) out.push(`  ${s}`);
    out.push("  Pass --strict to fail the scan when anything is skipped.", "");
  }
  if (stale.length > 0) {
    out.push(`[secret-gate] ${ALLOWLIST_FILE} has ${stale.length} stale entry/entries that matched nothing:`);
    for (const s of stale) out.push(`  ${s}`);
    out.push("  Remove them. An allowlist can only be trusted if it shrinks.", "");
  }
  if (findings.length === 0 && skipped.length === 0 && stale.length === 0) {
    out.push("[secret-gate] no credentials found.");
  }
  if (out.length > 0) process.stdout.write(out.join("\n") + "\n");
}

function scan(args) {
  const staged = args.includes("--staged");
  const strict = args.includes("--strict");
  const explicitArgs = args.filter((a) => !a.startsWith("--"));
  const root = repoRoot();
  const allowlist = loadAllowlist(root);

  const targets = staged
    ? stagedPaths(root)
    : explicitArgs.length > 0
      ? resolveExplicitPaths(root, process.cwd(), explicitArgs)
      : trackedPaths(root);
  const findings = [];
  const skipped = [];

  for (const rel of targets) {
    collect(rel, readTarget(root, rel, staged), allowlist, findings, skipped);
  }

  // staleEntries() only reports entries that never matched during the loop
  // above, so it must run after every isAllowed() call, not before.
  const stale = staleEntries(allowlist);
  report(findings, skipped, stale, staged);
  if (findings.length > 0) return 1;
  // The default stays 0 for a skip alone: a pre-commit hook branches on the
  // exit code, and making every skip fail would block every commit that
  // merely touches an image - a gate people learn to route around protects
  // nothing. --strict is for CI, where a red build over a skipped file is
  // the correct response because no human is waiting on it.
  if (strict && skipped.length > 0) return 1;
  return 0;
}

// --- fix -----------------------------------------------------------------
//
// The only command in this plugin that WRITES to a user's files, so every
// choice here is defensive rather than convenient. `fix` deliberately
// reuses scan's own file-reading machinery (readTarget, isBinary,
// MAX_SCAN_BYTES) rather than a second, looser read path, because it must
// inherit every edge case scan already learned to handle the hard way:
//
//   - A binary or oversize file is skipped, exactly like collect() skips it
//     in scan - never partially rewritten. A partial rewrite of a binary
//     file is data loss, not a fix.
//   - loadAllowlist(root) runs ONCE, before the loop touches a single file.
//     It throws on invalid JSON, an invalid regex or an unrecognized
//     version - and because that throw happens before any writeFileSync,
//     it propagates straight to main()'s catch (exit 2) having rewritten
//     nothing. Rewriting files under a broken allowlist would be the worst
//     possible combination this tool could produce, so the fix is
//     structural: there is no code path between "allowlist failed to load"
//     and "a file got rewritten."
//   - A file whose hits are ALL allowlisted is `continue`d before the
//     write, not rewritten-with-identical-content-and-restaged. The
//     tests compare git blob hashes, not just file content, to hold this.
//   - Only the exact [start, end) byte range findSecrets/tokenFor reported
//     is replaced; every other byte survives untouched. Splicing via
//     text.slice() rather than a global regex replace is what keeps a BOM,
//     CRLF line endings and a missing trailing newline byte-identical on
//     the way through - the same guarantee redactText() gives the hooks.
//
// fix rewrites the WORKTREE file (readTarget(..., staged: false)), because
// that is the copy the user has open, then restages exactly that file with
// `git add -- <rel>`.
function fix(args) {
  if (!args.includes("--staged")) {
    process.stderr.write("[secret-gate] fix requires --staged. It will not rewrite unstaged files.\n");
    return 2;
  }
  const root = repoRoot();
  const allowlist = loadAllowlist(root); // throws -> propagates to main()'s catch, exit 2, nothing written yet
  const lines = [];
  let total = 0;

  for (const rel of stagedPaths(root)) {
    const target = readTarget(root, rel, false);
    if (target.skip) continue; // unreadable/gone - nothing fix() can safely rewrite
    const { buffer } = target;
    if (buffer.length > MAX_SCAN_BYTES || isBinary(buffer)) continue;

    const text = buffer.toString("utf8");
    const hits = findSecrets(text).filter((hit) => !isAllowed(allowlist, rel, hit));
    if (hits.length === 0) continue;

    const state = newState();
    let out = "";
    let last = 0;
    for (const hit of hits) {
      out += text.slice(last, hit.start) + tokenFor(hit.value, hit.label, state);
      last = hit.end;
    }
    writeFileSync(path.join(root, rel), Buffer.from(out + text.slice(last), "utf8"));

    const added = git(["add", "--", rel], root);
    if (added.status !== 0) throw new Error(`could not restage ${rel}`);

    lines.push(`  ${rel}: ${hits.length} replaced (${[...new Set(hits.map((h) => h.label))].join(", ")})`);
    total += hits.length;
  }

  if (total === 0) {
    process.stdout.write("[secret-gate] nothing to fix.\n");
    return 0;
  }
  process.stdout.write(
    [`[secret-gate] rewrote ${total} value(s) to [REDACTED] markers and restaged:`, ...lines, ""].join("\n"),
  );
  return 0;
}

// --- entry point -------------------------------------------------------

export async function main(argv = process.argv.slice(2)) {
  const cmd = argv[0];
  try {
    if (cmd === "--version" || cmd === "-v") {
      process.stdout.write(VERSION + "\n");
      return 0;
    }
    if (cmd === "scan") return scan(argv.slice(1));
    if (cmd === "fix") return fix(argv.slice(1));
    process.stderr.write(USAGE);
    return 2;
  } catch (err) {
    process.stderr.write(`[secret-gate] ${err.message}\n`);
    return 2;
  }
}

// pathToFileURL handles the drive-letter and separator differences a
// hand-built `file://${...}` template can get wrong. That matters here
// specifically because a mismatch fails open: if this comparison is ever
// wrong, `invokedDirectly` is false, `main()` never runs, and the process
// exits 0 having scanned nothing.
const invokedDirectly = process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href;

if (invokedDirectly) {
  main().then((code) => process.exit(code));
}
