#!/usr/bin/env node
// lib/cli.mjs
//
// scan / fix / install. This file plus its whole relative-import closure
// (detect.mjs, allowlist.mjs, gitignore.mjs - see VENDORED_FILES below) is
// what `install` vendors into a repo, so all of them import each other with
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
import { existsSync, readFileSync, writeFileSync, statSync, lstatSync, mkdirSync, copyFileSync, chmodSync } from "node:fs";
import { spawnSync } from "node:child_process";
import path from "node:path";
import { pathToFileURL, fileURLToPath } from "node:url";
import { findSecrets, newState, redactRanges, MAX_SCAN_BYTES } from "./detect.mjs";
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
// choice here is defensive rather than convenient.
//
// FINDINGS from Task 10 review round 1, all fixed here:
//
//   1 (CRITICAL) fix used to decode with buffer.toString("utf8") and write
//     the decoded string back. For a file that is not valid UTF-8 (a
//     Latin-1/CP1252 config file, say) that decode is LOSSY - every invalid
//     byte becomes U+FFFD on the way in, and writing the string back turns
//     each one into the 3-byte UTF-8 encoding of U+FFFD on the way out.
//     Content OUTSIDE the finding changed, silently, and `git add` carried
//     the corruption into the index. Fixed by round-tripping every staged
//     buffer through Buffer.from(text, "utf8").equals(buffer) before ever
//     writing it - a file that fails that check is refused, not rewritten.
//   2 (CRITICAL) fix decided from the WORKTREE, scanned from the STAGED
//     blob, and assumed they matched. When they don't - hand-edited after
//     staging, deleted after staging, or partially staged with `git add
//     -p` - fix either reported "nothing to fix" while a credential stayed
//     in the index, or promoted deliberately-unstaged content into the
//     commit unannounced. Fixed by finding hits in the STAGED blob (so a
//     deleted-from-worktree file is still caught) and refusing to touch
//     anything that diverges from it. This is the cheap, safe half of the
//     fix: REFUSE on divergence rather than attempt to redact the index
//     blob directly (that needs its own task - hash-object -w plus
//     update-index --cacheinfo, with its own review).
//   A (review round 3) the divergence check above was originally a raw
//     byte comparison, which refused every file affected by git's own EOL
//     normalization - on a default Git-for-Windows install, core.autocrlf
//     =true means most text files legitimately differ byte-for-byte
//     between the index (LF) and the worktree (CRLF) with nobody having
//     edited anything, so fix became a dead end for most of a user's
//     files. Fixed by asking git the question instead: `git diff --quiet
//     -- <rel>`, which compares post-normalization/post-filter, exactly
//     like `git status` would. See the git() call itself for the exit-code
//     contract.
//   B (review round 4) once Finding A stopped treating an autocrlf-only
//     difference as divergence, fix still wrote a redaction of the STAGED
//     text back to the WORKTREE path - so a 3-line CRLF file with a
//     finding on one line came back with ALL THREE lines silently
//     reformatted to LF (the index's normalized form), not just the line
//     with the finding. Not data loss, but a broken promise (round 1's own
//     "everything outside the hit is byte-identical" guarantee). Fixed by
//     re-running findSecrets against the WORKTREE text and splicing into
//     THAT, rather than mapping staged offsets onto worktree bytes - the
//     decision to act still comes from the staged copy (Critical 2 is
//     unchanged), only the text that gets redacted and written does not.
//     If the two copies somehow yield a different number of hits despite
//     `git diff --quiet` calling them equivalent, fix refuses rather than
//     guess which count is right.
//   3 fix wrote THROUGH a symlink: readFileSync/writeFileSync on a tracked
//     symlink pointing outside the repo reads and rewrites the link's
//     TARGET, which `git show` (the index blob is just link text) never
//     sees and `scan --staged` therefore never flags. lstatSync(...).isFile()
//     gates the write; anything else (symlink, directory, fifo) is skipped.
//   4 `args.includes("--staged")` was the only inspection fix did of its
//     own argv - `fix --staged --dry-run some/path.md` silently rewrote
//     every staged finding in the whole repo. fix takes exactly one flag;
//     anything else is now a usage error (exit 2).
//   5 scan's report() lists every skip; fix's did not, so a file skipped
//     for being binary/oversize/invalid-UTF-8/a-symlink/diverged vanished
//     from the output with no way to tell "skipped" from "genuinely clean."
//     Every skip reason below is now collected into the same kind of skip
//     list scan already prints.
//   6 a mid-loop failure (an unwritable worktree file, `git add` failing)
//     used to throw straight out of the file loop, discarding the summary
//     of files already rewritten-and-restaged earlier in the same run. A
//     write/restage failure is now itself a per-file skip: the loop keeps
//     going, and whatever succeeded before or after it is still reported.
//
// Exit code: 0 only when every finding in scope was either fixed or was
// never a problem (fully allowlisted). 1 when a real, unresolved finding
// remains (invalid UTF-8, a symlink, staged/worktree divergence, a write
// failure) - the caller must not read fix's exit 0 as "the repo is now
// clean" unless it also reruns scan, same as this file's own remediation
// text already tells them to. 2 is reserved for usage errors and for
// repoRoot()/loadAllowlist()/stagedPaths() failing before any file is
// touched.
function fix(args) {
  const KNOWN_FLAGS = new Set(["--staged"]);
  const unknown = args.find((a) => !KNOWN_FLAGS.has(a));
  if (unknown !== undefined) {
    process.stderr.write(`[secret-gate] fix: unrecognized argument '${unknown}'. Usage: fix --staged\n`);
    return 2;
  }
  if (!args.includes("--staged")) {
    process.stderr.write("[secret-gate] fix requires --staged. It will not rewrite unstaged files.\n");
    return 2;
  }

  const root = repoRoot();
  const allowlist = loadAllowlist(root); // throws -> propagates to main()'s catch, exit 2, nothing written yet
  const lines = [];
  const skipped = [];
  let total = 0;
  let unresolved = 0;

  for (const rel of stagedPaths(root)) {
    // Finding 2: hits are found in the STAGED blob, not the worktree copy -
    // scan --staged is the promise fix is keeping, and the staged blob is
    // the only copy that promise is actually about.
    const stagedTarget = readTarget(root, rel, true);
    if (stagedTarget.skip) {
      skipped.push(stagedTarget.skip);
      continue;
    }
    const stagedBuffer = stagedTarget.buffer;

    if (stagedBuffer.length > MAX_SCAN_BYTES) {
      skipped.push(`${rel} (${stagedBuffer.length} bytes, over the ${MAX_SCAN_BYTES} byte limit)`);
      continue;
    }
    if (isBinary(stagedBuffer)) {
      skipped.push(`${rel} (binary)`);
      continue;
    }

    const stagedText = stagedBuffer.toString("utf8");
    const hits = findSecrets(stagedText).filter((hit) => !isAllowed(allowlist, rel, hit));
    if (hits.length === 0) continue; // no unresolved finding here - nothing to report either

    // Finding 1: refuse rather than corrupt. A file that round-trips
    // cleanly through UTF-8 gets its bytes back unchanged outside the
    // hits; one that doesn't would silently mangle every invalid byte,
    // not just the ones inside a finding.
    if (!Buffer.from(stagedText, "utf8").equals(stagedBuffer)) {
      skipped.push(`${rel} (not valid UTF-8 - rewriting it would corrupt bytes outside the finding, left as-is)`);
      unresolved++;
      continue;
    }

    const abs = path.join(root, rel);

    // Finding 3: a tracked symlink's worktree entry is the link, not the
    // target - lstat (which does NOT follow the link) before anything that
    // would (readFileSync/writeFileSync both follow it).
    let lst;
    try {
      lst = lstatSync(abs);
    } catch {
      // Finding 2, case C: staged content exists (we already have a real
      // hit in stagedBuffer) but the worktree copy is gone.
      skipped.push(`${rel}: staged content differs from the worktree (the file is missing) - fix cannot rewrite it safely`);
      unresolved++;
      continue;
    }
    if (!lst.isFile()) {
      skipped.push(`${rel} (not a regular file on disk - e.g. a symlink - fix will not follow it)`);
      unresolved++;
      continue;
    }

    // Finding 2, cases A and B / Finding A (review round 3): ask GIT whether
    // the worktree and the index differ for this path, rather than compare
    // raw bytes. A byte comparison refuses every file affected by git's own
    // EOL normalization or a clean/smudge filter (Git LFS included) - on a
    // default Git-for-Windows install, core.autocrlf=true means the index
    // legitimately holds LF while the worktree legitimately holds CRLF for
    // a file nobody has hand-edited, and a byte comparison called that
    // "diverged" and refused nearly every text file in the repo.
    // `git diff --quiet` answers the same question git itself would give
    // `git status` - after normalization and filters, not before - so an
    // autocrlf-only difference reads as "no divergence" while a real
    // hand-edit (cases A and B) or a partial stage (case B) still reads as
    // one. Routed through the shared git() choke-point, so it keeps
    // gitEnv()'s hardening against a poisoned GIT_* environment.
    //
    // Exit code contract: 0 = no divergence, proceed. 1 = a real
    // difference, refuse. Anything else (a spawn failure, git erroring for
    // an unrelated reason) means git could not give a clear answer - and a
    // command that writes files must not proceed on an unclear one, so
    // that also refuses.
    const diverges = git(["diff", "--quiet", "--", rel], root);
    if (diverges.status === 1) {
      skipped.push(`${rel}: staged content differs from the worktree - fix cannot rewrite it safely`);
      unresolved++;
      continue;
    }
    if (diverges.status !== 0) {
      skipped.push(`${rel}: could not determine whether the staged content matches the worktree - fix cannot rewrite it safely`);
      unresolved++;
      continue;
    }

    // Finding B (review round 4): splice into the WORKTREE's own text, not
    // the staged text. `git diff --quiet` just confirmed the two copies are
    // equivalent in git's terms, so the same secrets are present in both -
    // they simply sit at different byte offsets whenever core.autocrlf, a
    // .gitattributes normalization rule, or a clean/smudge filter is in
    // play (which is the ordinary case on Windows, not an edge case).
    // Splicing the STAGED offsets into the WORKTREE text - or writing the
    // staged text back to the worktree path at all - silently reformats
    // every line in the file to match the index's line endings, not just
    // the ones with a finding. Finding the hits again directly in the
    // worktree text sidesteps offset-translation entirely and cannot drift.
    //
    // The decision that there is something to fix, and the divergence
    // refusal above, still come from the STAGED copy (hits, stagedBuffer,
    // stagedText) - only the text that gets redacted and written changes.
    let worktreeBuffer;
    try {
      worktreeBuffer = readFileSync(abs);
    } catch (err) {
      skipped.push(`${rel} (worktree copy could not be read: ${err.code ?? err.constructor.name})`);
      unresolved++;
      continue;
    }
    const worktreeText = worktreeBuffer.toString("utf8");

    // Finding 1's guarantee, carried over to whichever buffer is actually
    // written: since the write target changed from the staged buffer to
    // the worktree buffer, the round-trip check has to move with it, or a
    // worktree copy produced by an encoding-changing filter could be
    // corrupted exactly the way Finding 1 already fixed once.
    if (!Buffer.from(worktreeText, "utf8").equals(worktreeBuffer)) {
      skipped.push(`${rel} (worktree copy is not valid UTF-8 - rewriting it would corrupt bytes outside the finding, left as-is)`);
      unresolved++;
      continue;
    }

    const worktreeHits = findSecrets(worktreeText).filter((hit) => !isAllowed(allowlist, rel, hit));

    // git diff --quiet said the staged and worktree copies are equivalent,
    // so they should carry the same number of unresolved findings. If they
    // don't - a filter that changes content in a way `git diff` doesn't
    // consider a difference, or anything else this file didn't anticipate
    // - refuse rather than guess which count is right. A command that
    // writes files does not proceed on an inconsistency it cannot explain.
    if (worktreeHits.length !== hits.length) {
      skipped.push(
        `${rel}: found ${hits.length} finding(s) in the staged copy but ${worktreeHits.length} in the worktree copy - fix cannot rewrite it safely`,
      );
      unresolved++;
      continue;
    }

    const state = newState();
    const rewritten = redactRanges(worktreeText, worktreeHits, state);

    // Finding 6: a write or restage failure demotes this file to a skip
    // instead of throwing out of the loop, so files handled earlier (or
    // later) in the same run are still rewritten, restaged and reported.
    try {
      writeFileSync(abs, Buffer.from(rewritten, "utf8"));
      const added = git(["add", "--", rel], root);
      if (added.status !== 0) {
        throw new Error(added.error ? (added.error.code ?? added.error.message) : "git add failed");
      }
    } catch (err) {
      skipped.push(`${rel} (could not be rewritten/restaged: ${err.code ?? err.message})`);
      unresolved++;
      continue;
    }

    lines.push(`  ${rel}: ${worktreeHits.length} replaced (${[...new Set(worktreeHits.map((h) => h.label))].join(", ")})`);
    total += worktreeHits.length;
  }

  // Finding 5: report skips the way scan's report() does, not silently.
  const out = [];
  if (total > 0) {
    out.push(`[secret-gate] rewrote ${total} value(s) to [REDACTED] markers and restaged:`, ...lines, "");
  } else if (skipped.length === 0) {
    out.push("[secret-gate] nothing to fix.");
  }
  if (skipped.length > 0) {
    out.push(`[secret-gate] skipped ${skipped.length} file(s):`);
    for (const s of skipped) out.push(`  ${s}`);
    out.push("");
  }
  if (out.length > 0) process.stdout.write(out.join("\n") + "\n");

  return unresolved > 0 ? 1 : 0;
}

// --- install ---------------------------------------------------------------
//
// Vendors this library into a target repo as plain, dependency-free files so
// the gate belongs to the REPO, not to a machine that happens to have this
// plugin installed - it has to work in CI, in a fresh clone, and for someone
// who does not use Claude Code at all.
//
// VENDORED_FILES is the import closure of this file, not a hand-picked list.
// Vendoring three files (detect, allowlist, cli) shipped once already and
// made every install DOA the moment allowlist.mjs and this file itself
// started importing gitEnv/gitIgnores from gitignore.mjs: the vendored copy
// of cli.mjs failed on its very first run, in every installed repo, with
// Cannot find module './gitignore.mjs'. Closing that by name (adding
// "gitignore.mjs" to a literal array) fixes today; the exported constant
// here plus test/cli-install.test.mjs's closure-derivation test is what
// keeps the next added import from repeating it a fourth time.
export const VENDORED_FILES = ["detect.mjs", "allowlist.mjs", "gitignore.mjs", "cli.mjs"];

const MARK_START = "# >>> secret-gate";
const MARK_END = "# <<< secret-gate";
const VENDOR_DIR = path.join("scripts", "secret-gate");
const LF_RULE = ".githooks/** text eol=lf";

function here() {
  return path.dirname(fileURLToPath(import.meta.url));
}

function template(name) {
  const file = path.join(here(), "..", "templates", name);
  if (!existsSync(file)) {
    throw new Error(
      "templates/ is missing. Run `install` from the plugin, not from a vendored scripts/secret-gate/ copy.",
    );
  }
  return readFileSync(file, "utf8").replaceAll("__VERSION__", VERSION).replaceAll("\r\n", "\n");
}

function writeLf(file, contents) {
  mkdirSync(path.dirname(file), { recursive: true });
  writeFileSync(file, contents.replaceAll("\r\n", "\n"), { encoding: "utf8" });
}

function spliceHook(existing, block) {
  const start = existing.indexOf(MARK_START);
  const end = existing.indexOf(MARK_END);
  if (start !== -1 && end !== -1 && end > start) {
    return existing.slice(0, start) + block.trim() + existing.slice(end + MARK_END.length);
  }
  return existing.replace(/\s*$/, "") + "\n\n" + block.trim() + "\n";
}

function stampOf(text) {
  const match = text.match(/secret-gate (\d+\.\d+\.\d+)/);
  return match ? match[1] : null;
}

function install(args) {
  const force = args.includes("--force");
  const root = repoRoot();
  const notes = [];

  // 1. vendor the library's actual import closure plus a version stamp
  const vendorTarget = path.join(root, VENDOR_DIR);
  mkdirSync(vendorTarget, { recursive: true });
  for (const name of VENDORED_FILES) {
    copyFileSync(path.join(here(), name), path.join(vendorTarget, name));
  }
  writeFileSync(path.join(vendorTarget, "VERSION"), VERSION + "\n");
  notes.push(`vendored ${VENDOR_DIR}/ at ${VERSION}`);

  // 2. allowlist, never clobbered without --force
  const allowFile = path.join(root, ALLOWLIST_FILE);
  if (!existsSync(allowFile) || force) {
    writeLf(allowFile, template("secretgate.json"));
    notes.push(`wrote ${ALLOWLIST_FILE}`);
  } else {
    notes.push(`kept your existing ${ALLOWLIST_FILE}`);
  }

  // 3. pre-commit, spliced between markers so a sibling hook survives
  const hookFile = path.join(root, ".githooks", "pre-commit");
  const full = template("pre-commit");
  const block = full.slice(full.indexOf(MARK_START));
  if (existsSync(hookFile)) {
    writeLf(hookFile, spliceHook(readFileSync(hookFile, "utf8"), block));
    notes.push("updated the secret-gate block in .githooks/pre-commit, left the rest alone");
  } else {
    writeLf(hookFile, full);
    notes.push("wrote .githooks/pre-commit");
  }
  try {
    chmodSync(hookFile, 0o755);
  } catch {
    // Windows has no exec bit. git handles it on checkout.
  }

  // 4. CI workflow, rewritten only when its stamp is older
  const wfFile = path.join(root, ".github", "workflows", "secret-gate.yml");
  const wf = template("workflow.yml");
  if (!existsSync(wfFile) || force || stampOf(readFileSync(wfFile, "utf8")) !== VERSION) {
    writeLf(wfFile, wf);
    notes.push("wrote .github/workflows/secret-gate.yml");
  } else {
    notes.push("workflow already at " + VERSION);
  }

  // 5. LF pin. A CRLF shebang breaks git-for-windows sh.
  const attrFile = path.join(root, ".gitattributes");
  const attrs = existsSync(attrFile) ? readFileSync(attrFile, "utf8") : "";
  if (!attrs.includes(LF_RULE)) {
    writeLf(attrFile, attrs.replace(/\s*$/, "") + (attrs.trim() ? "\n" : "") + LF_RULE + "\n");
    notes.push("pinned .githooks/** to LF in .gitattributes");
  }

  // 6. hooksPath, only when it is unset or already ours
  const current = git(["config", "--get", "core.hooksPath"], root);
  const value = current.status === 0 ? current.stdout.trim() : "";
  if (value === "" || value === ".githooks") {
    git(["config", "core.hooksPath", ".githooks"], root);
    notes.push("set core.hooksPath to .githooks");
  } else {
    notes.push(
      `LEFT ALONE: core.hooksPath is ${value}, not .githooks. ` +
        `Wire .githooks/pre-commit into ${value} yourself, or run: git config core.hooksPath .githooks`,
    );
  }

  process.stdout.write(
    [
      `[secret-gate] installed ${VERSION} into ${root}`,
      ...notes.map((n) => "  " + n),
      "",
      "Commit the new files so the gate travels with the repo:",
      `  git add ${VENDOR_DIR} ${ALLOWLIST_FILE} .githooks .github/workflows/secret-gate.yml .gitattributes`,
      "",
      "On another clone of this repo, run:  git config core.hooksPath .githooks",
      "",
    ].join("\n"),
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
    if (cmd === "install") return install(argv.slice(1));
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
