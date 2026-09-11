import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync, writeFileSync, mkdirSync, existsSync, readdirSync } from "node:fs";
import { execFileSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import path from "node:path";
import { makeRepo, runCli, runGit, isolatedGitEnv } from "./helpers/temp-repo.mjs";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const GITLEAKS_HOOK = readFileSync(path.join(HERE, "fixtures", "gitleaks-pre-commit"), "utf8");
const STRIPE_SHAPED_KEY = "sk_live_" + "a".repeat(24); // synthetic - matches detect.mjs's shape, not a real key

function installInto(dir, args = []) {
  return runCli(dir, ["install", ...args]);
}

// Task 11 review Findings 1 and 2 need to execute the COMBINED hook (the
// generated block spliced into a host hook) as a real shell script, not just
// regex-match its text - that is the exact class of hole review Finding 1
// found: file-existence/text assertions passed while the real gate never
// fired. Both findings' tests run this repo's real `gitleaks` if it happens
// to be on PATH (it is, on this machine, via scoop), so PATH is filtered to
// remove any directory that actually contains a gitleaks binary rather than
// trusting the ambient environment to be gitleaks-free.
function pathWithoutGitleaks() {
  const raw = process.env.PATH ?? process.env.Path ?? "";
  const dirs = raw.split(path.delimiter).filter(Boolean);
  const kept = dirs.filter((dir) => {
    let entries;
    try {
      entries = readdirSync(dir);
    } catch {
      return true; // unreadable or missing - nothing to hide here, keep it
    }
    return !entries.some((e) => /^gitleaks(\.(exe|shim))?$/i.test(e));
  });
  return kept.join(path.delimiter);
}

// Runs a hook file with `sh`, the same interpreter git itself uses to run a
// `.githooks/pre-commit` script on this platform, and normalizes the
// exit-code/output shape whether it succeeds or throws.
function runHook(hookFile, { cwd, env } = {}) {
  try {
    const stdout = execFileSync("sh", [hookFile], { cwd, env: env ?? process.env, encoding: "utf8" });
    return { status: 0, output: stdout };
  } catch (err) {
    return { status: err.status ?? 1, output: (err.stdout ?? "") + (err.stderr ?? "") };
  }
}

test("install writes the vendored library, config, hook and workflow into an empty repo", () => {
  const dir = makeRepo({ "a.md": "clean\n" });
  const { code } = installInto(dir);
  assert.equal(code, 0);
  for (const rel of [
    // The vendored library is the actual import closure of cli.mjs, not a
    // hand-picked subset - see the "VENDORED equals the actual import
    // closure" test below, which fails if this list and cli.mjs drift apart
    // again the way it did once already (gitignore.mjs was added to the
    // import graph after this list was first written, and vendoring only
    // three files made every install DOA with a Cannot find module error).
    "scripts/secret-gate/detect.mjs",
    "scripts/secret-gate/allowlist.mjs",
    "scripts/secret-gate/gitignore.mjs",
    "scripts/secret-gate/cli.mjs",
    "scripts/secret-gate/VERSION",
    ".secretgate.json",
    ".githooks/pre-commit",
    ".github/workflows/secret-gate.yml",
    ".gitattributes",
  ]) {
    assert.ok(existsSync(path.join(dir, rel)), rel + " was not written");
  }
});

test("the vendored copy actually runs and blocks", () => {
  const dir = makeRepo({ "a.md": "clean\n" });
  installInto(dir);
  writeFileSync(path.join(dir, "leak.md"), "STRIPE_KEY=" + STRIPE_SHAPED_KEY + "\n");
  runGit(dir, "add", "-A");
  let status = 0;
  try {
    execFileSync(process.execPath, [path.join(dir, "scripts", "secret-gate", "cli.mjs"), "scan", "--staged"], {
      cwd: dir,
      stdio: "pipe",
    });
  } catch (err) {
    status = err.status;
  }
  assert.equal(status, 1);
});

test("install sets core.hooksPath", () => {
  const dir = makeRepo({ "a.md": "clean\n" });
  installInto(dir);
  // Isolated env, same as the write beside it in the next test - a bare
  // execFileSync here would read whatever repo an inherited GIT_DIR names
  // instead of `dir`, same class as the writes runGit() already protects.
  const value = execFileSync("git", ["config", "core.hooksPath"], { cwd: dir, encoding: "utf8", env: isolatedGitEnv(dir) }).trim();
  assert.equal(value, ".githooks");
});

test("install appends to an existing pre-commit and the gitleaks line survives", () => {
  const dir = makeRepo({ "a.md": "clean\n" });
  mkdirSync(path.join(dir, ".githooks"), { recursive: true });
  writeFileSync(path.join(dir, ".githooks", "pre-commit"), GITLEAKS_HOOK);
  installInto(dir);
  const after = readFileSync(path.join(dir, ".githooks", "pre-commit"), "utf8");
  assert.match(after, /gitleaks protect --staged --redact/);
  assert.match(after, /# >>> secret-gate/);
  assert.match(after, /# <<< secret-gate/);
});

test("a second install replaces only the marked block, exactly once", () => {
  const dir = makeRepo({ "a.md": "clean\n" });
  mkdirSync(path.join(dir, ".githooks"), { recursive: true });
  writeFileSync(path.join(dir, ".githooks", "pre-commit"), GITLEAKS_HOOK);
  installInto(dir);
  installInto(dir);
  const after = readFileSync(path.join(dir, ".githooks", "pre-commit"), "utf8");
  assert.equal(after.match(/# >>> secret-gate/g).length, 1);
  assert.match(after, /gitleaks protect --staged --redact/);
});

test("install never overwrites an existing .secretgate.json", () => {
  const dir = makeRepo({ "a.md": "clean\n" });
  const mine = JSON.stringify({ version: 1, paths: ["^vendor/"] });
  writeFileSync(path.join(dir, ".secretgate.json"), mine);
  installInto(dir);
  assert.equal(readFileSync(path.join(dir, ".secretgate.json"), "utf8"), mine);
});

test("--force does overwrite .secretgate.json", () => {
  const dir = makeRepo({ "a.md": "clean\n" });
  writeFileSync(path.join(dir, ".secretgate.json"), JSON.stringify({ version: 1, paths: ["^vendor/"] }));
  installInto(dir, ["--force"]);
  assert.ok(!readFileSync(path.join(dir, ".secretgate.json"), "utf8").includes("vendor"));
});

test("the shipped .secretgate.json ships with zero regexes, so a fresh install has no stale-entry warning", () => {
  // Review, small finding: a "your-[a-z-]+" example regex matched nothing in
  // a fresh repo, so a user's very first scan ended with a complaint that
  // their own brand-new allowlist had a stale entry - a gate whose first
  // impression is a complaint about itself trains people to ignore it.
  const dir = makeRepo({ "a.md": "clean\n" });
  installInto(dir);
  const config = JSON.parse(readFileSync(path.join(dir, ".secretgate.json"), "utf8"));
  assert.deepEqual(config.regexes, []);
});

test("install pins .githooks to LF in .gitattributes without dropping existing rules", () => {
  const dir = makeRepo({ "a.md": "clean\n" });
  writeFileSync(path.join(dir, ".gitattributes"), "*.sh text eol=lf\n");
  installInto(dir);
  const after = readFileSync(path.join(dir, ".gitattributes"), "utf8");
  assert.match(after, /\*\.sh text eol=lf/);
  assert.match(after, /\.githooks\/\*\* text eol=lf/);
});

test("install refuses to change a core.hooksPath that points elsewhere", () => {
  const dir = makeRepo({ "a.md": "clean\n" });
  // A bare execFileSync here (no env) would inherit whatever GIT_* the
  // process already carries - GIT_DIR included - and this WRITE would land
  // in whichever repo GIT_DIR names, not `dir`. Reproduced directly: with an
  // inherited GIT_DIR pointing at a second repo, this exact command set
  // core.hooksPath on that OTHER repo while `dir` stayed untouched. runGit()
  // strips every GIT_*-prefixed variable before spawning, closing that.
  runGit(dir, "config", "core.hooksPath", ".myhooks");
  const { stdout, code } = installInto(dir);
  assert.match(stdout, /core\.hooksPath/);
  assert.match(stdout, /\.myhooks/);
  // Review Finding 4: this branch leaves the gate NOT wired into git at all
  // (core.hooksPath still points at .myhooks, which was never told about
  // .githooks/pre-commit) - the identical failure mode fix (c) closed for
  // the marker-splice refusal, in a different branch of the same function.
  // A scripted rollout must not read this as success either.
  assert.notEqual(code, 0, "install must exit non-zero when it left core.hooksPath pointing elsewhere, gate not wired");
  const value = execFileSync("git", ["config", "core.hooksPath"], { cwd: dir, encoding: "utf8", env: isolatedGitEnv(dir) }).trim();
  assert.equal(value, ".myhooks");
});

test("the generated pre-commit has no CRLF line endings", () => {
  const dir = makeRepo({ "a.md": "clean\n" });
  installInto(dir);
  const raw = readFileSync(path.join(dir, ".githooks", "pre-commit"));
  assert.ok(!raw.includes(Buffer.from("\r\n")), "a CRLF shebang breaks git-for-windows sh");
});

test("the generated CI workflow passes --strict, the generated hook does not", () => {
  // Correction 2: --strict belongs in CI only. Locally a gate that blocks a
  // developer over a file it could not read (an image, say) is a gate they
  // learn to disable, and a gate people disable protects nothing. In CI no
  // human is waiting, so a skip should redden the build.
  const dir = makeRepo({ "a.md": "clean\n" });
  installInto(dir);
  const workflow = readFileSync(path.join(dir, ".github", "workflows", "secret-gate.yml"), "utf8");
  const hook = readFileSync(path.join(dir, ".githooks", "pre-commit"), "utf8");
  assert.match(workflow, /cli\.mjs scan --strict/);
  assert.doesNotMatch(hook, /--strict/);
});

test("a workflow file with an older version stamp is rewritten", () => {
  const dir = makeRepo({ "a.md": "clean\n" });
  mkdirSync(path.join(dir, ".github", "workflows"), { recursive: true });
  writeFileSync(
    path.join(dir, ".github", "workflows", "secret-gate.yml"),
    "# secret-gate 0.0.1\nname: secret-gate\n",
  );
  installInto(dir);
  const after = readFileSync(path.join(dir, ".github", "workflows", "secret-gate.yml"), "utf8");
  assert.match(after, /cli\.mjs scan --strict/);
});

// --- Finding 1 (CRITICAL): the appended block must run even when a host
// hook exits 0 for its own reasons before reaching end-of-file. -----------

test("Finding 1: the block still runs and blocks when the host hook would otherwise exit 0 first (gitleaks absent)", () => {
  const dir = makeRepo({ "a.md": "clean\n" });
  mkdirSync(path.join(dir, ".githooks"), { recursive: true });
  writeFileSync(path.join(dir, ".githooks", "pre-commit"), GITLEAKS_HOOK);
  installInto(dir);
  writeFileSync(path.join(dir, "leak.md"), "STRIPE_KEY=" + STRIPE_SHAPED_KEY + "\n");
  runGit(dir, "add", "-A");
  const env = { ...process.env, PATH: pathWithoutGitleaks() };
  const { status, output } = runHook(path.join(dir, ".githooks", "pre-commit"), { cwd: dir, env });
  assert.notEqual(status, 0, "the combined hook let a staged credential through with gitleaks absent:\n" + output);
});

// --- Finding 2 (Important): `set -e` ahead of the block must not turn a
// crashed scanner (exit 2) into a blocked commit. --------------------------

test("Finding 2: a crashed scanner still warns-and-allows even when set -e precedes the block", () => {
  const dir = makeRepo({ "a.md": "clean\n" });
  mkdirSync(path.join(dir, ".githooks"), { recursive: true });
  // Pre-seed markers with `set -euo pipefail` already ahead of them, then
  // let install splice-replace only the marked span (the same code path
  // every second install takes) - this isolates Finding 2 from Finding 1's
  // fix, which only changes where a block lands when there are NO markers
  // yet. Whatever moved it there (a shebang flag, a legacy layout, a
  // hand-edit), a `set -e` ahead of our block is the scenario in question.
  const preexisting =
    "#!/usr/bin/env sh\n" +
    "set -euo pipefail\n" +
    "# >>> secret-gate 0.0.1\n" +
    "echo stale\n" +
    "# <<< secret-gate\n";
  writeFileSync(path.join(dir, ".githooks", "pre-commit"), preexisting);
  installInto(dir);
  // A real crash, not a stub: invalid JSON makes loadAllowlist() throw,
  // which main()'s catch turns into exit 2 - "the scanner itself broke,"
  // exactly the case Correction 3 says must warn and allow, never block.
  writeFileSync(path.join(dir, ".secretgate.json"), "{ not json");
  writeFileSync(path.join(dir, "clean.md"), "nothing secret here\n");
  runGit(dir, "add", "-A");
  const { status, output } = runHook(path.join(dir, ".githooks", "pre-commit"), { cwd: dir });
  assert.equal(status, 0, "a broken scanner must not block a commit when set -e precedes the block:\n" + output);
});

// --- Finding 4 (Important, destructive): the workflow must not be
// overwritten just because its stamp differs - only when it is OLDER. -----

test("Finding 4: a hand-written workflow file with no version stamp is kept, not destroyed", () => {
  const dir = makeRepo({ "a.md": "clean\n" });
  mkdirSync(path.join(dir, ".github", "workflows"), { recursive: true });
  const handWritten = "name: my-own-ci\non: [push]\njobs: {}\n";
  writeFileSync(path.join(dir, ".github", "workflows", "secret-gate.yml"), handWritten);
  installInto(dir);
  assert.equal(readFileSync(path.join(dir, ".github", "workflows", "secret-gate.yml"), "utf8"), handWritten);
});

test("Finding 4: a workflow stamped newer than this version is not downgraded", () => {
  const dir = makeRepo({ "a.md": "clean\n" });
  mkdirSync(path.join(dir, ".github", "workflows"), { recursive: true });
  const newer = "# secret-gate 9.9.9\nname: secret-gate\n";
  writeFileSync(path.join(dir, ".github", "workflows", "secret-gate.yml"), newer);
  installInto(dir);
  assert.equal(readFileSync(path.join(dir, ".github", "workflows", "secret-gate.yml"), "utf8"), newer);
});

test("Finding 4: --force still overwrites a hand-written or newer-stamped workflow file", () => {
  const dir = makeRepo({ "a.md": "clean\n" });
  mkdirSync(path.join(dir, ".github", "workflows"), { recursive: true });
  writeFileSync(path.join(dir, ".github", "workflows", "secret-gate.yml"), "# secret-gate 9.9.9\nname: mine\n");
  installInto(dir, ["--force"]);
  const after = readFileSync(path.join(dir, ".github", "workflows", "secret-gate.yml"), "utf8");
  assert.match(after, /cli\.mjs scan --strict/);
});

// --- Finding 5 (Important, destructive and silent): a lone marker must
// refuse, never splice from the wrong pair and delete what's between. -----

test("Finding 5: a lone start marker with no matching end marker is refused, not spliced into data loss", () => {
  const dir = makeRepo({ "a.md": "clean\n" });
  mkdirSync(path.join(dir, ".githooks"), { recursive: true });
  const broken =
    "#!/usr/bin/env sh\n" +
    "# >>> secret-gate 1.0.0\n" +
    "echo old\n" +
    "# user content below, no end marker\n" +
    "echo user-line\n";
  writeFileSync(path.join(dir, ".githooks", "pre-commit"), broken);

  const first = installInto(dir);
  const after1 = readFileSync(path.join(dir, ".githooks", "pre-commit"), "utf8");
  assert.equal(after1, broken, "install must not touch a file with an unmatched marker");
  assert.match(first.stdout, /marker/i);
  assert.notEqual(first.code, 0, "install must exit non-zero when it refused to wire the hook up");

  const second = installInto(dir);
  const after2 = readFileSync(path.join(dir, ".githooks", "pre-commit"), "utf8");
  assert.equal(after2, broken, "a second install must not touch it either");
  assert.match(second.stdout, /marker/i);
  assert.notEqual(second.code, 0, "a second refused install must also exit non-zero");
});

// --- Finding A (Important, destructive): a duplicate start marker inside
// an otherwise well-formed span must not delete what's between the two. --

test("Finding A: a second start marker between a real pair is refused, not spliced into data loss", () => {
  const dir = makeRepo({ "a.md": "clean\n" });
  mkdirSync(path.join(dir, ".githooks"), { recursive: true });
  const broken =
    "#!/usr/bin/env sh\n" +
    "# >>> secret-gate 1.0.0\n" +
    "echo user-line-1\n" +
    "# >>> secret-gate 1.0.0\n" +
    "echo user-line-2\n" +
    "# <<< secret-gate\n" +
    "echo user-line-3\n";
  writeFileSync(path.join(dir, ".githooks", "pre-commit"), broken);

  const first = installInto(dir);
  const after1 = readFileSync(path.join(dir, ".githooks", "pre-commit"), "utf8");
  assert.equal(after1, broken, "install must not delete content between a duplicate start marker and the real end marker");
  assert.match(first.stdout, /marker/i);
  assert.doesNotMatch(first.stdout, /left the rest alone/, "the note must not claim success when it refused");
  assert.notEqual(first.code, 0, "install must exit non-zero when it refused to wire the hook up");

  const second = installInto(dir);
  const after2 = readFileSync(path.join(dir, ".githooks", "pre-commit"), "utf8");
  assert.equal(after2, broken, "a second install must not touch it either");
  assert.notEqual(second.code, 0, "a second refused install must also exit non-zero");
});

// --- Finding B (Minor): the end-marker-only refusal must be reachable. ---

test("Finding B: a lone end marker with no start marker is refused (the mirror case of Finding 5)", () => {
  const dir = makeRepo({ "a.md": "clean\n" });
  mkdirSync(path.join(dir, ".githooks"), { recursive: true });
  const broken = "#!/usr/bin/env sh\necho before\n# <<< secret-gate\necho after\n";
  writeFileSync(path.join(dir, ".githooks", "pre-commit"), broken);

  const { stdout, code } = installInto(dir);
  const after = readFileSync(path.join(dir, ".githooks", "pre-commit"), "utf8");
  assert.equal(after, broken, "a lone end marker must be refused, not silently treated as no-markers-at-all");
  assert.match(stdout, /marker/i);
  assert.notEqual(code, 0, "install must exit non-zero when it refused to wire the hook up");
});

// --- Finding C (Minor): the shebang must survive an empty file, a
// whitespace-only file, and a BOM sitting ahead of a real shebang. --------

test("Finding C: installing over an empty existing hook file writes the full template, shebang included", () => {
  const dir = makeRepo({ "a.md": "clean\n" });
  mkdirSync(path.join(dir, ".githooks"), { recursive: true });
  writeFileSync(path.join(dir, ".githooks", "pre-commit"), "");
  installInto(dir);
  const after = readFileSync(path.join(dir, ".githooks", "pre-commit"), "utf8");
  assert.match(after, /^#!\/usr\/bin\/env sh\n/, "an empty existing hook must not lose the shebang");
  assert.match(after, /# >>> secret-gate/);
});

test("Finding C: installing over a whitespace-only existing hook file writes the full template, shebang included", () => {
  const dir = makeRepo({ "a.md": "clean\n" });
  mkdirSync(path.join(dir, ".githooks"), { recursive: true });
  writeFileSync(path.join(dir, ".githooks", "pre-commit"), "   \n\n\t\n");
  installInto(dir);
  const after = readFileSync(path.join(dir, ".githooks", "pre-commit"), "utf8");
  assert.match(after, /^#!\/usr\/bin\/env sh\n/, "a whitespace-only existing hook must not lose the shebang");
  assert.match(after, /# >>> secret-gate/);
});

test("Finding C: a BOM ahead of the host's shebang does not demote it to an inert comment", () => {
  const dir = makeRepo({ "a.md": "clean\n" });
  mkdirSync(path.join(dir, ".githooks"), { recursive: true });
  const withBom = "\uFEFF#!/usr/bin/env bash\nset -e\necho host-body\n";
  writeFileSync(path.join(dir, ".githooks", "pre-commit"), withBom);
  installInto(dir);
  const raw = readFileSync(path.join(dir, ".githooks", "pre-commit"));
  const text = raw.toString("utf8");
  assert.ok(!raw.includes(Buffer.from("\uFEFF", "utf8")), "the BOM must not survive into the merged file");
  assert.match(text, /^#!\/usr\/bin\/env bash\n/, "the host's real shebang must be the file's first line, not an inert comment further down");
  assert.match(text, /echo host-body/, "the host's own body must survive alongside the block");
  assert.match(text, /# >>> secret-gate/);
});

// --- close-by-class follow-up to Finding C: a single `\uFEFF` strip only
// covers ONE leading BOM. A double BOM, a leading blank line, or leading
// spaces ahead of the shebang all reach the same `noBom.startsWith("#!")`
// check still false, and the shebang gets demoted into the merged file's
// body exactly the way a lone BOM used to. -------------------------------

test("Finding C follow-up: a double BOM ahead of the host's shebang does not demote it", () => {
  const dir = makeRepo({ "a.md": "clean\n" });
  mkdirSync(path.join(dir, ".githooks"), { recursive: true });
  const doubleBom = "\uFEFF\uFEFF#!/usr/bin/env bash\nset -e\necho host-body\n";
  writeFileSync(path.join(dir, ".githooks", "pre-commit"), doubleBom);
  installInto(dir);
  const raw = readFileSync(path.join(dir, ".githooks", "pre-commit"));
  const text = raw.toString("utf8");
  assert.ok(!raw.includes(Buffer.from("\uFEFF", "utf8")), "no BOM must survive into the merged file");
  assert.match(text, /^#!\/usr\/bin\/env bash\n/, "the host's real shebang must be the file's first line");
  assert.match(text, /echo host-body/, "the host's own body must survive alongside the block");
  assert.match(text, /# >>> secret-gate/);
});

test("Finding C follow-up: a leading blank line ahead of the host's shebang does not demote it", () => {
  const dir = makeRepo({ "a.md": "clean\n" });
  mkdirSync(path.join(dir, ".githooks"), { recursive: true });
  const leadingBlank = "\n#!/usr/bin/env bash\nset -e\necho host-body\n";
  writeFileSync(path.join(dir, ".githooks", "pre-commit"), leadingBlank);
  installInto(dir);
  const text = readFileSync(path.join(dir, ".githooks", "pre-commit"), "utf8");
  assert.match(text, /^#!\/usr\/bin\/env bash\n/, "the host's real shebang must be the file's first line");
  assert.match(text, /echo host-body/, "the host's own body must survive alongside the block");
  assert.match(text, /# >>> secret-gate/);
});

test("Finding C follow-up: leading spaces ahead of the host's shebang do not demote it", () => {
  const dir = makeRepo({ "a.md": "clean\n" });
  mkdirSync(path.join(dir, ".githooks"), { recursive: true });
  const leadingSpaces = "   #!/usr/bin/env bash\nset -e\necho host-body\n";
  writeFileSync(path.join(dir, ".githooks", "pre-commit"), leadingSpaces);
  installInto(dir);
  const text = readFileSync(path.join(dir, ".githooks", "pre-commit"), "utf8");
  assert.match(text, /^#!\/usr\/bin\/env bash\n/, "the host's real shebang must be the file's first line");
  assert.match(text, /echo host-body/, "the host's own body must survive alongside the block");
  assert.match(text, /# >>> secret-gate/);
});

// --- Finding 6 (Important): the hook must be staged executable, or POSIX
// git on a clone from this machine silently never runs it. -----------------

test("Finding 6: the installed hook is staged executable (100755) so POSIX git will run it", () => {
  const dir = makeRepo({ "a.md": "clean\n" });
  installInto(dir);
  const out = execFileSync("git", ["ls-files", "-s", ".githooks/pre-commit"], { cwd: dir, encoding: "utf8" });
  assert.match(out, /^100755\s/, "git ls-files -s reported: " + out);
});

test("Finding 6: a second install over an existing hook keeps it staged executable", () => {
  const dir = makeRepo({ "a.md": "clean\n" });
  mkdirSync(path.join(dir, ".githooks"), { recursive: true });
  writeFileSync(path.join(dir, ".githooks", "pre-commit"), GITLEAKS_HOOK);
  installInto(dir);
  installInto(dir);
  const out = execFileSync("git", ["ls-files", "-s", ".githooks/pre-commit"], { cwd: dir, encoding: "utf8" });
  assert.match(out, /^100755\s/, "git ls-files -s reported: " + out);
});

// --- small finding: the printed copy-paste command must use forward
// slashes, or bash treats a Windows-built backslash as an escape. ----------

test("the printed git add hint uses forward slashes even where path.join would use backslashes", () => {
  const dir = makeRepo({ "a.md": "clean\n" });
  const { stdout } = installInto(dir);
  const addLine = stdout.split("\n").find((l) => l.includes("git add"));
  assert.ok(addLine, "no git add hint found in:\n" + stdout);
  assert.ok(!addLine.includes("\\"), "git add hint must not contain a backslash (breaks bash): " + addLine);
  assert.match(addLine, /scripts\/secret-gate/);
});

// --- Finding 7 (Important): the closure walk must see every relative
// import form, not only `from "./x.mjs"`. -----------------------------

// Shared with the closure test below: walks the STATIC relative-import edges
// out of one file's source text. Matches three forms - `import ... from
// "./x.mjs"`, a bare side-effect `import "./x.mjs"`, and a dynamic
// `import("./x.mjs")` - because any of the three creates a real edge that a
// from-only pattern would miss, and missing one reproduces the exact
// `Cannot find module` failure Correction 1 exists to prevent, one import
// form later.
function relativeImportsOf(src) {
  const found = new Set();
  const patterns = [
    /\bfrom\s+["']\.\/([A-Za-z0-9_.-]+\.mjs)["']/g,
    /^\s*import\s+["']\.\/([A-Za-z0-9_.-]+\.mjs)["']\s*;?/gm,
    /import\s*\(\s*["']\.\/([A-Za-z0-9_.-]+\.mjs)["']\s*\)/g,
  ];
  for (const re of patterns) {
    let m;
    while ((m = re.exec(src)) !== null) found.add(m[1]);
  }
  return found;
}

function importClosure(entryName, readSource) {
  const closure = new Set();
  const queue = [entryName];
  while (queue.length > 0) {
    const name = queue.pop();
    if (closure.has(name)) continue;
    closure.add(name);
    for (const dep of relativeImportsOf(readSource(name))) {
      if (!closure.has(dep)) queue.push(dep);
    }
  }
  return closure;
}

test("relativeImportsOf catches a plain named import: from \"./x.mjs\"", () => {
  const found = relativeImportsOf('import { a } from "./a.mjs";\n');
  assert.deepEqual([...found], ["a.mjs"]);
});

test("relativeImportsOf catches a bare side-effect import: import \"./x.mjs\"", () => {
  const found = relativeImportsOf('import "./b.mjs";\n');
  assert.deepEqual([...found], ["b.mjs"]);
});

test("relativeImportsOf catches a dynamic import: import(\"./x.mjs\")", () => {
  const found = relativeImportsOf('const m = await import("./c.mjs");\n');
  assert.deepEqual([...found], ["c.mjs"]);
});

test("VENDORED_FILES equals the actual import closure of cli.mjs, not a hand-picked list", () => {
  // Correction 1: three files vendored (detect, allowlist, cli) made every
  // install DOA the moment allowlist.mjs and cli.mjs started importing
  // gitignore.mjs, because that import is a relative path that only
  // resolves if gitignore.mjs is vendored alongside it. Hardcoding four
  // instead of three would only fix today; walking the ACTUAL
  // `import ... from "./x.mjs"` graph (plus the two forms above, per
  // Finding 7) starting at cli.mjs and asserting the exported
  // VENDORED_FILES list equals that closure exactly means the next import
  // someone adds fails this test instead of failing silently in twenty
  // vendored repos.
  const libDir = path.join(HERE, "..", "lib");
  const closure = importClosure("cli.mjs", (name) => readFileSync(path.join(libDir, name), "utf8"));
  assert.ok(closure.size > 0, "the import closure walk found nothing - regex or entry point is wrong");
  return import("../lib/cli.mjs").then(({ VENDORED_FILES }) => {
    assert.deepEqual([...VENDORED_FILES].sort(), [...closure].sort());
  });
});
