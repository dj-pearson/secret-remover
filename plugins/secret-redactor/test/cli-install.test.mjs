import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync, writeFileSync, mkdirSync, existsSync } from "node:fs";
import { execFileSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import path from "node:path";
import { makeRepo, runCli } from "./helpers/temp-repo.mjs";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const GITLEAKS_HOOK = readFileSync(path.join(HERE, "fixtures", "gitleaks-pre-commit"), "utf8");

function installInto(dir, args = []) {
  return runCli(dir, ["install", ...args]);
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
  writeFileSync(path.join(dir, "leak.md"), "STRIPE_KEY=sk_live_" + "a".repeat(24) + "\n");
  execFileSync("git", ["add", "-A"], { cwd: dir, stdio: "ignore" });
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
  const value = execFileSync("git", ["config", "core.hooksPath"], { cwd: dir, encoding: "utf8" }).trim();
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
  execFileSync("git", ["config", "core.hooksPath", ".myhooks"], { cwd: dir, stdio: "ignore" });
  const { stdout } = installInto(dir);
  assert.match(stdout, /core\.hooksPath/);
  assert.match(stdout, /\.myhooks/);
  const value = execFileSync("git", ["config", "core.hooksPath"], { cwd: dir, encoding: "utf8" }).trim();
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

test("VENDORED equals the actual import closure of cli.mjs, not a hand-picked list", () => {
  // Correction 1: three files vendored (detect, allowlist, cli) made every
  // install DOA the moment allowlist.mjs and cli.mjs started importing
  // gitignore.mjs, because that import is a relative path that only
  // resolves if gitignore.mjs is vendored alongside it. Hardcoding four
  // instead of three would only fix today; this test walks the ACTUAL
  // `import ... from "./x.mjs"` graph starting at cli.mjs and asserts the
  // exported VENDORED_FILES list equals that closure exactly, so the next
  // import someone adds fails this test instead of failing silently in
  // twenty vendored repos.
  const libDir = path.join(HERE, "..", "lib");
  const closure = new Set();
  const queue = ["cli.mjs"];
  while (queue.length > 0) {
    const name = queue.pop();
    if (closure.has(name)) continue;
    closure.add(name);
    const src = readFileSync(path.join(libDir, name), "utf8");
    const re = /from\s+["']\.\/([A-Za-z0-9_.-]+\.mjs)["']/g;
    let match;
    while ((match = re.exec(src)) !== null) {
      if (!closure.has(match[1])) queue.push(match[1]);
    }
  }
  assert.ok(closure.size > 0, "the import closure walk found nothing - regex or entry point is wrong");
  return import("../lib/cli.mjs").then(({ VENDORED_FILES }) => {
    assert.deepEqual([...VENDORED_FILES].sort(), [...closure].sort());
  });
});
