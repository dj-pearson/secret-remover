import { execFile } from "node:child_process";
import { fileURLToPath } from "node:url";
import path from "node:path";

const HOOKS = path.join(path.dirname(path.dirname(fileURLToPath(import.meta.url))), "..", "hooks");

// `options.env`, when supplied, replaces the child's environment entirely
// (same semantics as node:child_process's own `env` option). Omitting it
// keeps the original behaviour of inheriting the test runner's own
// `process.env`, so every existing call site is unaffected.
export function runHook(scriptName, payload, options = {}) {
  return new Promise((resolve) => {
    const child = execFile(
      process.execPath,
      [path.join(HOOKS, scriptName)],
      { encoding: "utf8", cwd: options.cwd ?? process.cwd(), env: options.env ?? process.env },
      (error, stdout, stderr) => resolve({ code: error?.code ?? 0, stdout, stderr }),
    );
    child.stdin.end(typeof payload === "string" ? payload : JSON.stringify(payload));
  });
}
