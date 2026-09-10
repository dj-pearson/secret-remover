import { execFile } from "node:child_process";
import { fileURLToPath } from "node:url";
import path from "node:path";

const HOOKS = path.join(path.dirname(path.dirname(fileURLToPath(import.meta.url))), "..", "hooks");

export function runHook(scriptName, payload, options = {}) {
  return new Promise((resolve) => {
    const child = execFile(
      process.execPath,
      [path.join(HOOKS, scriptName)],
      { encoding: "utf8", cwd: options.cwd ?? process.cwd() },
      (error, stdout, stderr) => resolve({ code: error?.code ?? 0, stdout, stderr }),
    );
    child.stdin.end(typeof payload === "string" ? payload : JSON.stringify(payload));
  });
}
