// Shared stdin/stdout plumbing for all three hooks.
//
// Rule 1 of this plugin: never break a tool call or a prompt. Every failure
// path here exits 0 with no output.

export const MAX_BYTES = 8 * 1024 * 1024;

export async function readStdinJson(limit = MAX_BYTES) {
  try {
    const chunks = [];
    let size = 0;
    for await (const chunk of process.stdin) {
      size += chunk.length;
      if (size > limit) return null;
      chunks.push(chunk);
    }
    const raw = Buffer.concat(chunks).toString("utf8");
    if (!raw.trim()) return null;
    return JSON.parse(raw);
  } catch {
    return null;
  }
}

export function writeResult(result) {
  try {
    process.stdout.write(JSON.stringify(result));
  } catch {
    // A write failure must not become a non-zero exit.
  }
}

process.on("uncaughtException", () => process.exit(0));
process.on("unhandledRejection", () => process.exit(0));
