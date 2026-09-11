// Shared stdin/stdout plumbing for all three hooks.
//
// Rule 1 of this plugin: never break a tool call or a prompt. Every failure
// path here exits 0 with no output.

export const MAX_BYTES = 8 * 1024 * 1024;

// `onOversize`, when supplied, is called with the observed byte count before
// this returns null for hitting the cap. It exists so a caller can tell
// "oversized" apart from "malformed" or "empty", which all otherwise look
// identical (null). The default (no callback) is the original behaviour:
// every failure path here still returns null with no side effect.
export async function readStdinJson(limit = MAX_BYTES, { onOversize = null } = {}) {
  try {
    const chunks = [];
    let size = 0;
    for await (const chunk of process.stdin) {
      size += chunk.length;
      if (size > limit) {
        if (onOversize) onOversize(size);
        return null;
      }
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
