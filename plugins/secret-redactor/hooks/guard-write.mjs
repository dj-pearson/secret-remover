#!/usr/bin/env node
// PreToolUse on Write / Edit / NotebookEdit: refuse to put a credential into a
// file git will carry. This is the gate that stops a key reaching a repo
// document at all, before git is ever involved.
import path from "node:path";
import { readStdinJson, writeResult, MAX_BYTES } from "./io.mjs";
import { findSecrets, redactText } from "../lib/detect.mjs";
import { envExemption, repoRootFor } from "../lib/gitignore.mjs";
import { loadAllowlist, isAllowed, ALLOWLIST_FILE } from "../lib/allowlist.mjs";

// Oversized input is a special case for THIS hook only: a throw or malformed
// stdin still fails open (the hook is broken; don't brick the session), but
// oversized input means the hook is working fine and is being asked to
// certify content it never got to examine. Refusing is the honest answer -
// it costs a rare oversized write with an obvious workaround (split it),
// while silently allowing it risks an unexamined credential. The two
// redactor hooks keep failing open on oversize; there the alternative is
// corrupting output, which is worse.
let oversizeBytes = null;
const input = await readStdinJson(MAX_BYTES, {
  onOversize: (size) => {
    oversizeBytes = size;
  },
});

// Everything below is nested inside these two conditions rather than a chain
// of early `process.exit(0)` calls after the first write. `process.exit()`
// can truncate a pending stdout write, so once writeResult() has run, the
// script must fall off the end on its own (like the credential deny below
// always has) instead of exiting explicitly. The other `process.exit(0)`
// calls that used to be here were all silent, pre-write skips, which
// `else if` / nested `if` reproduce exactly - they still print nothing and
// still end the script, just without a call that could race a write.
if (oversizeBytes !== null) {
  writeResult({
    systemMessage: `secret-redactor: refused a write too large to scan for credentials (${oversizeBytes} bytes)`,
    hookSpecificOutput: {
      hookEventName: "PreToolUse",
      permissionDecision: "deny",
      permissionDecisionReason:
        `secret-gate: this write is ${oversizeBytes} bytes, over the ${MAX_BYTES}-byte scan limit, ` +
        `so it cannot be checked for credentials. Split it into smaller writes.`,
    },
  });
} else if (input && input.hook_event_name === "PreToolUse") {
  const toolInput = input.tool_input ?? {};
  // file_path/notebook_path may not be a string at all if tool_input is
  // malformed; coerce so downstream .replaceAll()/path.basename() calls can't
  // throw and turn a would-be deny into a silent allow via an uncaught
  // rejection (io.mjs's handler exits 0 on those).
  const rawFilePath = toolInput.file_path ?? toolInput.notebook_path ?? "";
  const filePath = typeof rawFilePath === "string" ? rawFilePath : "";
  const content = toolInput.content ?? toolInput.new_string ?? toolInput.new_source ?? "";

  if (typeof content === "string" && content.length > 0) {
    const hits = findSecrets(content);

    if (hits.length > 0) {
      const { exempt, reason } = envExemption(filePath, process.cwd());

      if (!exempt) {
        // Resolve the repo that owns this file the same way envExemption
        // does (climb to the nearest existing ancestor first - Write
        // routinely targets a not-yet-created folder), then see whether it
        // allowlists any of what findSecrets found. No repo, or no
        // .secretgate.json in it, behaves exactly as before: every hit
        // survives.
        const repoRoot = filePath ? repoRootFor(filePath, process.cwd()) : null;

        let allowlist = null;
        let allowlistError = null;
        if (repoRoot) {
          try {
            allowlist = loadAllowlist(repoRoot);
          } catch (err) {
            allowlistError = err;
          }
        }

        if (allowlistError) {
          // A malformed or invalid-regex .secretgate.json must NOT fail
          // open just because it means the harness couldn't decide what's
          // allowlisted - a broken allowlist is not permission to write a
          // credential. loadAllowlist's own error message never contains
          // file content (it's a JSON-parse or regex-compile error, not the
          // .secretgate.json body), so it's safe to surface as-is.
          writeResult({
            systemMessage: `secret-redactor: blocked a write because ${ALLOWLIST_FILE} could not be read`,
            hookSpecificOutput: {
              hookEventName: "PreToolUse",
              permissionDecision: "deny",
              permissionDecisionReason:
                `secret-gate: ${ALLOWLIST_FILE} is unreadable (${allowlistError.message}). ` +
                `Fix or remove it before writing credential-shaped content.`,
            },
          });
        } else {
          const relPath = allowlist && repoRoot ? path.relative(repoRoot, path.resolve(filePath)).replaceAll("\\", "/") : null;
          const survivingHits = allowlist ? hits.filter((hit) => !isAllowed(allowlist, relPath, hit)) : hits;

          if (survivingHits.length > 0) {
            const shown = survivingHits.slice(0, 3).map((h) => `${h.label} at line ${h.line}`).join(", ");
            const more = survivingHits.length > 3 ? `, and ${survivingHits.length - 3} more` : "";
            // The basename itself can be credential-shaped (a pasted key used as
            // a filename). "Never print a secret value" has no exceptions, so
            // redact it same as any other text before it goes into the deny
            // message.
            const name = filePath ? redactText(path.basename(filePath)) : "this file";

            writeResult({
              systemMessage: `secret-redactor: blocked a write of ${survivingHits.length} credential(s) into ${name}`,
              hookSpecificOutput: {
                hookEventName: "PreToolUse",
                permissionDecision: "deny",
                permissionDecisionReason:
                  `secret-gate: this would write ${shown}${more} into ${name} (${reason}). ` +
                  `Put the value in a gitignored .env file and reference it by name instead. ` +
                  `If it is a fixture, add it to ${ALLOWLIST_FILE} first.`,
              },
            });
          }
        }
      }
    }
  }
}
