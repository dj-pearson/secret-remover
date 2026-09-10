#!/usr/bin/env node
// PreToolUse on Write / Edit / NotebookEdit: refuse to put a credential into a
// file git will carry. This is the gate that stops a key reaching a repo
// document at all, before git is ever involved.
import path from "node:path";
import { readStdinJson, writeResult, MAX_BYTES } from "./io.mjs";
import { findSecrets } from "../lib/detect.mjs";
import { envExemption } from "../lib/gitignore.mjs";

const input = await readStdinJson(MAX_BYTES);
if (!input || input.hook_event_name !== "PreToolUse") process.exit(0);

const toolInput = input.tool_input ?? {};
const filePath = toolInput.file_path ?? toolInput.notebook_path ?? "";
const content = toolInput.content ?? toolInput.new_string ?? toolInput.new_source ?? "";
if (typeof content !== "string" || content.length === 0) process.exit(0);

const hits = findSecrets(content);
if (hits.length === 0) process.exit(0);

const { exempt, reason } = envExemption(filePath, process.cwd());
if (exempt) process.exit(0);

const shown = hits.slice(0, 3).map((h) => `${h.label} at line ${h.line}`).join(", ");
const more = hits.length > 3 ? `, and ${hits.length - 3} more` : "";
const name = filePath ? path.basename(filePath) : "this file";

writeResult({
  systemMessage: `secret-redactor: blocked a write of ${hits.length} credential(s) into ${name}`,
  hookSpecificOutput: {
    hookEventName: "PreToolUse",
    permissionDecision: "deny",
    permissionDecisionReason:
      `secret-gate: this would write ${shown}${more} into ${name} (${reason}). ` +
      `Put the value in a gitignored .env file and reference it by name instead. ` +
      `If it is a fixture, add it to .secretgate.json first.`,
  },
});
