#!/usr/bin/env node
// PostToolUse: strip credentials out of a tool result before the model reads it.
//
// Emits nothing when there is nothing to do. An identity rewrite would race
// last-write-wins against a sibling hook doing a real redaction.
import { readStdinJson, writeResult, MAX_BYTES } from "./io.mjs";
import { redactDeep, summarize } from "../lib/detect.mjs";

const input = await readStdinJson(MAX_BYTES);
if (!input || input.hook_event_name !== "PostToolUse") process.exit(0);

const response = input.tool_response;
if (response === undefined || response === null) process.exit(0);

const { value, total, hits } = redactDeep(response);
if (total === 0) process.exit(0);

const tool = input.tool_name || "tool";
const plural = total === 1 ? "secret" : "secrets";

writeResult({
  systemMessage: `secret-remover: ${total} ${plural} redacted from ${tool} output`,
  hookSpecificOutput: {
    hookEventName: "PostToolUse",
    updatedToolOutput: value,
    additionalContext:
      `secret-remover replaced ${total} ${plural} in this ${tool} result (${summarize(hits)}). ` +
      `Each one appears as [REDACTED <kind> #n]; the same number means the same value. ` +
      `The real values were never sent to you, so do not guess them or try to reconstruct them. ` +
      `If you need one, read it at run time from the environment or ask the user.`,
  },
});
