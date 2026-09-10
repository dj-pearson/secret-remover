#!/usr/bin/env node
// UserPromptSubmit: rewrite a pasted credential out of the prompt before it
// enters the transcript or reaches the model.
//
// Escape hatch: a prompt containing the literal token #allow-secret passes
// through untouched. That exists so a deliberate paste stays possible without
// disabling the hook.
import { readStdinJson, writeResult, MAX_BYTES } from "./io.mjs";
import { redactText, newState, summarize } from "../lib/detect.mjs";

const ESCAPE = "#allow-secret";

const input = await readStdinJson(MAX_BYTES);
if (!input || input.hook_event_name !== "UserPromptSubmit") process.exit(0);

const prompt = input.prompt;
if (typeof prompt !== "string" || prompt.length === 0) process.exit(0);
if (prompt.includes(ESCAPE)) process.exit(0);

const state = newState();
const updatedPrompt = redactText(prompt, state);
if (state.hits.length === 0) process.exit(0);

const total = state.hits.length;
const plural = total === 1 ? "secret" : "secrets";

writeResult({
  systemMessage:
    `secret-redactor: ${total} ${plural} redacted from your prompt. ` +
    `Add ${ESCAPE} to the prompt if you meant to send it.`,
  hookSpecificOutput: {
    hookEventName: "UserPromptSubmit",
    updatedPrompt,
    additionalContext:
      `secret-redactor replaced ${total} ${plural} in the user's prompt (${summarize(state.hits)}). ` +
      `Each one appears as [REDACTED <kind> #n]. The real values were never sent to you, ` +
      `so do not guess them or ask the user to paste them again. Read them at run time ` +
      `from the environment instead.`,
  },
});
