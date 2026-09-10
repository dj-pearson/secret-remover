import test from "node:test";
import assert from "node:assert/strict";
import { findSecrets, looksLikeSecret, DETECTOR_LABELS } from "../lib/detect.mjs";

test("finds a github token and reports its position", () => {
  const text = "line one\nGITHUB_TOKEN=ghp_" + "a".repeat(36) + "\n";
  const hits = findSecrets(text);
  assert.equal(hits.length, 1);
  assert.equal(hits[0].label, "github-token");
  assert.equal(hits[0].line, 2);
  assert.equal(hits[0].column, "GITHUB_TOKEN=".length + 1);
  assert.equal(text.slice(hits[0].start, hits[0].end), hits[0].value);
});

test("finds a whole PEM block, not just the header", () => {
  const text = "-----BEGIN PRIVATE KEY-----\nMIIEvgIBADANBgkqhkiG9w0BAQE\n-----END PRIVATE KEY-----";
  const hits = findSecrets(text);
  assert.equal(hits.length, 1);
  assert.equal(hits[0].label, "private-key");
  assert.equal(hits[0].start, 0);
  assert.equal(hits[0].end, text.length);
});

test("finds the password inside a database url", () => {
  const hits = findSecrets("postgres://admin:h3nrY8Qz2w@db.internal:5432/app");
  assert.equal(hits.length, 1);
  assert.equal(hits[0].label, "url-password");
  assert.equal(hits[0].value, "h3nrY8Qz2w");
});

test("returns hits sorted by start and never overlapping", () => {
  const text =
    "aws=[REDACTED aws-access-key-id #2] token=ghp_" + "b".repeat(36) + " jwt=[REDACTED jwt #3]";
  const hits = findSecrets(text);
  for (let i = 1; i < hits.length; i++) {
    assert.ok(hits[i].start >= hits[i - 1].end, "hit " + i + " overlaps its predecessor");
  }
});

test("returns an empty array for a clean string and for non-strings", () => {
  assert.deepEqual(findSecrets("246 tests, 246 passing"), []);
  assert.deepEqual(findSecrets(""), []);
  assert.deepEqual(findSecrets(null), []);
  assert.deepEqual(findSecrets(42), []);
});

test("looksLikeSecret rejects the obvious non-credentials", () => {
  for (const value of [
    "process.env.API_KEY",
    "${GITHUB_TOKEN}",
    "your_password_here",
    "https://example.com/x",
    "0f3460ab",
    "550e8400-e29b-41d4-a716-446655440000",
    "sha512-abcdefghijklmnop",
    "undefined",
    "aaaaaaaa",
  ]) {
    assert.equal(looksLikeSecret(value), false, value + " should be rejected");
  }
});

test("DETECTOR_LABELS is frozen and covers every label findSecrets can emit", () => {
  assert.ok(Object.isFrozen(DETECTOR_LABELS));
  assert.ok(DETECTOR_LABELS.includes("labeled-secret"));
  assert.ok(DETECTOR_LABELS.includes("url-password"));
  assert.ok(DETECTOR_LABELS.includes("bearer-token"));
});

import { redactText, redactDeep, newState } from "../lib/detect.mjs";

test("redactText replaces the value and leaves the label in place", () => {
  const token = "ghp_" + "c".repeat(36);
  const out = redactText("GITHUB_TOKEN=" + token);
  assert.equal(out, "GITHUB_TOKEN=[REDACTED github-token #1]");
  assert.ok(!out.includes(token));
});

test("the same value gets the same number twice", () => {
  const token = "ghp_" + "d".repeat(36);
  const out = redactText(token + " and again " + token);
  assert.equal(out, "[REDACTED github-token #1] and again [REDACTED github-token #1]");
});

test("redaction is idempotent", () => {
  const once = redactText("aws=[REDACTED aws-access-key-id #1]");
  const twice = redactText(once);
  assert.equal(twice, once);
});

test("redactText returns the input unchanged when nothing is found", () => {
  const clean = "246 tests, 246 passing";
  assert.equal(redactText(clean), clean);
});

test("redactDeep walks objects and arrays and keeps the shape", () => {
  const input = {
    stdout: "token=ghp_" + "e".repeat(36),
    stderr: "",
    interrupted: false,
    codes: [0, 1],
    nested: { deeper: ["AKIAZZZZZZZZZZZZZZZZ"] },
  };
  const { value, total, hits } = redactDeep(input);
  assert.equal(total, 2);
  assert.equal(value.interrupted, false);
  assert.deepEqual(value.codes, [0, 1]);
  assert.equal(value.stderr, "");
  assert.ok(value.nested.deeper[0].startsWith("[REDACTED aws-access-key-id"));
  assert.deepEqual(new Set(hits.map((h) => h.label)), new Set(["github-token", "aws-access-key-id"]));
});

test("redactDeep returns the original object when there is nothing to redact", () => {
  const input = { stdout: "all good", exitCode: 0 };
  const { value, total } = redactDeep(input);
  assert.equal(total, 0);
  assert.equal(value, input, "must be the same reference, not a copy");
});

test("a shared state numbers values consistently across calls", () => {
  const state = newState();
  const a = redactText("AKIAZZZZZZZZZZZZZZZZ", state);
  const b = redactText("see AKIAZZZZZZZZZZZZZZZZ again", state);
  assert.ok(a.includes("#1"));
  assert.ok(b.includes("#1"));
  assert.equal(state.hits.length, 1);
});

test("redactDeep with a shared state returns the original reference on clean second call", () => {
  const state = newState();
  const token = "ghp_" + "x".repeat(36);
  redactDeep({ stdout: "token=" + token }, state);
  assert.equal(state.hits.length, 1);

  const input = { stdout: "all good", exitCode: 0 };
  const { value, total } = redactDeep(input, state);
  assert.equal(total, 0, "second call found no new secrets");
  assert.equal(value, input, "must return the original reference, not a copy");
});

test("redaction is idempotent for all detector labels", () => {
  for (const label of DETECTOR_LABELS) {
    const marker = `[REDACTED ${label} #1]`;
    const once = redactText(marker);
    const twice = redactText(once);
    assert.equal(twice, once, `marker for ${label} should not be re-detected`);
  }
});

test("URL_PASSWORD redaction is idempotent across full database URLs", () => {
  const url = "postgres://admin:SecurePassword123@db.internal:5432/app";
  const once = redactText(url);
  const twice = redactText(once);
  assert.equal(twice, once, "redacted URL should not be re-detected on second pass");
  assert.ok(once.includes("[REDACTED url-password #1]"), "first redaction should succeed");
});
