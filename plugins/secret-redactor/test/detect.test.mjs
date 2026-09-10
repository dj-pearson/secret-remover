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
