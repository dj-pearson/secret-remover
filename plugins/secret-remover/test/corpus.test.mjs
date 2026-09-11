import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import path from "node:path";
import { findSecrets, DETECTOR_LABELS } from "../lib/detect.mjs";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const CORPUS = readFileSync(path.join(HERE, "fixtures", "corpus.txt"), "utf8")
  .replaceAll("TEST_", "")
  .replaceAll("test-services", "services")
  .replaceAll("AC_", "AC")
  .replaceAll("M_", "M");

const [POSITIVES, NEGATIVES] = (() => {
  const marker = "### negatives";
  const at = CORPUS.indexOf(marker);
  assert.ok(at > 0, "corpus.txt is missing its '### negatives' marker");
  return [CORPUS.slice(0, at), CORPUS.slice(at)];
})();

test("every detector label fires at least once on the corpus", () => {
  const found = new Set(findSecrets(POSITIVES).map((h) => h.label));
  const missing = DETECTOR_LABELS.filter((label) => !found.has(label));
  assert.deepEqual(missing, [], "these detectors stopped firing: " + missing.join(", "));
});

test("the corpus negatives produce no findings at all", () => {
  const hits = findSecrets(NEGATIVES);
  const where = hits.map((h) => h.label + " at line " + h.line);
  assert.deepEqual(where, [], "false positives: " + where.join("; "));
});

test("a sentence ending in a secret word does not eat the next paragraph", () => {
  const text = "Twilio SIDs, Discord bot tokens.\n\n**Structural shapes** - PEM private key blocks\n";
  assert.deepEqual(findSecrets(text), []);
});

test("a labeled secret still needs a colon or an equals sign", () => {
  assert.deepEqual(findSecrets("the password Zx9Qw3Er7Ty1Ui5Op is stored elsewhere"), []);
  assert.equal(findSecrets("password=Zx9Qw3Er7Ty1Ui5Op").length, 1);
  assert.equal(findSecrets('password: "Zx9Qw3Er7Ty1Ui5Op"').length, 1);
});

test("the separator may not cross a newline", () => {
  assert.deepEqual(findSecrets("api_key:\nZx9Qw3Er7Ty1Ui5Op"), []);
});
