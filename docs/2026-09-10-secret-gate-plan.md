# secret-gate Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Stop a plaintext credential from reaching GitHub or a Claude Code transcript, across every Pearson Media repo and both laptops.

**Architecture:** One detector core (`lib/detect.mjs`) with four consumers: three Claude Code hooks and a CLI. The hooks ship globally through a GitHub-backed plugin marketplace. The CLI is vendored into each repo by an `install` command so the commit gate belongs to the repo, not to the machine.

**Tech Stack:** Node 22+ ESM, zero dependencies, `node --test` for the suite, `git` shelled out via `node:child_process`. No TypeScript, no bundler, no build step.

**Spec:** `docs/2026-09-10-secret-gate-design.md`

## Global Constraints

- **Zero runtime dependencies.** `package.json` gets no `dependencies` and no `devDependencies`. If a task seems to need one, stop and ask.
- **Node 22 or newer.** `package.json` sets `"engines": { "node": ">=22" }`. The CI workflow pins `node-version: '22'`.
- **ESM only.** `"type": "module"`, `.mjs` extensions, `import`, never `require`.
- **Never print a secret value.** Every report prints `path:line:column` and a label. The value never leaves the process. This applies to error messages and test failure output too.
- **Plain ASCII in every generated file.** No curly quotes, no en or em dashes, no non-breaking spaces. Verify with `rg -n '[^\x00-\x7F]'` before each commit.
- **Marker format is frozen:** `[REDACTED <label> #<n>]`. Same value gets the same number within one scan.
- **Fail open in the hooks, fail closed on findings.** A hook that throws must exit 0 and print nothing. The CLI exits 1 on findings and 2 on internal error.
- **Three version strings must agree:** `plugins/secret-redactor/package.json`, `plugins/secret-redactor/.claude-plugin/plugin.json`, and the `plugins[0].version` entry in `.claude-plugin/marketplace.json`. Target version for this work is `2.0.0`.
- **Commit trailer:** end each commit message with one blank line then `Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>` and the `Claude-Session:` line. Nothing else.

## Two changes from the spec

Both are corrections found while planning. They are deliberate.

1. **Three vendored files, not two.** `install` vendors `detect.mjs`, `allowlist.mjs` and `cli.mjs`. The spec said two. Keeping the allowlist loader in its own file lets the vendored copies import each other with plain relative paths (`./detect.mjs`), which is what removes the need for a bundler.
2. **`scan --staged` reads full staged content, not just added lines.** The spec said added lines. Reading `git show :<path>` gives line numbers that match the file, which is what makes the `path:label:line` fingerprint stable. The cost is that a pre-existing secret in a touched file also blocks. That is the correct outcome, since it is still on its way to GitHub, and `fingerprints` in the allowlist is the escape hatch.

## File structure

```
pearson-claude-plugins/
  .claude-plugin/marketplace.json          marketplace "pearson-media"
  plugins/secret-redactor/
    .claude-plugin/plugin.json             plugin manifest
    package.json                           name, version, test script, engines
    README.md                              user-facing docs
    hooks/
      hooks.json                           registers the three hooks
      redact-tool-output.mjs               PostToolUse   -> updatedToolOutput
      redact-prompt.mjs                    UserPromptSubmit -> updatedPrompt
      guard-write.mjs                      PreToolUse    -> permissionDecision
    lib/
      detect.mjs                           the only definition of a credential
      allowlist.mjs                        .secretgate.json loader and matcher
      cli.mjs                              scan / fix / install
    bin/
      secret-gate.mjs                      shim so the slash command has a path
    commands/
      secret-gate.md                       /secret-gate slash command
    templates/
      pre-commit                           written into .githooks/
      workflow.yml                         written into .github/workflows/
      secretgate.json                      written as .secretgate.json
    test/
      fixtures/corpus.txt                  one of every shape, one of every FP
      fixtures/gitleaks-pre-commit         GradeThread's real hook, for append test
      helpers/temp-repo.mjs                builds a throwaway git repo
      version.test.mjs
      detect.test.mjs
      corpus.test.mjs
      allowlist.test.mjs
      hooks.test.mjs
      cli-scan.test.mjs
      cli-fix.test.mjs
      cli-install.test.mjs
  docs/
    2026-09-10-secret-gate-design.md       the spec
    2026-09-10-secret-gate-plan.md         this file
  README.md
```

Responsibility split, one line each:

- `detect.mjs` answers "is this a credential and where is it". Nothing else.
- `allowlist.mjs` answers "should we ignore this particular finding".
- `cli.mjs` walks files, reports, rewrites, and installs. It never decides what a credential is.
- Each hook translates one Claude Code event into a call on the two libraries above.

---

### Task 1: Repo skeleton and the version contract

**Files:**
- Create: `.claude-plugin/marketplace.json`
- Create: `plugins/secret-redactor/.claude-plugin/plugin.json`
- Create: `plugins/secret-redactor/package.json`
- Create: `README.md`
- Test: `plugins/secret-redactor/test/version.test.mjs`

**Interfaces:**
- Consumes: nothing.
- Produces: the version `2.0.0` in three files; `npm test` runnable from `plugins/secret-redactor/`.

- [ ] **Step 1: Write the failing test**

`plugins/secret-redactor/test/version.test.mjs`:

```js
import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import path from "node:path";

const PLUGIN = path.dirname(path.dirname(fileURLToPath(import.meta.url)));
const ROOT = path.dirname(path.dirname(PLUGIN));

const read = (p) => JSON.parse(readFileSync(p, "utf8"));

test("the three version strings agree", () => {
  const pkg = read(path.join(PLUGIN, "package.json"));
  const manifest = read(path.join(PLUGIN, ".claude-plugin", "plugin.json"));
  const market = read(path.join(ROOT, ".claude-plugin", "marketplace.json"));

  const entry = market.plugins.find((p) => p.name === "secret-redactor");
  assert.ok(entry, "secret-redactor is missing from marketplace.json");

  assert.equal(manifest.version, pkg.version);
  assert.equal(entry.version, pkg.version);
});

test("the marketplace is named pearson-media and points at the plugin", () => {
  const market = read(path.join(ROOT, ".claude-plugin", "marketplace.json"));
  assert.equal(market.name, "pearson-media");
  const entry = market.plugins.find((p) => p.name === "secret-redactor");
  assert.equal(entry.source, "./plugins/secret-redactor");
});

test("the plugin declares zero dependencies", () => {
  const pkg = read(path.join(PLUGIN, "package.json"));
  assert.equal(pkg.dependencies, undefined);
  assert.equal(pkg.devDependencies, undefined);
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd plugins/secret-redactor && node --test test/version.test.mjs`
Expected: FAIL with `ENOENT` on `package.json`.

- [ ] **Step 3: Write the three manifests**

`.claude-plugin/marketplace.json`:

```json
{
  "name": "pearson-media",
  "owner": {
    "name": "Pearson Media LLC",
    "url": "https://github.com/dj-pearson"
  },
  "metadata": {
    "description": "Claude Code plugins used across the Pearson Media portfolio",
    "version": "1.0.0"
  },
  "plugins": [
    {
      "name": "secret-redactor",
      "source": "./plugins/secret-redactor",
      "version": "2.0.0",
      "description": "Keeps plaintext credentials out of transcripts, out of files, and out of GitHub.",
      "category": "security",
      "keywords": ["security", "secrets", "redaction", "hooks", "pre-commit"]
    }
  ]
}
```

`plugins/secret-redactor/.claude-plugin/plugin.json`:

```json
{
  "name": "secret-redactor",
  "version": "2.0.0",
  "description": "Keeps plaintext credentials out of transcripts, out of files, and out of GitHub.",
  "author": {
    "name": "Pearson Media LLC"
  },
  "keywords": ["security", "secrets", "redaction", "hooks", "pre-commit"]
}
```

`plugins/secret-redactor/package.json`:

```json
{
  "name": "secret-redactor",
  "version": "2.0.0",
  "private": true,
  "type": "module",
  "description": "Claude Code hooks plus a commit gate that keep plaintext credentials out of transcripts and out of GitHub.",
  "engines": {
    "node": ">=22"
  },
  "scripts": {
    "test": "node --test"
  }
}
```

Root `README.md`:

```markdown
# pearson-claude-plugins

Claude Code plugins used across the Pearson Media portfolio.

Marketplace name: `pearson-media`

## Install on a new machine

```bash
claude plugin marketplace add dj-pearson/pearson-claude-plugins
claude plugin install secret-redactor
```

Restart the session afterwards.

## Plugins

- [secret-redactor](plugins/secret-redactor/) - keeps plaintext credentials out
  of transcripts, out of files, and out of GitHub.
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd plugins/secret-redactor && node --test test/version.test.mjs`
Expected: 3 tests, 3 passing.

- [ ] **Step 5: Commit**

```bash
git add .claude-plugin plugins/secret-redactor/.claude-plugin plugins/secret-redactor/package.json plugins/secret-redactor/test/version.test.mjs README.md
git commit -m "feat: plugin skeleton and the three-version contract"
```

---

### Task 2: `findSecrets` and the detector set

**Files:**
- Create: `plugins/secret-redactor/lib/detect.mjs`
- Test: `plugins/secret-redactor/test/detect.test.mjs`

**Interfaces:**
- Consumes: nothing.
- Produces:
  - `findSecrets(text) -> Array<{ start, end, line, column, label, value }>` sorted by `start`, non-overlapping, 1-indexed `line` and `column`.
  - `DETECTOR_LABELS: readonly string[]`
  - `looksLikeSecret(value) -> boolean`
  - `MAX_SCAN_BYTES: number`

Port note: the detector regexes come from `~/.claude/plugins/local/secret-redactor/hooks/redact.mjs` v1.0.2 unchanged. What is new is that they now report positions instead of doing chained string replacement, which is what makes the CLI and idempotence possible.

- [ ] **Step 1: Write the failing test**

`plugins/secret-redactor/test/detect.test.mjs`:

```js
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
  const text = [
    "-----BEGIN PRIVATE KEY-----",
    "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQ",
    "-----END PRIVATE KEY-----",
  ].join("\n");
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
    "aws=AKIAIOSFODNN7EXAMPLE token=ghp_" + "b".repeat(36) + " jwt=eyJhbGciOiJI.eyJzdWIiOiIx.dBjftJeZ4CVP";
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
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd plugins/secret-redactor && node --test test/detect.test.mjs`
Expected: FAIL, cannot find module `../lib/detect.mjs`.

- [ ] **Step 3: Write `lib/detect.mjs`**

```js
// lib/detect.mjs
//
// The only place in this plugin that knows what a credential looks like.
// Everything else - the three hooks and the CLI - is built on findSecrets().
//
// findSecrets reports positions rather than doing string replacement, which is
// what lets the CLI print path:line:column without ever printing the value, and
// what makes redaction idempotent.

export const MAX_SCAN_BYTES = 2 * 1024 * 1024;

// --- value guards ----------------------------------------------------------

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const GIT_SHA = /^[0-9a-f]{7,40}$/i;
const INTEGRITY = /^sha(?:1|256|384|512)[-:]/i;
const URL_SCHEME = /^[a-z][a-z0-9+.-]*:\/\//i;
const DOTTED_CODE = /^[A-Za-z_$][A-Za-z0-9_$]*(?:\.[A-Za-z_$][A-Za-z0-9_$]*)+$/;
const LITERAL = /^(?:null|undefined|true|false|none|nil|empty|unset|not|n\/a)$/i;
const PLACEHOLDER =
  /(?:^|[_\-.])(?:your|here|changeme|change_me|placeholder|redacted|todo|insert|xxxx+)(?:$|[_\-.])|placeholder|changeme|x{6,}|\*{4,}/i;
const OPENERS = new Set(["$", "<", "(", "[", "{", "/", "\\", ".", "~", "-", "#", "%", "@", "|", "'", '"', "`"]);

export function looksLikeSecret(value) {
  if (typeof value !== "string" || value.length < 8 || value.length > 512) return false;
  if (OPENERS.has(value[0])) return false;
  if (URL_SCHEME.test(value) || value.includes("://")) return false;
  if (value.includes("\\") || value.includes("/./")) return false;
  if (DOTTED_CODE.test(value)) return false;
  if (LITERAL.test(value)) return false;
  if (PLACEHOLDER.test(value)) return false;
  if (UUID.test(value) || GIT_SHA.test(value) || INTEGRITY.test(value)) return false;
  if (/^(.)\1*$/.test(value)) return false;
  return /[0-9]/.test(value) || (/[a-z]/.test(value) && /[A-Z]/.test(value));
}

// --- detectors -------------------------------------------------------------

// `whole: true` means the entire match is the secret. Otherwise group 1 is.
const DETECTORS = [
  {
    label: "private-key",
    whole: true,
    re: /-----BEGIN (?:[A-Z ]+ )?PRIVATE KEY-----[\s\S]*?-----END (?:[A-Z ]+ )?PRIVATE KEY-----/g,
  },
  { label: "aws-access-key-id", re: /\b((?:AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16})\b/g },
  { label: "github-token", re: /\b((?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{30,})\b/g },
  { label: "github-token", re: /\b(github_pat_[A-Za-z0-9_]{30,})\b/g },
  { label: "stripe-key", re: /\b((?:sk|rk)_live_[A-Za-z0-9]{20,})\b/g },
  { label: "anthropic-key", re: /\b(sk-ant-[A-Za-z0-9_-]{20,})/g },
  { label: "openai-key", re: /\b(sk-(?:proj-|svcacct-)?[A-Za-z0-9]{20,})\b/g },
  { label: "google-api-key", re: /\b(AIza[0-9A-Za-z_-]{35})\b/g },
  { label: "slack-token", re: /\b(xox[abprs]-[0-9A-Za-z-]{10,})/g },
  { label: "slack-webhook", re: /(https:\/\/hooks\.slack\.com\/services\/[0-9A-Za-z/+]{20,})/g },
  { label: "npm-token", re: /\b(npm_[A-Za-z0-9]{30,})\b/g },
  { label: "pypi-token", re: /\b(pypi-[A-Za-z0-9_-]{30,})/g },
  { label: "sendgrid-key", re: /\b(SG\.[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{16,})/g },
  { label: "twilio-sid", re: /\b((?:AC|SK)[0-9a-f]{32})\b/g },
  { label: "discord-token", re: /\b([MNO][A-Za-z0-9_-]{23,}\.[A-Za-z0-9_-]{6}\.[A-Za-z0-9_-]{27,})\b/g },
  { label: "jwt", re: /\b(eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,})/g },
];

const URL_PASSWORD = /([a-z][a-z0-9+.-]*:\/\/[^\s:@/]{1,64}:)([^\s@/]{3,256})@/gi;
const BEARER = /\b([Bb]earer\s+)([A-Za-z0-9_\-.=+/]{20,})/g;

const SECRET_WORD =
  "secret|token|passwd|password|pwd|api[_-]?key|apikey|access[_-]?key|private[_-]?key|credential|auth|session[_-]?id";

// Task 3 tightens this. Keep it as-is for now so the corpus positive pass is
// what turns green here, and the negative pass is what turns green there.
const LABELED = new RegExp(
  `([A-Za-z0-9_.-]*(?:${SECRET_WORD})[A-Za-z0-9_.-]*)(["'\`]?\\s*[:=]\\s*|\\s+)(["'\`]?)([^\\s"'\`,;)\\]}]{8,})\\3`,
  "gi",
);

export const DETECTOR_LABELS = Object.freeze([
  "private-key",
  "aws-access-key-id",
  "github-token",
  "stripe-key",
  "anthropic-key",
  "openai-key",
  "google-api-key",
  "slack-token",
  "slack-webhook",
  "npm-token",
  "pypi-token",
  "sendgrid-key",
  "twilio-sid",
  "discord-token",
  "jwt",
  "url-password",
  "bearer-token",
  "labeled-secret",
]);

// --- position helpers ------------------------------------------------------

function lineStarts(text) {
  const starts = [0];
  for (let i = 0; i < text.length; i++) if (text[i] === "\n") starts.push(i + 1);
  return starts;
}

function positionOf(starts, offset) {
  let lo = 0;
  let hi = starts.length - 1;
  while (lo < hi) {
    const mid = (lo + hi + 1) >> 1;
    if (starts[mid] <= offset) lo = mid;
    else hi = mid - 1;
  }
  return { line: lo + 1, column: offset - starts[lo] + 1 };
}

// --- the primitive ---------------------------------------------------------

export function findSecrets(text) {
  if (typeof text !== "string" || text.length === 0) return [];

  const raw = [];
  const push = (start, label, value) => raw.push({ start, end: start + value.length, label, value });

  for (const { label, re, whole } of DETECTORS) {
    for (const m of text.matchAll(re)) {
      const value = whole ? m[0] : m[1];
      if (!value) continue;
      push(whole ? m.index : m.index + m[0].indexOf(value), label, value);
    }
  }

  for (const m of text.matchAll(URL_PASSWORD)) {
    const value = m[2];
    if (value.length < 4 && !/[0-9]/.test(value)) continue;
    push(m.index + m[1].length, "url-password", value);
  }

  for (const m of text.matchAll(BEARER)) {
    if (!looksLikeSecret(m[2])) continue;
    push(m.index + m[1].length, "bearer-token", m[2]);
  }

  for (const m of text.matchAll(LABELED)) {
    if (!looksLikeSecret(m[4])) continue;
    push(m.index + m[1].length + m[2].length + m[3].length, "labeled-secret", m[4]);
  }

  // Earliest wins; on a tie the longer match wins. Then drop anything that
  // starts inside a hit we already kept.
  raw.sort((a, b) => a.start - b.start || b.end - b.start - (a.end - a.start));

  const starts = lineStarts(text);
  const out = [];
  let cursor = 0;
  for (const hit of raw) {
    if (hit.start < cursor) continue;
    cursor = hit.end;
    out.push({ ...hit, ...positionOf(starts, hit.start) });
  }
  return out;
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd plugins/secret-redactor && node --test test/detect.test.mjs`
Expected: 7 tests, 7 passing.

- [ ] **Step 5: Commit**

```bash
git add plugins/secret-redactor/lib/detect.mjs plugins/secret-redactor/test/detect.test.mjs
git commit -m "feat: findSecrets reports credential positions instead of replacing text"
```

---

### Task 3: The corpus self-check, and the prose false positive

This is the task that would have caught the README bug. It asserts in both
directions: every detector still fires, and every known false positive stays
untouched.

**Files:**
- Create: `plugins/secret-redactor/test/fixtures/corpus.txt`
- Create: `plugins/secret-redactor/test/corpus.test.mjs`
- Modify: `plugins/secret-redactor/lib/detect.mjs` (the `LABELED` regex and `looksLikeSecret`)

**Interfaces:**
- Consumes: `findSecrets`, `DETECTOR_LABELS` from Task 2.
- Produces: no new exports. Behaviour change only.

The false positive being fixed, confirmed by reading the v1.0.2 README on
2026-09-10: line 31 ends `...Discord bot tokens.` and line 33 begins
`**Structural shapes** - PEM private key blocks`. The `LABELED` rule allows
`\s+` as a separator and `\s` matches newlines, so it matched the key `tokens.`
across a blank line and took `**Structural` as the value.

Three changes, each independently sufficient, kept together as defence in depth:

1. Drop the bare-whitespace separator. A labeled secret is written with `:` or
   `=`, never with a space.
2. Forbid the separator from crossing a newline: `[ \t]*` instead of `\s*`.
3. Drop `.` from the key character class, so a sentence-ending word like
   `tokens.` is not a key.
4. Reject a candidate value containing a markdown emphasis run, and reject a
   plain capitalized word such as `Structural`.

- [ ] **Step 1: Write the corpus fixture**

`plugins/secret-redactor/test/fixtures/corpus.txt`. Every value here is
synthetic and opens nothing.

```
### positives - one per label, each must be found

private-key:
-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCwZ0000000000
-----END PRIVATE KEY-----

aws-access-key-id: AKIAIOSFODNN7EXAMPLE
github-token: ghp_0123456789abcdefghijklmnopqrstuvwxyz
github-token-fine: github_pat_0123456789abcdefghijklmnopqrstuvwxyz_ABC
stripe-key: sk_TEST_live_0123456789abcdefghijklmn
anthropic-key: sk-ant-api03-0123456789abcdefghijklmnop
openai-key: sk-proj-0123456789abcdefghijklmnopqrst
google-api-key: AIzaSyA0123456789abcdefghijklmnopqrstuvw
slack-token: xoxb-0123456789-0123456789-abcdefghijkl
slack-webhook: https://hooks.slack.com/test-services/T00000000/B00000000/abcdefghijklmnopqrst
npm-token: npm_0123456789abcdefghijklmnopqrstuvwxyz
pypi-token: pypi-0123456789abcdefghijklmnopqrstuvwxyz
sendgrid-key: SG.0123456789abcdef.0123456789abcdefghij
twilio-sid: AC_TEST_0123456789abcdef0123456789abcdef
discord-token: M_TEST_TIzNDU2Nzg5MDEyMzQ1Njc4.Abcdef.0123456789abcdefghijklmnopq
jwt: eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dBjftJeZ4CVPmB92K27uhbUJU1p1r
url-password: postgres://admin:h3nrY8Qz2w@db.internal:5432/app
bearer-token: Authorization: Bearer aB3dEf7hIj9kLm2nOp4qRs6t
labeled-secret: API_SECRET=Zx9Qw3Er7Ty1Ui5Op

### negatives - none of these may be found

A sentence that ends in a word about tokens.

**Structural shapes** - PEM private key blocks (whole block, not just the
header), JWTs, Bearer tokens, and passwords inside a URL.

**Labeled values** - anything assigned to a key whose name contains secret.

const key = process.env.API_KEY;
export PASSWORD="${DB_PASSWORD}"
api_key: your-api-key-here
password: changeme
token: <insert-token>
STRIPE_KEY=sk_TEST_test_0123456789abcdefghijklmn
commit 9ab707253f79dbdd06a3c5a86c5573c1c9c2f1ab
uuid 550e8400-e29b-41d4-a716-446655440000
integrity sha512-abcdefghijklmnopqrstuvwxyz0123456789
secret: null
auth = undefined
The password is in the vault, ask the owner.
```

- [ ] **Step 2: Write the failing test**

`plugins/secret-redactor/test/corpus.test.mjs`:

```js
import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import path from "node:path";
import { findSecrets, DETECTOR_LABELS } from "../lib/detect.mjs";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const CORPUS = readFileSync(path.join(HERE, "fixtures", "corpus.txt"), "utf8");

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
```

- [ ] **Step 3: Run test to verify it fails**

Run: `cd plugins/secret-redactor && node --test test/corpus.test.mjs`
Expected: the positives test passes, and the four negative tests FAIL because
`LABELED` still allows `\s+` across newlines.

- [ ] **Step 4: Tighten `LABELED` and `looksLikeSecret`**

In `lib/detect.mjs`, replace the `LABELED` constant and its comment:

```js
// Separator must be an explicit `:` or `=`. A bare run of whitespace used to be
// allowed and it matched across blank lines, so a paragraph ending in the word
// "tokens." swallowed the first word of the next paragraph. Observed on this
// plugin's own README, 2026-09-10.
//
// `.` is out of the key class for the same reason: it let `tokens.` be a key.
const LABELED = new RegExp(
  `([A-Za-z0-9_-]*(?:${SECRET_WORD})[A-Za-z0-9_-]*)(["'\`]?[ \\t]*[:=][ \\t]*)(["'\`]?)([^\\s"'\`,;)\\]}]{8,})\\3`,
  "gi",
);
```

In `looksLikeSecret`, add these two constants above the function:

```js
const MARKDOWN_EMPHASIS = /\*\*|__/;
const CAPITALIZED_WORD = /^[A-Z][a-z]+$/;
```

and these two lines inside it, immediately after the `PLACEHOLDER` check:

```js
  if (MARKDOWN_EMPHASIS.test(value)) return false;
  if (CAPITALIZED_WORD.test(value)) return false;
```

- [ ] **Step 5: Run the whole suite to verify it passes**

Run: `cd plugins/secret-redactor && npm test`
Expected: all tests passing, including Task 2's, which must not regress.

- [ ] **Step 6: Commit**

```bash
git add plugins/secret-redactor/lib/detect.mjs plugins/secret-redactor/test/corpus.test.mjs plugins/secret-redactor/test/fixtures/corpus.txt
git commit -m "fix: stop the labeled-value rule from eating prose across blank lines"
```

---

### Task 4: `redactText`, `redactDeep`, and idempotence

**Files:**
- Modify: `plugins/secret-redactor/lib/detect.mjs` (append)
- Test: `plugins/secret-redactor/test/detect.test.mjs` (append)

**Interfaces:**
- Consumes: `findSecrets`, `looksLikeSecret` from Task 2.
- Produces:
  - `newState() -> { n: 0, seen: Map, hits: [] }`
  - `tokenFor(value, label, state) -> string`
  - `redactText(text, state?) -> string`
  - `redactDeep(value, state?) -> { value, total, hits }` where `hits` is `[{ label, id }]` and `value` is the ORIGINAL object when `total === 0`.

- [ ] **Step 1: Write the failing test**

Append to `plugins/secret-redactor/test/detect.test.mjs`:

```js
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
  const once = redactText("aws=AKIAIOSFODNN7EXAMPLE");
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
    nested: { deeper: ["AKIAIOSFODNN7EXAMPLE"] },
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
  const a = redactText("AKIAIOSFODNN7EXAMPLE", state);
  const b = redactText("see AKIAIOSFODNN7EXAMPLE again", state);
  assert.ok(a.includes("#1"));
  assert.ok(b.includes("#1"));
  assert.equal(state.hits.length, 1);
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd plugins/secret-redactor && node --test test/detect.test.mjs`
Expected: FAIL, `redactText` is not exported.

- [ ] **Step 3: Append to `lib/detect.mjs`**

```js
// --- redaction -------------------------------------------------------------

export function newState() {
  return { n: 0, seen: new Map(), hits: [] };
}

export function tokenFor(value, label, state) {
  const existing = state.seen.get(value);
  if (existing) return existing;
  const id = ++state.n;
  const token = `[REDACTED ${label} #${id}]`;
  state.seen.set(value, token);
  state.hits.push({ label, id });
  return token;
}

export function redactText(text, state = newState()) {
  const hits = findSecrets(text);
  if (hits.length === 0) return text;
  let out = "";
  let last = 0;
  for (const hit of hits) {
    out += text.slice(last, hit.start) + tokenFor(hit.value, hit.label, state);
    last = hit.end;
  }
  return out + text.slice(last);
}

// Returns the ORIGINAL value when nothing was found. Callers rely on this: a
// hook that emits an identity rewrite races last-write-wins against a sibling
// hook doing a real redaction.
export function redactDeep(value, state = newState()) {
  const walk = (node) => {
    if (typeof node === "string") return redactText(node, state);
    if (Array.isArray(node)) return node.map(walk);
    if (node && typeof node === "object") {
      const copy = {};
      for (const key of Object.keys(node)) copy[key] = walk(node[key]);
      return copy;
    }
    return node;
  };
  const redacted = walk(value);
  return { value: state.hits.length ? redacted : value, total: state.hits.length, hits: state.hits };
}

export function summarize(hits) {
  const counts = new Map();
  for (const { label } of hits) counts.set(label, (counts.get(label) ?? 0) + 1);
  return [...counts].map(([label, n]) => `${n} ${label}`).join(", ");
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd plugins/secret-redactor && npm test`
Expected: all passing.

- [ ] **Step 5: Commit**

```bash
git add plugins/secret-redactor/lib/detect.mjs plugins/secret-redactor/test/detect.test.mjs
git commit -m "feat: idempotent redaction built on findSecrets"
```

---

### Task 5: The PostToolUse hook and `hooks.json`

Ports v1.0.2's behaviour onto the new core. Behaviour is unchanged; only the
file name and the import are new.

**Files:**
- Create: `plugins/secret-redactor/hooks/redact-tool-output.mjs`
- Create: `plugins/secret-redactor/hooks/hooks.json`
- Create: `plugins/secret-redactor/test/helpers/run-hook.mjs`
- Test: `plugins/secret-redactor/test/hooks.test.mjs`

**Interfaces:**
- Consumes: `redactDeep`, `summarize` from Task 4.
- Produces: `runHook(scriptName, payload) -> { code, stdout, stderr }` test helper, reused by Tasks 6 and 7.

- [ ] **Step 1: Write the test helper**

`plugins/secret-redactor/test/helpers/run-hook.mjs`:

```js
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
```

- [ ] **Step 2: Write the failing test**

`plugins/secret-redactor/test/hooks.test.mjs`:

```js
import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import path from "node:path";
import { runHook } from "./helpers/run-hook.mjs";

const PLUGIN = path.dirname(path.dirname(fileURLToPath(import.meta.url)));
const TOKEN = "ghp_" + "f".repeat(36);

test("PostToolUse: rewrites the result and reports the count", async () => {
  const { code, stdout, stderr } = await runHook("redact-tool-output.mjs", {
    hook_event_name: "PostToolUse",
    tool_name: "Bash",
    tool_response: { stdout: "GITHUB_TOKEN=" + TOKEN, stderr: "", interrupted: false },
  });
  assert.equal(code, 0);
  assert.equal(stderr, "");
  assert.ok(!stdout.includes(TOKEN), "the hook leaked the secret into its own output");
  const out = JSON.parse(stdout);
  assert.equal(out.hookSpecificOutput.hookEventName, "PostToolUse");
  assert.equal(out.hookSpecificOutput.updatedToolOutput.interrupted, false);
  assert.match(out.hookSpecificOutput.additionalContext, /replaced 1 secret/);
});

test("PostToolUse: prints nothing at all for a clean payload", async () => {
  const { code, stdout } = await runHook("redact-tool-output.mjs", {
    hook_event_name: "PostToolUse",
    tool_name: "Bash",
    tool_response: { stdout: "246 tests, 246 passing", exitCode: 0 },
  });
  assert.equal(code, 0);
  assert.equal(stdout, "");
});

test("PostToolUse: fails open on malformed and on empty stdin", async () => {
  for (const payload of ["this is not json{{{", ""]) {
    const { code, stdout } = await runHook("redact-tool-output.mjs", payload);
    assert.equal(code, 0);
    assert.equal(stdout, "");
  }
});

test("PostToolUse: ignores an event that is not its own", async () => {
  const { code, stdout } = await runHook("redact-tool-output.mjs", {
    hook_event_name: "PreToolUse",
    tool_name: "Bash",
    tool_response: { stdout: "GITHUB_TOKEN=" + TOKEN },
  });
  assert.equal(code, 0);
  assert.equal(stdout, "");
});

test("hooks.json registers all three hooks against the right events", () => {
  const cfg = JSON.parse(readFileSync(path.join(PLUGIN, "hooks", "hooks.json"), "utf8"));
  assert.ok(cfg.hooks.PostToolUse, "PostToolUse is not registered");
  assert.ok(cfg.hooks.UserPromptSubmit, "UserPromptSubmit is not registered");
  assert.ok(cfg.hooks.PreToolUse, "PreToolUse is not registered");
  assert.equal(cfg.hooks.PreToolUse[0].matcher, "Write|Edit|NotebookEdit");
  const commands = JSON.stringify(cfg);
  for (const script of ["redact-tool-output.mjs", "redact-prompt.mjs", "guard-write.mjs"]) {
    assert.ok(commands.includes(script), script + " is not wired in hooks.json");
  }
});
```

- [ ] **Step 3: Run test to verify it fails**

Run: `cd plugins/secret-redactor && node --test test/hooks.test.mjs`
Expected: FAIL, the hook script and `hooks.json` do not exist.

- [ ] **Step 4: Write the hook and the config**

`plugins/secret-redactor/hooks/redact-tool-output.mjs`:

```js
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
  systemMessage: `secret-redactor: ${total} ${plural} redacted from ${tool} output`,
  hookSpecificOutput: {
    hookEventName: "PostToolUse",
    updatedToolOutput: value,
    additionalContext:
      `secret-redactor replaced ${total} ${plural} in this ${tool} result (${summarize(hits)}). ` +
      `Each one appears as [REDACTED <kind> #n]; the same number means the same value. ` +
      `The real values were never sent to you, so do not guess them or try to reconstruct them. ` +
      `If you need one, read it at run time from the environment or ask the user.`,
  },
});
```

`plugins/secret-redactor/hooks/io.mjs`:

```js
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
```

`plugins/secret-redactor/hooks/hooks.json`:

```json
{
  "description": "Redact credentials from prompts and tool results, and refuse to write one into a tracked file",
  "hooks": {
    "UserPromptSubmit": [
      {
        "hooks": [
          {
            "type": "command",
            "command": "node \"${CLAUDE_PLUGIN_ROOT}/hooks/redact-prompt.mjs\"",
            "timeout": 15
          }
        ]
      }
    ],
    "PreToolUse": [
      {
        "matcher": "Write|Edit|NotebookEdit",
        "hooks": [
          {
            "type": "command",
            "command": "node \"${CLAUDE_PLUGIN_ROOT}/hooks/guard-write.mjs\"",
            "timeout": 15
          }
        ]
      }
    ],
    "PostToolUse": [
      {
        "matcher": "*",
        "hooks": [
          {
            "type": "command",
            "command": "node \"${CLAUDE_PLUGIN_ROOT}/hooks/redact-tool-output.mjs\"",
            "timeout": 15
          }
        ]
      }
    ]
  }
}
```

Note: the `hooks.json` test in Step 2 will still fail until Tasks 6 and 7 create
the two remaining scripts, but the config referencing them now is correct. If
the executor wants a green suite at the end of this task, skip that one test with
`test.todo` and remove the todo in Task 7.

- [ ] **Step 5: Run test to verify it passes**

Run: `cd plugins/secret-redactor && node --test test/hooks.test.mjs`
Expected: the four PostToolUse tests pass. The `hooks.json` test passes too,
since it only reads the config.

- [ ] **Step 6: Commit**

```bash
git add plugins/secret-redactor/hooks plugins/secret-redactor/test/hooks.test.mjs plugins/secret-redactor/test/helpers
git commit -m "feat: port the PostToolUse redactor onto the shared detector core"
```

---

### Task 6: The UserPromptSubmit hook

**Files:**
- Create: `plugins/secret-redactor/hooks/redact-prompt.mjs`
- Test: `plugins/secret-redactor/test/hooks.test.mjs` (append)

**Interfaces:**
- Consumes: `readStdinJson`, `writeResult` from Task 5; `redactText`, `newState`, `summarize` from Task 4.
- Produces: nothing importable.

- [ ] **Step 1: Write the failing test**

Append to `plugins/secret-redactor/test/hooks.test.mjs`:

```js
test("UserPromptSubmit: rewrites a pasted secret out of the prompt", async () => {
  const { code, stdout } = await runHook("redact-prompt.mjs", {
    hook_event_name: "UserPromptSubmit",
    prompt: "put this in the env file: STRIPE_KEY=sk_TEST_live_0123456789abcdefghijklmn",
  });
  assert.equal(code, 0);
  assert.ok(!stdout.includes("sk_TEST_live_0123456789abcdefghijklmn"));
  const out = JSON.parse(stdout);
  assert.equal(out.hookSpecificOutput.hookEventName, "UserPromptSubmit");
  assert.match(out.hookSpecificOutput.updatedPrompt, /\[REDACTED stripe-key #1\]/);
  assert.match(out.hookSpecificOutput.updatedPrompt, /^put this in the env file: /);
  assert.match(out.systemMessage, /1 secret redacted from your prompt/);
});

test("UserPromptSubmit: says nothing for a clean prompt", async () => {
  const { code, stdout } = await runHook("redact-prompt.mjs", {
    hook_event_name: "UserPromptSubmit",
    prompt: "run the tests and tell me what broke",
  });
  assert.equal(code, 0);
  assert.equal(stdout, "");
});

test("UserPromptSubmit: #allow-secret is an escape hatch", async () => {
  const { code, stdout } = await runHook("redact-prompt.mjs", {
    hook_event_name: "UserPromptSubmit",
    prompt: "#allow-secret STRIPE_KEY=sk_TEST_live_0123456789abcdefghijklmn",
  });
  assert.equal(code, 0);
  assert.equal(stdout, "");
});

test("UserPromptSubmit: fails open on malformed stdin", async () => {
  const { code, stdout } = await runHook("redact-prompt.mjs", "}}}not json");
  assert.equal(code, 0);
  assert.equal(stdout, "");
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd plugins/secret-redactor && node --test test/hooks.test.mjs`
Expected: FAIL, cannot find `redact-prompt.mjs`.

- [ ] **Step 3: Write the hook**

`plugins/secret-redactor/hooks/redact-prompt.mjs`:

```js
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
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd plugins/secret-redactor && node --test test/hooks.test.mjs`
Expected: the four new tests pass alongside Task 5's.

- [ ] **Step 5: Commit**

```bash
git add plugins/secret-redactor/hooks/redact-prompt.mjs plugins/secret-redactor/test/hooks.test.mjs
git commit -m "feat: redact credentials out of pasted prompts before they reach the transcript"
```

---

### Task 7: The PreToolUse write guard

**Files:**
- Create: `plugins/secret-redactor/lib/gitignore.mjs`
- Create: `plugins/secret-redactor/hooks/guard-write.mjs`
- Test: `plugins/secret-redactor/test/hooks.test.mjs` (append)

**Interfaces:**
- Consumes: `findSecrets` from Task 2; `readStdinJson`, `writeResult` from Task 5.
- Produces: `envExemption(filePath, cwd) -> { exempt: boolean, reason: string }`.

The .env rule, restated: exempt a `.env*` file only when git actually ignores
it. `.env.production` and `.env.example` are tracked in GradeThread, so a
name-only rule would let a real key through.

- [ ] **Step 1: Write the failing test**

Append to `plugins/secret-redactor/test/hooks.test.mjs`:

```js
import { mkdtempSync, writeFileSync, mkdirSync } from "node:fs";
import { tmpdir } from "node:os";
import { execFileSync } from "node:child_process";

function tempGitRepo() {
  const dir = mkdtempSync(path.join(tmpdir(), "secret-gate-"));
  const git = (...args) => execFileSync("git", args, { cwd: dir, stdio: "ignore" });
  git("init", "-q");
  git("config", "user.email", "test@example.com");
  git("config", "user.name", "test");
  writeFileSync(path.join(dir, ".gitignore"), ".env\n.env.local\n");
  writeFileSync(path.join(dir, ".env.production"), "VITE_PUBLIC=1\n");
  git("add", ".gitignore", ".env.production");
  git("commit", "-qm", "init");
  return dir;
}

const LIVE = "sk_TEST_live_0123456789abcdefghijklmn";

test("PreToolUse: denies writing a secret into a tracked file", async () => {
  const cwd = tempGitRepo();
  const { code, stdout } = await runHook(
    "guard-write.mjs",
    {
      hook_event_name: "PreToolUse",
      tool_name: "Write",
      tool_input: { file_path: path.join(cwd, "docs", "setup.md"), content: "STRIPE_KEY=" + LIVE },
    },
    { cwd },
  );
  assert.equal(code, 0);
  assert.ok(!stdout.includes(LIVE), "the deny reason leaked the value");
  const out = JSON.parse(stdout);
  assert.equal(out.hookSpecificOutput.permissionDecision, "deny");
  assert.match(out.hookSpecificOutput.permissionDecisionReason, /stripe-key/);
  assert.match(out.hookSpecificOutput.permissionDecisionReason, /setup\.md/);
});

test("PreToolUse: allows writing a secret into a gitignored .env", async () => {
  const cwd = tempGitRepo();
  const { code, stdout } = await runHook(
    "guard-write.mjs",
    {
      hook_event_name: "PreToolUse",
      tool_name: "Write",
      tool_input: { file_path: path.join(cwd, ".env.local"), content: "STRIPE_KEY=" + LIVE },
    },
    { cwd },
  );
  assert.equal(code, 0);
  assert.equal(stdout, "");
});

test("PreToolUse: denies a secret in a TRACKED .env.production", async () => {
  const cwd = tempGitRepo();
  const { code, stdout } = await runHook(
    "guard-write.mjs",
    {
      hook_event_name: "PreToolUse",
      tool_name: "Write",
      tool_input: { file_path: path.join(cwd, ".env.production"), content: "STRIPE_KEY=" + LIVE },
    },
    { cwd },
  );
  assert.equal(code, 0);
  const out = JSON.parse(stdout);
  assert.equal(out.hookSpecificOutput.permissionDecision, "deny");
});

test("PreToolUse: reads Edit new_string and NotebookEdit new_source", async () => {
  const cwd = tempGitRepo();
  for (const [tool, key] of [["Edit", "new_string"], ["NotebookEdit", "new_source"]]) {
    const { stdout } = await runHook(
      "guard-write.mjs",
      {
        hook_event_name: "PreToolUse",
        tool_name: tool,
        tool_input: { file_path: path.join(cwd, "notes.md"), [key]: "STRIPE_KEY=" + LIVE },
      },
      { cwd },
    );
    const out = JSON.parse(stdout);
    assert.equal(out.hookSpecificOutput.permissionDecision, "deny", tool + " was not blocked");
  }
});

test("PreToolUse: stays silent for clean content", async () => {
  const cwd = tempGitRepo();
  const { code, stdout } = await runHook(
    "guard-write.mjs",
    {
      hook_event_name: "PreToolUse",
      tool_name: "Write",
      tool_input: { file_path: path.join(cwd, "notes.md"), content: "# Notes\n\nnothing here\n" },
    },
    { cwd },
  );
  assert.equal(code, 0);
  assert.equal(stdout, "");
});

test("PreToolUse: outside a git repo, falls back to the .env name rule and says so", async () => {
  const cwd = mkdtempSync(path.join(tmpdir(), "secret-gate-nogit-"));
  const { stdout } = await runHook(
    "guard-write.mjs",
    {
      hook_event_name: "PreToolUse",
      tool_name: "Write",
      tool_input: { file_path: path.join(cwd, "notes.md"), content: "STRIPE_KEY=" + LIVE },
    },
    { cwd },
  );
  const out = JSON.parse(stdout);
  assert.equal(out.hookSpecificOutput.permissionDecision, "deny");
  assert.match(out.hookSpecificOutput.permissionDecisionReason, /not a git repo/i);
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd plugins/secret-redactor && node --test test/hooks.test.mjs`
Expected: FAIL, cannot find `guard-write.mjs`.

- [ ] **Step 3: Write `lib/gitignore.mjs`**

```js
// lib/gitignore.mjs
//
// The .env exemption is "git ignores this file", not "this file is called .env".
// GradeThread tracks .env.production and .env.example, so a name-only rule would
// let a real key reach GitHub in the one place nobody would look for it.
import { spawnSync } from "node:child_process";
import path from "node:path";

const ENV_NAME = /(^|[/\\])\.env(\.|$)/;

// exit 0 = ignored, exit 1 = not ignored, anything else = git could not answer.
export function gitIgnores(filePath, cwd) {
  const result = spawnSync("git", ["check-ignore", "--quiet", "--no-index", "--", filePath], {
    cwd,
    stdio: "ignore",
  });
  if (result.error || result.status === null) return { available: false, ignored: false };
  if (result.status === 0) return { available: true, ignored: true };
  if (result.status === 1) return { available: true, ignored: false };
  return { available: false, ignored: false };
}

export function envExemption(filePath, cwd = process.cwd()) {
  const looksLikeEnv = ENV_NAME.test(filePath.replaceAll("\\", "/"));
  const { available, ignored } = gitIgnores(filePath, cwd);

  if (available && ignored) {
    return { exempt: true, reason: "git ignores this path" };
  }
  if (available) {
    return { exempt: false, reason: "git tracks this path" };
  }
  if (looksLikeEnv) {
    return { exempt: true, reason: "not a git repo, falling back to the .env name rule" };
  }
  return { exempt: false, reason: "not a git repo, and this is not a .env file" };
}

export { path as _path };
```

- [ ] **Step 4: Write `hooks/guard-write.mjs`**

```js
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
```

- [ ] **Step 5: Run the whole suite**

Run: `cd plugins/secret-redactor && npm test`
Expected: all passing, including the `hooks.json` wiring test from Task 5 (remove
its `test.todo` if one was added).

- [ ] **Step 6: Commit**

```bash
git add plugins/secret-redactor/lib/gitignore.mjs plugins/secret-redactor/hooks/guard-write.mjs plugins/secret-redactor/test/hooks.test.mjs
git commit -m "feat: refuse to write a credential into a file git will carry"
```

---

### Task 8: The allowlist

**Files:**
- Create: `plugins/secret-redactor/lib/allowlist.mjs`
- Test: `plugins/secret-redactor/test/allowlist.test.mjs`

**Interfaces:**
- Consumes: nothing from earlier tasks.
- Produces:
  - `ALLOWLIST_FILE = ".secretgate.json"`
  - `loadAllowlist(repoRoot) -> { version, paths, regexes, fingerprints, used: Set }`
  - `fingerprintOf(relPath, hit) -> string` in the form `path:label:line`
  - `isAllowed(allowlist, relPath, hit) -> boolean`
  - `staleEntries(allowlist) -> string[]`

- [ ] **Step 1: Write the failing test**

`plugins/secret-redactor/test/allowlist.test.mjs`:

```js
import test from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { loadAllowlist, isAllowed, staleEntries, fingerprintOf, ALLOWLIST_FILE } from "../lib/allowlist.mjs";

function repoWith(config) {
  const dir = mkdtempSync(path.join(tmpdir(), "secret-gate-allow-"));
  if (config !== null) writeFileSync(path.join(dir, ALLOWLIST_FILE), JSON.stringify(config));
  return dir;
}

const hit = { label: "stripe-key", line: 14, value: "sk_TEST_live_0123456789abcdefghijklmn" };

test("an absent file yields an empty allowlist that allows nothing", () => {
  const list = loadAllowlist(repoWith(null));
  assert.equal(isAllowed(list, "docs/setup.md", hit), false);
});

test("a path pattern allows every finding in that file", () => {
  const list = loadAllowlist(repoWith({ version: 1, paths: ["^test/fixtures/"] }));
  assert.equal(isAllowed(list, "test/fixtures/corpus.txt", hit), true);
  assert.equal(isAllowed(list, "src/app.ts", hit), false);
});

test("a value pattern allows a matching value anywhere", () => {
  const list = loadAllowlist(repoWith({ version: 1, regexes: ["^sk_live_0123"] }));
  assert.equal(isAllowed(list, "anywhere.md", hit), true);
});

test("a fingerprint allows exactly one finding", () => {
  const fp = fingerprintOf("docs/setup.md", hit);
  assert.equal(fp, "docs/setup.md:stripe-key:14");
  const list = loadAllowlist(repoWith({ version: 1, fingerprints: [fp] }));
  assert.equal(isAllowed(list, "docs/setup.md", hit), true);
  assert.equal(isAllowed(list, "docs/setup.md", { ...hit, line: 15 }), false);
  assert.equal(isAllowed(list, "docs/other.md", hit), false);
});

test("an entry that matched nothing is reported as stale", () => {
  const list = loadAllowlist(repoWith({ version: 1, paths: ["^used/"], regexes: ["never-matches-this"] }));
  isAllowed(list, "used/file.md", hit);
  assert.deepEqual(staleEntries(list), ["never-matches-this"]);
});

test("invalid JSON throws with the file named and no secret in the message", () => {
  const dir = mkdtempSync(path.join(tmpdir(), "secret-gate-allow-"));
  writeFileSync(path.join(dir, ALLOWLIST_FILE), "{ not json");
  assert.throws(() => loadAllowlist(dir), /\.secretgate\.json is not valid JSON/);
});

test("an invalid regex throws with the pattern named", () => {
  const dir = repoWith({ version: 1, paths: ["["] });
  assert.throws(() => loadAllowlist(dir), /\[/);
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd plugins/secret-redactor && node --test test/allowlist.test.mjs`
Expected: FAIL, cannot find `../lib/allowlist.mjs`.

- [ ] **Step 3: Write `lib/allowlist.mjs`**

```js
// lib/allowlist.mjs
//
// JSON rather than TOML because Node has no built-in TOML parser and this
// plugin takes no dependencies.
//
// An entry that stops matching anything is reported as stale on every scan.
// That is what keeps the list shrinking rather than growing: a silenced rule
// nobody re-checks is how a live key ends up allowlisted forever.
import { existsSync, readFileSync } from "node:fs";
import path from "node:path";

export const ALLOWLIST_FILE = ".secretgate.json";

function compile(patterns, field) {
  return (patterns ?? []).map((src) => {
    if (typeof src !== "string") {
      throw new Error(`${ALLOWLIST_FILE}: ${field} entries must be strings`);
    }
    try {
      return { src, re: new RegExp(src) };
    } catch (err) {
      throw new Error(`${ALLOWLIST_FILE}: ${field} entry ${src} is not a valid regex: ${err.message}`);
    }
  });
}

export function loadAllowlist(repoRoot) {
  const file = path.join(repoRoot, ALLOWLIST_FILE);
  const empty = { version: 1, paths: [], regexes: [], fingerprints: [], used: new Set() };
  if (!existsSync(file)) return empty;

  let parsed;
  try {
    parsed = JSON.parse(readFileSync(file, "utf8"));
  } catch (err) {
    throw new Error(`${ALLOWLIST_FILE} is not valid JSON: ${err.message}`);
  }

  return {
    version: parsed.version ?? 1,
    paths: compile(parsed.paths, "paths"),
    regexes: compile(parsed.regexes, "regexes"),
    fingerprints: (parsed.fingerprints ?? []).map((src) => ({ src })),
    used: new Set(),
  };
}

export function fingerprintOf(relPath, hit) {
  return `${relPath.replaceAll("\\", "/")}:${hit.label}:${hit.line}`;
}

export function isAllowed(allowlist, relPath, hit) {
  const rel = relPath.replaceAll("\\", "/");
  for (const entry of allowlist.paths) {
    if (entry.re.test(rel)) {
      allowlist.used.add(entry.src);
      return true;
    }
  }
  for (const entry of allowlist.regexes) {
    if (entry.re.test(hit.value)) {
      allowlist.used.add(entry.src);
      return true;
    }
  }
  const fp = fingerprintOf(rel, hit);
  for (const entry of allowlist.fingerprints) {
    if (entry.src === fp) {
      allowlist.used.add(entry.src);
      return true;
    }
  }
  return false;
}

export function staleEntries(allowlist) {
  return [...allowlist.paths, ...allowlist.regexes, ...allowlist.fingerprints]
    .map((entry) => entry.src)
    .filter((src) => !allowlist.used.has(src));
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd plugins/secret-redactor && node --test test/allowlist.test.mjs`
Expected: 7 tests, 7 passing.

- [ ] **Step 5: Commit**

```bash
git add plugins/secret-redactor/lib/allowlist.mjs plugins/secret-redactor/test/allowlist.test.mjs
git commit -m "feat: .secretgate.json allowlist with stale-entry reporting"
```

---

### Task 9: `scan`

**Files:**
- Create: `plugins/secret-redactor/lib/cli.mjs`
- Create: `plugins/secret-redactor/bin/secret-gate.mjs`
- Create: `plugins/secret-redactor/test/helpers/temp-repo.mjs`
- Test: `plugins/secret-redactor/test/cli-scan.test.mjs`

**Interfaces:**
- Consumes: `findSecrets`, `MAX_SCAN_BYTES` from Task 2; the whole allowlist API from Task 8.
- Produces:
  - `VERSION` string constant, must equal `package.json` version.
  - `main(argv) -> Promise<number>` exit code.
  - `repoRoot(cwd) -> string`, `isBinary(buffer) -> boolean` used by Tasks 10 and 11.
  - test helper `makeRepo({ files, staged }) -> dir`.

Exit codes: `0` clean, `1` findings, `2` internal error or bad usage.

- [ ] **Step 1: Write the test helper**

`plugins/secret-redactor/test/helpers/temp-repo.mjs`:

```js
import { mkdtempSync, mkdirSync, writeFileSync } from "node:fs";
import { execFileSync } from "node:child_process";
import { tmpdir } from "node:os";
import path from "node:path";

// files: { "docs/setup.md": "contents" }
// stage: true runs `git add -A` afterwards
export function makeRepo(files = {}, { stage = true, commitFirst = false } = {}) {
  const dir = mkdtempSync(path.join(tmpdir(), "secret-gate-repo-"));
  const git = (...args) => execFileSync("git", args, { cwd: dir, stdio: "ignore" });
  git("init", "-q");
  git("config", "user.email", "test@example.com");
  git("config", "user.name", "test");
  git("config", "commit.gpgsign", "false");

  writeFileSync(path.join(dir, ".gitkeep"), "");
  git("add", ".gitkeep");
  git("commit", "-qm", "init");

  for (const [rel, contents] of Object.entries(files)) {
    const abs = path.join(dir, rel);
    mkdirSync(path.dirname(abs), { recursive: true });
    writeFileSync(abs, contents);
  }
  if (stage) git("add", "-A");
  if (commitFirst) git("commit", "-qm", "files");
  return dir;
}

export function runCli(dir, args) {
  const cliPath = path.join(
    path.dirname(path.dirname(new URL(import.meta.url).pathname.replace(/^\/([A-Za-z]:)/, "$1"))),
    "..",
    "lib",
    "cli.mjs",
  );
  try {
    const stdout = execFileSync(process.execPath, [cliPath, ...args], {
      cwd: dir,
      encoding: "utf8",
      stdio: ["ignore", "pipe", "pipe"],
    });
    return { code: 0, stdout, stderr: "" };
  } catch (err) {
    return { code: err.status ?? 2, stdout: err.stdout ?? "", stderr: err.stderr ?? "" };
  }
}
```

- [ ] **Step 2: Write the failing test**

`plugins/secret-redactor/test/cli-scan.test.mjs`:

```js
import test from "node:test";
import assert from "node:assert/strict";
import { writeFileSync } from "node:fs";
import path from "node:path";
import { makeRepo, runCli } from "./helpers/temp-repo.mjs";

const LIVE = "sk_TEST_live_0123456789abcdefghijklmn";

test("scan --staged exits 1 and names the file, line and label", () => {
  const dir = makeRepo({ "docs/setup.md": "# Setup\n\nSTRIPE_KEY=" + LIVE + "\n" });
  const { code, stdout } = runCli(dir, ["scan", "--staged"]);
  assert.equal(code, 1);
  assert.match(stdout, /docs\/setup\.md:3/);
  assert.match(stdout, /stripe-key/);
  assert.ok(!stdout.includes(LIVE), "the report printed the secret value");
});

test("scan --staged exits 0 on a clean tree", () => {
  const dir = makeRepo({ "docs/setup.md": "# Setup\n\nnothing here\n" });
  const { code } = runCli(dir, ["scan", "--staged"]);
  assert.equal(code, 0);
});

test("scan --staged reads the STAGED content, not the worktree", () => {
  const dir = makeRepo({ "a.md": "clean\n" });
  writeFileSync(path.join(dir, "a.md"), "STRIPE_KEY=" + LIVE + "\n");
  const { code } = runCli(dir, ["scan", "--staged"]);
  assert.equal(code, 0, "an unstaged edit must not block the commit");
});

test("scan with no --staged walks tracked files", () => {
  const dir = makeRepo({ "docs/setup.md": "STRIPE_KEY=" + LIVE + "\n" }, { commitFirst: true });
  const { code, stdout } = runCli(dir, ["scan"]);
  assert.equal(code, 1);
  assert.match(stdout, /docs\/setup\.md/);
});

test("the allowlist suppresses a finding and the exit code goes to 0", () => {
  const dir = makeRepo({
    "test/fixtures/keys.txt": "STRIPE_KEY=" + LIVE + "\n",
    ".secretgate.json": JSON.stringify({ version: 1, paths: ["^test/fixtures/"] }),
  });
  const { code } = runCli(dir, ["scan", "--staged"]);
  assert.equal(code, 0);
});

test("a stale allowlist entry is reported but does not change the exit code", () => {
  const dir = makeRepo({
    "a.md": "clean\n",
    ".secretgate.json": JSON.stringify({ version: 1, regexes: ["matches-nothing-at-all"] }),
  });
  const { code, stdout } = runCli(dir, ["scan", "--staged"]);
  assert.equal(code, 0);
  assert.match(stdout, /stale/i);
  assert.match(stdout, /matches-nothing-at-all/);
});

test("binary and oversize files are skipped and the skip is reported", () => {
  const dir = makeRepo({
    "logo.png": "\u0000\u0001PNG" + LIVE,
    "a.md": "clean\n",
  });
  const { code, stdout } = runCli(dir, ["scan", "--staged"]);
  assert.equal(code, 0);
  assert.match(stdout, /skipped/i);
  assert.match(stdout, /logo\.png/);
});

test("--version prints the version and exits 0", () => {
  const dir = makeRepo({ "a.md": "clean\n" });
  const { code, stdout } = runCli(dir, ["--version"]);
  assert.equal(code, 0);
  assert.match(stdout.trim(), /^\d+\.\d+\.\d+$/);
});

test("an unknown command exits 2 and prints usage", () => {
  const dir = makeRepo({ "a.md": "clean\n" });
  const { code, stderr } = runCli(dir, ["frobnicate"]);
  assert.equal(code, 2);
  assert.match(stderr, /usage/i);
});

test("running outside a git repo exits 2 with a clear message", () => {
  const { code, stderr } = runCli(process.env.TMPDIR || require("node:os").tmpdir(), ["scan", "--staged"]);
  assert.equal(code, 2);
  assert.match(stderr, /not a git repository/i);
});
```

- [ ] **Step 3: Run test to verify it fails**

Run: `cd plugins/secret-redactor && node --test test/cli-scan.test.mjs`
Expected: FAIL, cannot find `../lib/cli.mjs`.

- [ ] **Step 4: Write `lib/cli.mjs` with `scan` only**

```js
#!/usr/bin/env node
// lib/cli.mjs
//
// scan / fix / install. This file plus detect.mjs and allowlist.mjs are what
// `install` vendors into a repo, so the three of them import each other with
// plain relative paths and nothing else.
//
// Exit codes:
//   0  clean
//   1  findings
//   2  internal error or bad usage
//
// The failure asymmetry is deliberate. The generated pre-commit hook treats 2
// as a warning and lets the commit through, because a crashing scanner must not
// brick committing in twenty repos. CI treats 2 as a failure, because there the
// right response to a broken scanner is a red build.
import { existsSync, readFileSync, writeFileSync } from "node:fs";
import { spawnSync } from "node:child_process";
import path from "node:path";
import { findSecrets, MAX_SCAN_BYTES, newState, tokenFor } from "./detect.mjs";
import { loadAllowlist, isAllowed, staleEntries, ALLOWLIST_FILE } from "./allowlist.mjs";

export const VERSION = "2.0.0";

const USAGE = `usage: secret-gate <command>

  scan [--staged] [paths...]   exit 1 if a credential is present
  fix --staged                 rewrite staged findings to [REDACTED] markers
  install [--force]            wire this repo up with the commit gate
  --version                    print ${VERSION}
`;

// --- git helpers -----------------------------------------------------------

function git(args, cwd, encoding = "utf8") {
  return spawnSync("git", args, { cwd, encoding, maxBuffer: MAX_SCAN_BYTES * 4 });
}

export function repoRoot(cwd = process.cwd()) {
  const result = git(["rev-parse", "--show-toplevel"], cwd);
  if (result.status !== 0) throw new Error("not a git repository");
  return result.stdout.trim();
}

function stagedPaths(root) {
  const result = git(["diff", "--cached", "--name-only", "--diff-filter=ACMR", "-z"], root);
  if (result.status !== 0) throw new Error("could not list staged files");
  return result.stdout.split("\u0000").filter(Boolean);
}

function trackedPaths(root) {
  const result = git(["ls-files", "-z"], root);
  if (result.status !== 0) throw new Error("could not list tracked files");
  return result.stdout.split("\u0000").filter(Boolean);
}

function stagedBuffer(root, rel) {
  const result = git(["show", `:${rel}`], root, "buffer");
  return result.status === 0 ? result.stdout : null;
}

export function isBinary(buffer) {
  return buffer.subarray(0, 8192).includes(0);
}

// --- scan ------------------------------------------------------------------

function collect(root, rel, buffer, allowlist, findings, skipped) {
  if (buffer === null) return;
  if (buffer.length > MAX_SCAN_BYTES) {
    skipped.push(`${rel} (${buffer.length} bytes, over the ${MAX_SCAN_BYTES} byte limit)`);
    return;
  }
  if (isBinary(buffer)) {
    skipped.push(`${rel} (binary)`);
    return;
  }
  for (const hit of findSecrets(buffer.toString("utf8"))) {
    if (isAllowed(allowlist, rel, hit)) continue;
    findings.push({ file: rel, line: hit.line, column: hit.column, label: hit.label });
  }
}

function report(findings, skipped, stale, staged) {
  const out = [];
  if (findings.length > 0) {
    const where = staged ? "staged files" : "tracked files";
    const plural = findings.length === 1 ? "secret" : "secrets";
    out.push(`[secret-gate] BLOCKED - ${findings.length} ${plural} in ${where}`, "");
    const width = Math.max(...findings.map((f) => `${f.file}:${f.line}:${f.column}`.length));
    for (const f of findings) {
      out.push(`  ${`${f.file}:${f.line}:${f.column}`.padEnd(width)}  ${f.label}`);
    }
    out.push(
      "",
      "Fix one of these ways:",
      "  1. Remove the value and read it from a gitignored .env file instead, or",
      "  2. node scripts/secret-gate/cli.mjs fix --staged",
      `  3. If it is a fixture, pin it in ${ALLOWLIST_FILE}:`,
      `       { "fingerprints": ["${findings[0].file}:${findings[0].label}:${findings[0].line}"] }`,
      "",
    );
  }
  if (skipped.length > 0) {
    out.push(`[secret-gate] skipped ${skipped.length} file(s):`);
    for (const s of skipped) out.push(`  ${s}`);
    out.push("");
  }
  if (stale.length > 0) {
    out.push(`[secret-gate] ${ALLOWLIST_FILE} has ${stale.length} stale entry/entries that matched nothing:`);
    for (const s of stale) out.push(`  ${s}`);
    out.push("  Remove them. An allowlist can only be trusted if it shrinks.", "");
  }
  if (out.length > 0) process.stdout.write(out.join("\n") + "\n");
}

function scan(args) {
  const staged = args.includes("--staged");
  const explicit = args.filter((a) => !a.startsWith("--"));
  const root = repoRoot();
  const allowlist = loadAllowlist(root);

  const targets = staged ? stagedPaths(root) : explicit.length > 0 ? explicit : trackedPaths(root);
  const findings = [];
  const skipped = [];

  for (const rel of targets) {
    const buffer = staged
      ? stagedBuffer(root, rel)
      : existsSync(path.join(root, rel))
        ? readFileSync(path.join(root, rel))
        : null;
    collect(root, rel, buffer, allowlist, findings, skipped);
  }

  report(findings, skipped, staleEntries(allowlist), staged);
  if (findings.length === 0 && skipped.length === 0 && staleEntries(allowlist).length === 0) {
    process.stdout.write("[secret-gate] no credentials found.\n");
  }
  return findings.length > 0 ? 1 : 0;
}

// --- entry point -----------------------------------------------------------

export async function main(argv = process.argv.slice(2)) {
  const cmd = argv[0];
  try {
    if (cmd === "--version" || cmd === "-v") {
      process.stdout.write(VERSION + "\n");
      return 0;
    }
    if (cmd === "scan") return scan(argv.slice(1));
    process.stderr.write(USAGE);
    return 2;
  } catch (err) {
    process.stderr.write(`[secret-gate] ${err.message}\n`);
    return 2;
  }
}

const invokedDirectly =
  process.argv[1] &&
  import.meta.url === new URL(`file://${process.argv[1].replaceAll("\\", "/")}`).href;

if (invokedDirectly) {
  main().then((code) => process.exit(code));
}
```

`plugins/secret-redactor/bin/secret-gate.mjs`:

```js
#!/usr/bin/env node
// Shim so the slash command and package.json have a stable path to the CLI.
// The real implementation is lib/cli.mjs, which is also what gets vendored.
import { main } from "../lib/cli.mjs";
main().then((code) => process.exit(code));
```

- [ ] **Step 5: Run test to verify it passes**

Run: `cd plugins/secret-redactor && node --test test/cli-scan.test.mjs`
Expected: 10 tests, 10 passing.

- [ ] **Step 6: Commit**

```bash
git add plugins/secret-redactor/lib/cli.mjs plugins/secret-redactor/bin plugins/secret-redactor/test/cli-scan.test.mjs plugins/secret-redactor/test/helpers/temp-repo.mjs
git commit -m "feat: secret-gate scan, reporting positions and never values"
```

---

### Task 10: `fix --staged`

**Files:**
- Modify: `plugins/secret-redactor/lib/cli.mjs`
- Test: `plugins/secret-redactor/test/cli-fix.test.mjs`

**Interfaces:**
- Consumes: `repoRoot`, `isBinary` from Task 9; `newState`, `tokenFor`, `findSecrets` from Tasks 2 and 4; the allowlist API from Task 8.
- Produces: nothing new importable. `main` now accepts `fix`.

`fix` rewrites the **worktree** file, because that is the copy the user has open,
then restages it.

- [ ] **Step 1: Write the failing test**

`plugins/secret-redactor/test/cli-fix.test.mjs`:

```js
import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync, writeFileSync } from "node:fs";
import { execFileSync } from "node:child_process";
import path from "node:path";
import { makeRepo, runCli } from "./helpers/temp-repo.mjs";

const LIVE = "sk_TEST_live_0123456789abcdefghijklmn";

test("fix --staged rewrites the file and leaves the label alone", () => {
  const dir = makeRepo({ "docs/setup.md": "# Setup\n\nSTRIPE_KEY=" + LIVE + "\n" });
  const { code } = runCli(dir, ["fix", "--staged"]);
  assert.equal(code, 0);
  const after = readFileSync(path.join(dir, "docs", "setup.md"), "utf8");
  assert.equal(after, "# Setup\n\nSTRIPE_KEY=[REDACTED stripe-key #1]\n");
});

test("fix --staged restages the rewritten file", () => {
  const dir = makeRepo({ "docs/setup.md": "STRIPE_KEY=" + LIVE + "\n" });
  runCli(dir, ["fix", "--staged"]);
  const stagedNow = execFileSync("git", ["show", ":docs/setup.md"], { cwd: dir, encoding: "utf8" });
  assert.ok(!stagedNow.includes(LIVE));
  assert.match(stagedNow, /\[REDACTED stripe-key #1\]/);
});

test("scan is clean immediately after fix", () => {
  const dir = makeRepo({ "docs/setup.md": "STRIPE_KEY=" + LIVE + "\n" });
  runCli(dir, ["fix", "--staged"]);
  assert.equal(runCli(dir, ["scan", "--staged"]).code, 0);
});

test("fix respects the allowlist and leaves an allowed fixture alone", () => {
  const original = "STRIPE_KEY=" + LIVE + "\n";
  const dir = makeRepo({
    "test/fixtures/keys.txt": original,
    ".secretgate.json": JSON.stringify({ version: 1, paths: ["^test/fixtures/"] }),
  });
  runCli(dir, ["fix", "--staged"]);
  assert.equal(readFileSync(path.join(dir, "test", "fixtures", "keys.txt"), "utf8"), original);
});

test("fix is a no-op on a clean tree and says so", () => {
  const dir = makeRepo({ "a.md": "clean\n" });
  const { code, stdout } = runCli(dir, ["fix", "--staged"]);
  assert.equal(code, 0);
  assert.match(stdout, /nothing to fix/i);
});

test("fix without --staged exits 2 rather than touching the whole tree", () => {
  const dir = makeRepo({ "a.md": "STRIPE_KEY=" + LIVE + "\n" });
  const { code, stderr } = runCli(dir, ["fix"]);
  assert.equal(code, 2);
  assert.match(stderr, /--staged/);
  assert.match(readFileSync(path.join(dir, "a.md"), "utf8"), /sk_live/);
});

test("fix never prints the value it replaced", () => {
  const dir = makeRepo({ "a.md": "STRIPE_KEY=" + LIVE + "\n" });
  const { stdout, stderr } = runCli(dir, ["fix", "--staged"]);
  assert.ok(!(stdout + stderr).includes(LIVE));
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd plugins/secret-redactor && node --test test/cli-fix.test.mjs`
Expected: FAIL, `fix` falls through to usage and exits 2.

- [ ] **Step 3: Add `fix` to `lib/cli.mjs`**

Insert above the `--- entry point ---` divider:

```js
// --- fix -------------------------------------------------------------------

function fix(args) {
  if (!args.includes("--staged")) {
    process.stderr.write("[secret-gate] fix requires --staged. It will not rewrite unstaged files.\n");
    return 2;
  }
  const root = repoRoot();
  const allowlist = loadAllowlist(root);
  const lines = [];
  let total = 0;

  for (const rel of stagedPaths(root)) {
    const abs = path.join(root, rel);
    if (!existsSync(abs)) continue;
    const buffer = readFileSync(abs);
    if (buffer.length > MAX_SCAN_BYTES || isBinary(buffer)) continue;

    const text = buffer.toString("utf8");
    const hits = findSecrets(text).filter((hit) => !isAllowed(allowlist, rel, hit));
    if (hits.length === 0) continue;

    const state = newState();
    let out = "";
    let last = 0;
    for (const hit of hits) {
      out += text.slice(last, hit.start) + tokenFor(hit.value, hit.label, state);
      last = hit.end;
    }
    writeFileSync(abs, out + text.slice(last));

    const added = git(["add", "--", rel], root);
    if (added.status !== 0) throw new Error(`could not restage ${rel}`);

    lines.push(`  ${rel}: ${hits.length} replaced (${[...new Set(hits.map((h) => h.label))].join(", ")})`);
    total += hits.length;
  }

  if (total === 0) {
    process.stdout.write("[secret-gate] nothing to fix.\n");
    return 0;
  }
  process.stdout.write(
    [`[secret-gate] rewrote ${total} value(s) to [REDACTED] markers and restaged:`, ...lines, ""].join("\n"),
  );
  return 0;
}
```

And in `main`, add above the usage fallthrough:

```js
    if (cmd === "fix") return fix(argv.slice(1));
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd plugins/secret-redactor && node --test test/cli-fix.test.mjs`
Expected: 7 tests, 7 passing.

- [ ] **Step 5: Commit**

```bash
git add plugins/secret-redactor/lib/cli.mjs plugins/secret-redactor/test/cli-fix.test.mjs
git commit -m "feat: secret-gate fix --staged rewrites and restages"
```

---

### Task 11: `install` and the templates

**Files:**
- Create: `plugins/secret-redactor/templates/pre-commit`
- Create: `plugins/secret-redactor/templates/workflow.yml`
- Create: `plugins/secret-redactor/templates/secretgate.json`
- Create: `plugins/secret-redactor/test/fixtures/gitleaks-pre-commit`
- Modify: `plugins/secret-redactor/lib/cli.mjs`
- Test: `plugins/secret-redactor/test/cli-install.test.mjs`

**Interfaces:**
- Consumes: `repoRoot`, `VERSION` from Task 9.
- Produces: nothing new importable. `main` now accepts `install`.

Append safety is the whole point of this task. GradeThread already has a
`pre-commit` running gitleaks and it must survive install, and a second install.

- [ ] **Step 1: Write the templates**

`plugins/secret-redactor/templates/pre-commit`:

```sh
#!/usr/bin/env sh
# >>> secret-gate __VERSION__
# Blocks a commit that stages a plaintext credential.
#
# Exit 1 from the scanner means findings, and the commit is refused.
# Any other non-zero exit means the scanner itself broke. That warns and lets
# the commit through on purpose: a crashing scanner must not brick committing.
# The CI job runs the same scan and does treat that as a failure.
if command -v node >/dev/null 2>&1; then
  node "$(git rev-parse --show-toplevel)/scripts/secret-gate/cli.mjs" scan --staged
  __secret_gate_status=$?
  if [ "$__secret_gate_status" -eq 1 ]; then
    exit 1
  fi
  if [ "$__secret_gate_status" -ne 0 ]; then
    echo "[secret-gate] scanner error (exit $__secret_gate_status) - allowing the commit. CI will still check."
  fi
else
  echo "[secret-gate] node not found - skipping the local scan. CI will still check."
fi
# <<< secret-gate
```

`plugins/secret-redactor/templates/workflow.yml`:

```yaml
# secret-gate __VERSION__
# Regenerated by `secret-gate install`. Edit the template, not this file.
name: secret-gate
on:
  push:
  pull_request:

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with:
          node-version: '22'
      - name: Scan tracked files for plaintext credentials
        run: node scripts/secret-gate/cli.mjs scan
```

`plugins/secret-redactor/templates/secretgate.json`:

```json
{
  "version": 1,
  "paths": [],
  "regexes": [
    "your-[a-z-]+"
  ],
  "fingerprints": []
}
```

`plugins/secret-redactor/test/fixtures/gitleaks-pre-commit` (a copy of
GradeThread's real hook, used to prove install does not clobber it):

```sh
#!/usr/bin/env bash
# Pre-commit secret scan (US-272).
set -euo pipefail

if ! command -v gitleaks >/dev/null 2>&1; then
  echo "[pre-commit] gitleaks not installed - skipping local secret scan."
  exit 0
fi

echo "[pre-commit] Scanning staged changes for secrets..."
if ! gitleaks protect --staged --redact --config .gitleaks.toml; then
  echo "[pre-commit] BLOCKED: a potential secret was found in your staged changes."
  exit 1
fi

echo "[pre-commit] No secrets detected."
```

- [ ] **Step 2: Write the failing test**

`plugins/secret-redactor/test/cli-install.test.mjs`:

```js
import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync, writeFileSync, mkdirSync, existsSync } from "node:fs";
import { execFileSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import path from "node:path";
import { makeRepo, runCli } from "./helpers/temp-repo.mjs";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const GITLEAKS_HOOK = readFileSync(path.join(HERE, "fixtures", "gitleaks-pre-commit"), "utf8");

function installInto(dir, args = []) {
  return runCli(dir, ["install", ...args]);
}

test("install writes the four things into an empty repo", () => {
  const dir = makeRepo({ "a.md": "clean\n" });
  const { code } = installInto(dir);
  assert.equal(code, 0);
  for (const rel of [
    "scripts/secret-gate/detect.mjs",
    "scripts/secret-gate/allowlist.mjs",
    "scripts/secret-gate/cli.mjs",
    "scripts/secret-gate/VERSION",
    ".secretgate.json",
    ".githooks/pre-commit",
    ".github/workflows/secret-gate.yml",
    ".gitattributes",
  ]) {
    assert.ok(existsSync(path.join(dir, rel)), rel + " was not written");
  }
});

test("the vendored copy actually runs and blocks", () => {
  const dir = makeRepo({ "a.md": "clean\n" });
  installInto(dir);
  writeFileSync(path.join(dir, "leak.md"), "STRIPE_KEY=sk_TEST_live_0123456789abcdefghijklmn\n");
  execFileSync("git", ["add", "-A"], { cwd: dir, stdio: "ignore" });
  let status = 0;
  try {
    execFileSync(process.execPath, [path.join(dir, "scripts", "secret-gate", "cli.mjs"), "scan", "--staged"], {
      cwd: dir,
      stdio: "pipe",
    });
  } catch (err) {
    status = err.status;
  }
  assert.equal(status, 1);
});

test("install sets core.hooksPath", () => {
  const dir = makeRepo({ "a.md": "clean\n" });
  installInto(dir);
  const value = execFileSync("git", ["config", "core.hooksPath"], { cwd: dir, encoding: "utf8" }).trim();
  assert.equal(value, ".githooks");
});

test("install appends to an existing pre-commit and the gitleaks line survives", () => {
  const dir = makeRepo({ "a.md": "clean\n" });
  mkdirSync(path.join(dir, ".githooks"), { recursive: true });
  writeFileSync(path.join(dir, ".githooks", "pre-commit"), GITLEAKS_HOOK);
  installInto(dir);
  const after = readFileSync(path.join(dir, ".githooks", "pre-commit"), "utf8");
  assert.match(after, /gitleaks protect --staged --redact/);
  assert.match(after, /# >>> secret-gate/);
  assert.match(after, /# <<< secret-gate/);
});

test("a second install replaces only the marked block, exactly once", () => {
  const dir = makeRepo({ "a.md": "clean\n" });
  mkdirSync(path.join(dir, ".githooks"), { recursive: true });
  writeFileSync(path.join(dir, ".githooks", "pre-commit"), GITLEAKS_HOOK);
  installInto(dir);
  installInto(dir);
  const after = readFileSync(path.join(dir, ".githooks", "pre-commit"), "utf8");
  assert.equal(after.match(/# >>> secret-gate/g).length, 1);
  assert.match(after, /gitleaks protect --staged --redact/);
});

test("install never overwrites an existing .secretgate.json", () => {
  const dir = makeRepo({ "a.md": "clean\n" });
  const mine = JSON.stringify({ version: 1, paths: ["^vendor/"] });
  writeFileSync(path.join(dir, ".secretgate.json"), mine);
  installInto(dir);
  assert.equal(readFileSync(path.join(dir, ".secretgate.json"), "utf8"), mine);
});

test("--force does overwrite .secretgate.json", () => {
  const dir = makeRepo({ "a.md": "clean\n" });
  writeFileSync(path.join(dir, ".secretgate.json"), JSON.stringify({ version: 1, paths: ["^vendor/"] }));
  installInto(dir, ["--force"]);
  assert.ok(!readFileSync(path.join(dir, ".secretgate.json"), "utf8").includes("vendor"));
});

test("install pins .githooks to LF in .gitattributes without dropping existing rules", () => {
  const dir = makeRepo({ "a.md": "clean\n" });
  writeFileSync(path.join(dir, ".gitattributes"), "*.sh text eol=lf\n");
  installInto(dir);
  const after = readFileSync(path.join(dir, ".gitattributes"), "utf8");
  assert.match(after, /\*\.sh text eol=lf/);
  assert.match(after, /\.githooks\/\*\* text eol=lf/);
});

test("install refuses to change a core.hooksPath that points elsewhere", () => {
  const dir = makeRepo({ "a.md": "clean\n" });
  execFileSync("git", ["config", "core.hooksPath", ".myhooks"], { cwd: dir, stdio: "ignore" });
  const { stdout } = installInto(dir);
  assert.match(stdout, /core\.hooksPath/);
  assert.match(stdout, /\.myhooks/);
  const value = execFileSync("git", ["config", "core.hooksPath"], { cwd: dir, encoding: "utf8" }).trim();
  assert.equal(value, ".myhooks");
});

test("the generated pre-commit has no CRLF line endings", () => {
  const dir = makeRepo({ "a.md": "clean\n" });
  installInto(dir);
  const raw = readFileSync(path.join(dir, ".githooks", "pre-commit"));
  assert.ok(!raw.includes(Buffer.from("\r\n")), "a CRLF shebang breaks git-for-windows sh");
});
```

- [ ] **Step 3: Run test to verify it fails**

Run: `cd plugins/secret-redactor && node --test test/cli-install.test.mjs`
Expected: FAIL, `install` falls through to usage and exits 2.

- [ ] **Step 4: Add `install` to `lib/cli.mjs`**

Add these imports at the top of the file:

```js
import { mkdirSync, copyFileSync, chmodSync } from "node:fs";
import { fileURLToPath } from "node:url";
```

Insert above the `--- entry point ---` divider:

```js
// --- install ---------------------------------------------------------------

const MARK_START = "# >>> secret-gate";
const MARK_END = "# <<< secret-gate";
const VENDOR_DIR = path.join("scripts", "secret-gate");
const VENDORED = ["detect.mjs", "allowlist.mjs", "cli.mjs"];
const LF_RULE = ".githooks/** text eol=lf";

function here() {
  return path.dirname(fileURLToPath(import.meta.url));
}

function template(name) {
  const file = path.join(here(), "..", "templates", name);
  if (!existsSync(file)) {
    throw new Error(
      "templates/ is missing. Run `install` from the plugin, not from a vendored scripts/secret-gate/ copy.",
    );
  }
  return readFileSync(file, "utf8").replaceAll("__VERSION__", VERSION).replaceAll("\r\n", "\n");
}

function writeLf(file, contents) {
  mkdirSync(path.dirname(file), { recursive: true });
  writeFileSync(file, contents.replaceAll("\r\n", "\n"), { encoding: "utf8" });
}

function spliceHook(existing, block) {
  const start = existing.indexOf(MARK_START);
  const end = existing.indexOf(MARK_END);
  if (start !== -1 && end !== -1 && end > start) {
    return existing.slice(0, start) + block.trim() + existing.slice(end + MARK_END.length);
  }
  return existing.replace(/\s*$/, "") + "\n\n" + block.trim() + "\n";
}

function stampOf(text) {
  const match = text.match(/secret-gate (\d+\.\d+\.\d+)/);
  return match ? match[1] : null;
}

function install(args) {
  const force = args.includes("--force");
  const root = repoRoot();
  const notes = [];

  // 1. vendor the three library files plus a version stamp
  const vendorTarget = path.join(root, VENDOR_DIR);
  mkdirSync(vendorTarget, { recursive: true });
  for (const name of VENDORED) {
    copyFileSync(path.join(here(), name), path.join(vendorTarget, name));
  }
  writeFileSync(path.join(vendorTarget, "VERSION"), VERSION + "\n");
  notes.push(`vendored ${VENDOR_DIR}/ at ${VERSION}`);

  // 2. allowlist, never clobbered without --force
  const allowFile = path.join(root, ALLOWLIST_FILE);
  if (!existsSync(allowFile) || force) {
    writeLf(allowFile, template("secretgate.json"));
    notes.push(`wrote ${ALLOWLIST_FILE}`);
  } else {
    notes.push(`kept your existing ${ALLOWLIST_FILE}`);
  }

  // 3. pre-commit, spliced between markers so a sibling hook survives
  const hookFile = path.join(root, ".githooks", "pre-commit");
  const full = template("pre-commit");
  const block = full.slice(full.indexOf(MARK_START));
  if (existsSync(hookFile)) {
    writeLf(hookFile, spliceHook(readFileSync(hookFile, "utf8"), block));
    notes.push("updated the secret-gate block in .githooks/pre-commit, left the rest alone");
  } else {
    writeLf(hookFile, full);
    notes.push("wrote .githooks/pre-commit");
  }
  try {
    chmodSync(hookFile, 0o755);
  } catch {
    // Windows has no exec bit. git handles it on checkout.
  }

  // 4. CI workflow, rewritten only when its stamp is older
  const wfFile = path.join(root, ".github", "workflows", "secret-gate.yml");
  const wf = template("workflow.yml");
  if (!existsSync(wfFile) || force || stampOf(readFileSync(wfFile, "utf8")) !== VERSION) {
    writeLf(wfFile, wf);
    notes.push("wrote .github/workflows/secret-gate.yml");
  } else {
    notes.push("workflow already at " + VERSION);
  }

  // 5. LF pin. A CRLF shebang breaks git-for-windows sh.
  const attrFile = path.join(root, ".gitattributes");
  const attrs = existsSync(attrFile) ? readFileSync(attrFile, "utf8") : "";
  if (!attrs.includes(LF_RULE)) {
    writeLf(attrFile, attrs.replace(/\s*$/, "") + (attrs.trim() ? "\n" : "") + LF_RULE + "\n");
    notes.push("pinned .githooks/** to LF in .gitattributes");
  }

  // 6. hooksPath, only when it is unset or already ours
  const current = git(["config", "--get", "core.hooksPath"], root);
  const value = current.status === 0 ? current.stdout.trim() : "";
  if (value === "" || value === ".githooks") {
    git(["config", "core.hooksPath", ".githooks"], root);
    notes.push("set core.hooksPath to .githooks");
  } else {
    notes.push(
      `LEFT ALONE: core.hooksPath is ${value}, not .githooks. ` +
        `Wire .githooks/pre-commit into ${value} yourself, or run: git config core.hooksPath .githooks`,
    );
  }

  process.stdout.write(
    [
      `[secret-gate] installed ${VERSION} into ${root}`,
      ...notes.map((n) => "  " + n),
      "",
      "Commit the new files so the gate travels with the repo:",
      `  git add ${VENDOR_DIR} ${ALLOWLIST_FILE} .githooks .github/workflows/secret-gate.yml .gitattributes`,
      "",
      "On another clone of this repo, run:  git config core.hooksPath .githooks",
      "",
    ].join("\n"),
  );
  return 0;
}
```

And in `main`, above the usage fallthrough:

```js
    if (cmd === "install") return install(argv.slice(1));
```

- [ ] **Step 5: Run the whole suite**

Run: `cd plugins/secret-redactor && npm test`
Expected: every test file passing.

- [ ] **Step 6: Verify no non-ASCII crept into the templates**

Run: `rg -n '[^\x00-\x7F]' plugins/secret-redactor/templates plugins/secret-redactor/lib plugins/secret-redactor/hooks`
Expected: no matches.

- [ ] **Step 7: Commit**

```bash
git add plugins/secret-redactor/lib/cli.mjs plugins/secret-redactor/templates plugins/secret-redactor/test/cli-install.test.mjs plugins/secret-redactor/test/fixtures/gitleaks-pre-commit
git commit -m "feat: secret-gate install, append-safe against an existing pre-commit"
```

---

### Task 12: Slash command, README, publish, and migrate off the local plugin

**Files:**
- Create: `plugins/secret-redactor/commands/secret-gate.md`
- Create: `plugins/secret-redactor/README.md`
- Modify: `C:\Users\dpearson\.claude\settings.json`
- Delete: `C:\Users\dpearson\.claude\plugins\local\secret-redactor`

**Interfaces:**
- Consumes: everything.
- Produces: a working install on this machine and a repeatable one on the second.

- [ ] **Step 1: Write the slash command**

`plugins/secret-redactor/commands/secret-gate.md`:

```markdown
---
description: Install or run the secret-gate commit guard in the current repo
---

Run the secret-gate CLI in the current working directory.

Arguments given: `$ARGUMENTS`

Run exactly this, substituting the arguments (default to `install` when none were given):

```bash
node "${CLAUDE_PLUGIN_ROOT}/bin/secret-gate.mjs" $ARGUMENTS
```

Then report the result to the user in plain language:

- On `install`: say which files were written and remind them to commit those
  files, since that is what makes the gate travel with the repo.
- On `scan` exiting 1: list the file, line and label for each finding. Never
  print the secret value, and never ask the user to paste it.
- On `scan` exiting 2: say the scanner itself failed and show the stderr line.

Do not offer to run `fix` automatically. Blocking rather than rewriting is the
point; the user chooses.
```

- [ ] **Step 2: Write the plugin README**

`plugins/secret-redactor/README.md`. Cover, in this order: what it does across
the four surfaces, the `#allow-secret` escape hatch, the gitignored-`.env` rule
and why it is not a name rule, `install` and what it writes, the
`.secretgate.json` schema with a worked example, the exit codes and the
fail-open/fail-closed asymmetry with its reason, the known trade-off that a
redacted file read makes a later `Edit` fail to match, and the three-place
version bump needed to ship an update.

- [ ] **Step 3: Run the full suite and the ASCII check one more time**

```bash
cd plugins/secret-redactor && npm test
rg -n '[^\x00-\x7F]' plugins/secret-redactor --glob '!test/fixtures/*'
```

Expected: all tests passing, no non-ASCII matches.

- [ ] **Step 4: Commit and publish**

```bash
git add plugins/secret-redactor/commands plugins/secret-redactor/README.md
git commit -m "docs: slash command and plugin README"
gh repo create dj-pearson/pearson-claude-plugins --public --source=. --remote=origin --push
```

- [ ] **Step 5: Install from the marketplace and cut over**

```bash
claude plugin marketplace add dj-pearson/pearson-claude-plugins
claude plugin install secret-redactor
```

Then in `C:\Users\dpearson\.claude\settings.json`, set
`"secret-redactor@local": false` in `enabledPlugins` and add
`"secret-redactor@pearson-media": true`. Restart the session.

Running both at once would double every marker number, so this is a required
step, not a cleanup.

- [ ] **Step 6: Verify the cutover on a scratch branch in GradeThread**

```bash
cd /c/Users/dpearson/Documents/GradeThread
git checkout -b scratch/secret-gate-verify
```

In that session run `/secret-gate install`, then:

1. Confirm `.githooks/pre-commit` still contains the gitleaks invocation.
2. Create a file holding `sk_TEST_live_0123456789abcdefghijklmn`, `git add` it, and
   confirm `git commit` is refused and names the file and line.
3. Run `node scripts/secret-gate/cli.mjs fix --staged`, confirm the file now
   holds `[REDACTED stripe-key #1]`, and confirm the commit succeeds.
4. Run `npm run verify` and confirm nothing regressed.
5. `git checkout main && git branch -D scratch/secret-gate-verify`.

Report each of the five as pass or fail with the actual output. Do not claim the
cutover works until all five have run.

- [ ] **Step 7: Delete the old local plugin**

```bash
rm -rf /c/Users/dpearson/.claude/plugins/local/secret-redactor
```

Leave `~/.claude/plugins/local/.claude-plugin/marketplace.json` in place only if
another plugin still uses it. It does not today, so remove the `local` entry
from `extraKnownMarketplaces` in `~/.claude/settings.json` as well.

- [ ] **Step 8: Commit the rollout note**

```bash
git add docs
git commit -m "docs: record the cutover from the local marketplace"
```

---

## Remaining rollout, after the plan

Not tasks, because each is one command with nothing to test.

- `/secret-gate install` in the other 19 repos, then commit the generated files
  in each. Order by risk: Printyx, Loci, Des-Moines-Insider, Seddly first.
- Loci has an orphaned `.gitleaks.toml` with no hook. Read it before installing;
  its contents have never been reviewed.
- On laptop 2: `claude plugin marketplace add dj-pearson/pearson-claude-plugins`,
  `claude plugin install secret-redactor`, then
  `git config core.hooksPath .githooks` in each clone.

## Self-review notes

Checked against the spec on 2026-09-10.

- Every spec section maps to a task. The four surfaces are Tasks 5, 6, 7 and 9.
  The .env rule is Task 7. The allowlist is Task 8. Install and append-safety
  are Task 11. Distribution and migration are Task 12.
- The two spec deviations are listed at the top of this plan with reasons rather
  than being buried.
- Names used across tasks were checked for drift: `findSecrets`, `redactText`,
  `redactDeep`, `newState`, `tokenFor`, `summarize`, `loadAllowlist`,
  `isAllowed`, `staleEntries`, `fingerprintOf`, `envExemption`, `repoRoot`,
  `isBinary`, `VERSION`, `main`.
- One thing this plan does not verify and should be checked during Task 12,
  Step 6: whether Claude Code honours `updatedPrompt` in the installed version
  on this machine. The field is documented, but documented is not observed. If
  it turns out to be ignored, the fallback is to keep the hook and have it
  block with `decision: "deny"` plus a message, which is worse but still safe.
