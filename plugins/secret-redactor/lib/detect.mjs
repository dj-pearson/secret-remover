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
const MARKDOWN_EMPHASIS = /\*\*|__/;
const CAPITALIZED_WORD = /^[A-Z][a-z]+$/;

export function looksLikeSecret(value) {
  if (typeof value !== "string" || value.length < 8 || value.length > 512) return false;
  if (OPENERS.has(value[0])) return false;
  if (URL_SCHEME.test(value) || value.includes("://")) return false;
  if (value.includes("\\") || value.includes("/./")) return false;
  if (DOTTED_CODE.test(value)) return false;
  if (LITERAL.test(value)) return false;
  if (PLACEHOLDER.test(value)) return false;
  if (MARKDOWN_EMPHASIS.test(value)) return false;
  if (CAPITALIZED_WORD.test(value)) return false;
  if (UUID.test(value) || GIT_SHA.test(value) || INTEGRITY.test(value)) return false;
  if (/^(.)\1*$/.test(value)) return false;
  return /[0-9]/.test(value) || (/[a-z]/.test(value) && /[A-Z]/.test(value));
}

// --- detectors -------------------------------------------------------------

// `whole: true` means the entire match is the secret. [REDACTED labeled-secret #5] group 1 is.
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

// Stock example connection strings (postgres://user:pass@..., mysql://root:root@...)
// use a short placeholder word as the password, so a plain length/digit floor
// can't tell them apart from a real short database password. looksLikeSecret's
// 8-char floor is no help either - it would reject legitimate short passwords
// too, which is exactly why this detector has its own guard instead of
// delegating like BEARER and LABELED do. Reject the placeholder words by name
// instead.
const URL_PASSWORD_PLACEHOLDERS = new Set([
  "pass",
  "password",
  "passwd",
  "test",
  "demo",
  "admin",
  "root",
  "user",
  "username",
  "secret",
  "changeme",
  "example",
  "dbpass",
]);
const BEARER = /\b([Bb]earer\s+)([A-Za-z0-9_\-.=+/]{20,})/g;

const SECRET_WORD =
  "secret|token|passwd|password|pwd|api[_-]?key|apikey|access[_-]?key|private[_-]?key|credential|auth|session[_-]?id";

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
    if (URL_PASSWORD_PLACEHOLDERS.has(value.toLowerCase())) continue;
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
