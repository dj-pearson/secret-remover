# secret-gate: design

Date: 2026-09-10
Status: approved, ready for implementation planning
Owner: Pearson Media LLC

> Note (2026-09-10, Task 12): the repo this plan built toward shipped as
> `dj-pearson/claude-secret-remover`, not `pearson-claude-plugins` as named
> below. The rest of this document is the historical record of what was
> decided that day and is left as written.

## Problem

A credential pasted in plain text into a repo document reaches GitHub. Nothing
stops it today across most of the portfolio.

Current coverage, measured 2026-09-10:

- `secret-redactor@local` v1.0.2 is a `PostToolUse` hook. It rewrites secrets
  found in tool *results* before the model reads them. It is the only thing
  guarding the Claude Code side, and it guards exactly one of three surfaces.
- GradeThread has `.githooks/pre-commit` running gitleaks. It blocks a commit;
  it does not offer a fix.
- Of 20 local git repos, only GradeThread has that git-side gate. Loci carries a
  `.gitleaks.toml` with no hook wired to it.
- Nothing covers a key the user pastes into chat.
- Nothing covers a key the model is about to write into a file.
- The plugin source lives at `C:\Users\dpearson\.claude\plugins\local`, which is
  not a git repo, so none of it reaches a second machine.

## Goals

1. A plaintext credential cannot reach GitHub from any Pearson Media repo.
2. A plaintext credential does not enter a Claude Code transcript, whether it
   arrives from a tool result or from a pasted prompt.
3. The model cannot write a credential into a tracked file.
4. Installing all of the above into a repo is one command.
5. Both laptops get the same protection from the same source of truth.

## Non-goals

- Rewriting git history. Existing leaks in history are a separate decision, and
  GradeThread's `.gitleaks.toml` already documents that call for `extension.pem`.
- Scanning existing transcript history at `~/.claude/projects/*/*.jsonl`.
  Deferred; see Follow-ons.
- Blocking outbound requests that carry a key (`curl`, `WebFetch`). Considered
  and declined: too many legitimate authed API calls in this portfolio.
- Replacing gitleaks. Where gitleaks is present it keeps running alongside.

## Decisions

These were settled before this document was written. They are not open.

| Question | Decision |
|---|---|
| Commit-time behaviour on a finding | Block, and print a one-command fix. Never rewrite a file without being asked. |
| Claude-side surfaces to add | `UserPromptSubmit` (rewrite) and `PreToolUse` on Write/Edit (deny). |
| Outbound guard on Bash/WebFetch | Declined. |
| Distribution | One plugin. Chat side ships globally via the plugin; git side is vendored per repo by an install command. |
| Plugin home | New public repo `dj-pearson/pearson-claude-plugins`, serving a marketplace named `pearson-media`. |

### Why block rather than auto-redact

An automatic in-place rewrite edits the working tree without being asked. It can
break a test fixture, a config file, or code that consumed the value, and the
breakage surfaces later and somewhere else. Blocking is loud, immediate, and
reversible. The fix command exists so that choosing the rewrite stays cheap.

### Why public rather than private

The repo holds a secret scanner. It contains no credentials, and its detector
patterns are the same public shapes gitleaks publishes. Public removes the git
credential setup as a thing that can fail on a fresh machine.

## The .env rule

The stated requirement was: redact a plaintext key unless it sits in an `.env*`
file. This design tightens that by one notch.

**The exemption is for gitignored `.env*`, not for anything named `.env*`.**

Reason: `.env.production` and `.env.example` are tracked in GradeThread. A
name-only rule would let a real key pasted into `.env.production` reach GitHub,
which is the exact failure this project exists to prevent.

Applying the rule:

- **Git side.** No exemption logic is needed. `pre-commit` only ever sees staged
  files, and a gitignored file is never staged. `.env.production` is scanned
  because it is tracked. This falls out for free.
- **Write guard.** Runs `git check-ignore --quiet <path>`. Exit 0 means ignored,
  which means allow. Outside a git repo, or when `git` is unavailable, fall back
  to the name-based `.env*` match and record that the fallback was used in the
  deny reason.

## Architecture

One detector core. Four consumers. Exactly one place knows what a key looks
like.

```
lib/detect.mjs          the only definition of "this is a credential"
  |
  +-- hooks/redact-tool-output.mjs   PostToolUse       rewrite
  +-- hooks/redact-prompt.mjs        UserPromptSubmit  rewrite
  +-- hooks/guard-write.mjs          PreToolUse        deny
  +-- bin/cli.mjs                    scan / fix / install
```

### lib/detect.mjs

Exports, and nothing else:

- `findSecrets(text) -> [{ start, end, line, column, label, value }]`
  The primitive. Every other function is built on it.
- `redactText(text, state?) -> string`
- `redactDeep(value, state?) -> { value, total, hits }`
- `looksLikeSecret(value) -> boolean`
- `DETECTOR_LABELS` - the frozen list of labels, used by the corpus self-check.

The detector set carries over from `redact.mjs` v1.0.2 unchanged in coverage:
PEM private key blocks, AWS access key ids, GitHub tokens and fine-grained PATs,
Stripe live keys, Anthropic, OpenAI, Google, Slack tokens and webhooks, npm,
PyPI, SendGrid, Twilio, Discord, JWT, URL passwords, `Bearer` tokens, and
labeled values.

Marker format is unchanged: `[REDACTED <label> #<n>]`. The same value always
gets the same number within one scan.

### The labeled-value false positive

The labeled-value rule fires on ordinary prose. Observed 2026-09-10: it redacted
a line of the plugin's own `README.md` while that file was being read in a
session, replacing text in a bold markdown heading that happened to contain the
word "secret".

Fix, in `looksLikeSecret()` and in the `LABELED` regex:

1. Reject a candidate value containing markdown emphasis runs (`**`, `__`).
2. Require the separator to be `:` or `=`, optionally quoted. Drop bare
   whitespace as a separator, which is what let a two-word phrase match.
3. Reject a candidate whose value is a dictionary word with no digit, no
   underscore, and no mixed case.

Each of the three gets a regression test. See Testing.

### hooks/redact-prompt.mjs

`UserPromptSubmit`. Reads the hook JSON, runs `redactText` over `prompt`.

- No findings: exit 0, write nothing.
- Findings: emit `hookSpecificOutput.updatedPrompt` with the rewritten text,
  plus `additionalContext` naming the count and labels, plus a `systemMessage`
  so the user sees it happened.

Escape hatch: if the prompt contains the literal token `#allow-secret`, the hook
exits 0 without rewriting. Documented in the README. This exists so that a
deliberate paste stays possible without disabling the hook.

### hooks/guard-write.mjs

`PreToolUse`, matcher `Write|Edit|NotebookEdit`.

Reads the candidate content from, in order: `tool_input.content`,
`tool_input.new_string`, `tool_input.new_source`.

Deny when both hold:

1. `findSecrets()` returns at least one hit, and
2. the target path is not exempt under the .env rule above, and is not matched
   by the repo's `.secretgate.json` allowlist when one exists.

Deny output:

```json
{
  "hookSpecificOutput": {
    "hookEventName": "PreToolUse",
    "permissionDecision": "deny",
    "permissionDecisionReason": "secret-gate: writing a stripe-key into docs/setup.md. Put the value in a gitignored .env file and reference it by name."
  }
}
```

This is the hook that stops a key reaching a repo document at all, before git is
involved.

### bin/cli.mjs

| Command | Behaviour |
|---|---|
| `scan --staged` | Scans added lines in staged files. The pre-commit path. |
| `scan [paths...]` | Scans working tree files. Defaults to tracked files. The CI path. |
| `fix --staged` | Rewrites findings to markers, restages, prints a per-file diff summary. |
| `install [--force]` | Wires the current repo. See below. |
| `--version` | Prints the vendored version stamp. |

Exit codes:

- `0` clean
- `1` findings present
- `2` internal error

**The failure asymmetry is deliberate.** `pre-commit` treats exit 2 as a loud
warning and lets the commit through, because a crashing scanner must not brick
committing in twenty repos. CI treats exit 2 as a failure, because there the
right response to a broken scanner is a red build. Both are documented inline in
the generated files.

Binary files are skipped by a NUL-byte sniff on the first 8 KB. Files over 2 MB
are skipped and named in the output, so a skip is never silent.

## What install writes

`/secret-gate install` writes four things into the current repo.

```
scripts/secret-gate/detect.mjs     vendored copy of lib/detect.mjs
scripts/secret-gate/cli.mjs        vendored copy of bin/cli.mjs
scripts/secret-gate/VERSION        version stamp, used to detect staleness
.secretgate.json                   allowlist
.githooks/pre-commit               calls the vendored cli
.github/workflows/secret-gate.yml  the same scan on push and pull_request
```

Two files rather than one bundled file, because bundling needs a build step and
concatenating ES modules is fragile. Two files in one directory is still zero
dependencies.

**Why vendor at all.** The vendored copy runs in CI, in a fresh clone, and for
anyone who does not use Claude Code. Depending on the plugin being installed
would make the git-side gate a property of the machine rather than of the repo.

### Install is append-safe

`install` never overwrites a file it did not write. Specifically:

- `.githooks/pre-commit` exists: append the secret-gate block, guarded by a
  `# >>> secret-gate` / `# <<< secret-gate` marker pair. Re-running replaces
  only the text between the markers. GradeThread's gitleaks invocation is
  preserved and keeps running.
- `.secretgate.json` exists: leave it alone entirely.
- `.github/workflows/secret-gate.yml` exists: rewrite only if its version stamp
  is older than the plugin's.
- `scripts/secret-gate/*`: rewrite when `VERSION` differs. This is how an update
  propagates to a repo installed months ago.
- `core.hooksPath`: set to `.githooks` only if unset or already `.githooks`. If
  it points somewhere else, print the conflict and do not change it.

`--force` overrides the "leave it alone" cases and is never the default.

### .secretgate.json

JSON, not TOML. Node has no built-in TOML parser and this project takes no
dependencies. This is a change from the shape discussed during design, where
`.secretgate.toml` was named.

```json
{
  "version": 1,
  "paths": ["^deno\\.lock$", "^prd\\.json$"],
  "regexes": ["your-[a-z-]+"],
  "fingerprints": ["docs/setup.md:stripe-key:14"]
}
```

- `paths` - regexes against the repo-relative path, POSIX separators.
- `regexes` - regexes against the matched value.
- `fingerprints` - `path:label:line`, to pin one specific known finding rather
  than opening a whole path.

An allowlist entry that stops matching anything is reported as stale on every
scan. Borrowed from the GradeThread `ui:check` wrapper, where the same rule
means the list can only shrink.

## Distribution

### Repo layout

```
pearson-claude-plugins/
  .claude-plugin/marketplace.json      name: pearson-media
  plugins/secret-redactor/
    .claude-plugin/plugin.json
    hooks/{hooks.json,redact-tool-output.mjs,redact-prompt.mjs,guard-write.mjs}
    lib/detect.mjs
    bin/cli.mjs
    commands/secret-gate.md
    templates/{pre-commit,secretgate.json,workflow.yml}
    test/
    package.json
    README.md
  docs/2026-09-10-secret-gate-design.md
  README.md
```

### Two machines

The two halves travel by different routes, and that is fine.

**Git side travels with each project repo.** `scripts/secret-gate/` and
`.githooks/` are committed. On laptop 2 the only step is
`git config core.hooksPath .githooks` after cloning, and `install` prints that
line so it is not folklore.

**Chat side travels through the marketplace.** On a new machine:

```
claude plugin marketplace add dj-pearson/pearson-claude-plugins
claude plugin install secret-redactor
```

Shipping an update from either machine:

```
git push
claude plugin marketplace update pearson-media
claude plugin update secret-redactor
```

The version must be bumped in three places for the update to take: the plugin's
`plugin.json`, its `package.json`, and the matching entry in
`.claude-plugin/marketplace.json`. Without the bump, `plugin update` reports it
is already current and the old copy keeps running. A test asserts the three
agree.

### Migration off the local marketplace

`secret-redactor@local` v1.0.2 stays installed and working until the new plugin
is verified. Then: disable `secret-redactor@local` in
`~/.claude/settings.json`, remove the `local` entry from
`extraKnownMarketplaces` if nothing else uses it, and delete
`~/.claude/plugins/local/secret-redactor`. Running both at once would double
every marker number, so this is a required step, not a cleanup.

## Testing

Node's built-in test runner. No dependencies.

**Fixture corpus with a self-check.** `test/fixtures/corpus.txt` holds one
example of every detector label and one example of every known false positive.
Two assertions:

1. Every label in `DETECTOR_LABELS` fires at least once on the corpus. A rule
   that stops firing fails the suite. A rename cannot silently disarm a
   detector.
2. Every known false positive stays untouched, including the markdown heading
   case observed 2026-09-10.

Both directions matter. Only the first is the usual reflex, and only the second
would have caught the README bug.

Other suites:

- `detect.test.mjs` - detector behaviour, marker numbering, idempotence
  (redacting twice yields the same string).
- `hooks.test.mjs` - the stdin/stdout contract for all three hooks, including
  malformed input, oversized input, and the fail-open guarantee. Explicitly:
  no output at all when there are no findings, because an identity rewrite
  races last-write-wins against a sibling hook doing a real redaction.
- `cli.test.mjs` - exit codes, `--staged` against a temp git repo, `fix`
  restaging, binary and oversize skips being reported.
- `install.test.mjs` - the append-safe cases. Three fixtures: an empty repo, a
  repo with an existing unrelated `pre-commit`, and a copy of GradeThread's
  gitleaks `pre-commit`. The third asserts the gitleaks line still runs after
  install and after a second install.
- `version.test.mjs` - the three version strings agree.

## Rollout

1. Build and test in `pearson-claude-plugins`. Suite green.
2. Create the GitHub repo, push.
3. `claude plugin marketplace add dj-pearson/pearson-claude-plugins`,
   `claude plugin install secret-redactor`, restart.
4. Disable and remove `secret-redactor@local`.
5. `/secret-gate install` in GradeThread first. It is the hard case: existing
   `pre-commit`, existing `.gitleaks.toml`, existing `core.hooksPath`. Verify
   gitleaks still runs and `npm run verify` is unaffected.
6. Verify by committing a fixture key on a scratch branch and confirming the
   block, the fix command, and the CI job.
7. Roll out to the remaining 19 repos.
8. Laptop 2: two marketplace commands, then `core.hooksPath` per clone.

## Follow-ons

Not in this project. Listed so they are not rediscovered as new ideas.

- Scanning existing transcript history at `~/.claude/projects/*/*.jsonl`.
- An outbound guard on Bash and WebFetch.
- A scheduled full-history scan per repo, matching GradeThread's
  `secret-scan-history.yml`.
- Wiring Loci's orphaned `.gitleaks.toml` to an actual hook. `install` covers
  this incidentally, but the file's contents have not been reviewed.
