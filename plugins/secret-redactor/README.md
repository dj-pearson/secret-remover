# secret-redactor

Keeps plaintext credentials out of Claude Code transcripts, out of files, and
out of GitHub - for the credential shapes it recognizes; see Known
limitations for what that leaves out. Zero dependencies, Node 22+, ESM only.

## What it does

Four surfaces, four defenses:

1. **Pasted prompts.** `UserPromptSubmit` rewrites a credential out of your
   prompt before it enters the transcript or reaches the model
   (`hooks/redact-prompt.mjs`).
2. **Tool results.** `PostToolUse` strips credentials out of a tool's output
   before the model reads it (`hooks/redact-tool-output.mjs`) - this covers
   the case where the secret came from a file Claude read, not from you.
3. **File writes.** `PreToolUse` on `Write`/`Edit`/`NotebookEdit` refuses the
   write outright rather than redacting it (`hooks/guard-write.mjs`). This is
   the gate that stops a key reaching a repo file through Claude Code's
   file-editing tools, before git is ever involved - it does not see a write
   made through the Bash tool (`cat > x`, `tee`, a script); see Known
   limitations.
4. **Commits.** A generated `.githooks/pre-commit` hook scans everything
   staged and refuses the commit if a credential is in it. The same scan runs
   again in CI, so a commit made from a machine without this plugin installed
   is still caught before it merges.

Surfaces 1 and 2 redact (rewrite the value to a `[REDACTED <kind> #n]`
marker and let the interaction continue). Surfaces 3 and 4 block (refuse the
write or the commit outright) - by the time content is headed into a file
git will carry, blocking is the safer default, not redacting on the sly.

## Install

Three names are involved, and each belongs to a different command:

| Name | What it is | Command that uses it |
|---|---|---|
| `claude-secret-remover` | the GitHub repo | `claude plugin marketplace add dj-pearson/claude-secret-remover` |
| `secret-remover` | the marketplace (`.claude-plugin/marketplace.json`) | `claude plugin marketplace update secret-remover` |
| `secret-redactor` | this plugin | `claude plugin install secret-redactor` |

```bash
claude plugin marketplace add dj-pearson/claude-secret-remover
claude plugin install secret-redactor
```

Then, in a repo you want the commit gate wired into:

```bash
/secret-gate install
```

or, without Claude Code, from a clone that already has the vendored copy:

```bash
node scripts/secret-gate/cli.mjs install
```

## The `#allow-secret` escape hatch

Surface 1 (pasted prompts) recognizes one literal token: a prompt containing
`#allow-secret` passes through completely untouched, with nothing redacted.
It exists so a deliberate paste - you copying a real key to hand it to
Claude on purpose - stays possible without disabling the hook for anyone
else's prompts.

**Caveat:** the check is "does this prompt contain the literal string
`#allow-secret` anywhere," not "is this specific value meant to be sent."
Pasting documentation *about* this hook - a design doc, a code review, this
very README - into a prompt silently disables redaction for that whole
message, because that kind of text legitimately contains the literal token.
This README is itself an example: it has to say `#allow-secret` in order to
document it, which means pasting this file into a prompt turns redaction off
for that message. There is no way to describe the escape hatch without
containing the string that triggers it.

## The `.env` rule

The exemption is **"git ignores this file," not "this file is named
`.env*`."** A name-only rule would let a real key reach GitHub in exactly the
place nobody would think to look for it: a `.env.production` that is
*tracked* (checked in) rather than gitignored is not exempt, and a leaked key
sitting in a tracked `.env.production` is the hardest place for anyone to
notice it, because the filename looks like the safe kind of file.
`git check-ignore` decides; the filename is only a fallback used when git
itself can't answer (no repo, a timeout) and the path is `.env`-shaped.

## What `install` writes

Running `install` (or `/secret-gate install`) in a repo writes:

- `scripts/secret-gate/{detect,allowlist,gitignore,paths,cli}.mjs` plus a `VERSION`
  stamp - the actual import closure of the CLI, vendored so the gate belongs
  to the repo (works in CI, in a fresh clone, for someone without this
  plugin) rather than to a machine that happens to have it installed.
- `.secretgate.json` - the allowlist, written once and never overwritten
  again without `--force`.
- `.githooks/pre-commit` - spliced in between `# >>> secret-gate` /
  `# <<< secret-gate` markers. An existing hook (gitleaks's, say) is never
  overwritten wholesale: the block lands right after the shebang line (so a
  host hook that exits early can't skip it) and a second `install` replaces
  only the marked span, leaving the rest of the file alone. The hook is also
  staged executable (`git update-index --chmod=+x`) in the index, because a
  Windows working tree has no exec bit at all and POSIX git on a clone from
  one otherwise silently never runs it.
- `.github/workflows/secret-gate.yml` - the CI job. Written when missing,
  rewritten when it carries an older secret-gate version stamp, left alone
  otherwise (including a hand-written workflow with no stamp at all).
  `--force` rewrites it unconditionally, regardless of stamp.
- `.gitattributes` - pins `.githooks/**` to LF, because a CRLF shebang
  breaks Git-for-Windows `sh`.
- `core.hooksPath` - set to `.githooks` in the repo's git config, but only
  when it's currently unset or already `.githooks`. If it points somewhere
  else, install leaves it alone rather than overwrite a setup you already
  have a reason for.

**`install` refuses rather than guesses, in two different ways, and exits
non-zero either time.** If `.githooks/pre-commit` has a marker that's
missing its pair, or a duplicate start marker inside what looks like a real
span, install leaves the file untouched. A wrong guess there could delete
everything between two markers permanently the next time someone re-runs
install; a loud refusal is the only safe response to a state the tool can't
interpret. Separately, if `core.hooksPath` already points somewhere other
than `.githooks`, the gate is never actually wired into git no matter how
many of the other files above got written - install still leaves that
alone rather than override it, and exits non-zero for the same reason: a
scripted install across many repos must not read either kind of refusal as
success. Both cases print exactly what happened and what to run by hand.

## `.secretgate.json`

```json
{
  "version": 1,
  "paths": ["^third_party/"],
  "regexes": ["^dummy-[a-f0-9]{8}$"],
  "fingerprints": ["test/fixtures/sample.env:stripe-key:12"]
}
```

`version` must be exactly `1` (a missing `version` field is also treated as
`1`). Any other value is a hard error - `scan`/`fix` refuse to run rather
than silently reinterpret a future schema under today's rules.

- `paths` - allowlist an entire file by its repo-relative path.
- `regexes` - allowlist any matched value that fits the pattern (a synthetic
  test fixture's key shape, say).
- `fingerprints` - allowlist one specific finding: `<path>:<label>:<line>`,
  exactly as printed in a scan's own remediation text.

**`paths` entries are unanchored regexes, matched against a POSIX
repo-relative path** (forward slashes, even on Windows) - not glob patterns,
and not required to match the whole path. `"paths": ["fixtures"]` allows any
path containing that substring anywhere, including `src/fixtures-prod.env`.
Anchor your own entries (`"^test/fixtures/"`) unless you mean the broad
match.

The only question that decides whether `.secretgate.json` is honored is
whether git ignores it - not whether it's tracked or staged yet. An
**untracked-but-not-gitignored** file is honored as soon as it exists, which
means it may not show up in any diff until someone actually runs
`git add .secretgate.json` - a change to it can be silently missing from a
PR someone thinks they reviewed. A **gitignored** `.secretgate.json` is not
honored at all and is treated the same as if it didn't exist - self-service
to something that already has write access should still leave a reviewable
trail.

An allowlist entry that stops matching anything shows up on every scan as
stale. Remove it. An allowlist can only be trusted if it shrinks.

## Exit codes

Exit codes mean different things for different commands - don't read `1`
from `install` as "a credential was found." Nothing in `install` scans for
credentials at all.

**`scan` and `fix --staged`:**

- `0` - clean (or, for `fix`, every finding in scope was fixed or was
  already allowlisted).
- `1` - a credential was found (or, with `--strict`, something was skipped);
  for `fix`, a real unresolved finding remains (invalid UTF-8, a symlink,
  staged/worktree divergence, a write failure).
- `2` - the scanner itself broke (bad usage, unreadable `.secretgate.json`,
  not a git repo).

`--strict` is a `scan`-only flag, and CI-only by convention. The generated
pre-commit hook does **not** pass it; the generated `secret-gate.yml`
workflow does. That's a deliberate asymmetry: locally, a scanner that broke
on one unreadable file (an oversized image, say) still **warns and lets the
commit through**, because a gate that can brick a developer's commit over a
file it couldn't check is a gate people learn to route around, and a gate
people disable protects nothing. In CI, the same broken-scanner exit code
**fails the build**, because no human is waiting on it there and a red
build is the right response to "the scanner couldn't check something."

**`install`:**

- `0` - the gate is wired into git (or already was).
- `1` - install refused to finish wiring the gate up: either
  `.githooks/pre-commit` had a marker it wouldn't guess how to fix, or
  `core.hooksPath` already points somewhere other than `.githooks`. Every
  other file `install` writes (the vendored library, the allowlist, the CI
  workflow, `.gitattributes`) may still have been written even when it
  exits `1` - read stdout for exactly which step refused. A script driving
  `install` across many repos must treat this as "not installed here,"
  never as success.
- `2` - not a git repository, or some other internal error before any file
  was written.

## Shipping a new version

Four places have to move together, not three - `test/version.test.mjs`
asserts all four are equal and fails the build if they drift:

- `plugins/secret-redactor/package.json` (`version`)
- `plugins/secret-redactor/.claude-plugin/plugin.json` (`version`)
- the `secret-redactor` entry in the root `.claude-plugin/marketplace.json`
  (`version`)
- `VERSION` in `plugins/secret-redactor/lib/cli.mjs`

That fourth one matters beyond keeping a number consistent: `install` stamps
it into every repo it vendors into, so a mismatch there means a vendored
copy reports the wrong version and its own staleness check (whether an
installed CI workflow is older than the plugin) goes quiet without anyone
noticing.

## Known limitations

- **Detection is a fixed pattern list, not entropy-based.** Seventeen
  fixed formats (AWS, GitHub, Stripe, Anthropic, OpenAI, Google, Slack,
  npm, PyPI, SendGrid, Twilio, Discord, a private-key block, a JWT, a URL
  password, a bearer token) plus one heuristic for a `KEY: value` /
  `key=value` assignment where the key name looks credential-shaped. A
  credential with no recognizable prefix and no labeled assignment near it
  - a bare high-entropy string - passes every surface here silently. This
  tool is not a substitute for not committing secrets in the first place.
- **File writes made through the Bash tool are not covered.** The write
  guard's matcher is `Write`/`Edit`/`NotebookEdit` only; a file created or
  overwritten via the Bash tool (`cat > x`, `tee`, a script Claude runs)
  never reaches it. The commit gate (surface 4) is the real backstop for
  that path - it catches the credential at `git add`/commit time instead of
  at write time.
- **A redacted tool result can make a later `Edit` fail to match.** If
  surface 2 rewrites a credential in a file Claude just read, the model
  only ever sees the `[REDACTED <kind> #n]` marker, not the original value.
  An `Edit` call built from that read, with the real value as `old_string`,
  will not match what's actually in the file. This is the intended
  trade-off, not a bug - the alternative is leaving the real value visible
  to the model.
- **`fix --staged` refuses rather than repairs when the index and worktree
  diverge.** If a staged file was hand-edited afterward, deleted, or
  partially staged with `git add -p`, `fix` will not guess which version is
  right - it lists the file as skipped and leaves it for you to resolve by
  hand.
- **`fix` refuses a file that is not valid UTF-8.** Rewriting it would risk
  corrupting bytes outside the finding itself (a lossy decode/re-encode
  round trip), so a non-UTF-8 file is left untouched and reported as
  skipped.
- **A skipped file does not fail the build without `--strict`.** `scan`
  alone (no flag) treats "couldn't be checked" as informational, not a
  finding - see the exit-code asymmetry above.
- **An import-level crash in a vendored copy looks like findings, not like a
  broken scanner.** The `exit 2 = broken, warn and allow` contract only
  covers failures `main()`'s own try/catch produces. A missing or
  syntactically invalid vendored file fails before `main()` ever runs - a
  plain Node module-resolution or syntax error - and Node exits `1` for
  that, identical to "a credential was found." This is exactly why the
  vendored file set is derived from the real import graph by a test rather
  than trusted to stay correct by hand: a wrong file list doesn't degrade to
  a warning here, it wedges every future commit.
- **A system-level `core.hooksPath` has no test coverage.** `install`'s git
  calls strip every `GIT_*`-prefixed environment variable before running, so
  a poisoned `GIT_CONFIG_SYSTEM` pointing install at the wrong hooks path
  can't reach it that way - but a `core.hooksPath` set in the actual system
  gitconfig (`/etc/gitconfig` or Windows's machine-wide config) is real git
  configuration, not an environment variable, and nothing in this plugin's
  test harness can simulate or block that. No machine this was built on has
  one set, so this is untested territory rather than a confirmed gap.
- **Surface 1 (pasted prompts) is documented behavior, not yet observed
  behavior.** Whether the installed build of Claude Code actually honors
  `updatedPrompt` in a `UserPromptSubmit` hook response has not been
  confirmed on this machine - it's what the field is documented to do, not
  something watched happen. Surface 2 (`PostToolUse` / `updatedToolOutput`)
  is observably live. If `updatedPrompt` turns out to be ignored, the
  fallback is to have the hook deny the prompt outright instead of
  rewriting it - worse for the person typing, but still safe.
- **This plugin has only been exercised on Windows so far.** The test suite
  has a documented skip (this sandbox can't create real symlinks) and a
  hung-git regression test that is Windows-specific by construction (it
  relies on Windows resolving an extension-less `git` command to a
  same-named `git.exe`). CI now runs the suite on Ubuntu and macOS as well;
  expect the first run there to surface platform gaps this file doesn't yet
  know about.
