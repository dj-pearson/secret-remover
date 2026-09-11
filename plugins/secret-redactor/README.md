# secret-redactor

Keeps plaintext credentials out of Claude Code transcripts, out of files, and
out of GitHub. Zero dependencies, Node 22+, ESM only.

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
   the gate that stops a key reaching a repo file at all, before git is ever
   involved.
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
| `pearson-media` | the marketplace (`.claude-plugin/marketplace.json`) | `claude plugin marketplace update pearson-media` |
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

- `scripts/secret-gate/{detect,allowlist,gitignore,cli}.mjs` plus a `VERSION`
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
- `.gitattributes` - pins `.githooks/**` to LF, because a CRLF shebang
  breaks Git-for-Windows `sh`.

**`install` refuses rather than guesses.** If `.githooks/pre-commit` has a
marker that's missing its pair, or a duplicate start marker inside what
looks like a real span, install leaves the file untouched, prints why on
stdout, and exits non-zero. A wrong guess there could delete everything
between two markers permanently the next time someone re-runs install; a
loud refusal is the only safe response to a state the tool can't interpret.

## `.secretgate.json`

```json
{
  "version": 1,
  "paths": ["^third_party/"],
  "regexes": ["^dummy-[a-f0-9]{8}$"],
  "fingerprints": ["test/fixtures/sample.env:stripe-key:12"]
}
```

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

- `0` - clean.
- `1` - a credential was found (or, with `--strict`, something was skipped).
- `2` - the scanner itself broke (bad usage, unreadable `.secretgate.json`,
  not a git repo).

`--strict` is CI-only by design. The generated pre-commit hook does **not**
pass it; the generated `secret-gate.yml` workflow does. That's a deliberate
asymmetry: locally, a scanner that broke on one unreadable file (an
oversized image, say) still **warns and lets the commit through**, because a
gate that can brick a developer's commit over a file it couldn't check is a
gate people learn to route around, and a gate people disable protects
nothing. In CI, the same broken-scanner exit code **fails the build**,
because no human is waiting on it there and a red build is the right
response to "the scanner couldn't check something."

## Known limitations

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
- **This plugin has only been exercised on Windows so far.** The test suite
  has a documented skip (this sandbox can't create real symlinks) and a
  hung-git regression test that is Windows-specific by construction (it
  relies on Windows resolving an extension-less `git` command to a
  same-named `git.exe`). CI now runs the suite on Ubuntu and macOS as well;
  expect the first run there to surface platform gaps this file doesn't yet
  know about.
