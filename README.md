# claude-secret-remover

Keeps plaintext credentials out of Claude Code transcripts, out of your
files, and out of GitHub.

Two identifiers are involved in installing from this repository, plus one you
type afterwards:

| Name | What it is | Where you use it |
|---|---|---|
| `claude-secret-remover` | the GitHub repo | `claude plugin marketplace add dj-pearson/claude-secret-remover` |
| `secret-remover` | both the marketplace and the plugin it lists | `claude plugin install secret-remover` |
| `secret-gate` | the commit gate the plugin installs into a repo | `/secret-gate install`, `scripts/secret-gate/`, `.secretgate.json` |

The marketplace and the plugin deliberately share a name: this marketplace
carries exactly one plugin. `secret-gate` is the tool the plugin wires into a
repo - a separate name because it keeps working in a clone that has never had
this plugin, or Claude Code, installed at all.

## Install on a new machine

```bash
claude plugin marketplace add dj-pearson/claude-secret-remover
claude plugin install secret-remover
```

Restart the session afterwards.

## Plugins

- [secret-remover](plugins/secret-remover/) - keeps plaintext credentials out
  of transcripts, out of files, and out of GitHub.
