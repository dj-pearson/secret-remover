# secret-remover

Keeps plaintext credentials out of Claude Code transcripts, out of your
files, and out of GitHub.

One name covers the repo, the marketplace and the plugin. There is a second
name you type afterwards:

| Name | What it is | Where you use it |
|---|---|---|
| `secret-remover` | the repo, the marketplace and the plugin - all three | `claude plugin marketplace add dj-pearson/secret-remover` then `claude plugin install secret-remover` |
| `secret-gate` | the commit gate the plugin installs into a repo | `/secret-gate install`, `scripts/secret-gate/`, `.secretgate.json` |

`secret-gate` is the tool the plugin wires into a repo - a separate name
because it keeps working in a clone that has never had this plugin, or Claude
Code, installed at all.

## Install on a new machine

```bash
claude plugin marketplace add dj-pearson/secret-remover
claude plugin install secret-remover
```

Restart the session afterwards.

## Plugins

- [secret-remover](plugins/secret-remover/) - keeps plaintext credentials out
  of transcripts, out of files, and out of GitHub.
