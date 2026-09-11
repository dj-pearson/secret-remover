# claude-secret-remover

Claude Code plugins used across the Pearson Media portfolio.

This repository is `dj-pearson/claude-secret-remover`. Three different names
are involved in installing from it, and each belongs to a different command:

| Name | What it is | Command that uses it |
|---|---|---|
| `claude-secret-remover` | the GitHub repo | `claude plugin marketplace add dj-pearson/claude-secret-remover` |
| `pearson-media` | the marketplace (`.claude-plugin/marketplace.json`) | `claude plugin marketplace update pearson-media` |
| `secret-redactor` | the plugin | `claude plugin install secret-redactor` |

## Install on a new machine

```bash
claude plugin marketplace add dj-pearson/claude-secret-remover
claude plugin install secret-redactor
```

Restart the session afterwards.

## Plugins

- [secret-redactor](plugins/secret-redactor/) - keeps plaintext credentials out
  of transcripts, out of files, and out of GitHub.
