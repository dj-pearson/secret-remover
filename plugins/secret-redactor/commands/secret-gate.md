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
