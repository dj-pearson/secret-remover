#!/usr/bin/env node
// Shim so the slash command and package.json have a stable path to the CLI.
// The real implementation is lib/cli.mjs, which is also what gets vendored.
import { main } from "../lib/cli.mjs";
main().then((code) => process.exit(code));
