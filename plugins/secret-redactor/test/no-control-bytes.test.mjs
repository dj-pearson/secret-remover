// FINDING A (Task 9 review): lib/cli.mjs and test/cli-scan.test.mjs shipped
// with literal raw NUL/SOH bytes where the source meant a JS string escape
// naming those code points - git classified both files as binary, so this
// plugin's own scanner could not scan itself, and lib/cli.mjs is one of the
// three files Task 11's `install` vendors into every consuming repo. An
// ASCII scan (`rg '[^\x00-\x7F]'`) cannot catch this: NUL is below 0x7F, not
// above it. This guard closes the class rather than the two named files, so
// it cannot come back anywhere under lib/, hooks/, bin/ or test/.
//
// Deliberately not spelling that escape sequence out in this comment: doing
// exactly that is how Finding A happened in the first place (see the task
// report for how the sequence gets silently converted into the raw byte on
// the way to disk), and it happened a second time, in this very file's
// first draft, while writing this paragraph.
import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync, readdirSync, statSync } from "node:fs";
import { fileURLToPath } from "node:url";
import path from "node:path";

const PLUGIN = path.dirname(path.dirname(fileURLToPath(import.meta.url)));
const GUARDED_DIRS = ["lib", "hooks", "bin", "test"];

function walk(dir) {
  const out = [];
  for (const entry of readdirSync(dir)) {
    const full = path.join(dir, entry);
    if (statSync(full).isDirectory()) out.push(...walk(full));
    else out.push(full);
  }
  return out;
}

test("no file under lib/, hooks/, bin/ or test/ contains a raw byte below 0x09", () => {
  const offenders = [];
  for (const dirName of GUARDED_DIRS) {
    for (const file of walk(path.join(PLUGIN, dirName))) {
      const buffer = readFileSync(file);
      for (let i = 0; i < buffer.length; i++) {
        if (buffer[i] < 0x09) {
          const rel = path.relative(PLUGIN, file).replaceAll("\\", "/");
          offenders.push(`${rel} (byte 0x${buffer[i].toString(16).padStart(2, "0")} at offset ${i})`);
          break;
        }
      }
    }
  }
  assert.deepEqual(offenders, [], `files with a control byte below 0x09:\n${offenders.join("\n")}`);
});
