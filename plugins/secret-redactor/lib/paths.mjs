// lib/paths.mjs
//
// Every path comparison in this plugin has one side that came from git and
// one side that came from Node, and the two do not spell the same file the
// same way:
//
//   - macOS: os.tmpdir() and any path under /var, /tmp or /etc traverses a
//     symlink, so Node says /var/folders/.../repo while `git rev-parse
//     --show-toplevel` says /private/var/folders/.../repo.
//   - Windows: TEMP is handed out in 8.3 short form, so Node says
//     C:\Users\RUNNER~1\AppData\Local\Temp\... while git says
//     C:/Users/runneradmin/AppData/Local/Temp/..., and drive-letter and
//     directory casing can differ on top of that.
//   - Anywhere: a repo reached through a symlinked home, a junction, or an
//     automounted network path has the same shape.
//
// Left uncanonicalized, path.relative(gitRoot, nodePath) between those two
// spellings returns a "../../../.." escape rather than a root-relative path,
// and every consumer downstream reads that as "not this repo": an explicit
// scan path reports "outside the repository" (exit 2), and the write guard's
// allowlist lookup misses so an allowlisted fixture path is denied. The
// worst case was the entry-point check in cli.mjs, where the mismatch made
// the vendored CLI exit 0 having scanned nothing - a gate that is silently
// not a gate.
//
// So: canonicalize BOTH sides before ever comparing them.
import { realpathSync, statSync } from "node:fs";
import path from "node:path";

// realpathSync.native is what resolves an 8.3 short name and normalizes
// directory casing on Windows; the JS implementation resolves symlinks but
// leaves both of those alone. Prefer native, fall back to the JS one if the
// platform's call fails for its own reasons, and report null rather than
// throwing when the path simply does not exist yet - callers climb.
function realpathOf(p) {
  try {
    return realpathSync.native(p);
  } catch {
    try {
      return realpathSync(p);
    } catch {
      return null;
    }
  }
}

// Fully canonical form of `p`, symlinks in the final component included.
//
// Write routinely names a file in a directory that does not exist yet, and a
// scan can name a path that was deleted between listing and reading, so a
// bare realpathSync would throw on exactly the inputs that matter. Climb to
// the nearest ancestor that does resolve, canonicalize that, then re-attach
// the components that were climbed past - the same "nearest existing
// ancestor" idea gitignore.mjs already uses to pick a cwd for git.
export function canonicalize(p) {
  if (typeof p !== "string" || p.length === 0) return p;
  const resolved = path.resolve(p);
  let current = resolved;
  const tail = [];
  for (;;) {
    const real = realpathOf(current);
    if (real !== null) return tail.length > 0 ? path.join(real, ...tail) : real;
    const parent = path.dirname(current);
    if (parent === current) return resolved; // hit the root and nothing resolved; best effort
    tail.unshift(path.basename(current));
    current = parent;
  }
}

// Canonicalizes only the DIRECTORY a file sits in, keeping its own name as
// given. Use this for anything the repo tracks: git tracks a symlink as a
// symlink, and resolving the last component would silently retarget a scan
// or an allowlist lookup at the link's destination - which may be a
// different file, or outside the repo entirely. The directory prefix is
// where the /private/var and 8.3 mismatches actually live, and canonicalizing
// it alone is enough to make path.relative() agree with git.
export function canonicalizeParent(filePath) {
  if (typeof filePath !== "string" || filePath.length === 0) return filePath;
  const abs = path.resolve(filePath);
  const dir = path.dirname(abs);
  if (dir === abs) return canonicalize(abs); // a filesystem root has no parent
  return path.join(canonicalize(dir), path.basename(abs));
}

// Windows path comparison is case-insensitive; POSIX is not. Canonicalizing
// both sides already normalizes casing when the path exists, but the entry
// point below can be handed a spelling realpath declined to resolve, so the
// comparison itself has to be platform-correct too.
export function samePath(a, b) {
  if (typeof a !== "string" || typeof b !== "string") return false;
  if (a === b) return true;
  if (process.platform === "win32") return a.toLowerCase() === b.toLowerCase();
  return false;
}

// Answers "do these two names denote the same file?" without assuming either
// name is spelled canonically - because on Windows neither one is, and they
// are not un-canonical in the SAME way:
//
//   fs.realpathSync.native   expands an 8.3 short name and fixes casing
//   Node's own ESM resolver  resolves symlinks and junctions, but does NOT
//                            expand a short name
//
// So under a short TEMP path, `import.meta.url` keeps C:/Users/RUNNER~1/...
// while realpath gives C:/Users/runneradmin/... - canonicalizing only ONE
// side swaps which of the two is wrong and the comparison stays false. That
// is not hypothetical: it is what the first attempt at this fix did, and it
// turned a passing Windows leg red while fixing macOS.
//
// Asking the filesystem for identity sidesteps the whole spelling question:
// st_dev + st_ino is the same pair for every name of one file, on POSIX and
// on Windows (where Node fills them from the NTFS file index). Falling back
// to canonicalizing BOTH sides covers a filesystem that reports no usable
// inode, and only then does string comparison happen at all.
export function isSameFile(a, b) {
  if (typeof a !== "string" || typeof b !== "string" || a.length === 0 || b.length === 0) return false;
  try {
    const sa = statSync(a);
    const sb = statSync(b);
    if (sa.ino !== 0 && sb.ino !== 0 && sa.dev === sb.dev && sa.ino === sb.ino) return true;
  } catch {
    // One of them does not exist or cannot be stat'd - fall through to the
    // string comparison rather than deciding anything from the failure.
  }
  return samePath(canonicalize(a), canonicalize(b));
}
