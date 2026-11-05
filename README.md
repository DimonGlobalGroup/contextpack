# ContextPack

Pack a codebase into one AI-ready file. One Python file, no dependencies.

## Why it's different

1. **Secrets are redacted inline, not by dropping files.** A file with an API key stays in the pack, readable and
   with its structure intact. Only the value is replaced, with a stable placeholder such as
   `«REDACTED:github-token:1»`. Redaction is on by default.
2. **The token budget is a hard limit.** With `--budget N`, the pack's own estimated size, including headers and
   manifest, is at most N. Files that don't fit are reduced to a skeleton first, then omitted, and every token is
   accounted for. If the budget can't be met, the tool says so and exits instead of writing an oversized pack.
3. **Every pack is verifiable.** `--manifest` writes JSON with the SHA-256 of each original file, its mode and its
   token cost. Feed that manifest to `--delta` later to pack only what changed.

## Install

Download one file: `contextpack.py`. It needs Python 3.10 or newer and nothing else.

## Quick start

```sh
python3 contextpack.py . -o pack.md                     # pack the current directory
python3 contextpack.py . --budget 50000 -o pack.md      # hold the pack to 50,000 estimated tokens
python3 contextpack.py . --format xml -o pack.xml       # XML instead of Markdown
python3 contextpack.py . -o pack.md --manifest v1.json  # also write a manifest
python3 contextpack.py . -o delta.md --delta v1.json    # later: only new and changed files
```

## CLI reference

```
contextpack.py [PATH] [-o OUT] [--format md|xml] [--budget N] [--manifest M] [--delta M]
               [--include GLOB]... [--exclude GLOB]... [--max-file-bytes N] [--no-redact] [--version]
```

| Option | Meaning |
| --- | --- |
| `PATH` | Directory to pack. Default: the current directory. |
| `-o OUT` | Write the pack to a file. Default: stdout. |
| `--format md\|xml` | `md` (default) uses fenced blocks under file-path headers. `xml` uses `<file path="...">` elements. |
| `--budget N` | Hard limit on the pack's estimated tokens. N must be 1 or greater. |
| `--manifest M` | Write the JSON manifest to `M`. |
| `--delta M` | Pack only files that are new or changed since manifest `M`. |
| `--include GLOB` | Pack only matching files. Repeatable. |
| `--exclude GLOB` | Skip matching files and directories. Repeatable. |
| `--max-file-bytes N` | Skip files larger than N bytes. Default: 1000000. |
| `--no-redact` | Turn off redaction. Prints a warning to stderr. |
| `--version` | Print the version. |

`--include` and `--exclude` use `.gitignore` glob syntax. A trailing `/` matches directories, and a pattern
containing `/` is anchored to `PATH`.

The summary line goes to stderr, so stdout carries only the pack.

### Exit codes

| Code | Meaning |
| --- | --- |
| 0 | Success. |
| 2 | Usage error: bad arguments, a missing directory, an unreadable manifest, or an unwritable output path. |
| 3 | Budget impossible. Nothing is written, and stderr says what didn't fit. |

## What goes in the pack

The pack holds a directory tree, the files, and a manifest section. The manifest section lists totals, each file's
mode and token cost, skipped files with reasons, redactions, and deleted paths for delta packs. The tree lists the
files covered by this pack, including omitted ones.

**Walking.** `.gitignore` files are honored at every level below `PATH`, including comments, `!` negation, directory
patterns, `*`, `**`, `?`, character classes, and anchored and floating patterns. `.git/` is always skipped without
being reported. These directories are always skipped and listed in the manifest: `__pycache__`, `node_modules`,
`.venv`, `venv`, `.tox`, `.nox`, `.mypy_cache`, `.pytest_cache`, `.ruff_cache`, `.gradle`, `.hg`, `.svn`, `dist`,
`build`, `target`.

**Skipped files.** Binary files (a NUL byte, or not valid UTF-8), files over the size cap, unreadable files and
symlinks are listed in the manifest with the reason. Symlinks are never followed. The tool's own `-o`, `--manifest`
and `--delta` files are left out, so packing into the tree doesn't change the next pack.

**Order.** Inside a git repository, files with commit history come first, most recently committed first. All other
files follow, newest modification time first, then by path. Within each of those two tiers, the root README comes
first, then main entry files such as `main.py`, `index.js` and `__main__.py`. Output is byte-identical for an
identical tree, git history and set of modification times.

## Redaction

| Rule | Detects |
| --- | --- |
| `aws-access-key` | `AKIA` or `ASIA` followed by 16 characters |
| `github-token` | `ghp_`, `gho_`, `ghu_`, `ghs_` and `github_pat_` tokens |
| `slack-token` | `xoxb-`, `xoxa-`, `xoxp-`, `xoxr-` and `xoxs-` tokens |
| `private-key` | `-----BEGIN ... PRIVATE KEY-----` through the next `END` line |
| `jwt` | Three-part tokens starting with `eyJ` |
| `generic-assignment` | `api_key`, `apikey`, `secret`, `token`, `password`, `passwd` or `auth`, followed by `:` or `=` and a value of at least 12 characters with high character diversity |

The same value gets the same placeholder throughout a pack, and different values get different placeholders. The
number in a placeholder counts distinct secrets across the pack. Redaction happens before skeletons are built, so
skeletons are covered too.

Each redaction is listed with its file, original line number, rule and placeholder. The value is never written, nor
is any prefix of it.

## Budget

With `--budget N`, files are taken in priority order. Each goes in full if it fits, otherwise as a skeleton if that
fits, otherwise it is omitted and later, smaller files still get their chance.

| File type | Skeleton |
| --- | --- |
| Python | Imports, class and function signatures, first line of each docstring |
| Markdown | Headings and the first line of each section |
| Other text | First 40 lines |

Every skeleton ends with a `[... skeleton: full file is X tokens]` marker. A skeleton is used only if it is smaller
than the file.

The manifest reports tokens packed, tokens saved by skeletons, and tokens omitted, and lists every omitted file with
its full cost. Skipped and omitted files are still listed, so the listing itself uses part of the budget.

The tool exits with code 3 if the highest-priority file can't fit even as a skeleton, or if the headers and manifest
alone exceed the budget.

## Manifest

```json
{
  "tool": "contextpack",
  "version": "1.0.0",
  "timestamp": "2026-01-31T12:00:00Z",
  "git_head": "40-character SHA, or null",
  "budget": 50000,
  "files": [
    {"path": "src/app.py", "sha256": "...", "bytes": 1234, "est_tokens": 310,
     "packed_tokens": 310, "mode": "full", "redactions": 1}
  ],
  "skipped": [{"path": "logo.bin", "reason": "binary (NUL byte)", "bytes": 2048}],
  "deleted": [],
  "totals": {"files_full": 1, "files_skeleton": 0, "files_omitted": 0, "files_skipped": 1,
             "tokens_packed": 310, "tokens_saved_by_skeleton": 0, "tokens_omitted": 0,
             "pack_tokens": 450},
  "redaction_entries": [
    {"file": "src/app.py", "line": 3, "rule": "generic-assignment",
     "placeholder": "«REDACTED:generic-assignment:1»"}
  ]
}
```

- `mode` is `full`, `skeleton` or `omitted`.
- `sha256` and `bytes` describe the original file on disk, before redaction.
- `est_tokens` is the cost of the whole file after redaction. `packed_tokens` is what the pack actually carries.
- `pack_tokens` is the size of the pack file itself.

### Delta packs

`--delta OLD.json` packs files whose SHA-256 differs from `OLD.json` and files it doesn't list. Paths in `OLD.json`
that no longer exist appear in `deleted`. Redaction and budget rules still apply. Delta manifests also carry an
`unchanged` list, so a delta manifest works as the base for the next delta.

An unchanged file is not sent again, even if the base pack only carried it as a skeleton or omitted it. The tool
prints a note on stderr when that happens.

## Limitations

- **Token counts are an estimate, not a tokenizer.** Every count is characters divided by 4, rounded up. Real counts
  vary by model and content, so a budget is exact against this estimate only. Leave a margin if you're close to a
  model's hard limit.
- **Redaction is pattern matching, so treat it as a safety net.** It can miss secrets in forms it doesn't recognize.
  Examples are `<password>...</password>` in XML, passwords embedded in connection URLs, values passed as call
  arguments such as `getenv("X", "default")`, keywords not listed above, and high-entropy strings with no keyword.
  Review a pack before sharing it outside your organization.
- **File and directory names are not redacted.** A secret in a path appears in the tree, the manifest and the JSON.
- **Redaction errs toward over-matching.** Any quoted value of 12 or more characters after a matching keyword is
  usually replaced, so `token_type = 'address-list'` is redacted too. This costs some readability, not safety.
- **Private key blocks run from `BEGIN` to the next `END`.** If a file mentions the two lines far apart, everything
  between them is redacted. With no `END` line, redaction covers the `BEGIN` line and the key-shaped lines after it.
- **Skeletons of very long lines are not much smaller.** A minified single-line file has no useful skeleton, so it
  goes in full or is omitted.
- **`.gitignore` support is a subset.** Files above `PATH`, `.git/info/exclude` and the global git excludes file are
  not read. Files that are tracked but match an ignore pattern are treated as ignored.
- **Text means UTF-8.** Files in other encodings, including UTF-16, are reported as binary.
- **Ordering uses modification times outside git history.** Two checkouts with different times can order those
  files differently. Git history order is unaffected.

## License

MIT License.

A Dimon Global Group release.
