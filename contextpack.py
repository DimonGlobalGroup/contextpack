#!/usr/bin/env python3
"""ContextPack: pack a codebase into one AI-ready file.

Secrets are redacted inline, the token budget is a hard limit, and every pack
can carry a verifiable JSON manifest that also drives delta packs.

Single file, Python 3.10+, standard library only. See README.md.
"""

from __future__ import annotations

import argparse
import ast
import bisect
import datetime
import hashlib
import json
import os
import re
import stat
import subprocess
import sys
from dataclasses import dataclass
from typing import Callable, Optional
from xml.sax.saxutils import quoteattr

VERSION = "1.0.0"
TOOL_NAME = "contextpack"

DEFAULT_MAX_FILE_BYTES = 1_000_000
SKELETON_TEXT_LINES = 40
GIT_TIMEOUT_SECONDS = 60

EXIT_OK = 0
EXIT_USAGE = 2
EXIT_BUDGET = 3

# Directories that hold generated or binary content. `.git` is handled
# separately and never reported; these are listed in the manifest as skipped.
ALWAYS_SKIP_DIRS = frozenset({
    "__pycache__", "node_modules", ".venv", "venv", ".tox", ".nox",
    ".mypy_cache", ".pytest_cache", ".ruff_cache", ".gradle", ".hg", ".svn",
    "dist", "build", "target",
})

PYTHON_SUFFIXES = (".py", ".pyi")
MARKDOWN_SUFFIXES = (".md", ".markdown")


class UsageError(Exception):
    """Bad input from the caller; exits with EXIT_USAGE."""


class BudgetImpossible(Exception):
    """The budget cannot hold even the minimum pack; exits with EXIT_BUDGET."""


def estimate_tokens(text: str) -> int:
    """The one token heuristic used everywhere: chars/4, rounded up."""
    return (len(text) + 3) // 4


def display_path(path: str) -> str:
    """Make a path safe to print: valid UTF-8, no control characters."""
    safe = path.encode("utf-8", "backslashreplace").decode("utf-8")
    return re.sub(r"[\x00-\x1f\x7f]", lambda m: "\\x%02x" % ord(m.group()), safe)


# ---------------------------------------------------------------------------
# Glob and .gitignore matching
# ---------------------------------------------------------------------------

def _char_class(pattern: str, start: int) -> tuple[Optional[str], int]:
    """Translate the [...] class at `start`. Returns (regex, next index)."""
    i = start + 1
    if i < len(pattern) and pattern[i] in "!^":
        i += 1
    if i < len(pattern) and pattern[i] == "]":
        i += 1
    while i < len(pattern) and pattern[i] != "]":
        i += 2 if pattern[i] == "\\" else 1
    if i >= len(pattern):
        return None, start
    body = pattern[start + 1:i]
    negate = body[:1] in ("!", "^")
    if negate:
        body = body[1:]
    body = body.replace("[", "\\[")
    if body.startswith("]"):
        body = "\\" + body
    return "(?!/)[" + ("^" if negate else "") + body + "]", i + 1


def _glob_to_regex(pattern: str) -> str:
    """Translate one gitignore-style glob into a regex body."""
    out = []
    i, n = 0, len(pattern)
    while i < n:
        c = pattern[i]
        if c == "*":
            j = i
            while j < n and pattern[j] == "*":
                j += 1
            starts_segment = i == 0 or pattern[i - 1] == "/"
            ends_segment = j == n or pattern[j] == "/"
            if j - i >= 2 and starts_segment and ends_segment:
                if j == n:
                    out.append(".+")
                    i = j
                else:
                    out.append("(?:[^/]+/)*")
                    i = j + 1
            else:
                out.append("[^/]*")
                i = j
        elif c == "?":
            out.append("[^/]")
            i += 1
        elif c == "[":
            regex, next_i = _char_class(pattern, i)
            if regex is None:
                out.append(re.escape(c))
                i += 1
            else:
                out.append(regex)
                i = next_i
        elif c == "\\" and i + 1 < n:
            out.append(re.escape(pattern[i + 1]))
            i += 2
        else:
            out.append(re.escape(c))
            i += 1
    return "".join(out)


@dataclass(frozen=True)
class GlobRule:
    regex: "re.Pattern[str]"
    dir_only: bool
    negated: bool = False
    base: str = ""  # "sub/dir/" for rules from a nested .gitignore


def compile_glob(pattern: str, negated: bool = False, base: str = "") -> Optional[GlobRule]:
    """Compile a pattern; anchored if it has a non-trailing slash."""
    dir_only = pattern.endswith("/")
    pattern = pattern.rstrip("/")
    anchored = "/" in pattern
    pattern = pattern.lstrip("/")
    if not pattern:
        return None
    body = _glob_to_regex(pattern)
    if not anchored:
        body = "(?:.*/)?" + body
    try:
        regex = re.compile(body, re.DOTALL)
    except re.error:
        return None
    return GlobRule(regex, dir_only, negated, base)


def parse_gitignore(text: str, base: str = "") -> list[GlobRule]:
    rules = []
    for raw in text.splitlines():
        line = raw
        while line.endswith(" ") and not line.endswith("\\ "):
            line = line[:-1]
        if not line or line.startswith("#"):
            continue
        negated = line.startswith("!")
        if negated:
            line = line[1:]
        elif line.startswith("\\#") or line.startswith("\\!"):
            line = line[1:]
        rule = compile_glob(line, negated, base)
        if rule is not None:
            rules.append(rule)
    return rules


def is_ignored(rel: str, is_dir: bool, rules: list[GlobRule]) -> bool:
    """Last matching rule wins, deeper .gitignore files come later."""
    ignored = False
    for rule in rules:
        if rule.dir_only and not is_dir:
            continue
        if rule.regex.fullmatch(rel[len(rule.base):]):
            ignored = not rule.negated
    return ignored


def glob_hit(rules: list[GlobRule], rel: str, is_dir: bool = False) -> bool:
    """True if a CLI glob matches this path or any directory above it."""
    parts = rel.split("/")
    for k in range(1, len(parts) + 1):
        sub = "/".join(parts[:k])
        sub_is_dir = is_dir or k < len(parts)
        for rule in rules:
            if rule.dir_only and not sub_is_dir:
                continue
            if rule.regex.fullmatch(sub):
                return True
    return False


# ---------------------------------------------------------------------------
# Secret redaction
# ---------------------------------------------------------------------------

_PRIVATE_KEY_RULE = "private-key"
_KEY_BEGIN = re.compile(r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY(?: BLOCK)?-----")
_KEY_END = re.compile(r"-----END [A-Z0-9 ]*PRIVATE KEY(?: BLOCK)?-----")
# With no END line, take what still looks like key material: base64 runs and
# PEM headers, split by spaces, newlines or literal \n sequences.
_KEY_TAIL = re.compile(r"(?:(?:\\n|\r?\n|[ \t]+)(?:[A-Za-z0-9+/=]*|[A-Za-z-]+:[ ][^\r\n]*))*")

_SPECIFIC_RULES = (
    ("aws-access-key", re.compile(r"(?<![A-Z0-9])(?:AKIA|ASIA)[A-Z0-9]{16}(?![A-Z0-9])")),
    ("github-token", re.compile(
        r"(?<![A-Za-z0-9])(?:gh[opus]_[A-Za-z0-9]{16,}|github_pat_[A-Za-z0-9_]{16,})")),
    ("slack-token", re.compile(r"(?<![A-Za-z0-9])xox[baprs]-[A-Za-z0-9-]{10,}")),
    ("jwt", re.compile(
        r"(?<![A-Za-z0-9_-])eyJ[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]{4,}")),
)

_GENERIC_RULE = "generic-assignment"
_GENERIC_ASSIGNMENT = re.compile(
    r"""
    (?:api[_-]?key|secret|token|password|passwd|auth(?:orization|entication)?)
    (?:key|[_.-][\w.-]{0,64})?         # secretKey, AWS_SECRET_ACCESS_KEY, auth_token
    ["'`]?\]?                          # "password": / cfg["token"] =
    (?:[ \t]*:[ \t]*[\w.\[\], |]{1,40}?(?=[ \t]*=))?  # api_key: str = ...
    [ \t]*(?::=|=>|={1,3}|:)[ \t]*
    \(?[ \t]*                          # password = ("...")
    (?:(?:bearer|basic|token)[ \t]+)?  # Authorization: Bearer xxxx
    (?:[bruf]{1,2}(?=["'`]))?          # b"..." r'...'
    (?:
        (?P<t>"{3}|'{3})(?P<tv>(?s:.*?))(?:(?P=t)|\Z)
      | (?P<q>["'`])(?P<qv>(?:\\.|(?!(?P=q))[^\n])*)(?:(?P=q)|$)
      | (?P<uv>[^\s"'`]\S*?)(?=["'`,;:)\]}]{0,8}(?:\s|$))
    )
    """,
    re.IGNORECASE | re.VERBOSE | re.MULTILINE,
)

# Unquoted right-hand sides that are code or references, not credentials.
_NOT_A_SECRET = re.compile(
    r"""^(?:
        [A-Za-z_][\w.]*[(\[].*                # call or subscript
      | [A-Za-z_]\w*(?:\.[A-Za-z_]\w*)+       # dotted name
      | \$\{?\w+\}?                           # environment reference
      | <[^>]*>                               # <placeholder>
      | \{\{.*\}\}                            # template
      | [A-Z]?[a-z]{2,}(?:[A-Z][a-z]{2,})+    # CamelCaseName
    )$""",
    re.VERBOSE,
)
_PLAIN_URL = re.compile(r"^https?://[^@?\s]*$", re.IGNORECASE)


def looks_like_secret(value: str, quoted: bool) -> bool:
    """Length >= 12 with high character diversity, minus obvious non-secrets."""
    if len(value) < 12 or len(set(value)) < 6 or _PLAIN_URL.match(value):
        return False
    if quoted:
        return True
    if _NOT_A_SECRET.match(value):
        return False
    classes = (
        any(c.islower() for c in value),
        any(c.isupper() for c in value),
        any(c.isdigit() for c in value),
        any(not c.isalnum() and c not in "_-" for c in value),
    )
    return sum(classes) >= 2


def _private_key_spans(text: str) -> list[tuple[int, int]]:
    spans = []
    position = 0
    no_more_ends = False
    while True:
        begin = _KEY_BEGIN.search(text, position)
        if begin is None:
            return spans
        end = None if no_more_ends else _KEY_END.search(text, begin.end())
        no_more_ends = end is None
        position = end.end() if end else _KEY_TAIL.match(text, begin.end()).end()
        spans.append((begin.start(), position))


def find_secrets(text: str) -> list[tuple[int, int, str]]:
    """Return non-overlapping (start, end, rule) spans, sorted by start."""
    spans = [(start, end, -1, _PRIVATE_KEY_RULE) for start, end in _private_key_spans(text)]
    for priority, (rule, regex) in enumerate(_SPECIFIC_RULES):
        for match in regex.finditer(text):
            spans.append((match.start(), match.end(), priority, rule))
    for match in _GENERIC_ASSIGNMENT.finditer(text):
        group = next(name for name in ("tv", "qv", "uv") if match.group(name) is not None)
        if looks_like_secret(match.group(group), group != "uv"):
            start, end = match.span(group)
            spans.append((start, end, len(_SPECIFIC_RULES), _GENERIC_RULE))
    spans.sort()
    merged: list[tuple[int, int, str]] = []
    for start, end, _, rule in spans:
        if merged and start < merged[-1][1]:
            # Overlaps are unioned so no tail of a secret can survive.
            last = merged[-1]
            merged[-1] = (last[0], max(last[1], end), last[2])
        else:
            merged.append((start, end, rule))
    return merged


class Redactor:
    """Replaces secret values with placeholders that are stable per pack."""

    def __init__(self) -> None:
        self._placeholders: dict[str, tuple[str, str]] = {}
        self.entries: list[dict] = []

    def redact(self, path: str, text: str) -> tuple[str, int]:
        spans = find_secrets(text)
        if not spans:
            return text, 0
        newlines = [m.start() for m in re.finditer("\n", text)]
        out, cursor = [], 0
        for start, end, rule in spans:
            value = text[start:end]
            if value not in self._placeholders:
                number = len(self._placeholders) + 1
                self._placeholders[value] = (rule, f"\u00abREDACTED:{rule}:{number}\u00bb")
            rule_name, placeholder = self._placeholders[value]
            out.append(text[cursor:start])
            out.append(placeholder)
            cursor = end
            self.entries.append({
                "file": path,
                "line": bisect.bisect_left(newlines, start) + 1,
                "rule": rule_name,
                "placeholder": placeholder,
            })
        out.append(text[cursor:])
        return "".join(out), len(spans)


# ---------------------------------------------------------------------------
# Skeletons
# ---------------------------------------------------------------------------

_PY_FALLBACK = re.compile(r"^\s*(?:import\s|from\s.+\simport\s|class\s|def\s|async\s+def\s|@)")


def _signature_lines(node: ast.AST, lines: list[str]) -> list[str]:
    start = min([d.lineno for d in node.decorator_list] + [node.lineno])
    first = node.body[0]
    body_line = lines[first.lineno - 1]
    before_body = body_line.encode("utf-8")[:first.col_offset].decode("utf-8", "ignore")
    if before_body.strip():  # one-liner: `def f(): return 1`
        return lines[start - 1:first.lineno - 1] + [before_body.rstrip()]
    signature = lines[start - 1:first.lineno - 1]
    while signature and (not signature[-1].strip() or signature[-1].lstrip().startswith("#")):
        signature.pop()
    return signature


def skeleton_python(text: str) -> str:
    source = text.replace("\r\n", "\n").replace("\r", "\n")
    lines = source.split("\n")
    try:
        tree = ast.parse(source)
    except (SyntaxError, ValueError, RecursionError, MemoryError):
        return "\n".join(line for line in lines if _PY_FALLBACK.match(line))

    out: list[str] = []

    def docstring(node: ast.AST, indent: int) -> None:
        doc = ast.get_docstring(node)
        if doc and doc.strip():
            out.append(" " * indent + '"""' + doc.strip().split("\n")[0].strip() + '"""')

    def visit(body: list) -> None:
        for node in body:
            if isinstance(node, (ast.Import, ast.ImportFrom)):
                out.extend(lines[node.lineno - 1:node.end_lineno])
            elif isinstance(node, (ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)):
                out.extend(_signature_lines(node, lines))
                docstring(node, node.body[0].col_offset)
                if isinstance(node, ast.ClassDef):
                    visit(node.body)
            else:  # imports and defs inside if/try/with blocks
                for name in ("body", "orelse", "handlers", "finalbody"):
                    children = getattr(node, name, None)
                    if isinstance(children, list):
                        visit(children)

    docstring(tree, 0)
    visit(tree.body)
    return "\n".join(out)


def skeleton_markdown(text: str) -> str:
    out = []
    code_fence = None
    want_first_line = True
    for line in text.split("\n"):
        line = line.rstrip()
        stripped = line.strip()
        if code_fence:
            if stripped.startswith(code_fence):
                code_fence = None
            continue
        fence_match = re.match(r"```+|~~~+", stripped)
        if fence_match:
            code_fence = fence_match.group()
        elif re.match(r"#{1,6}(?:\s|$)", stripped):
            out.append(line)
            want_first_line = True
        elif want_first_line and stripped:
            out.append(line)
            want_first_line = False
    return "\n".join(out)


def make_skeleton(path: str, text: str, tokens: int) -> Optional[str]:
    """Return the skeleton text, or None if it would not save anything."""
    lowered = path.lower()
    if lowered.endswith(PYTHON_SUFFIXES):
        body = skeleton_python(text)
    elif lowered.endswith(MARKDOWN_SUFFIXES):
        body = skeleton_markdown(text)
    else:
        body = "\n".join(text.split("\n")[:SKELETON_TEXT_LINES])
    skeleton = f"{body}\n[... skeleton: full file is {tokens} tokens]\n"
    return skeleton if estimate_tokens(skeleton) < tokens else None


# ---------------------------------------------------------------------------
# Walking the tree
# ---------------------------------------------------------------------------

@dataclass
class Entry:
    path: str
    sha256: str
    size: int
    mtime_ns: int
    text: str
    tokens: int = 0
    redactions: int = 0
    mode: str = "full"
    _skeleton: Optional[str] = None
    _skeleton_ready: bool = False

    @property
    def skeleton(self) -> Optional[str]:
        if not self._skeleton_ready:
            self._skeleton = make_skeleton(self.path, self.text, self.tokens)
            self._skeleton_ready = True
        return self._skeleton

    @property
    def body(self) -> str:
        return self.skeleton if self.mode == "skeleton" else self.text

    @property
    def packed_tokens(self) -> int:
        return 0 if self.mode == "omitted" else estimate_tokens(self.body)


@dataclass
class ScanOptions:
    include: list[GlobRule]
    exclude: list[GlobRule]
    max_file_bytes: int
    own_paths: frozenset[str]


def _load_gitignore(abs_dir: str, rel_dir: str) -> list[GlobRule]:
    path = os.path.join(abs_dir, ".gitignore")
    try:
        if not stat.S_ISREG(os.lstat(path).st_mode):
            return []
        with open(path, "r", encoding="utf-8", errors="replace") as handle:
            return parse_gitignore(handle.read(), rel_dir)
    except OSError:
        return []


def _classify_file(abs_path: str, rel: str, st: os.stat_result, options: ScanOptions):
    """Return (Entry, None) for a usable text file, else (None, skip record)."""
    def skip(reason: str) -> tuple[None, dict]:
        return None, {"path": rel, "reason": reason, "bytes": st.st_size}

    if stat.S_ISLNK(st.st_mode):
        return skip("symlink (not followed)")
    if not stat.S_ISREG(st.st_mode):
        return skip("not a regular file")
    if st.st_size > options.max_file_bytes:
        return skip(f"too large (over {options.max_file_bytes} bytes)")
    try:
        with open(abs_path, "rb") as handle:
            data = handle.read()
    except OSError as exc:
        return skip(f"unreadable ({type(exc).__name__})")
    if b"\0" in data:
        return skip("binary (NUL byte)")
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        return skip("binary (not valid UTF-8)")
    digest = hashlib.sha256(data).hexdigest()
    return Entry(rel, digest, len(data), st.st_mtime_ns, text), None


def scan_tree(root: str, options: ScanOptions) -> tuple[list[Entry], list[dict]]:
    entries: list[Entry] = []
    skipped: list[dict] = []

    def walk(abs_dir: str, rel_dir: str, inherited: list[GlobRule]) -> None:
        rules = inherited + _load_gitignore(abs_dir, rel_dir)
        try:
            with os.scandir(abs_dir) as iterator:
                items = sorted(iterator, key=lambda item: item.name)
        except OSError as exc:
            skipped.append({"path": rel_dir or "./",
                            "reason": f"unreadable ({type(exc).__name__})", "bytes": None})
            return
        for item in items:
            if item.name == ".git":
                continue
            rel = rel_dir + item.name
            try:
                st = os.lstat(item.path)
            except OSError as exc:
                skipped.append({"path": rel, "reason": f"unreadable ({type(exc).__name__})",
                                "bytes": None})
                continue
            is_dir = stat.S_ISDIR(st.st_mode)
            if is_ignored(rel, is_dir, rules) or glob_hit(options.exclude, rel, is_dir):
                continue
            if is_dir:
                if item.name in ALWAYS_SKIP_DIRS:
                    skipped.append({"path": rel + "/", "reason": "always-skipped directory",
                                    "bytes": None})
                else:
                    walk(item.path, rel + "/", rules)
                continue
            if os.path.realpath(item.path) in options.own_paths:
                continue
            if options.include and not glob_hit(options.include, rel):
                continue
            entry, skip_record = _classify_file(item.path, rel, st, options)
            if entry is not None:
                entries.append(entry)
            else:
                skipped.append(skip_record)

    walk(root, "", [])
    skipped.sort(key=lambda record: record["path"])
    return entries, skipped


# ---------------------------------------------------------------------------
# Git and ordering
# ---------------------------------------------------------------------------

def _run_git(root: str, args: list[str]) -> Optional[bytes]:
    command = ["git", "-c", "core.fsmonitor=false", "-C", root, *args]
    env = dict(os.environ, GIT_OPTIONAL_LOCKS="0")
    try:
        result = subprocess.run(command, capture_output=True, env=env,
                                timeout=GIT_TIMEOUT_SECONDS, check=False)
    except (OSError, subprocess.SubprocessError):
        return None
    return result.stdout if result.returncode == 0 else None


def git_head(root: str) -> Optional[str]:
    output = _run_git(root, ["rev-parse", "--verify", "HEAD"])
    return output.decode("ascii", "replace").strip() if output else None


def git_recency(root: str) -> dict[str, int]:
    """Map path -> rank, 0 being the most recently committed."""
    output = _run_git(root, ["log", "--relative", "--no-renames", "--no-ext-diff",
                             "--name-only", "--format=", "-z"])
    ranks: dict[str, int] = {}
    for raw in (output or b"").split(b"\0"):
        path = raw.lstrip(b"\n").decode("utf-8", "surrogateescape")
        if path and path not in ranks:
            ranks[path] = len(ranks)
    return ranks


_README = re.compile(r"^readme(?:\.[^/]*)?$", re.IGNORECASE)
_ENTRY_POINT = re.compile(r"^(?:__main__\.py|(?:main|index|app|cli)\.[^/.]+|lib\.rs)$",
                          re.IGNORECASE)


def entry_rank(path: str) -> int:
    """0 for the root README, 1 for main entry files, 2 for everything else."""
    parts = path.split("/")
    if len(parts) == 1 and _README.match(parts[0]):
        return 0
    if len(parts) <= 2 and _ENTRY_POINT.match(parts[-1]):
        return 1
    return 2


def order_entries(entries: list[Entry], recency: dict[str, int]) -> list[Entry]:
    """Files with git history first, then the rest by mtime, then by path.

    Entry points float up within their tier. The result depends only on the
    tree, its git history and its mtimes.
    """
    def key(entry: Entry) -> tuple:
        if entry.path in recency:
            return (0, entry_rank(entry.path), recency[entry.path], entry.path)
        return (1, entry_rank(entry.path), -entry.mtime_ns, entry.path)

    return sorted(entries, key=key)


# ---------------------------------------------------------------------------
# Rendering
# ---------------------------------------------------------------------------

@dataclass
class Pack:
    entries: list[Entry]
    skipped: list[dict]
    redactions: list[dict]
    deleted: list[str]
    unchanged: list[dict]
    budget: Optional[int]
    fmt: str
    redacting: bool
    is_delta: bool


def tree_text(paths: list[str]) -> str:
    root: dict = {}
    for path in paths:
        node = root
        for part in display_path(path).split("/"):
            node = node.setdefault(part, {})
    lines = ["."]

    def emit(node: dict, prefix: str) -> None:
        names = sorted(node)
        for index, name in enumerate(names):
            last = index == len(names) - 1
            lines.append(prefix + ("`-- " if last else "|-- ") + name)
            emit(node[name], prefix + ("    " if last else "|   "))

    emit(root, "")
    return "\n".join(lines)


def totals_for(pack: Pack, pack_tokens: int) -> dict:
    by_mode = {"full": 0, "skeleton": 0, "omitted": 0}
    saved = omitted = 0
    for entry in pack.entries:
        by_mode[entry.mode] += 1
        if entry.mode == "skeleton":
            saved += entry.tokens - entry.packed_tokens
        elif entry.mode == "omitted":
            omitted += entry.tokens
    return {
        "files_full": by_mode["full"],
        "files_skeleton": by_mode["skeleton"],
        "files_omitted": by_mode["omitted"],
        "files_skipped": len(pack.skipped),
        "tokens_packed": sum(entry.packed_tokens for entry in pack.entries),
        "tokens_saved_by_skeleton": saved,
        "tokens_omitted": omitted,
        "pack_tokens": pack_tokens,
    }


def manifest_text(pack: Pack, pack_tokens: int) -> str:
    totals = totals_for(pack, pack_tokens)
    lines = ["[totals]"]
    lines.extend(f"{key}: {value}" for key, value in totals.items())
    lines.append(f"budget: {pack.budget if pack.budget is not None else 'none'}")
    if pack.is_delta:
        lines.append(f"unchanged_files_not_packed: {len(pack.unchanged)}")
    lines.extend(["", "[files] path | mode | est_tokens | redactions"])
    for entry in pack.entries:
        lines.append(f"{display_path(entry.path)} | {entry.mode} | "
                     f"{entry.tokens} | {entry.redactions}")
    if pack.skipped:
        lines.extend(["", "[skipped] path | reason | bytes"])
        for record in pack.skipped:
            size = "-" if record["bytes"] is None else record["bytes"]
            lines.append(f"{display_path(record['path'])} | {record['reason']} | {size}")
    if pack.redactions:
        lines.extend(["", "[redactions] file | line | rule | placeholder"])
        for item in pack.redactions:
            lines.append(f"{display_path(item['file'])} | {item['line']} | "
                         f"{item['rule']} | {item['placeholder']}")
    if pack.deleted:
        lines.extend(["", "[deleted] path"])
        lines.extend(display_path(path) for path in pack.deleted)
    return "\n".join(lines)


def intro_text(pack: Pack) -> str:
    lines = [f"Generated by {TOOL_NAME} {VERSION}. Token counts are estimates "
             "(chars/4, rounded up)."]
    if pack.is_delta:
        lines.append("Delta pack: only new and changed files are included.")
    if pack.redacting:
        lines.append("Secret values are replaced with \u00abREDACTED:<rule>:<n>\u00bb placeholders.")
    else:
        lines.append("Redaction was disabled for this pack.")
    return "\n".join(lines)


def _fenced(text: str) -> str:
    runs = re.findall(r"`{3,}", text)
    fence = "`" * max(3, max((len(run) for run in runs), default=0) + 1)
    if not text.endswith("\n"):
        text += "\n"
    return f"{fence}\n{text}{fence}\n"


def _size_label(entry: Entry) -> str:
    if entry.mode == "skeleton":
        return f"skeleton, {entry.packed_tokens} of {entry.tokens} tokens"
    return f"full, {entry.tokens} tokens"


def file_block_md(entry: Entry) -> str:
    title = f"### {display_path(entry.path)} ({_size_label(entry)})"
    return f"{title}\n\n{_fenced(entry.body)}\n"


def render_md(pack: Pack, pack_tokens: int) -> str:
    parts = [
        f"# Context Pack\n\n{intro_text(pack)}\n\n## Directory tree\n\n",
        _fenced(tree_text([entry.path for entry in pack.entries])),
        "\n## Files\n\n",
    ]
    parts.extend(file_block_md(entry) for entry in pack.entries if entry.mode != "omitted")
    parts.extend(["## Manifest\n\n", _fenced(manifest_text(pack, pack_tokens))])
    return "".join(parts)


_XML_INVALID = re.compile("[^\t\n\r\x20-\ud7ff\ue000-\ufffd\U00010000-\U0010ffff]")


def _cdata(text: str) -> str:
    cleaned = _XML_INVALID.sub("\ufffd", text)
    return "<![CDATA[" + cleaned.replace("]]>", "]]]]><![CDATA[>") + "]]>"


def file_block_xml(entry: Entry) -> str:
    path = quoteattr(display_path(entry.path))
    return (f'<file path={path} mode="{entry.mode}" tokens="{entry.packed_tokens}">'
            f"{_cdata(entry.body)}</file>\n")


def render_xml(pack: Pack, pack_tokens: int) -> str:
    tree = tree_text([entry.path for entry in pack.entries])
    parts = [
        f'<contextpack version="{VERSION}">\n',
        f"<about>{_cdata(intro_text(pack))}</about>\n",
        f"<tree>{_cdata(tree)}</tree>\n",
        "<files>\n",
    ]
    parts.extend(file_block_xml(entry) for entry in pack.entries if entry.mode != "omitted")
    parts.extend(["</files>\n", f"<manifest>{_cdata(manifest_text(pack, pack_tokens))}</manifest>\n",
                  "</contextpack>\n"])
    return "".join(parts)


def render(pack: Pack) -> tuple[str, int]:
    """Render the pack with a token total that counts the total itself."""
    renderer = render_xml if pack.fmt == "xml" else render_md
    pack_tokens = 0
    while True:
        text = renderer(pack, pack_tokens)
        measured = estimate_tokens(text)
        if measured == pack_tokens:
            return text, pack_tokens
        pack_tokens = measured


# ---------------------------------------------------------------------------
# Budget
# ---------------------------------------------------------------------------

def _demote_lowest_priority(entries: list[Entry]) -> bool:
    for entry in reversed(entries):
        if entry.mode == "full":
            entry.mode = "skeleton" if entry.skeleton else "omitted"
            return True
        if entry.mode == "skeleton":
            entry.mode = "omitted"
            return True
    return False


def _impossible(pack: Pack, base_tokens: int) -> BudgetImpossible:
    if not pack.entries:
        return BudgetImpossible(
            f"budget impossible: the pack needs at least {base_tokens} tokens for its "
            f"headers and manifest, but the budget is {pack.budget}.")
    first = pack.entries[0]
    needed = estimate_tokens(first.skeleton or first.text)
    return BudgetImpossible(
        f"budget impossible: {display_path(first.path)} is the highest-priority file and "
        f"needs {needed} tokens at its smallest, on top of {base_tokens} tokens for the "
        f"tree and manifest, but the budget is {pack.budget}.")


def fit_to_budget(pack: Pack) -> tuple[str, int]:
    """Fill in priority order: full, then skeleton, then omitted."""
    budget = pack.budget
    block: Callable[[Entry], str] = file_block_xml if pack.fmt == "xml" else file_block_md
    for entry in pack.entries:
        entry.mode = "full"
    text, pack_tokens = render(pack)
    if pack_tokens <= budget:
        return text, pack_tokens

    for entry in pack.entries:
        entry.mode = "omitted"
    text, base_tokens = render(pack)
    used = len(text)
    limit = budget * 4
    for entry in pack.entries:
        for mode in ("full", "skeleton"):
            if mode == "skeleton" and not entry.skeleton:
                continue
            entry.mode = mode
            cost = len(block(entry)) + len(mode) - len("omitted")  # file block + manifest row
            if used + cost <= limit:
                used += cost
                break
            entry.mode = "omitted"

    while True:  # the running total is an estimate; this check is exact
        text, pack_tokens = render(pack)
        if pack_tokens <= budget:
            break
        if not _demote_lowest_priority(pack.entries):
            raise _impossible(pack, base_tokens)
    if pack.entries and pack.entries[0].mode == "omitted":
        raise _impossible(pack, base_tokens)
    return text, pack_tokens


# ---------------------------------------------------------------------------
# Manifest and delta
# ---------------------------------------------------------------------------

def _valid_manifest_path(path: object) -> bool:
    if not isinstance(path, str) or not path or os.path.isabs(path):
        return False
    return ".." not in path.split("/")


def load_baseline(path: str) -> tuple[dict[str, dict], list[str]]:
    """Read an old manifest: ({path: file record}, all paths it knew about)."""
    try:
        with open(path, "r", encoding="utf-8") as handle:
            document = json.load(handle)
    except (OSError, ValueError) as exc:
        raise UsageError(f"cannot read manifest {path}: {exc}") from exc
    if not isinstance(document, dict) or not isinstance(document.get("files"), list):
        raise UsageError(f"{path} is not a {TOOL_NAME} manifest")
    known: dict[str, dict] = {}
    try:
        for record in document["files"] + document.get("unchanged", []):
            if not _valid_manifest_path(record["path"]) or not isinstance(record["sha256"], str):
                raise UsageError(f"{path} has an invalid file record")
            known[record["path"]] = record
        skipped = [record["path"] for record in document.get("skipped", [])]
    except (KeyError, TypeError) as exc:
        raise UsageError(f"{path} has an invalid file record") from exc
    return known, list(known) + [p for p in skipped if _valid_manifest_path(p)]


def apply_delta(entries: list[Entry], root: str, known: dict[str, dict],
                all_paths: list[str]) -> tuple[list[Entry], list[dict], list[str], int]:
    """Split into changed entries, unchanged records, deleted paths."""
    changed, unchanged = [], []
    undelivered = 0
    for entry in entries:
        record = known.get(entry.path)
        if record is not None and record["sha256"] == entry.sha256:
            unchanged.append({"path": entry.path, "sha256": entry.sha256,
                              "mode": record.get("mode")})
            if record.get("mode") in ("skeleton", "omitted"):
                undelivered += 1
        else:
            changed.append(entry)
    deleted = sorted({path for path in all_paths
                      if not path.endswith("/")
                      and not os.path.lexists(os.path.join(root, path))})
    return changed, unchanged, deleted, undelivered


def manifest_document(pack: Pack, pack_tokens: int, head: Optional[str]) -> dict:
    now = datetime.datetime.now(datetime.timezone.utc)
    document = {
        "tool": TOOL_NAME,
        "version": VERSION,
        "timestamp": now.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "git_head": head,
        "budget": pack.budget,
        "files": [{
            "path": entry.path,
            "sha256": entry.sha256,
            "bytes": entry.size,
            "est_tokens": entry.tokens,
            "packed_tokens": entry.packed_tokens,
            "mode": entry.mode,
            "redactions": entry.redactions,
        } for entry in pack.entries],
        "skipped": pack.skipped,
        "deleted": pack.deleted,
        "totals": totals_for(pack, pack_tokens),
        "redaction_entries": pack.redactions,
    }
    if pack.is_delta:
        document["unchanged"] = pack.unchanged
    return document


# ---------------------------------------------------------------------------
# Command line
# ---------------------------------------------------------------------------

def _positive_int(value: str) -> int:
    try:
        number = int(value)
    except ValueError:
        raise argparse.ArgumentTypeError(f"{value!r} is not an integer") from None
    if number < 1:
        raise argparse.ArgumentTypeError("must be 1 or greater")
    return number


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="contextpack.py",
        description="Pack a codebase into one AI-ready file, with inline secret "
                    "redaction, a hard token budget and a verifiable manifest.")
    parser.add_argument("path", nargs="?", default=".", metavar="PATH",
                        help="directory to pack (default: current directory)")
    parser.add_argument("-o", dest="out", metavar="OUT", help="output file (default: stdout)")
    parser.add_argument("--format", choices=("md", "xml"), default="md", help="default: md")
    parser.add_argument("--budget", type=_positive_int, metavar="N",
                        help="hard limit on the pack's estimated tokens")
    parser.add_argument("--manifest", metavar="M", help="write the JSON manifest here")
    parser.add_argument("--delta", metavar="M",
                        help="pack only files new or changed since this manifest")
    parser.add_argument("--include", action="append", default=[], metavar="GLOB",
                        help="pack only matching files (repeatable)")
    parser.add_argument("--exclude", action="append", default=[], metavar="GLOB",
                        help="skip matching files and directories (repeatable)")
    parser.add_argument("--max-file-bytes", type=_positive_int, default=DEFAULT_MAX_FILE_BYTES,
                        metavar="N", help="skip larger files (default: 1000000)")
    parser.add_argument("--no-redact", action="store_true", help="disable secret redaction")
    parser.add_argument("--version", action="version", version=f"{TOOL_NAME} {VERSION}")
    return parser


def _compile_cli_globs(patterns: list[str], flag: str) -> list[GlobRule]:
    rules = []
    for pattern in patterns:
        rule = compile_glob(pattern)
        if rule is None:
            raise UsageError(f"invalid {flag} pattern: {pattern!r}")
        rules.append(rule)
    return rules


def run(args: argparse.Namespace) -> int:
    if not os.path.isdir(args.path):
        raise UsageError(f"not a directory: {args.path}")
    if args.out and args.manifest and os.path.abspath(args.out) == os.path.abspath(args.manifest):
        raise UsageError("-o and --manifest must be different files")
    root = os.path.realpath(args.path)
    if args.no_redact:
        print("!" * 66 + "\n!! WARNING: --no-redact is set. Secrets WILL appear in this pack. !!\n"
              + "!" * 66, file=sys.stderr)

    known: dict[str, dict] = {}
    known_paths: list[str] = []
    if args.delta:
        known, known_paths = load_baseline(args.delta)

    options = ScanOptions(
        include=_compile_cli_globs(args.include, "--include"),
        exclude=_compile_cli_globs(args.exclude, "--exclude"),
        max_file_bytes=args.max_file_bytes,
        own_paths=frozenset(os.path.realpath(path)
                            for path in (args.out, args.manifest, args.delta) if path),
    )
    entries, skipped = scan_tree(root, options)
    entries = order_entries(entries, git_recency(root))

    unchanged: list[dict] = []
    deleted: list[str] = []
    undelivered = 0
    if args.delta:
        entries, unchanged, deleted, undelivered = apply_delta(entries, root, known, known_paths)

    redactor = Redactor()
    for entry in entries:
        if not args.no_redact:
            entry.text, entry.redactions = redactor.redact(entry.path, entry.text)
        entry.tokens = estimate_tokens(entry.text)

    pack = Pack(entries, skipped, redactor.entries, deleted, unchanged, args.budget,
                args.format, not args.no_redact, bool(args.delta))
    text, pack_tokens = fit_to_budget(pack) if args.budget else render(pack)
    document = manifest_document(pack, pack_tokens, git_head(root))

    payload = text.encode("utf-8")
    try:
        if args.out:
            with open(args.out, "wb") as handle:
                handle.write(payload)
        else:
            sys.stdout.buffer.write(payload)
            sys.stdout.buffer.flush()
        if args.manifest:
            with open(args.manifest, "w", encoding="utf-8", newline="\n") as handle:
                json.dump(document, handle, indent=2, sort_keys=True)
                handle.write("\n")
    except OSError as exc:
        raise UsageError(f"cannot write output: {exc}") from exc

    totals = document["totals"]
    print(f"{TOOL_NAME}: {totals['files_full']} full, {totals['files_skeleton']} skeleton, "
          f"{totals['files_omitted']} omitted, {totals['files_skipped']} skipped, "
          f"{len(pack.redactions)} redacted, about {pack_tokens} tokens", file=sys.stderr)
    if undelivered:
        print(f"{TOOL_NAME}: note: {undelivered} unchanged file(s) were skeleton or omitted in "
              "the base manifest and are not re-sent", file=sys.stderr)
    return EXIT_OK


def main(argv: Optional[list[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return run(args)
    except UsageError as exc:
        print(f"{TOOL_NAME}: error: {exc}", file=sys.stderr)
        return EXIT_USAGE
    except BudgetImpossible as exc:
        print(f"{TOOL_NAME}: {exc}", file=sys.stderr)
        return EXIT_BUDGET


if __name__ == "__main__":
    sys.exit(main())
