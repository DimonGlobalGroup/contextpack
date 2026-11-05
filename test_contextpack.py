"""Test suite for contextpack.py. Run with: python3 -m unittest test_contextpack -v"""

import ast
import hashlib
import json
import math
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
import xml.etree.ElementTree as ET

import contextpack

TOOL = os.path.join(os.path.dirname(os.path.abspath(__file__)), "contextpack.py")

CANARY = "sup3rCanary-Value-9f8e7d6c5b4a"
HAS_GIT = shutil.which("git") is not None


def tokens(text):
    return math.ceil(len(text) / 4)


class PackTestCase(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.base = self._tmp.name
        self.root = os.path.join(self.base, "project")
        os.mkdir(self.root)

    def write(self, rel, content):
        path = os.path.join(self.root, rel)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        mode = "wb" if isinstance(content, bytes) else "w"
        kwargs = {} if isinstance(content, bytes) else {"encoding": "utf-8", "newline": ""}
        with open(path, mode, **kwargs) as handle:
            handle.write(content)
        return path

    def run_tool(self, *args, expect=0):
        env = dict(os.environ, GIT_CEILING_DIRECTORIES=self.base)
        result = subprocess.run([sys.executable, TOOL, *args], capture_output=True, check=False,
                                env=env)
        stdout = result.stdout.decode("utf-8")
        stderr = result.stderr.decode("utf-8")
        self.assertEqual(result.returncode, expect, stderr)
        return stdout, stderr

    def pack(self, *args):
        """Pack self.root, returning (pack text, manifest dict, stderr)."""
        manifest_path = os.path.join(self.base, "manifest.json")
        stdout, stderr = self.run_tool(self.root, "--manifest", manifest_path, *args)
        with open(manifest_path, encoding="utf-8") as handle:
            return stdout, json.load(handle), stderr

    def manifest_raw(self):
        with open(os.path.join(self.base, "manifest.json"), encoding="utf-8") as handle:
            return handle.read()

    @staticmethod
    def modes(manifest):
        return {record["path"]: record["mode"] for record in manifest["files"]}


class RedactionTests(PackTestCase):
    def test_canary_never_appears_but_placeholder_and_file_do(self):
        self.write("config.py", f'NAME = "demo"\nAPI_KEY = "{CANARY}"\nPORT = 8080\n')
        out, manifest, stderr = self.pack()
        for blob in (out, self.manifest_raw(), stderr):
            self.assertNotIn(CANARY, blob)
            self.assertNotIn(CANARY[:8], blob)
        self.assertIn("\u00abREDACTED:generic-assignment:1\u00bb", out)
        self.assertIn('NAME = "demo"', out)
        self.assertIn("PORT = 8080", out)
        self.assertEqual(self.modes(manifest), {"config.py": "full"})
        self.assertEqual(manifest["files"][0]["redactions"], 1)
        entry = manifest["redaction_entries"][0]
        self.assertEqual(entry, {"file": "config.py", "line": 2, "rule": "generic-assignment",
                                 "placeholder": "\u00abREDACTED:generic-assignment:1\u00bb"})

    def test_same_value_same_placeholder_different_value_different(self):
        self.write("a.env", "password=Secret-Alpha-12345\ntoken=Secret-Beta-678901\n")
        self.write("b.env", "password=Secret-Alpha-12345\n")
        out, manifest, _ = self.pack()
        self.assertNotIn("Secret-Alpha", out)
        self.assertNotIn("Secret-Beta", out)
        by_line = {(e["file"], e["line"]): e["placeholder"]
                   for e in manifest["redaction_entries"]}
        self.assertEqual(by_line[("a.env", 1)], by_line[("b.env", 1)])
        self.assertNotEqual(by_line[("a.env", 1)], by_line[("a.env", 2)])

    def test_each_named_rule(self):
        jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0In0.c2lnbmF0dXJlLWJ5dGVz"
        cases = [
            ("aws-access-key", "AKIAIOSFODNN7EXAMPLE"),
            ("aws-access-key", "ASIAIOSFODNN7EXAMPLE"),
            ("github-token", "ghp_" + "a1B2" * 9),
            ("github-token", "gho_" + "a1B2" * 9),
            ("github-token", "ghu_" + "a1B2" * 9),
            ("github-token", "ghs_" + "a1B2" * 9),
            ("github-token", "github_pat_" + "a1B2_" * 8),
            ("slack-token", "xoxb-123456789012-abcdefGHIJKL"),
            ("jwt", jwt),
        ]
        for index, (_, secret) in enumerate(cases):
            self.write(f"f{index}.txt", f"value in prose {secret} and more\n")
        out, _, _ = self.pack()
        for rule, secret in cases:
            self.assertNotIn(secret, out)
            self.assertIn(f"REDACTED:{rule}:", out)
        self.assertIn("value in prose", out)

    def test_private_key_block_is_replaced_whole(self):
        body = "MIIEvQIBADANBgkqhkiG9w0BAQEFAASC\nBKcwggSjAgEAAoIBAQC7"
        self.write("key.pem", f"before\n-----BEGIN RSA PRIVATE KEY-----\n{body}\n"
                              "-----END RSA PRIVATE KEY-----\nafter\n")
        out, manifest, _ = self.pack()
        self.assertNotIn("MIIEvQ", out)
        self.assertNotIn("BEGIN RSA", out)
        self.assertIn("before", out)
        self.assertIn("after", out)
        self.assertEqual(manifest["redaction_entries"][0]["line"], 2)

    def test_unterminated_private_key_takes_key_material_only(self):
        self.write("key.pem", "-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkq\nAoIBAQC7ab==\n")
        self.write("doc.py", 'x = "-----BEGIN PRIVATE KEY-----\\nMIIEvQIBADANBgkq\\n"\nkeep = 1\n')
        out, _, _ = self.pack()
        self.assertNotIn("MIIEvQ", out)
        self.assertNotIn("AoIBAQ", out)
        self.assertIn("keep = 1", out)

    def test_escaped_one_line_private_key(self):
        self.write("cfg.json", '{"key": "-----BEGIN PRIVATE KEY-----\\nMIIEvQIBADANBgkq\\n'
                               '-----END PRIVATE KEY-----\\n", "keep": 1}\n')
        out, _, _ = self.pack()
        self.assertNotIn("MIIEvQ", out)
        self.assertIn('"keep": 1', out)

    def test_many_unterminated_key_headers_finish_quickly(self):
        self.write("slow.txt", "-----BEGIN PRIVATE KEY----- !\n" * 30_000)
        self.pack()

    def test_generic_forms(self):
        secrets = {
            'AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCY': "wJalrXUtnFEMI",
            '"password": "correct-horse-battery"': "correct-horse",
            "client_secret: 9f8e7d6c5b4a3210ffee": "9f8e7d6c5b4a",
            'Authorization: Bearer abc123DEF456ghi789': "abc123DEF456",
            "api-key := 'k9J2mQ7xL4pZ8wR1'": "k9J2mQ7xL4pZ",
            'cfg["auth_token"] = "z8Y7x6W5v4U3t2S1"': "z8Y7x6W5v4U3",
            'token = b"Qw3rTy-Uiop-Asdf1"': "Qw3rTy",
            'api_key: str = "Tp4-annotated-Value"': "annotated-Value",
            'password: Optional[str] = "Tp5-optional-Value"': "optional-Value",
            'password = """Tp6-triple-Value"""': "triple-Value",
            "token = '''Tp7-single-triple-Value'''": "single-triple",
            'secretKey = "Tp8-camel-Value"': "camel-Value",
            'password = ("Tp9-paren-Value")': "paren-Value",
            "password=abc,Tq1-comma-Value": "comma-Value",
            'password=ab"Tq2-quote-Value': "quote-Value",
            'curl -H "Authorization: Bearer Tq3-curl-Value" http://x': "curl-Value",
        }
        for index, line in enumerate(secrets):
            self.write(f"g{index}.txt", line + "\n")
        out, _, _ = self.pack()
        for fragment in secrets.values():
            self.assertNotIn(fragment, out)

    def test_ordinary_code_is_left_alone(self):
        lines = [
            "token = self.get_access_token()",
            'password = os.environ["DB_PASSWORD"]',
            "auth_host: api.example.com",
            "token: Optional[str] = None",
            "secret_manager: SecretManagerClient",
            'author = "Jane Q. Writer-Person"',
            "max_tokens = 4096",
            'token_url = "https://auth.example.com/oauth/token"',
            "password: aaaaaaaaaaaaaaaaaaaa",
            "api_key: ${EXTERNAL_API_KEY}",
            "auth = HTTPBasicAuth(username, password)",
            "if token == other.access_token:",
            "password=hash_password(password, salt),",
        ]
        self.write("code.txt", "\n".join(lines) + "\n")
        out, manifest, _ = self.pack()
        self.assertEqual(manifest["redaction_entries"], [])
        for line in lines:
            self.assertIn(line, out)

    def test_multiline_triple_quoted_value_is_replaced_whole(self):
        self.write("cfg.py", 'token = """\nLine1-of-value-AAA\nLine2-of-value-BBB\n"""\nkeep = 1\n')
        out, _, _ = self.pack()
        self.assertNotIn("Line1-of-value", out)
        self.assertNotIn("Line2-of-value", out)
        self.assertIn("keep = 1", out)

    def test_pathological_lines_finish_quickly(self):
        self.write("slow.txt", "secret-" * 140_000 + "\n" + "token=" + "," * 100_000 + "\n")
        self.pack()

    def test_secret_inside_skeleton_is_still_redacted(self):
        source = f'"""Doc."""\nimport os\nTOKEN = "{CANARY}"\n'
        source += "".join(f"def f{i}():\n    return {i}\n" for i in range(400))
        self.write("big.py", source)
        self.write("README.md", "# Hi\n")
        out, _, _ = self.pack("--budget", "400")
        self.assertNotIn(CANARY, out)

    def test_no_redact_warns_loudly_and_keeps_value(self):
        self.write("config.py", f'API_KEY = "{CANARY}"\n')
        out, manifest, stderr = self.pack("--no-redact")
        self.assertIn(CANARY, out)
        self.assertIn("WARNING", stderr)
        self.assertEqual(manifest["redaction_entries"], [])


class BudgetTests(PackTestCase):
    def make_fixtures(self):
        self.write("README.md", "# Project\n\nShort intro line.\n")
        python = '"""Module doc line.\n\nMore.\n"""\nimport os\nimport sys\n\n\n'
        for i in range(60):
            python += (f"def func_{i}(a, b):\n    \"\"\"Doc {i}.\n\n    Long.\n    \"\"\"\n"
                       + "    x = a + b\n" * 12 + "    return x\n\n")
        python += "class Thing:\n    \"\"\"Thing doc.\"\"\"\n\n    def method(self):\n"
        python += "        return 1\n"
        markdown = "".join(f"## Section {i}\n\nFirst line {i}.\n\n" + "filler text\n" * 40
                           for i in range(30))
        text = "".join(f"data line {i}\n" for i in range(3000))
        paths = {"big.py": python, "docs.md": markdown, "data.txt": text}
        for offset, (rel, content) in enumerate(paths.items()):
            path = self.write(rel, content)
            os.utime(path, (1_700_000_000 - offset, 1_700_000_000 - offset))

    def test_pack_fits_and_manifest_accounts(self):
        self.make_fixtures()
        out, manifest, _ = self.pack("--budget", "900")
        self.assertLessEqual(tokens(out), 900)
        self.assertEqual(manifest["totals"]["pack_tokens"], tokens(out))
        self.assertEqual(manifest["budget"], 900)
        modes = self.modes(manifest)
        self.assertIn("skeleton", modes.values())
        self.assertIn("omitted", modes.values())
        totals = manifest["totals"]
        self.assertEqual(totals["tokens_packed"] + totals["tokens_saved_by_skeleton"]
                         + totals["tokens_omitted"],
                         sum(record["est_tokens"] for record in manifest["files"]))
        self.assertGreater(totals["tokens_saved_by_skeleton"], 0)
        self.assertGreater(totals["tokens_omitted"], 0)
        for record in manifest["files"]:
            if record["mode"] == "omitted":
                self.assertIn(f"{record['path']} | omitted | {record['est_tokens']}", out)

    def test_exact_budget_keeps_every_file_full(self):
        self.make_fixtures()
        full, _, _ = self.pack("--budget", "10000000")
        size = tokens(full)
        out, manifest, _ = self.pack("--budget", str(size))
        self.assertEqual(out, full.replace("budget: 10000000", f"budget: {size}"))
        self.assertEqual(set(self.modes(manifest).values()), {"full"})
        out, manifest, _ = self.pack("--budget", str(size - 1))
        self.assertLessEqual(tokens(out), size - 1)
        self.assertNotEqual(set(self.modes(manifest).values()), {"full"})

    def test_every_budget_is_held_or_refused(self):
        self.make_fixtures()
        for fmt in ("md", "xml"):
            for budget in range(50, 3000, 137):
                result = subprocess.run(
                    [sys.executable, TOOL, self.root, "--format", fmt, "--budget", str(budget)],
                    capture_output=True, check=False)
                self.assertIn(result.returncode, (0, 3))
                if result.returncode == 0:
                    self.assertLessEqual(tokens(result.stdout.decode("utf-8")), budget)

    def test_skeleton_contents(self):
        self.make_fixtures()
        out, manifest, _ = self.pack("--budget", "2500")
        self.assertEqual(self.modes(manifest)["big.py"], "skeleton")
        self.assertIn("import os", out)
        self.assertIn("def func_7(a, b):", out)
        self.assertIn('"""Doc 7."""', out)
        self.assertIn("class Thing:", out)
        self.assertIn("    def method(self):", out)
        self.assertNotIn("x = a + b", out)
        self.assertIn("[... skeleton: full file is", out)

    def test_skeleton_of_markdown_and_text(self):
        self.assertEqual(
            contextpack.skeleton_markdown("# T\n\nfirst\nsecond\n```\n# no\n```\n## U\nbody\nmore\n"),
            "# T\nfirst\n## U\nbody")
        text = "\n".join(f"line {i}" for i in range(500))
        skeleton = contextpack.make_skeleton("notes.txt", text, 9999)
        self.assertIn("line 39\n", skeleton)
        self.assertNotIn("line 40\n", skeleton)
        self.assertTrue(skeleton.endswith("[... skeleton: full file is 9999 tokens]\n"))

    def test_python_skeleton_survives_syntax_error(self):
        result = contextpack.skeleton_python("import os\ndef broken(:\n    pass\n")
        self.assertEqual(result, "import os\ndef broken(:")

    def test_impossible_budget_exits_3_and_writes_nothing(self):
        self.make_fixtures()
        out_path = os.path.join(self.base, "out.md")
        _, stderr = self.run_tool(self.root, "-o", out_path, "--budget", "5", expect=3)
        self.assertIn("budget impossible", stderr)
        self.assertIn("README.md", stderr)
        self.assertFalse(os.path.exists(out_path))


    def test_exit_3_when_top_file_cannot_fit_but_a_later_file_could(self):
        self.write("README.md", "x" * 40_000)
        self.write("tiny.txt", "a\n")
        out_path = os.path.join(self.base, "out.md")
        _, stderr = self.run_tool(self.root, "-o", out_path, "--budget", "300", expect=3)
        self.assertIn("README.md is the highest-priority file", stderr)
        self.assertFalse(os.path.exists(out_path))


class DeltaTests(PackTestCase):
    def setUp(self):
        super().setUp()
        self.write("keep.py", "print('keep')\n")
        self.write("change.py", "print('old')\n")
        self.write("remove.py", "print('remove')\n")
        self.first = os.path.join(self.base, "first.json")
        self.run_tool(self.root, "--manifest", self.first)

    def test_delta_has_only_changed_file_and_lists_deleted(self):
        self.write("change.py", "print('new')\n")
        os.remove(os.path.join(self.root, "remove.py"))
        out, manifest, _ = self.pack("--delta", self.first)
        self.assertEqual(self.modes(manifest), {"change.py": "full"})
        self.assertEqual(manifest["deleted"], ["remove.py"])
        self.assertIn("print('new')", out)
        self.assertNotIn("print('keep')", out)
        self.assertNotIn("keep.py", out)
        self.assertIn("[deleted] path\nremove.py", out)

    def test_new_file_is_packed(self):
        self.write("fresh.py", "print('fresh')\n")
        _, manifest, _ = self.pack("--delta", self.first)
        self.assertEqual(self.modes(manifest), {"fresh.py": "full"})
        self.assertEqual(manifest["deleted"], [])

    def test_no_changes_is_a_valid_empty_pack(self):
        _, manifest, _ = self.pack("--delta", self.first)
        self.assertEqual(manifest["files"], [])

    def test_delta_manifests_chain(self):
        self.write("change.py", "print('two')\n")
        second = os.path.join(self.base, "second.json")
        self.run_tool(self.root, "--delta", self.first, "--manifest", second)
        self.write("change.py", "print('three')\n")
        _, manifest, _ = self.pack("--delta", second)
        self.assertEqual(self.modes(manifest), {"change.py": "full"})
        self.assertEqual(manifest["deleted"], [])

    def test_excluded_file_is_not_reported_deleted(self):
        _, manifest, _ = self.pack("--delta", self.first, "--exclude", "keep.py")
        self.assertEqual(manifest["deleted"], [])

    def test_redaction_and_budget_still_apply(self):
        self.write("change.py", f'API_KEY = "{CANARY}"\n' + "x = 1\n" * 2000)
        out, manifest, _ = self.pack("--delta", self.first, "--budget", "300")
        self.assertNotIn(CANARY, out)
        self.assertLessEqual(tokens(out), 300)
        self.assertEqual(self.modes(manifest)["change.py"], "skeleton")

    def test_bad_manifest_is_a_usage_error(self):
        bad = os.path.join(self.base, "bad.json")
        for content in ("not json", "[]", '{"files": [{"path": "../x", "sha256": "0"}]}'):
            with open(bad, "w", encoding="utf-8") as handle:
                handle.write(content)
            self.run_tool(self.root, "--delta", bad, expect=2)

    def test_note_when_unchanged_file_was_never_delivered(self):
        self.write("big.txt", "line of text\n" * 5000)
        base = os.path.join(self.base, "budgeted.json")
        self.run_tool(self.root, "--budget", "400", "--manifest", base)
        chained = os.path.join(self.base, "chained.json")
        _, stderr = self.run_tool(self.root, "--delta", base, "--manifest", chained)
        self.assertIn("not re-sent", stderr)
        _, stderr = self.run_tool(self.root, "--delta", chained)
        self.assertIn("not re-sent", stderr)


class GitignoreTests(PackTestCase):
    def test_ignored_excluded_and_negated_included(self):
        self.write(".gitignore", "*.log\n!keep.log\n# comment\n\nsecret-dir/\n/rootonly.txt\n")
        self.write("app.log", "noise\n")
        self.write("keep.log", "wanted\n")
        self.write("secret-dir/inner.txt", "hidden\n")
        self.write("rootonly.txt", "hidden\n")
        self.write("sub/rootonly.txt", "visible\n")
        self.write("sub/deep/app.log", "noise\n")
        _, manifest, _ = self.pack()
        self.assertEqual(set(self.modes(manifest)),
                         {".gitignore", "keep.log", "sub/rootonly.txt"})

    def test_pattern_matrix(self):
        cases = [
            ("*.pyc", "a/b/c.pyc", False, True),
            ("doc/*.txt", "doc/a.txt", False, True),
            ("doc/*.txt", "doc/sub/a.txt", False, False),
            ("doc/*.txt", "x/doc/a.txt", False, False),
            ("**/foo", "a/b/foo", False, True),
            ("**/foo", "foo", False, True),
            ("a/**/z", "a/z", False, True),
            ("a/**/z", "a/b/c/z", False, True),
            ("a/**", "a/b/c", False, True),
            ("a/**", "a", True, False),
            ("build/", "x/build", True, True),
            ("build/", "x/build", False, False),
            ("file?.txt", "file1.txt", False, True),
            ("file?.txt", "file/.txt", False, False),
            ("[ab].txt", "a.txt", False, True),
            ("[!ab].txt", "a.txt", False, False),
            ("\\#hash", "#hash", False, True),
            ("/top", "top", False, True),
            ("/top", "x/top", False, False),
            ("mid/file", "x/mid/file", False, False),
        ]
        for pattern, path, is_dir, expected in cases:
            rules = contextpack.parse_gitignore(pattern)
            self.assertEqual(contextpack.is_ignored(path, is_dir, rules), expected,
                             f"{pattern} vs {path}")

    def test_nested_gitignore_and_star_negation(self):
        self.write("pkg/.gitignore", "*.tmp\n!important.tmp\n")
        self.write("pkg/a.tmp", "x\n")
        self.write("pkg/important.tmp", "x\n")
        self.write("b.tmp", "x\n")
        self.write(".gitignore", "logs/*\n!logs/keep.txt\n")
        self.write("logs/drop.txt", "x\n")
        self.write("logs/keep.txt", "x\n")
        _, manifest, _ = self.pack()
        self.assertEqual(set(self.modes(manifest)),
                         {".gitignore", "pkg/.gitignore", "pkg/important.tmp", "b.tmp",
                          "logs/keep.txt"})

    def test_git_dir_and_binary_dirs_are_skipped(self):
        self.write(".git/config", "[core]\n")
        self.write("node_modules/x/index.js", "x\n")
        self.write("__pycache__/a.txt", "x\n")
        self.write("src/ok.py", "x = 1\n")
        out, manifest, _ = self.pack()
        self.assertEqual(set(self.modes(manifest)), {"src/ok.py"})
        reasons = {record["path"]: record["reason"] for record in manifest["skipped"]}
        self.assertEqual(reasons["node_modules/"], "always-skipped directory")
        self.assertNotIn(".git/", reasons)


class SkipTests(PackTestCase):
    def test_binary_skipped_with_reason(self):
        self.write("image.bin", b"\x89PNG\x00\x01\x02")
        self.write("latin.txt", "caf\u00e9\n".encode("latin-1"))
        self.write("ok.txt", "fine\n")
        out, manifest, _ = self.pack()
        self.assertEqual(set(self.modes(manifest)), {"ok.txt"})
        reasons = {record["path"]: record["reason"] for record in manifest["skipped"]}
        self.assertEqual(reasons["image.bin"], "binary (NUL byte)")
        self.assertEqual(reasons["latin.txt"], "binary (not valid UTF-8)")
        self.assertIn("image.bin | binary (NUL byte)", out)

    def test_size_cap(self):
        self.write("big.txt", "x" * 101)
        self.write("edge.txt", "y" * 100)
        _, manifest, _ = self.pack("--max-file-bytes", "100")
        self.assertEqual(set(self.modes(manifest)), {"edge.txt"})
        self.assertEqual(manifest["skipped"][0]["bytes"], 101)
        self.assertIn("too large", manifest["skipped"][0]["reason"])

    @unittest.skipUnless(hasattr(os, "symlink"), "needs symlinks")
    def test_symlinks_are_reported_not_followed(self):
        outside = os.path.join(self.base, "outside.txt")
        with open(outside, "w", encoding="utf-8") as handle:
            handle.write("private outside content\n")
        self.write("ok.txt", "fine\n")
        os.symlink(outside, os.path.join(self.root, "link.txt"))
        os.symlink(self.base, os.path.join(self.root, "linkdir"))
        out, manifest, _ = self.pack()
        self.assertNotIn("private outside content", out)
        reasons = {record["path"]: record["reason"] for record in manifest["skipped"]}
        self.assertIn("symlink", reasons["link.txt"])
        self.assertIn("symlink", reasons["linkdir"])


class DeterminismTests(PackTestCase):
    def build(self):
        self.write(".gitignore", "*.log\n")
        self.write("src/app.py", f'KEY = "{CANARY}"\n')
        self.write("b.txt", "b\n")
        self.write("a.txt", "a\n")
        self.write("image.bin", b"\x00")

    @staticmethod
    def strip_timestamp(manifest):
        return {key: value for key, value in manifest.items() if key != "timestamp"}

    def test_two_runs_are_identical(self):
        self.build()
        first, first_manifest, _ = self.pack("--budget", "2000")
        second, second_manifest, _ = self.pack("--budget", "2000")
        self.assertEqual(first, second)
        self.assertEqual(self.strip_timestamp(first_manifest),
                         self.strip_timestamp(second_manifest))

    def test_outputs_inside_the_tree_do_not_change_the_pack(self):
        self.build()
        out_path = os.path.join(self.root, "pack.md")
        manifest_path = os.path.join(self.root, "pack.json")
        for fmt_run in range(2):
            self.run_tool(self.root, "-o", out_path, "--manifest", manifest_path)
            with open(out_path, "rb") as handle:
                data = handle.read()
            if fmt_run:
                self.assertEqual(data, previous)
            previous = data
        self.assertNotIn(b"pack.md", data)

    def test_timestamp_is_utc(self):
        self.build()
        _, manifest, _ = self.pack()
        self.assertRegex(manifest["timestamp"], r"^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ$")
        self.assertIsNone(manifest["git_head"])


class ManifestTests(PackTestCase):
    def test_schema_and_original_hash(self):
        content = f'API_KEY = "{CANARY}"\n'
        self.write("config.py", content)
        _, manifest, _ = self.pack()
        self.assertEqual(manifest["tool"], "contextpack")
        self.assertEqual(manifest["version"], contextpack.VERSION)
        self.assertIsNone(manifest["budget"])
        record = manifest["files"][0]
        self.assertEqual(record["sha256"], hashlib.sha256(content.encode()).hexdigest())
        self.assertEqual(record["bytes"], len(content))
        self.assertEqual(record["mode"], "full")
        self.assertEqual(record["redactions"], 1)


class FormatTests(PackTestCase):
    def test_md_fence_survives_backticks(self):
        self.write("doc.md", "```python\ncode\n```\n")
        out, _, _ = self.pack()
        self.assertIn("````\n```python", out)

    def test_md_tree_header_comes_first(self):
        self.write("src/a.py", "x = 1\n")
        out, _, _ = self.pack()
        self.assertLess(out.index("Directory tree"), out.index("## Files"))
        self.assertIn("`-- src\n    `-- a.py", out)

    def test_xml_is_well_formed_even_with_hostile_content(self):
        hostile = "</file>]]><evil/>&\x0c\n"
        self.write("x<y>&\".txt", hostile)
        self.write("api.py", f'API_KEY = "{CANARY}"\n')
        out, _, _ = self.pack("--format", "xml")
        root = ET.fromstring(out)
        files = {node.get("path"): node for node in root.find("files")}
        self.assertIn('x<y>&".txt', files)
        self.assertIn("</file>]]><evil/>&", files['x<y>&".txt'].text)
        self.assertNotIn(CANARY, out)
        self.assertIn("api.py | full", root.find("manifest").text)

    def test_crlf_preserved_and_written_as_utf8(self):
        self.write("win.txt", "caf\u00e9\r\nsecond\r\n")
        out_path = os.path.join(self.base, "out.md")
        self.run_tool(self.root, "-o", out_path)
        with open(out_path, "rb") as handle:
            self.assertIn("caf\u00e9\r\nsecond\r\n".encode("utf-8"), handle.read())


class OrderingTests(PackTestCase):
    def test_mtime_then_path_with_entry_points_floated(self):
        for rel, stamp in (("old.txt", 100), ("new.txt", 300), ("main.py", 50),
                           ("README.md", 10), ("tie_b.txt", 200), ("tie_a.txt", 200)):
            path = self.write(rel, rel + "\n")
            os.utime(path, (stamp, stamp))
        _, manifest, _ = self.pack()
        self.assertEqual([record["path"] for record in manifest["files"]],
                         ["README.md", "main.py", "new.txt", "tie_a.txt", "tie_b.txt", "old.txt"])

    @unittest.skipUnless(HAS_GIT, "needs git")
    def test_git_recency_beats_mtime_and_head_is_recorded(self):
        def git(*args):
            subprocess.run(["git", "-C", self.root, "-c", "user.name=t",
                            "-c", "user.email=t@example.invalid", *args],
                           check=True, capture_output=True)
        self.write("first.txt", "1\n")
        self.write("second.txt", "2\n")
        self.write("README.md", "# R\n")
        git("init", "-q")
        git("add", "first.txt", "README.md")
        git("commit", "-qm", "one")
        git("add", "second.txt")
        git("commit", "-qm", "two")
        path = self.write("untracked.txt", "u\n")
        os.utime(path, (4_000_000_000, 4_000_000_000))
        os.utime(os.path.join(self.root, "first.txt"), (3_000_000_000, 3_000_000_000))
        _, manifest, _ = self.pack()
        self.assertEqual([record["path"] for record in manifest["files"]],
                         ["README.md", "second.txt", "first.txt", "untracked.txt"])
        self.assertRegex(manifest["git_head"], r"^[0-9a-f]{40}$")


class CliTests(PackTestCase):
    def test_include_and_exclude(self):
        self.write("src/a.py", "a\n")
        self.write("src/b.txt", "b\n")
        self.write("tests/c.py", "c\n")
        _, manifest, _ = self.pack("--include", "*.py", "--exclude", "tests/")
        self.assertEqual(set(self.modes(manifest)), {"src/a.py"})

    def test_include_directory_form(self):
        self.write("src/deep/a.txt", "a\n")
        self.write("other/b.txt", "b\n")
        _, manifest, _ = self.pack("--include", "src/")
        self.assertEqual(set(self.modes(manifest)), {"src/deep/a.txt"})

    def test_version(self):
        out, _ = self.run_tool("--version")
        self.assertEqual(out.strip(), f"contextpack {contextpack.VERSION}")

    def test_usage_errors_exit_2(self):
        missing = os.path.join(self.base, "nope")
        self.run_tool(missing, expect=2)
        self.run_tool(self.root, "--budget", "abc", expect=2)
        self.run_tool(self.root, "--budget", "0", expect=2)
        self.run_tool(self.root, "--format", "pdf", expect=2)
        self.run_tool(self.root, "--delta", missing, expect=2)
        self.run_tool(self.root, "-o", os.path.join(missing, "x"), expect=2)

    def test_stdlib_only(self):
        with open(TOOL, encoding="utf-8") as handle:
            source = handle.read()
        tree = ast.parse(source, feature_version=(3, 10))
        imported = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imported.update(alias.name.split(".")[0] for alias in node.names)
            elif isinstance(node, ast.ImportFrom):
                imported.add(node.module.split(".")[0])
        self.assertLessEqual(imported, set(sys.stdlib_module_names))


if __name__ == "__main__":
    unittest.main()
