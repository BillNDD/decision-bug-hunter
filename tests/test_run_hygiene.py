"""Gateway, CLI, indexer and run-directory hygiene (offline, synthetic only)."""
from contextlib import redirect_stderr, redirect_stdout
from decimal import Context, Decimal, Inexact
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from decision_bug_hunter import __main__ as cli
from decision_bug_hunter import protocol
from decision_bug_hunter import providers as p
from decision_bug_hunter.protocol import ERROR_CODES, QUESTION, ProviderError
from decision_bug_hunter.repository import CACHEDIR_SIGNATURE, ProjectIndex
from tests.support import FixtureProvider, clean_provider_env
from tests.test_provider_boundary import SyntheticProvider

KEY = "offline-hygiene-credential-5d1a"
STATE = {"source": "synthetic hygiene evidence", "context_scope": "declared_standalone"}
GOOD = {"q": {"type": "noul", "noul": 0.82}}
USAGE = {"input_tokens": 10, "output_tokens": 1}
CHOICE = {"type": "choice", "instructions": "Pick one.",
          "criteria": {"a": "first option", "b": "second option"}}


class GatewayHygieneTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)

    def gateway(self, response=None, failure=None):
        provider = SyntheticProvider(response or p.ProviderResponse(GOOD, USAGE),
                                     failure=failure)
        gateway = p.ValidatedGateway(provider, self.root / "receipts")
        self.addCleanup(gateway.close)
        return gateway, provider

    def evaluate(self, gateway, questions=None):
        return gateway.evaluate(STATE, questions or {"q": QUESTION}, metadata={})

    def saved(self, gateway):
        return json.loads(Path(gateway.last_receipt).read_text(encoding="utf-8"))

    def test_validate_call_deadline_bounds(self):
        for good in (0.001, 1, 30.0, 300):
            self.assertEqual(p.validate_call_deadline(good), float(good))
        for bad in (0, -1, 300.5, float("nan"), float("inf"), "30", True, None):
            with self.subTest(bad=bad), self.assertRaises(ProviderError) as caught:
                p.validate_call_deadline(bad)
            self.assertEqual(caught.exception.code, "invalid_deadline")

    def test_preflight_refusal_not_submitted(self):
        """Journal time exhausting the call deadline refuses before dispatch."""
        gateway, provider = self.gateway()
        clock = [100.0]
        original = p._write_receipt

        def slow_intent(path, receipt):
            original(path, receipt)
            if receipt["status"] == "dispatching":
                clock[0] = 131.0

        with patch.object(p.time, "monotonic", side_effect=lambda: clock[0]), \
                patch.object(p, "_write_receipt", side_effect=slow_intent):
            with self.assertRaises(ProviderError) as caught:
                self.evaluate(gateway)
        self.assertEqual(caught.exception.code, "deadline_exceeded")
        self.assertEqual(provider.requests, [])
        saved = self.saved(gateway)
        self.assertEqual((saved["status"], saved["error"]), ("failed", "deadline_exceeded"))
        self.assertIs(saved["submission_possible"], False)
        self.assertIs(gateway.last_call_stats["submission_possible"], False)
        # Nothing was sent, so the gateway is not blocked.
        self.assertEqual(self.evaluate(gateway)["q"]["noul"], Decimal("0.82"))
        self.assertEqual(len(provider.requests), 1)

    def test_intent_write_failure_not_submitted(self):
        gateway, provider = self.gateway()
        original = p._write_receipt

        def fail_intent(path, receipt):
            if receipt["status"] == "dispatching":
                raise ProviderError("receipt_failed")
            original(path, receipt)

        with patch.object(p, "_write_receipt", side_effect=fail_intent):
            with self.assertRaises(ProviderError) as caught:
                self.evaluate(gateway)
        self.assertEqual(caught.exception.code, "receipt_failed")
        self.assertEqual(provider.requests, [])
        self.assertIs(self.saved(gateway)["submission_possible"], False)

    def test_receipts_share_deadline_seconds(self):
        gateway, provider = self.gateway()
        gateway.set_run_deadline(110.0)
        clock = [100.0]
        written = []
        original = p._write_receipt

        def record(path, receipt):
            written.append(json.loads(json.dumps(p.plain(receipt))))
            original(path, receipt)
            if receipt["status"] == "dispatching":
                clock[0] = 102.5

        with patch.object(p.time, "monotonic", side_effect=lambda: clock[0]), \
                patch.object(p, "_write_receipt", side_effect=record):
            self.evaluate(gateway)
        self.assertEqual([r["status"] for r in written], ["dispatching", "validated"])
        self.assertEqual(written[0]["deadline_seconds"], 10.0)
        self.assertEqual(written[1]["deadline_seconds"], 10.0)
        # The provider receives only what is left of the same absolute deadline.
        self.assertEqual(provider.requests[0].timeout_seconds, 7.5)
        self.assertEqual(written[1]["timeout_seconds"], 7.5)

    def test_decimal_exception_is_response_distribution(self):
        tiny = Context(prec=1, traps=[Inexact])
        answer = {"type": "choice", "choice": "a",
                  "probabilities": {"a": Decimal("0.55"),
                                    "b": Decimal("0.45")},
                  "confidence": Decimal("0.1")}
        with patch.object(protocol, "_MASS_CONTEXT", tiny):
            with self.assertRaises(ProviderError) as caught:
                protocol.validate_answer_objects({"pick": answer}, {"pick": CHOICE})
            self.assertEqual(caught.exception.code, "response_distribution")
            gateway, provider = self.gateway(p.ProviderResponse({"pick": answer}, USAGE))
            # Answer-scoped since ADR-3: the answer is withheld as a defect.
            self.assertEqual(self.evaluate(gateway, {"pick": CHOICE}), {})
        self.assertEqual(gateway.last_defects, {"pick": "response_distribution"})
        self.assertEqual(self.saved(gateway)["scoped"], {"pick": "response_distribution"})
        self.assertEqual(self.saved(gateway)["usage"], USAGE)
        # A distribution defect is an answer verdict, not a blocked gateway.
        gateway.provider.response = p.ProviderResponse(GOOD, USAGE)
        self.evaluate(gateway)
        self.assertEqual(len(provider.requests), 2)

    def test_unexpected_exception_is_internal_error(self):
        gateway, provider = self.gateway(failure=RuntimeError("private-adapter-detail"))
        with self.assertRaises(ProviderError) as caught:
            self.evaluate(gateway)
        self.assertEqual(caught.exception.code, "internal_error")
        saved = self.saved(gateway)
        self.assertEqual(saved["error"], "internal_error")
        self.assertNotIn("private-adapter-detail", json.dumps(saved))
        # Unknown adapter state still stops this gateway.
        with self.assertRaises(ProviderError):
            self.evaluate(gateway)
        self.assertEqual(len(provider.requests), 1)

    def test_routing_invalid_is_a_documented_code(self):
        self.assertIn("routing_invalid", ERROR_CODES)
        self.assertEqual(ProviderError("routing_invalid").code, "routing_invalid")


def git_available():
    return shutil.which("git") is not None


class CliHygieneTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.source = self.root / "sample.txt"
        self.source.write_text("alpha\nbeta\n", encoding="utf-8")
        self.provider = SyntheticProvider(fixture=FixtureProvider())

    def run_cli(self, *extra, output=None):
        out, err = io.StringIO(), io.StringIO()
        argv = [str(self.source), "--scope", "standalone",
                "--output-dir", str(output or self.root / "runs"),
                "--no-whole-file", "--no-bug-lenses", "--max-action-steps", "0", *extra]
        with clean_provider_env(), redirect_stdout(out), redirect_stderr(err),                 patch.object(cli, "make_provider", return_value=self.provider):
            code = cli.main(argv)
        return code, out.getvalue(), err.getvalue()

    def test_invalid_deadline_creates_no_run_dir(self):
        for value in ("0", "-1", "nan", "inf", "301"):
            with self.subTest(value=value):
                output = self.root / f"out-{value}"
                code, out, err = self.run_cli("--deadline-seconds", value, output=output)
                self.assertEqual((code, out), (2, ""))
                self.assertIn("invalid_deadline", err)
                self.assertFalse(output.exists())
                self.assertEqual(self.provider.requests, [])

    def test_run_dir_gets_gitignore_and_cachedir_tag(self):
        output = self.root / "fresh" / "runs"
        code, _, err = self.run_cli(output=output)
        self.assertIn(code, (0, 1), err)
        run = next(output.glob("run-*"))
        for directory in (output, run):
            self.assertEqual((directory / ".gitignore").read_bytes(), b"*\n")
            tag = (directory / "CACHEDIR.TAG").read_bytes()
            self.assertTrue(tag.startswith(CACHEDIR_SIGNATURE + b"\n"))
            self.assertEqual(len(CACHEDIR_SIGNATURE), 43)
        # Only the directory this invocation created is marked.
        self.assertFalse((self.root / "fresh" / ".gitignore").exists())
        self.assertTrue((run / "report.json").is_file())

    def test_preexisting_output_parent_untouched(self):
        output = self.root / "existing"
        output.mkdir()
        (output / "keep.txt").write_text("user file\n", encoding="utf-8")
        for _ in range(2):
            code, _, err = self.run_cli(output=output)
            self.assertIn(code, (0, 1), err)
        self.assertEqual(sorted(path.name for path in output.iterdir()
                                if not path.name.startswith("run-")), ["keep.txt"])
        runs = list(output.glob("run-*"))
        self.assertEqual(len(runs), 2)
        for run in runs:
            self.assertTrue((run / ".gitignore").is_file())
            self.assertTrue((run / "CACHEDIR.TAG").is_file())

    def test_existing_parent_that_refuses_mkdir_counts_as_preexisting(self):
        # Windows raises PermissionError, not FileExistsError, for mkdir on an
        # existing drive root such as D:/ (verifier minor, WP-03).
        existing = self.root / "root-like"
        existing.mkdir()
        missing = self.root / "absent" / "denied"
        real_mkdir = Path.mkdir

        def refusing(path, *args, **kwargs):
            if path in (existing, missing):
                raise PermissionError(13, "access denied")
            return real_mkdir(path, *args, **kwargs)

        with patch.object(Path, "mkdir", refusing):
            self.assertFalse(cli.make_output_parent(existing))
            # A refusal for a directory that does not exist still fails.
            with self.assertRaises(PermissionError):
                cli.make_output_parent(missing)
        self.assertFalse((existing / ".gitignore").exists())

    @unittest.skipUnless(git_available(), "git is not installed")
    def test_git_status_clean_after_cli_run(self):
        repo = self.root / "repo"
        repo.mkdir()
        environment = {k: v for k, v in os.environ.items() if not k.startswith("GIT_")}
        environment.update(GIT_CONFIG_NOSYSTEM="1", GIT_CONFIG_GLOBAL=os.devnull)

        def git(*args):
            return subprocess.run(["git", *args], cwd=repo, env=environment,
                                  capture_output=True, text=True, timeout=60, check=True)

        git("init", "-q")
        for output in (repo / "dbh_runs", repo / "nested" / "out"):
            with self.subTest(output=output.name):
                code, _, err = self.run_cli(output=output)
                self.assertIn(code, (0, 1), err)
                status = git("status", "--porcelain", "--untracked-files=all").stdout
                self.assertEqual(status, "")
        # A pre-existing parent inside the repository: only the run is hidden.
        existing = repo / "existing"
        existing.mkdir()
        (existing / "keep.txt").write_text("user file\n", encoding="utf-8")
        code, _, err = self.run_cli(output=existing)
        self.assertIn(code, (0, 1), err)
        status = git("status", "--porcelain", "--untracked-files=all").stdout
        self.assertEqual(status.splitlines(), ["?? existing/keep.txt"])

    def test_help_default_strict(self):
        text = " ".join(cli.parser().format_help().split())
        self.assertIn("(default: strict mass)", text)
        self.assertIn("Compatibility no-op: strict Choice mass is already the default.", text)
        self.assertNotIn("instead of the default rounding tolerance", text)
        args = cli.parser().parse_args(["x"])
        self.assertIsNone(args.choice_rounding_places)
        self.assertFalse(args.strict_choice_mass)

    def test_malformed_org_id_routing_invalid_not_printed(self):
        sentinel = "routing-sentinel value"
        for variable in ("OPENAI_ORG_ID", "OPENAI_PROJECT_ID"):
            with self.subTest(variable=variable):
                output = self.root / f"out-{variable}"
                out, err = io.StringIO(), io.StringIO()
                argv = [str(self.source), "--scope", "standalone", "--judge", "openai",
                        "--provider", "openai", "--output-dir", str(output)]
                with clean_provider_env(OPENAI_API_KEY=KEY, **{variable: sentinel}), \
                        redirect_stdout(out), redirect_stderr(err):
                    code = cli.main(argv)
                self.assertEqual((code, out.getvalue()), (2, ""))
                self.assertIn("Scan failed (routing_invalid).", err.getvalue())
                self.assertIn(variable, err.getvalue())
                self.assertNotIn("routing-sentinel", err.getvalue())
                self.assertNotIn(KEY, err.getvalue())
                self.assertFalse(output.exists())


class IndexerHygieneTests(unittest.TestCase):
    def test_indexer_skips_dbh_runs_smoke_results_and_tagged_dirs(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "main.py").write_text("x = 1\n", encoding="utf-8")
            for name in ("dbh_runs", "smoke-results", "tagged", "wrong-tag", "plain"):
                (root / name).mkdir()
                (root / name / "inner.txt").write_text(f"{name}\n", encoding="utf-8")
            (root / "dbh_runs" / "run-1").mkdir()
            (root / "dbh_runs" / "run-1" / "report.json").write_text("{}\n", encoding="utf-8")
            (root / "tagged" / "CACHEDIR.TAG").write_bytes(
                CACHEDIR_SIGNATURE + b"\n# any comment\n")
            nested = root / "plain" / "cache"
            nested.mkdir()
            (nested / "CACHEDIR.TAG").write_bytes(CACHEDIR_SIGNATURE)
            (nested / "blob.txt").write_text("cached\n", encoding="utf-8")
            (root / "wrong-tag" / "CACHEDIR.TAG").write_bytes(b"Signature: not-the-tag\n")
            index = ProjectIndex.read(root)
            rels = sorted(entry.relpath for entry in index.entries)
            self.assertEqual(rels, ["main.py", "plain/inner.txt",
                                    "wrong-tag/CACHEDIR.TAG", "wrong-tag/inner.txt"])
            self.assertEqual(index.skipped_cache_dirs, 2)
            for rel in rels:
                self.assertFalse(rel.startswith(("dbh_runs/", "smoke-results/", "tagged/")))

    def test_cli_output_is_never_indexed_by_a_later_project_scan(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "main.py").write_text("x = 1\n", encoding="utf-8")
            output = root / "custom-out"
            output.mkdir()
            run = output / "run-abc"
            run.mkdir()
            cli.mark_output_directory(run)
            (run / "report.json").write_text("{}\n", encoding="utf-8")
            index = ProjectIndex.read(root)
            self.assertEqual([entry.relpath for entry in index.entries], ["main.py"])
            self.assertEqual(index.skipped_cache_dirs, 1)

    @unittest.skipUnless(hasattr(os, "symlink") and os.name == "posix",
                         "symlink creation needs POSIX")
    def test_symlinked_tag_is_not_followed(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "real.tag").write_bytes(CACHEDIR_SIGNATURE)
            (root / "dir").mkdir()
            (root / "dir" / "data.txt").write_text("kept\n", encoding="utf-8")
            os.symlink(root / "real.tag", root / "dir" / "CACHEDIR.TAG")
            index = ProjectIndex.read(root)
            self.assertIn("dir/data.txt", [entry.relpath for entry in index.entries])
            self.assertEqual(index.skipped_cache_dirs, 0)


if __name__ == "__main__":
    unittest.main()
