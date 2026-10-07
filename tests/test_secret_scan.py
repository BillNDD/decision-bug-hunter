"""Secret content scan and the b1 report shape (offline, synthetic only).

Every token-shaped string here is assembled at runtime from fragments, so no
committed file holds one; ``test_no_committed_file_holds_a_token_shape``
enforces that for the whole repository.
"""
from contextlib import redirect_stderr, redirect_stdout
import io
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from decision_bug_hunter import __main__ as cli
from decision_bug_hunter.core import Config
from decision_bug_hunter.protocol import ERROR_CODES
from decision_bug_hunter.repository import ProjectIndex
from decision_bug_hunter.secret_scan import PATTERN_IDS, describe, scan_lines
from tests.support import FixtureProvider, clean_provider_env, scan, source
from tests.test_beta_policy import RolesProvider, beta
from tests.test_provider_boundary import SyntheticProvider

ROOT = Path(__file__).resolve().parents[1]


def token(pattern_id: str) -> str:
    """A synthetic token of *pattern_id*'s shape, never a real credential."""
    return {
        "openrouter": "sk-" + "or-v1-" + "0123456789abcdef" * 4,
        "anthropic": "sk-" + "ant-api03-" + "Synthetic0Fixture_" * 3,
        "openai": "sk-" + "proj-" + "Syn0thetic" * 4,
        "aws": "AK" + "IA" + "SYNTHETIC0FIXT00",
        "private_key": "-----" + "BEGIN RSA PRIVATE KEY" + "-----",
        "github": "gh" + "p_" + "Synthetic0Fixture0" * 2,
        "slack": "xo" + "xb-" + "1234567890" + "-" + "Synthetic0Fixture",
        "google": "AI" + "za" + "Synthetic0Fixture0Synthetic0Fixture",
        "stripe": "sk" + "_test_" + "Synthetic0Fixture0",
        "jwt": ".".join(["ey" + "JhbGciOiJIUzI1NiJ9", "ey" + "JzdWIiOiJmaXh0dXJlIn0",
                         "SyntheticFixtureSignature0"]),
    }[pattern_id]


class ScannerTests(unittest.TestCase):
    def test_every_pattern_detected_with_line_number(self):
        for pattern_id in PATTERN_IDS:
            with self.subTest(pattern=pattern_id):
                lines = ["clean = 1", f"value = '{token(pattern_id)}'", "done"]
                self.assertEqual(scan_lines(lines), [(pattern_id, 2)])

    def test_near_misses_not_detected(self):
        lines = [
            "sk-" + "or-v1-" + "0123456789abcdef" * 3,           # too short
            "sk-" + "some-long-kebab-case-identifier-name-x",    # no mixed body
            "AK" + "IA" + "SHORT",
            "-----" + "BEGIN PUBLIC KEY" + "-----",
            "gh" + "p_short",
            "xo" + "xb-notdigits-abcdefgh",
            "pk" + "_test_" + "Synthetic0Fixture0",              # publishable
            "masked sk-" + "proj-ab***yz",
            "plain prose without credentials",
        ]
        self.assertEqual(scan_lines(lines), [])

    def test_hits_sorted_distinct_and_carry_no_text(self):
        aws, router = token("aws"), token("openrouter")
        lines = [f"{aws} {aws}", "x", f"{router} {aws}"]
        hits = scan_lines(lines)
        self.assertEqual(hits, [("aws", 1), ("openrouter", 3), ("aws", 3)])
        for pattern_id, line_no in hits:
            self.assertIn(pattern_id, PATTERN_IDS)
            self.assertIs(type(line_no), int)
        self.assertEqual(scan_lines([]), [])

    def test_scan_output_never_contains_match(self):
        lines = [f"k{i} = '{token(p)}'" for i, p in enumerate(PATTERN_IDS)]
        hits = scan_lines(lines)
        text = repr(hits) + describe("file", hits, limit=3) + describe("file", hits)
        for pattern_id in PATTERN_IDS:
            self.assertNotIn(token(pattern_id), text)
            # Not even a distinctive fragment of the token body.
            self.assertNotIn("Synthetic0Fixture", text)
        self.assertIn("(+7 more)", describe("file", hits, limit=3))

    def test_no_committed_file_holds_a_token_shape(self):
        try:
            listed = subprocess.run(["git", "ls-files", "-z"], cwd=ROOT, check=True,
                                    capture_output=True, timeout=30).stdout
        except (OSError, subprocess.SubprocessError):
            self.skipTest("not a git checkout")
        offenders = []
        for name in filter(None, listed.decode("utf-8").split("\0")):
            path = ROOT / name
            try:
                text = path.read_text(encoding="utf-8")
            except (OSError, UnicodeError):
                continue
            hits = scan_lines(text.splitlines())
            if hits:
                offenders.append((name, hits))
        self.assertEqual(offenders, [])


class CliSecretTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.source = self.root / "sample.txt"
        self.source.write_text("alpha\nbeta\n", encoding="utf-8")
        self.output = self.root / "runs"
        self.provider = SyntheticProvider(fixture=FixtureProvider())

    def run_cli(self, *extra, scope=("--scope", "standalone")):
        out, err = io.StringIO(), io.StringIO()
        argv = [str(self.source), *scope, "--output-dir", str(self.output),
                "--no-whole-file", "--no-bug-lenses", "--max-action-steps", "0", *extra]
        with clean_provider_env(), redirect_stdout(out), redirect_stderr(err), \
                patch.object(cli, "make_provider", return_value=self.provider):
            code = cli.main(argv)
        return code, out.getvalue(), err.getvalue()

    def report(self):
        run = next(self.output.glob("run-*"))
        return json.loads((run / "report.json").read_text(encoding="utf-8"))

    def test_secret_detected_is_a_known_code(self):
        self.assertIn("secret_detected", ERROR_CODES)

    def test_target_with_openrouter_key_refused_exit2(self):
        secret = token("openrouter")
        self.source.write_text(f"alpha\nkey = '{secret}'\n", encoding="utf-8")
        code, out, err = self.run_cli()
        self.assertEqual((code, out), (2, ""))
        self.assertIn("Scan failed (secret_detected).", err)
        self.assertIn("file: line 2 (openrouter)", err)
        self.assertIn("--allow-secrets", err)
        self.assertNotIn(secret, err)
        self.assertNotIn("0123456789abcdef", err)
        self.assertEqual(self.provider.requests, [])
        self.assertFalse(self.output.exists())

    def test_spec_with_secret_refused(self):
        spec = self.root / "spec.txt"
        spec.write_text("must add\n" + token("aws") + "\n", encoding="utf-8")
        code, _, err = self.run_cli("--spec-file", str(spec))
        self.assertEqual(code, 2)
        self.assertIn("specification: line 2 (aws)", err)
        self.assertFalse(self.output.exists())

    def test_scan_runs_before_mkdtemp(self):
        """The refusal precedes check_sensitive, indexing and every directory."""
        self.source.write_text(token("private_key") + "\n", encoding="utf-8")
        project = self.root / "project"
        project.mkdir()
        with patch.object(cli.tempfile, "mkdtemp", side_effect=AssertionError("mkdtemp")), \
                patch.object(ProjectIndex, "read", side_effect=AssertionError("index")), \
                patch.object(self.provider, "check_sensitive",
                             side_effect=AssertionError("check_sensitive")):
            code, _, err = self.run_cli(scope=("--scope", "project",
                                               "--project-root", str(project)))
        self.assertEqual(code, 2)
        self.assertIn("Scan failed (secret_detected).", err)
        self.assertFalse(self.output.exists())

    def test_allow_secrets_records_override(self):
        secret = token("github")
        self.source.write_text(f"alpha\n{secret}\n", encoding="utf-8")
        code, _, err = self.run_cli("--allow-secrets")
        self.assertIn(code, (0, 1), err)
        self.assertIn("file: line 2 (github)", err)
        self.assertNotIn(secret, err)
        report = self.report()
        self.assertEqual(report["secret_scan"], {"target": "overridden",
                                                 "project_files_skipped": 0})
        self.assertTrue(self.provider.requests)

    def test_clean_target_records_clean(self):
        code, _, err = self.run_cli("--allow-secrets")
        self.assertIn(code, (0, 1), err)
        self.assertNotIn("Secret-shaped", err)
        self.assertEqual(self.report()["secret_scan"],
                         {"target": "clean", "project_files_skipped": 0})

    def test_project_file_with_aws_key_skipped_counted(self):
        project = self.root / "project"
        project.mkdir()
        (project / "helper.py").write_bytes(b"def helper():\n    return 1\n")
        (project / "settings.py").write_text(f"KEY = '{token('aws')}'\n", encoding="utf-8")
        index = ProjectIndex.read(project)
        self.assertEqual([e.relpath for e in index.entries], ["helper.py"])
        self.assertEqual((index.skipped_secret_content, index.files_loaded), (1, 1))
        self.assertEqual(index.bytes_loaded, len(b"def helper():\n    return 1\n"))
        code, _, err = self.run_cli(scope=("--scope", "project", "--project-root", str(project)))
        self.assertIn(code, (0, 1), err)
        report = self.report()
        self.assertEqual(report["secret_scan"], {"target": "clean",
                                                 "project_files_skipped": 1})
        self.assertEqual(report["project"]["skipped_secret_content"], 1)
        wire = json.dumps([r.payload.decode("utf-8") if isinstance(r.payload, bytes)
                           else r.payload for r in self.provider.requests])
        self.assertNotIn("SYNTHETIC0FIXT00", wire)
        self.assertNotIn("settings.py", wire)


class ReportShapeTests(unittest.TestCase):
    LEGACY = {
        "answer_defects", "attempts_transmitted", "banners", "cache_hits", "calibration",
        "calls_attempted", "choice_rounding_places", "configuration", "context_scope",
        "contract", "coverage", "decision_actions", "events", "evidence_searches",
        "existence_checks", "findings", "handoff", "handoff_evidence", "handoff_status",
        "issues", "judge_diagnostics", "model", "possible_suppression", "project",
        "provenance", "provider", "question_pack_sha256", "questions_attempted",
        "questions_validated", "rechecks", "refusals", "relationships", "requests",
        "retries", "scan_status", "schema_version", "secret_scan", "source",
        "specification", "specification_mode", "specification_sha256", "spend",
        "status", "stop_reason", "stopped_at_sequence", "synthetic", "tool_version",
        "usage", "windows", "windows_planned"}
    SCOPED = LEGACY | {"assessment_status", "execution_status", "policy_sha256",
                       "scoped_verification"}
    HANDOFF = {"basis", "findings", "handoff_status", "line_numbering", "scan_status",
               "schema_version", "source", "specification", "specification_mode",
               "status", "stop_reason"}

    def test_report_b1_field_set(self):
        legacy = scan(source(4), FixtureProvider(bugs=[(2, 2)]),
                      Config(max_action_steps=0, whole_file=False))
        scoped = scan(source(4), RolesProvider(bugs=[(2, 2)]), beta(run_deadline_seconds=2))
        self.assertEqual((legacy["schema_version"], legacy["handoff"]["schema_version"]), (7, 4))
        self.assertEqual((scoped["schema_version"], scoped["handoff"]["schema_version"]), (8, 5))
        # Judge controls (WP-14, default on) add one record to the b1 set.
        self.assertEqual(set(legacy), self.LEGACY | {"controls"})
        self.assertEqual(set(scoped), self.SCOPED | {"controls"})
        off = scan(source(4), FixtureProvider(bugs=[(2, 2)]),
                   Config(max_action_steps=0, whole_file=False, canaries="off"))
        self.assertEqual(set(off), self.LEGACY)
        self.assertEqual(set(legacy["handoff"]), self.HANDOFF)
        self.assertEqual(set(scoped["handoff"]), self.HANDOFF)
        self.assertIsNone(legacy["secret_scan"])
        self.assertIsNone(legacy["handoff"]["stop_reason"])

    def test_secret_scan_record_validated(self):
        good = {"target": "overridden", "project_files_skipped": 2}
        result = scan(source(2), FixtureProvider(), Config(max_action_steps=0, whole_file=False),
                      secret_scan=good)
        self.assertEqual(result["secret_scan"], good)
        for bad in ({"target": "detected", "project_files_skipped": 0},
                    {"target": "clean", "project_files_skipped": -1},
                    {"target": "clean"}, {"target": "clean", "project_files_skipped": 0,
                                          "extra": 1}, "clean"):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                scan(source(2), FixtureProvider(), Config(), secret_scan=bad)


if __name__ == "__main__":
    unittest.main()
