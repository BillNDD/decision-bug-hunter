"""The command line of the ``tile-sieve-beta`` search policy, fully offline.

A catalog case runs through ``cli.main`` with the pilot's replay judge and the real
engine and gateway, so the report, the handoff and the summary line are the shipped
ones. A 1,000-line file runs through the legacy-v1 fallback and its stderr notice is
held against the engine's own report. The refusals (a conflicting option, and a judge
without a calibrated threshold set) must come before any read, any output directory
and any provider. No socket is opened and no real key is read.
"""
from __future__ import annotations

from contextlib import redirect_stderr, redirect_stdout
import io
import json
from pathlib import Path
import re
import tempfile
import unittest
from unittest import mock

from decision_bug_hunter import __main__ as cli
from decision_bug_hunter import tile_sieve_plan as plan
from decision_bug_hunter.core import Source
from decision_bug_hunter.decisions import DecisionsProvider
from tests import network_guard
from tests import tile_sieve_replay as replay
from tests.support import clean_provider_env
from tests.test_tile_sieve_engine import LegacyJudge
from tests.test_tile_sieve_plan import synthetic_text

OPENAI_KEY = "offline-openai-sentinel-credential-1a2b"
OPENROUTER_KEY = "offline-openrouter-sentinel-credential-3c4d"
POLICY = ["--search-policy", "tile-sieve-beta"]
NO_CALIBRATION = ("Scan failed (invalid_search_configuration: tile-sieve-beta has no "
                  "calibrated thresholds for judge microsoft).\n")
MICROSOFT_NOTICE = "Note: Microsoft-Decision-1 support is experimental"
FALLBACK = re.compile(r"^Search policy tile-sieve-beta: the file does not fit in one "
                      r"request \((\w+): (?:at least )?([\d,]+) B > ([\d,]+) B\); scanning "
                      r"with legacy-v1\.$",
                      re.MULTILINE)


def run_cli(argv, **environment):
    out, err = io.StringIO(), io.StringIO()
    with clean_provider_env(**environment), redirect_stdout(out), redirect_stderr(err):
        code = cli.main(argv)
    return code, out.getvalue(), err.getvalue()


def single_run(directory: Path) -> Path:
    runs = [path for path in directory.iterdir() if path.name.startswith("run-")]
    assert len(runs) == 1, runs
    return runs[0]


class NoNetworkTests(unittest.TestCase):
    def test_the_suite_runs_under_the_network_guard(self):
        self.assertTrue(network_guard.active())


class HelpTests(unittest.TestCase):
    def help_text(self):
        out = io.StringIO()
        with redirect_stdout(out), self.assertRaises(SystemExit) as caught:
            cli.main(["--help"])
        self.assertEqual(caught.exception.code, 0)
        return " ".join(out.getvalue().split())

    def test_help_lists_the_choice(self):
        text = self.help_text()
        self.assertIn("--search-policy {legacy-v1,scoped-v2-beta,tile-sieve-beta}", text)

    def test_help_describes_the_beta(self):
        text = self.help_text()
        for phrase in ("opt-in whole-file beta calibrated for the OpenAI judge only",
                       "(no stage 2)", "strong regions report at a lower bar",
                       "A larger file is scanned with legacy-v1",
                       "--canaries on, --state-layout v1 and --policy-placement instructions"):
            with self.subTest(phrase=phrase):
                self.assertIn(phrase, text)
        self.assertNotIn("second request", text)

    def test_the_default_policy_is_unchanged(self):
        args = cli.parser().parse_args(["target.py"])
        self.assertEqual(args.search_policy, "legacy-v1")

    def test_an_unknown_policy_is_a_usage_error(self):
        err = io.StringIO()
        with redirect_stderr(err), self.assertRaises(SystemExit) as caught:
            cli.main(["target.py", "--search-policy", "tile-sieve"])
        self.assertEqual(caught.exception.code, 2)
        self.assertEqual(err.getvalue(),
                         "Invalid command-line arguments; use --help for usage.\n")


@unittest.skipUnless(replay.EVAL.is_dir() and replay.FIXTURE.is_file(),
                     "catalog tools or fixtures absent")
class CatalogCliTests(unittest.TestCase):
    """Catalog cases C001 (a defect), C002 (clear) and C033 (unresolved), through the CLI."""

    @classmethod
    def setUpClass(cls):
        fixture = replay.load_fixture()
        cls.table = replay.requests_by_sha(fixture)
        cls.cases = {case["id"]: case for case in replay.tool("catalog").cases()}

    def run_case(self, case_id, *extra):
        case = self.cases[case_id]
        provider = replay.ReplayProvider(self.table)
        with tempfile.TemporaryDirectory() as temp:
            argv, out = replay.tool("run_catalog").materialize(case, Path(temp))
            with mock.patch.object(cli, "make_provider", return_value=provider):
                code, stdout, stderr = run_cli(argv + POLICY + list(extra))
            run = single_run(out)
            files = {name: (run / name).read_text(encoding="utf-8")
                     for name in ("report.json", "handoff.json", "findings.txt", "ranges.txt")}
        self.assertEqual(provider.unknown, [])
        return code, stdout, stderr, files, provider

    def test_a_defect_exits_1_with_the_whole_file_report(self):
        code, stdout, stderr, files, provider = self.run_case("C001")
        self.assertEqual(code, 1)
        report = json.loads(files["report.json"])
        self.assertEqual(report["schema_version"], 9)
        self.assertEqual(report["configuration"]["search_policy"], "tile-sieve-beta")
        self.assertEqual(report["tile_sieve"]["mode"], "whole-file")
        self.assertEqual(report["tile_sieve"]["policy_run"], "tile-sieve-beta")
        self.assertEqual(len(report["findings"]), 1)
        # Two protocol calls: the look (a 2-line file is one look) and the focus request.
        self.assertEqual(len(provider.sent), 2)
        self.assertEqual(report["calls_attempted"], 2)

    def test_the_handoff_is_version_6_with_a_search_block_and_the_search_line(self):
        _code, stdout, _stderr, files, _provider = self.run_case("C001")
        handoff = json.loads(files["handoff.json"])
        self.assertEqual(handoff["schema_version"], 6)
        self.assertEqual(handoff["search"], {"policy": "tile-sieve-beta", "mode": "whole-file",
                                             "policy_run": "tile-sieve-beta"})
        self.assertEqual(json.loads(stdout), handoff)
        self.assertIn("\nSEARCH: tile-sieve-beta whole-file\n", files["findings.txt"])
        self.assertEqual(json.loads(files["report.json"])["handoff"], handoff)

    def test_the_summary_line_names_the_policy_that_ran(self):
        _code, _stdout, stderr, _files, _provider = self.run_case("C001")
        summary = [line for line in stderr.splitlines() if line.startswith("Scan ")]
        self.assertEqual(len(summary), 1)
        self.assertTrue(summary[0].endswith(" source lines assessed (tile-sieve-beta whole-file)."),
                        summary[0])
        self.assertNotIn("legacy-v1", stderr)
        self.assertNotIn("does not fit", stderr)

    def test_a_clear_file_exits_0(self):
        code, _stdout, _stderr, files, provider = self.run_case("C002")
        self.assertEqual(code, 0)
        report = json.loads(files["report.json"])
        self.assertEqual((report["status"], report["findings"]), ("complete", []))
        self.assertEqual(report["schema_version"], 9)
        self.assertEqual(len(provider.sent), 1)
        self.assertIn("\nSEARCH: tile-sieve-beta whole-file\n", files["findings.txt"])

    def test_an_unresolved_case_is_incomplete_and_exits_2(self):
        code, _stdout, stderr, files, _provider = self.run_case("C033")
        self.assertEqual(code, 2)
        report = json.loads(files["report.json"])
        self.assertEqual(report["status"], "incomplete")
        self.assertIn("context_unresolved", [issue["code"] for issue in report["issues"]])
        self.assertIn("Scan incomplete;", stderr)
        self.assertTrue(stderr.rstrip().endswith("(tile-sieve-beta whole-file)."), stderr)

    def test_the_other_options_are_accepted_and_do_not_change_a_whole_file_run(self):
        base = self.run_case("C001")
        other = self.run_case("C001", "--width", "24", "--max-depth", "2", "--no-bug-lenses")
        self.assertEqual(other[0], base[0])
        self.assertEqual(json.loads(other[3]["handoff.json"])["findings"],
                         json.loads(base[3]["handoff.json"])["findings"])


class FallbackCliTests(unittest.TestCase):
    """A 1,000-line file cannot be read in one request: legacy-v1 runs and stderr says so."""

    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory()
        cls.addClassCleanup(cls.temp.cleanup)
        root = Path(cls.temp.name)
        target = root / "subject.py"
        target.write_bytes(synthetic_text(1000).encode("utf-8"))
        out = root / "out"
        judge = LegacyJudge()
        argv = [str(target), "--scope", "standalone", "--output-dir", str(out),
                "--output-format", "json", "--width", "200", "--min-width", "100",
                "--max-depth", "1", "--max-calls", "400", *POLICY]
        with mock.patch.object(cli, "make_provider", return_value=judge):
            cls.code, cls.stdout, cls.stderr = run_cli(argv)
        run = single_run(out)
        cls.report = json.loads((run / "report.json").read_text(encoding="utf-8"))
        cls.findings = (run / "findings.txt").read_text(encoding="utf-8")
        cls.source = Source.read(target)
        cls.judge = judge

    def test_the_notice_is_printed_once_before_the_run_starts(self):
        notices = [line for line in self.stderr.splitlines()
                   if line.startswith("Search policy tile-sieve-beta")]
        self.assertEqual(len(notices), 1, self.stderr)
        self.assertRegex(notices[0], FALLBACK)
        lines = self.stderr.splitlines()
        results = [i for i, line in enumerate(lines) if line.startswith("Results run:")]
        self.assertEqual(len(results), 1)
        self.assertLess(lines.index(notices[0]), results[0])
        self.assertLess(lines.index(notices[0]),
                        [i for i, line in enumerate(lines) if line.startswith("Intent is")][0])

    def test_the_notice_agrees_with_the_engine_report(self):
        block = self.report["tile_sieve"]
        self.assertEqual((block["mode"], block["policy_run"]), ("legacy-fallback", "legacy-v1"))
        reason, size, limit = FALLBACK.search(self.stderr).groups()
        self.assertEqual(reason, block["reason"])
        self.assertEqual(int(size.replace(",", "")), block["detail"]["bytes"])
        self.assertEqual(int(limit.replace(",", "")), block["detail"]["limit"])
        planned = plan.plan_whole_file(self.source, None, (), "declared_standalone")
        self.assertIsInstance(planned, plan.Fallback)
        self.assertEqual((planned.reason, planned.detail), (block["reason"], block["detail"]))

    def test_the_run_is_a_legacy_scan_marked_as_a_fallback(self):
        self.assertEqual(self.report["schema_version"], 9)
        self.assertEqual(self.report["configuration"]["search_policy"], "tile-sieve-beta")
        handoff = json.loads(self.stdout)
        self.assertEqual(handoff["schema_version"], 6)
        self.assertEqual(handoff["search"], {"policy": "tile-sieve-beta",
                                             "mode": "legacy-fallback",
                                             "policy_run": "legacy-v1",
                                             "reason": self.report["tile_sieve"]["reason"]})
        self.assertIn(f"\nSEARCH: tile-sieve-beta -> legacy-v1 "
                      f"({self.report['tile_sieve']['reason']})\n", self.findings)
        self.assertGreater(len(self.judge.sent), 10)

    def test_the_summary_line_says_so(self):
        summary = [line for line in self.stderr.splitlines() if line.startswith("Scan ")]
        self.assertEqual(len(summary), 1)
        self.assertTrue(summary[0].endswith(" (tile-sieve-beta: legacy-v1 fallback)."), summary[0])

    def test_the_exit_code_is_the_legacy_one(self):
        complete = self.report["status"] == "complete"
        expected = 2 if not complete else (1 if self.report["findings"] else 0)
        self.assertEqual(self.code, expected)


class NoticeTextTests(unittest.TestCase):
    """The one stderr line, for every shape of fallback detail."""

    def notice(self, reason, detail=None):
        found = plan.Fallback(reason, detail or {})
        with mock.patch.object(plan, "plan_whole_file", return_value=found):
            return cli.fallback_notice(Source.from_text("a = 1\n", "a.py"), None, None,
                                       "declared_standalone")

    def test_a_request_over_the_byte_cap(self):
        self.assertEqual(
            self.notice("request_bytes", {"bytes": 24493, "limit": 24064}),
            "Search policy tile-sieve-beta: the file does not fit in one request "
            "(request_bytes: 24,493 B > 24,064 B); scanning with legacy-v1.")

    def test_a_state_over_its_cap_and_a_floor_bound(self):
        self.assertIn("(state_bytes: 16,000 B > 15,872 B)",
                      self.notice("state_bytes", {"bytes": 16000, "limit": 15872}))
        self.assertIn("(state_bytes: at least 16,000 B > 15,872 B)",
                      self.notice("state_bytes", {"bytes": 16000, "limit": 15872,
                                                  "at_least": True}))

    def test_too_many_questions_and_a_split(self):
        self.assertIn("(too_many_questions: 70 > 64 questions)",
                      self.notice("too_many_questions", {"questions": 70, "limit": 64}))
        self.assertIn("(split_into_batches: 2 batches)",
                      self.notice("split_into_batches", {"batches": 2}))

    def test_reasons_without_a_detail(self):
        for reason in ("canaries_do_not_fit", "question_too_large", "provider_request_too_large"):
            with self.subTest(reason=reason):
                self.assertIn(f"({reason}); scanning with legacy-v1.", self.notice(reason))

    def test_an_empty_file(self):
        self.assertEqual(self.notice("empty_file"),
                         "Search policy tile-sieve-beta: the file is empty; "
                         "scanning with legacy-v1.")

    def test_a_file_that_fits_has_no_notice(self):
        source = Source.from_text("def f(x):\n    return x\n", "f.py")
        self.assertIsNone(cli.fallback_notice(source, None, None, "declared_standalone"))

    def test_an_integrity_failure_is_not_a_fallback(self):
        with mock.patch.object(plan, "plan_whole_file", side_effect=plan.IntegrityError("x")):
            with self.assertRaises(plan.IntegrityError):
                cli.fallback_notice(Source.from_text("a = 1\n", "a.py"), None, None,
                                    "declared_standalone")


class Untouched(unittest.TestCase):
    """The refusals happen before a read, an output directory or a provider."""

    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)
        self.target = self.root / "target.py"
        self.target.write_text("a = 1\nb = a / 0\n", encoding="utf-8")
        self.out = self.root / "out"
        self.read = self.enterContext(mock.patch.object(cli.Source, "read"))
        self.build = self.enterContext(mock.patch.object(cli.providers, "make_provider"))
        # A spy on the class itself: the CLI's provider name is never replaced
        # (test_offline_harness), and an OpenAI provider still builds for real.
        self.decisions = self.enterContext(mock.patch.object(
            DecisionsProvider, "__init__", autospec=True,
            side_effect=DecisionsProvider.__init__))

    def argv(self, *extra):
        return [str(self.target), "--scope", "standalone", "--output-dir", str(self.out),
                *extra]

    def assert_untouched(self):
        self.read.assert_not_called()
        self.build.assert_not_called()
        self.decisions.assert_not_called()
        self.assertFalse(self.out.exists())
        self.assertEqual(sorted(path.name for path in self.root.iterdir()), ["target.py"])


class RefusedOptionTests(Untouched):
    CASES = (
        (["--canaries", "off"], "tile-sieve-beta needs --canaries on"),
        (["--state-layout", "v2"], "tile-sieve-beta needs --state-layout v1"),
        (["--policy-placement", "state"], "tile-sieve-beta needs --policy-placement instructions"),
        (["--polarity-twin"], "tile-sieve-beta does not support --polarity-twin"),
        (["--require-verification"], "tile-sieve-beta does not support --require-verification"),
    )

    def test_each_conflicting_option_exits_2_with_its_flag_named(self):
        for options, detail in self.CASES:
            with self.subTest(options=options):
                code, out, err = run_cli(self.argv(*POLICY, *options))
                self.assertEqual(code, 2)
                self.assertEqual(out, "")
                self.assertEqual(err, f"Scan failed (invalid_search_configuration: {detail}).\n")
                self.assert_untouched()

    def test_the_refusal_comes_before_the_judge_is_asked_for(self):
        # No --judge and no --provider: a NEED_USER_INPUT (exit 3) would mean the order is wrong.
        code, _out, err = run_cli(self.argv(*POLICY, "--canaries", "off"))
        self.assertEqual(code, 2)
        self.assertNotIn("NEED_USER_INPUT", err)

    def test_the_first_conflict_in_a_fixed_order_is_named(self):
        _code, _out, err = run_cli(self.argv(*POLICY, "--require-verification", "--canaries",
                                             "off", "--polarity-twin"))
        self.assertIn("needs --canaries on", err)

    def test_the_same_options_are_not_refused_for_the_other_policies(self):
        for policy in ("legacy-v1", "scoped-v2-beta"):
            args = cli.parser().parse_args(self.argv(
                "--search-policy", policy, "--canaries", "off", "--state-layout", "v2",
                "--policy-placement", "state", "--polarity-twin", "--require-verification"))
            self.assertIsNone(cli.tile_sieve_conflict(args))
        args = cli.parser().parse_args(self.argv(*POLICY))
        self.assertIsNone(cli.tile_sieve_conflict(args))


class MicrosoftRefusalTests(Untouched):
    def test_every_microsoft_route_is_refused_with_nothing_read_or_written(self):
        for route in ("openrouter", "foundry"):
            with self.subTest(route=route):
                code, out, err = run_cli(
                    self.argv("--judge", "microsoft", "--provider", route, *POLICY),
                    OPENROUTER_API_KEY=OPENROUTER_KEY)
                self.assertEqual((code, out, err), (2, "", NO_CALIBRATION))
                self.assert_untouched()

    def test_the_refusal_names_no_notice_and_no_credential(self):
        _code, _out, err = run_cli(
            self.argv("--judge", "microsoft", "--provider", "openrouter", *POLICY),
            OPENROUTER_API_KEY=OPENROUTER_KEY)
        self.assertNotIn(MICROSOFT_NOTICE, err)
        self.assertNotIn(OPENROUTER_KEY, err)

    def test_the_refusal_is_made_right_after_the_judge_is_chosen(self):
        # A route that is not the judge's, or no route at all, still gets this refusal.
        for extra in (["--provider", "openai"], []):
            with self.subTest(extra=extra):
                code, out, err = run_cli(self.argv("--judge", "microsoft", *extra, *POLICY))
                self.assertEqual((code, out, err), (2, "", NO_CALIBRATION))
                self.assert_untouched()

    def test_the_judge_from_the_environment_is_refused_too(self):
        code, out, err = run_cli(self.argv("--provider", "openrouter", *POLICY),
                                 DBH_JUDGE="microsoft", OPENROUTER_API_KEY=OPENROUTER_KEY)
        self.assertEqual((code, out, err), (2, "", NO_CALIBRATION))
        self.assert_untouched()

    def test_a_conflicting_option_is_named_before_the_judge_is_considered(self):
        _code, _out, err = run_cli(self.argv("--judge", "microsoft", "--provider", "openrouter",
                                             *POLICY, "--canaries", "off"),
                                   OPENROUTER_API_KEY=OPENROUTER_KEY)
        self.assertIn("needs --canaries on", err)
        self.assertNotIn("no calibrated thresholds", err)

    def test_the_microsoft_judge_still_runs_the_other_policies(self):
        args = cli.parser().parse_args(self.argv("--judge", "microsoft", "--provider",
                                                 "openrouter", "--search-policy", "scoped-v2-beta"))
        with clean_provider_env(OPENROUTER_API_KEY=OPENROUTER_KEY):
            cli.make_provider(args)
        self.build.assert_called_once()

    def test_the_openai_judge_is_not_refused(self):
        for route in ("openai", "openrouter"):
            with self.subTest(route=route):
                self.build.reset_mock()
                self.decisions.reset_mock()
                args = cli.parser().parse_args(self.argv("--judge", "openai", "--provider",
                                                         route, *POLICY))
                with clean_provider_env(OPENAI_API_KEY=OPENAI_KEY,
                                        OPENROUTER_API_KEY=OPENROUTER_KEY):
                    cli.make_provider(args)
                self.assertEqual(self.build.call_count + self.decisions.call_count, 1)

    def test_the_check_is_the_threshold_file_not_a_judge_name(self):
        cli.require_calibrated_judge("legacy-v1", "microsoft")
        cli.require_calibrated_judge("tile-sieve-beta", "openai")
        with self.assertRaises(cli.SearchPolicyRefused) as caught:
            cli.require_calibrated_judge("tile-sieve-beta", "microsoft")
        self.assertEqual(caught.exception.detail,
                         "tile-sieve-beta has no calibrated thresholds for judge microsoft")


class RealOpenAiProviderTests(unittest.TestCase):
    def test_the_openai_judge_builds_its_provider_under_the_policy(self):
        args = cli.parser().parse_args(["t.py", "--scope", "standalone", "--judge", "openai",
                                        "--provider", "openai", *POLICY])
        with clean_provider_env(OPENAI_API_KEY=OPENAI_KEY):
            provider = cli.make_provider(args)
        self.assertIsInstance(provider, DecisionsProvider)


if __name__ == "__main__":
    unittest.main()
