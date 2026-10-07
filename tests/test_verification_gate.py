"""Revision-3 WP-17: verification gating (``--require-verification``, default off).

With the flag, a suspicion is reported as a finding only when its support
includes a second look: a supporting direct recheck, a promoted relationship
recheck or (scoped-v2-beta) a supported scoped verification. Screen-only
suspicions stay visible as ``unverified_suspicions`` in the report and the
handoff, never as findings. Without the flag the report is the pre-WP-17 one,
byte for byte.
"""
from contextlib import redirect_stderr, redirect_stdout
import dataclasses
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch

from decision_bug_hunter import __main__ as cli
from decision_bug_hunter.core import VERIFICATION_SUPPORT_PATHS, Config, Span
from decision_bug_hunter.engine import Search
from decision_bug_hunter.handoff import format_handoff
from decision_bug_hunter.protocol import ProviderError
from tests.support import FixtureProvider, ranges, scan, source
from tests.test_choice_gate import digests, scenarios
from tests.test_evidence_actions import visible_lines
from tests.test_policy_placement import PRE_WP13
from tests.test_provider_boundary import SyntheticProvider


def disagreeing_recheck(qid, q, state, target):
    # L1-12 screens high but its direct recheck disagrees (screen-only
    # support); the bug line L9-9 is directly rechecked at 0.95.
    if qid.startswith("verify_") and target.size == 12:
        return {"type": "noul", "noul": 0.05}
    return None


def screen_and_recheck(**options):
    """One screen-only span (1-12) and one direct-recheck span (9-9)."""
    provider = FixtureProvider([(9, 9)], override=disagreeing_recheck)
    return scan(source(12), provider, Config(whole_file=False, **options))


def relationship_only(**options):
    """L1-12 is reportable only through a promoted relationship recheck.

    The direct recheck fails (unknown, never a negative), so the evidence
    relationship is the only second look.
    """
    count = {}

    def override(qid, q, state, target):
        if qid.startswith(("screen_", "lens_")):
            return {"type": "noul", "noul": 0.65 if target == Span(1, 12) else 0.05}
        if qid.startswith("verify_") and not qid.startswith("verify_evidence_"):
            raise ProviderError("transport_failed")
        if qid == "continue":
            return {"type": "noul", "noul": 0.95 if target == Span(1, 12) else 0.05}
        if qid == "action":
            choice = "finish"
            if target == Span(1, 12):
                n = count.get(target, 0)
                choice = ["search_file", "test_relationship", "finish"][min(n, 2)]
                count[target] = n + 1
                if choice not in q["criteria"]:
                    choice = "finish"
            return {"type": "choice", "choice": choice, "confidence": 1,
                    "probabilities": {k: int(k == choice) for k in q["criteria"]}}
        if qid.startswith(("evidence_", "relation_", "verify_evidence_")):
            return {"type": "noul", "noul": 0.95 if 100 in visible_lines(state) else 0.05}
        return None

    cfg = Config(whole_file=False, max_action_targets=4, max_action_steps=3,
                 evidence_beam_width=2, evidence_max_depth=4,
                 max_evidence_candidates=40, **options)
    return scan(source(120), FixtureProvider(override=override), cfg)


class ConfigTests(unittest.TestCase):
    def test_flag_defaults_off_and_is_omitted_from_configuration(self):
        self.assertFalse(Config().require_verification)
        self.assertNotIn("require_verification", Config().as_dict())
        self.assertIs(Config(require_verification=True).as_dict()["require_verification"], True)

    def test_flag_must_be_a_bool(self):
        for value in (1, "on", None):
            with self.subTest(value=value), self.assertRaises(ValueError) as raised:
                Config(require_verification=value)
            self.assertEqual(str(raised.exception), "invalid_require_verification_flag")

    def test_second_look_paths(self):
        self.assertEqual(VERIFICATION_SUPPORT_PATHS,
                         ("direct_recheck", "relationship_recheck", "scoped_verification"))
        search = Search(source(12), FixtureProvider(), Config(require_verification=True), None)
        for origin, expected in (("screen", False), ("direct_recheck", True),
                                 ("relationship_recheck", True),
                                 ("scoped_verification", True)):
            span = Span(1, 1 + len(search.support))
            search.add_support(span, 0.9, origin, {}, "V1")
            with self.subTest(origin):
                self.assertIs(search.verification_supported(span), expected)
        self.assertFalse(search.verification_supported(Span(12, 12)))


class GatingTests(unittest.TestCase):
    def test_without_flag_both_are_findings_as_in_b1(self):
        result = screen_and_recheck()
        self.assertEqual(ranges(result), {(1, 12), (9, 9)})
        self.assertEqual({tuple(f["support_paths"]) for f in result["findings"]},
                         {("screen",), ("direct_recheck",)})
        self.assertNotIn("unverified_suspicions", result)
        self.assertNotIn("unverified_suspicions", result["handoff"])
        self.assertNotIn("UNVERIFIED", format_handoff(result["handoff"]))

    def test_require_verification_blocks_screen_only(self):
        result = screen_and_recheck(require_verification=True)
        self.assertEqual(ranges(result), {(9, 9)})
        finding = result["findings"][0]
        self.assertEqual((finding["finding_id"], finding["support_paths"],
                          finding["resolution"]), ("F1", ["direct_recheck"], "directly_rechecked"))
        # The withheld parent is no longer a finding, so it is no parent either.
        self.assertEqual(finding["unresolved_parents"], [])
        self.assertEqual(len(result["unverified_suspicions"]), 1)
        entry = result["unverified_suspicions"][0]
        self.assertEqual((entry["window_id"], entry["start_line"], entry["end_line"]),
                         ("L1-12", 1, 12))
        self.assertEqual(entry["support_paths"], ["screen"])
        self.assertEqual(entry["resolution"], "unresolved_initial_suspicion")
        self.assertEqual(entry["reason"], "no_supporting_recheck")
        # The disagreeing recheck stays visible through the assessment.
        self.assertEqual(entry["assessment"], "conflicting")
        self.assertEqual(result["configuration"]["require_verification"], True)
        # Gating withholds; it never makes the scan incomplete.
        self.assertEqual(result["status"], "complete")

    def test_handoff_lists_unverified(self):
        result = screen_and_recheck(require_verification=True)
        handoff = result["handoff"]
        self.assertEqual([f["suspect"] for f in handoff["findings"]], [[9, 9]])
        self.assertEqual(handoff["unverified_suspicions"],
                         [{"suspect": [1, 12], "assessment": "conflicting"}])
        text = format_handoff(handoff)
        self.assertIn("F1 | suspect: 9-9 | assessment: recheck-supported", text)
        self.assertTrue(text.endswith(
            "\nUNVERIFIED (no supporting recheck; not findings): 1-12 [conflicting]\n"))
        self.assertNotIn("suspect: 1-12", text)

    def test_gating_spends_no_extra_calls(self):
        default = screen_and_recheck()
        gated = screen_and_recheck(require_verification=True)
        # Withheld suspicions get no handoff judgments; the search is unchanged.
        self.assertLessEqual(gated["calls_attempted"], default["calls_attempted"])
        self.assertEqual(gated["windows"], default["windows"])
        self.assertEqual(gated["rechecks"], default["rechecks"])

    def test_relationship_recheck_counts_as_verification(self):
        result = relationship_only(require_verification=True)
        self.assertEqual(ranges(result), {(1, 12)})
        self.assertEqual(result["findings"][0]["support_paths"], ["relationship_recheck"])
        self.assertEqual(result["unverified_suspicions"], [])
        self.assertEqual(result["handoff"]["unverified_suspicions"], [])
        self.assertNotIn("UNVERIFIED", format_handoff(result["handoff"]))

    def test_scoped_screen_only_suspicions_are_withheld(self):
        provider, src, cfg, kwargs = scenarios(require_verification=True)["scoped"]
        result = scan(src, provider, cfg, **kwargs)
        self.assertEqual(result["findings"], [])
        self.assertTrue(result["unverified_suspicions"])
        self.assertTrue(all(u["support_paths"] == ["screen"]
                            for u in result["unverified_suspicions"]))
        self.assertEqual(result["handoff"]["schema_version"], 5)
        self.assertEqual(len(result["handoff"]["unverified_suspicions"]),
                         len(result["unverified_suspicions"]))
        self.assertIn("require_verification", result["configuration"])

    def test_default_reports_byte_identical_to_pre_wp17(self):
        # Every default (canaries on), the flag named explicitly off: the
        # wire and report digests of 7c6896c / 599a1c6.
        for name, (provider, src, cfg, kwargs) in scenarios(
                canaries="on", require_verification=False).items():
            with self.subTest(name):
                self.assertEqual(digests(provider, src, cfg, **kwargs), PRE_WP13[name])

    def test_flag_never_changes_the_wire_when_every_finding_is_verified(self):
        for name in ("legacy", "legacy_spec", "context"):
            with self.subTest(name):
                provider, src, cfg, kwargs = scenarios(canaries="on")[name]
                wire, _ = digests(provider, src,
                                  dataclasses.replace(cfg, require_verification=True), **kwargs)
                self.assertEqual(wire, PRE_WP13[name][0])


class CliTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.source = self.root / "sample.any"
        self.source.write_text("".join(f"line {i}\n" for i in range(1, 13)), encoding="utf-8")
        self.output = self.root / "results"
        self.enterContext(patch.object(cli, "make_provider", return_value=SyntheticProvider()))
        self.enterContext(patch.object(cli, "make_gateway", return_value=Mock()))

    def run_cli(self, *extra):
        def fixture_scan(src, gateway, *, config, context_scope, **_):
            provider = FixtureProvider([(9, 9)], override=disagreeing_recheck)
            return scan(source(12), provider, dataclasses.replace(config, whole_file=False),
                        context_scope=context_scope)
        stdout, stderr = io.StringIO(), io.StringIO()
        argv = [str(self.source), "--output-dir", str(self.output), "--output-format",
                "ranges", "--scope", "standalone", *extra]
        with patch.object(cli, "scan", side_effect=fixture_scan) as scan_mock, \
                redirect_stdout(stdout), redirect_stderr(stderr):
            code = cli.main(argv)
        return code, stdout.getvalue(), stderr.getvalue(), scan_mock

    def saved(self, name):
        return next(self.output.glob("run-*/" + name))

    def test_default_cli_reports_both(self):
        code, out, err, scan_mock = self.run_cli()
        self.assertFalse(scan_mock.call_args.kwargs["config"].require_verification)
        self.assertEqual(code, 1)
        self.assertEqual(out, "Bug suspected between lines 1 and 12.\n"
                              "Bug suspected between lines 9 and 9.\n")
        self.assertIn("2 suspected region(s);", err)
        self.assertNotIn("unverified", err)
        self.assertNotIn("unverified_suspicions",
                         json.loads(self.saved("handoff.json").read_text()))

    def test_require_verification_cli(self):
        code, out, err, scan_mock = self.run_cli("--require-verification")
        self.assertTrue(scan_mock.call_args.kwargs["config"].require_verification)
        self.assertEqual(code, 1)
        self.assertEqual(out, "Bug suspected between lines 9 and 9.\n")
        self.assertIn("1 suspected region(s) (1 unverified suspicion(s) withheld by "
                      "--require-verification);", err)
        report = json.loads(self.saved("report.json").read_text())
        self.assertEqual([(u["start_line"], u["end_line"])
                          for u in report["unverified_suspicions"]], [(1, 12)])
        handoff = json.loads(self.saved("handoff.json").read_text())
        self.assertEqual(handoff["unverified_suspicions"],
                         [{"suspect": [1, 12], "assessment": "conflicting"}])
        self.assertIn("UNVERIFIED (no supporting recheck; not findings): 1-12",
                      self.saved("findings.txt").read_text())

    def test_help_names_the_flag(self):
        self.assertIn("--require-verification", cli.parser().format_help())


if __name__ == "__main__":
    unittest.main()
