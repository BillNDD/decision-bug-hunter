"""The Tile Sieve engine: the pilot's catalog replayed through the real engine and gateway.

Nothing is sent anywhere. The decisive test builds the 34 catalog cases through
``core.scan`` over a real ``ValidatedGateway`` whose provider answers by the sha256 of
the request bytes from the pilot's recorded answers and fails on any unknown hash: every
request the engine sends is byte-identical to the pilot's, and the outcome is the 8C
replay's (34/34, 53 requests: 36 tiles and 17 focus). The other tests change recorded
answers, thresholds or budgets to reach the refusal, incomplete and fallback paths.
"""
from __future__ import annotations

import copy
import dataclasses
from decimal import Decimal
import hashlib
import json
from pathlib import Path
import re
import tempfile
import types
import unittest
from unittest import mock

from decision_bug_hunter import protocol
from decision_bug_hunter import tile_sieve
from decision_bug_hunter import tile_sieve_fusion as fusion
from decision_bug_hunter import tile_sieve_plan as plan
from decision_bug_hunter.core import Config, Source, Span, scan
from decision_bug_hunter.engine import Search
from decision_bug_hunter import handoff
from decision_bug_hunter.handoff import format_handoff
from decision_bug_hunter.hosted import ModelSpec
from decision_bug_hunter.providers import (ProviderIdentity, ProviderResponse, RetryPolicy,
                                           ValidatedGateway)
from tests import network_guard
from tests import tile_sieve_replay as replay
from tests.support import FixtureProvider, control_answer, is_control, spans_in

OPENAI_SPEC = ModelSpec("offline-replay", price_in_per_mtok=Decimal("0.10"),
                        price_out_upper_per_mtok=Decimal("0"),
                        confidence_identity="chance_normalized_p1")
TILE_SIEVE = Config(search_policy="tile-sieve-beta")


def exit_code(result):
    """The exit code the CLI gives a result: 2 incomplete, else 1 with findings, else 0."""
    if result["status"] != "complete":
        return 2
    return 1 if result["findings"] else 0


def patched_thresholds(**changes):
    """Patch the packaged threshold file with *changes* to the ``openai`` entry.

    ``microsoft=True`` adds a ``microsoft`` entry copied from the changed ``openai`` one."""
    microsoft = changes.pop("microsoft", False)
    data = json.loads(fusion._read_file())
    entry = data["judges"]["openai"]
    entry.update(changes)
    if microsoft:
        data["judges"]["microsoft"] = copy.deepcopy(entry)
    raw = json.dumps(data).encode("utf-8")
    return mock.patch.object(fusion, "_read_file", return_value=raw)


def control_flipper(shas):
    """An ``edit`` for ReplayProvider that flips every control answer of the given requests."""
    def edit(sha, answers, scoped):
        if sha in shas:
            for qid, answer in answers.items():
                if is_control(qid):
                    answer["noul"] = 1 - answer["noul"]
    return edit


class NoNetworkTests(unittest.TestCase):
    def test_the_suite_runs_under_the_network_guard(self):
        self.assertTrue(network_guard.active())


class ConfigTests(unittest.TestCase):
    def test_the_policy_is_accepted_with_its_defaults(self):
        config = Config(search_policy="tile-sieve-beta")
        self.assertEqual(config.as_dict()["search_policy"], "tile-sieve-beta")

    def test_every_forbidden_combination_is_refused(self):
        for options in ({"canaries": "off"}, {"state_layout": "v2"},
                        {"policy_placement": "state"}, {"polarity_twin": True},
                        {"require_verification": True}):
            with self.subTest(options=options):
                with self.assertRaises(ValueError) as caught:
                    Config(search_policy="tile-sieve-beta", **options)
                self.assertEqual(str(caught.exception), "invalid_search_configuration")

    def test_the_same_options_stay_valid_for_the_other_policies(self):
        for policy in ("legacy-v1", "scoped-v2-beta"):
            Config(search_policy=policy, canaries="off", state_layout="v2",
                   policy_placement="state", polarity_twin=True, require_verification=True)

    def test_an_unknown_policy_is_still_refused(self):
        with self.assertRaises(ValueError) as caught:
            Config(search_policy="tile-sieve")
        self.assertEqual(str(caught.exception), "invalid_search_policy")


@unittest.skipUnless(replay.EVAL.is_dir() and replay.FIXTURE.is_file(),
                     "catalog tools or fixtures absent")
class CatalogReplayTests(unittest.TestCase):
    """The 34 catalog cases through the real engine, answered from the pilot's recordings."""

    @classmethod
    def setUpClass(cls):
        cls.fixture = replay.load_fixture()
        cls.cases = {case["id"]: case for case in cls.fixture["cases"]}
        cls.table = replay.requests_by_sha(cls.fixture)
        cls.tmp = tempfile.TemporaryDirectory()
        cls.addClassCleanup(cls.tmp.cleanup)
        cls.inputs = {item.case["id"]: item
                      for item in replay.catalog_inputs(Path(cls.tmp.name))}
        cls.provider = replay.ReplayProvider(cls.table)
        cls.results = {cid: replay.run_case(item, cls.provider)
                       for cid, item in cls.inputs.items()}

    def run_case(self, cid, **kwargs):
        provider = kwargs.pop("provider", None) or replay.ReplayProvider(self.table)
        return replay.run_case(self.inputs[cid], provider, **kwargs), provider

    def expected_shas(self):
        tiles, focus = set(), set()
        for case in self.cases.values():
            for tile in case["tiles"]:
                if not (case["n"] <= 8 and tile["looks"] == [1]):
                    tiles.add(tile["sha256"])
            focus.update(row["sha256"] for row in case["focus"])
        return tiles, focus

    def test_catalog_replay_is_the_pilot(self):
        tiles, focus = self.expected_shas()
        self.assertEqual((len(tiles), len(focus)), (36, 17))
        # Every request is one the pilot sent, none is sent twice, and none is missing.
        self.assertEqual(self.provider.unknown, [])
        self.assertEqual(len(self.provider.sent), 53)
        self.assertEqual(set(self.provider.sent), tiles | focus)
        self.assertEqual(sum(r["calls_attempted"] for r in self.results.values()), 53)
        run_catalog = replay.tool("run_catalog")
        location = strict = 0
        for cid, result in self.results.items():
            case, expected = self.cases[cid], self.cases[cid]["expected_outcome"]
            with self.subTest(case=cid):
                self.assertEqual([[f["start_line"], f["end_line"]] for f in result["findings"]],
                                 expected["findings"])
                self.assertEqual(result["status"], expected["status"])
                self.assertEqual(result["schema_version"], 9)
                self.assertEqual(result["handoff"]["schema_version"], 6)
                self.assertEqual(result["handoff"]["search"],
                                 {"policy": "tile-sieve-beta", "mode": "whole-file",
                                  "policy_run": "tile-sieve-beta"})
                block = result["tile_sieve"]
                self.assertEqual(block["thresholds_set"], "openai")
                self.assertIs(block["judge_declared"], False)
                self.assertEqual(block["thresholds_sha256"], fusion.thresholds_sha256())
                self.assertEqual(block["screening_rule"], "pilot-full")
                self.assertEqual(block["thresholds"], fusion.load_thresholds("openai").as_dict())
                self.assertEqual(result["configuration"]["search_policy"], "tile-sieve-beta")
                self.assertEqual(result["controls"]["requests_failed"], 0)
                judged = run_catalog.judge(self.cases_catalog()[cid], result, exit_code(result))
                location += judged["location_pass"]
                strict += judged["strict_pass"]
                self.assertEqual(case["n"], result["source"]["line_count"])
        self.assertEqual(location, 34)
        # The strict score needs a helper citation that Tile Sieve does not make (C025, C027).
        self.assertEqual(strict, 32)

    def cases_catalog(self):
        return {item.case["id"]: item.case for item in self.inputs.values()}

    def test_clusters_decide_like_the_recorded_focus_requests(self):
        for cid, case in self.cases.items():
            clusters = self.results[cid]["tile_sieve"]["clusters"]
            with self.subTest(case=cid):
                self.assertEqual(len(clusters), len(case["focus"]))
                for got, row in zip(clusters, case["focus"]):
                    self.assertEqual(got["K"], row["K"])
                    self.assertEqual(got["focus_sha256"], row["sha256"])
                    self.assertEqual(float(got["E"]), row["E"])
                    self.assertEqual(got["decision"], row["decision"])
                    self.assertEqual(got["runs"], [list(run) for run in row["runs"]])
                    self.assertIs(got["twin_refused"], False)
                    self.assertEqual(got["bar"], "strong")
                    self.assertEqual(got["bar_value"], "0.39")
                    self.assertIs(got["strong"], True)

    def test_only_the_planned_phases_are_asked_and_stage_two_is_gone(self):
        phases = {row["phase"] for result in self.results.values() for row in result["requests"]}
        self.assertEqual(phases, {"ts-screen-l0", "ts-screen-l1", "ts-focus"})
        for result in self.results.values():
            self.assertNotIn("stage2", json.dumps(result["tile_sieve"]))

    def test_short_files_are_read_once_and_longer_files_twice(self):
        for cid, case in self.cases.items():
            block = self.results[cid]["tile_sieve"]
            with self.subTest(case=cid):
                if case["n"] <= 8:
                    self.assertEqual(block["looks"], 1)
                    self.assertEqual([d["looks_served"] for d in block["looks_detail"]], [[0, 1]])
                else:
                    self.assertEqual(block["looks"], 2)
                    self.assertEqual([d["looks_served"] for d in block["looks_detail"]],
                                     [[0], [1]])

    def test_the_unresolved_cases_are_incomplete_with_context_unresolved(self):
        for cid in ("C033", "C034"):
            result = self.results[cid]
            with self.subTest(case=cid):
                self.assertEqual(result["status"], "incomplete")
                self.assertEqual(result["findings"], [])
                self.assertIn(("context_unresolved", [1, 3]),
                              [(i["code"], i["range"]) for i in result["issues"]
                               if i["affects_completion"]])

    def test_the_report_is_plain_json(self):
        for result in self.results.values():
            self.assertEqual(json.loads(json.dumps(result)), result)

    def test_support_names_the_requests_that_flagged_and_decided(self):
        result = self.results["C029"]
        by_sha = {row["request_sha256"]: row for row in result["requests"]}
        for finding in result["findings"]:
            self.assertEqual(finding["resolution"], "focus_reported")
            self.assertEqual(finding["assessment"], "focus-supported")
            self.assertEqual(finding["support_paths"], ["focus", "tile_screen"])
            for row in finding["support"]:
                self.assertIn(row["request_sha256"], by_sha)
            self.assertEqual(finding["support"][-1]["origin"], "focus")
            self.assertEqual(by_sha[finding["support"][-1]["request_sha256"]]["phase"],
                             "ts-focus")

    def test_support_rows_carry_the_cells_and_the_score_that_decided(self):
        result = self.results["C029"]
        block = result["tile_sieve"]
        self.assertTrue(result["findings"])
        for finding in result["findings"]:
            expected = []
            for cluster in block["clusters"]:
                if cluster["decision"] != "report" or not any(
                        finding["start_line"] <= a and b <= finding["end_line"]
                        for a, b in cluster["runs"]):
                    continue
                lo, hi = cluster["core"]
                for look in block["looks_detail"]:
                    expected += [("tile_screen", look["request_sha256"], tuple(cell))
                                 for cell in look["flagged"] if cell[0] <= hi and lo <= cell[1]]
                expected.append(("focus", cluster["focus_sha256"], cluster["E"]))
            got = [(row["origin"], row["request_sha256"],
                    tuple(row["cell"]) if row["origin"] == "tile_screen" else row["E"])
                   for row in finding["support"]]
            self.assertEqual(got, expected)
            self.assertIn("tile_screen", finding["support_paths"])
            for row in finding["support"]:
                if row["origin"] == "tile_screen":
                    self.assertTrue(row["why"])

    # -- a judge declared by the gateway -----------------------------------------------
    def test_a_declared_openai_judge_is_recorded_as_declared(self):
        provider = replay.ReplayProvider(self.table, model_spec=OPENAI_SPEC)
        result, _ = self.run_case("C001", provider=provider)
        block = result["tile_sieve"]
        self.assertEqual(block["thresholds_set"], "openai")
        self.assertIs(block["judge_declared"], True)
        self.assertNotIn("judge", result)
        self.assertEqual(result["findings"][0]["start_line"], 1)

    def test_a_judge_without_a_calibrated_set_is_refused_before_any_call(self):
        spec = ModelSpec("offline-replay", price_in_per_mtok=Decimal("0.042"),
                         price_out_upper_per_mtok=Decimal("0"), judge="microsoft",
                         probability_precision="full")
        provider = replay.ReplayProvider(self.table, model_spec=spec)
        with self.assertRaises(ValueError) as caught:
            self.run_case("C001", provider=provider)
        self.assertEqual(str(caught.exception), "invalid_search_configuration")
        self.assertEqual(provider.sent, [])

    def test_a_judge_with_a_set_uses_it(self):
        spec = ModelSpec("offline-replay", price_in_per_mtok=Decimal("0.042"),
                         price_out_upper_per_mtok=Decimal("0"), judge="microsoft",
                         probability_precision="full")
        provider = replay.ReplayProvider(self.table, model_spec=spec)
        with patched_thresholds(microsoft=True, tau_strong="0.30"):
            result, _ = self.run_case("C001", provider=provider)
        block = result["tile_sieve"]
        self.assertEqual((block["thresholds_set"], block["judge_declared"]), ("microsoft", True))
        self.assertEqual(block["thresholds"]["judge"], "microsoft")
        self.assertEqual(block["thresholds"]["tau_strong"], 0.30)
        self.assertEqual(block["clusters"][0]["bar_value"], "0.3")
        self.assertEqual(result["judge"], "microsoft")

    # -- the 8C report rule --------------------------------------------------------------
    def test_a_strong_cluster_reports_at_the_strong_bar_and_another_at_tau_rep(self):
        strong, _ = self.run_case("C017")
        self.assertEqual([f["start_line"] for f in strong["findings"]], [1])
        # Without the strong floor the same cluster must reach tau_rep(n), here 0.95.
        with patched_thresholds(strong_cell="0.99", tau_rep_points=[[200, "0.95"]]):
            other, _ = self.run_case("C017")
        cluster = other["tile_sieve"]["clusters"][0]
        self.assertEqual((cluster["strong"], cluster["bar"], cluster["bar_value"]),
                         (False, "tau_rep", "0.95"))
        self.assertEqual(cluster["decision"], "clear")
        self.assertEqual((other["findings"], other["status"]), ([], "complete"))
        # And at 0.54 it reports again at the lower, non-strong bar.
        with patched_thresholds(strong_cell="0.99"):
            low, _ = self.run_case("C017")
        self.assertEqual(low["tile_sieve"]["clusters"][0]["bar_value"], "0.54")
        self.assertEqual([f["start_line"] for f in low["findings"]], [1])

    def test_leaf_only_screening_gives_the_same_catalog_outcome(self):
        provider = replay.ReplayProvider(self.table)
        with patched_thresholds(screening_rule="leaf-only"):
            results = {cid: replay.run_case(item, provider)
                       for cid, item in self.inputs.items()}
        self.assertEqual(provider.unknown, [])
        run_catalog = replay.tool("run_catalog")
        for cid, result in results.items():
            with self.subTest(case=cid):
                self.assertEqual(result["tile_sieve"]["screening_rule"], "leaf-only")
                # Strength reads the raw scores, so the report bar does not depend on the variant.
                self.assertTrue(all(c["strong"] and c["bar"] == "strong"
                                    for c in result["tile_sieve"]["clusters"]))
                judged = run_catalog.judge(self.cases_catalog()[cid], result, exit_code(result))
                self.assertTrue(judged["location_pass"], judged)
                self.assertEqual([[f["start_line"], f["end_line"]] for f in result["findings"]],
                                 self.cases[cid]["expected_outcome"]["findings"])

    # -- refused answers -----------------------------------------------------------------
    def refuse(self, sha_roles):
        """An ``edit`` that refuses the question of each (request sha, role name) given."""
        def edit(sha, answers, scoped):
            row = self.table[sha][2]
            for wanted_sha, role in sha_roles:
                if sha == wanted_sha:
                    for qid, info in row["roles"].items():
                        if info["role"] == role:
                            del answers[qid]
                            scoped[qid] = "question_refused"
        return edit

    def focus_sha(self, cid):
        return self.cases[cid]["focus"][0]["sha256"]

    def issue_rows(self, result, code):
        return [i for i in result["issues"] if i["code"] == code]

    def test_a_refused_twin_decides_on_verify_alone_and_stays_complete(self):
        sha = self.focus_sha("C001")
        provider = replay.ReplayProvider(self.table, edit=self.refuse([(sha, "twin")]))
        result, _ = self.run_case("C001", provider=provider)
        cluster = result["tile_sieve"]["clusters"][0]
        self.assertIs(cluster["twin_refused"], True)
        self.assertEqual((cluster["twin"], cluster["E"], cluster["decision"]),
                         (None, "1.0", "report"))
        self.assertEqual(result["status"], "complete")
        self.assertEqual([f["start_line"] for f in result["findings"]], [1])
        note = self.issue_rows(result, "twin_refused")
        self.assertEqual([(i["range"], i["phase"], i["affects_completion"]) for i in note],
                         [([1, 2], "ts-focus", False)])
        refused = self.issue_rows(result, "question_refused")
        self.assertEqual([i["affects_completion"] for i in refused], [False])
        self.assertEqual(result["findings"][0]["limitations"], ["question-refused"])

    def test_a_refused_twin_with_a_low_verify_is_cleared_and_complete(self):
        sha = self.focus_sha("C001")
        refused = self.refuse([(sha, "twin")])

        def edit(request_sha, answers, scoped):
            refused(request_sha, answers, scoped)
            if request_sha == sha:
                answers["verify"]["noul"] = Decimal("0.10")
        result, _ = self.run_case("C001", provider=replay.ReplayProvider(self.table, edit=edit))
        cluster = result["tile_sieve"]["clusters"][0]
        self.assertEqual((cluster["decision"], cluster["twin_refused"], cluster["E"]),
                         ("clear", True, "0.1"))
        self.assertEqual((result["findings"], result["status"]), ([], "complete"))
        self.assertEqual([i["code"] for i in result["issues"] if i["affects_completion"]], [])

    def test_a_refused_verify_leaves_the_cluster_unmeasured_and_the_scan_incomplete(self):
        sha = self.focus_sha("C001")
        provider = replay.ReplayProvider(self.table, edit=self.refuse([(sha, "verify")]))
        result, _ = self.run_case("C001", provider=provider)
        cluster = result["tile_sieve"]["clusters"][0]
        self.assertEqual((cluster["decision"], cluster["E"]), ("unmeasured", None))
        self.assertEqual((result["findings"], result["status"]), ([], "incomplete"))
        self.assertEqual([i["affects_completion"] for i in
                          self.issue_rows(result, "question_refused")], [True])
        self.assertEqual(self.issue_rows(result, "twin_refused"), [])

    def test_a_refused_twin_does_not_excuse_another_missing_answer(self):
        sha = self.focus_sha("C001")
        provider = replay.ReplayProvider(
            self.table, edit=self.refuse([(sha, "twin"), (sha, "multiple")]))
        result, _ = self.run_case("C001", provider=provider)
        cluster = result["tile_sieve"]["clusters"][0]
        self.assertEqual(cluster["decision"], "unmeasured")
        self.assertIs(cluster["twin_refused"], False)
        self.assertEqual(result["status"], "incomplete")
        self.assertEqual(self.issue_rows(result, "twin_refused"), [])
        self.assertTrue(all(i["affects_completion"]
                            for i in self.issue_rows(result, "question_refused")))

    def test_a_twin_missing_for_another_reason_is_not_a_refusal(self):
        sha = self.focus_sha("C001")
        twin = next(qid for qid, info in self.table[sha][2]["roles"].items()
                    if info["role"] == "twin")
        refused = self.refuse([(sha, "twin")])
        for code in ("response_vector_missing", "response_distribution",
                     "choice_argmax_mismatch", None):
            # The gateway admits only a refusal for a noul question, so the other codes
            # are put in the engine's own lookup of what the gateway reported.
            with self.subTest(code=code), mock.patch.object(
                    tile_sieve.TileSieve, "_defects",
                    return_value={} if code is None else {twin: code}):
                provider = replay.ReplayProvider(self.table, edit=refused)
                result, _ = self.run_case("C001", provider=provider)
                cluster = result["tile_sieve"]["clusters"][0]
                self.assertEqual((cluster["decision"], cluster["E"]), ("unmeasured", None))
                self.assertIs(cluster["twin_refused"], False)
                self.assertEqual((result["findings"], result["status"]), ([], "incomplete"))
                self.assertEqual(self.issue_rows(result, "twin_refused"), [])
                self.assertEqual([i["affects_completion"] for i in
                                  self.issue_rows(result, "question_refused")], [True])

    def test_a_twin_the_gateway_rejects_with_another_code_leaves_the_cluster_unmeasured(self):
        sha = self.focus_sha("C001")
        twin = next(qid for qid, info in self.table[sha][2]["roles"].items()
                    if info["role"] == "twin")

        def edit(request_sha, answers, scoped):
            if request_sha == sha:
                del answers[twin]
                scoped[twin] = "response_vector_missing"
        result, _ = self.run_case("C001", provider=replay.ReplayProvider(self.table, edit=edit))
        cluster = result["tile_sieve"]["clusters"][0]
        self.assertEqual((cluster["decision"], cluster["E"]), ("unmeasured", None))
        self.assertIs(cluster["twin_refused"], False)
        self.assertEqual((result["findings"], result["status"]), ([], "incomplete"))
        self.assertEqual(self.issue_rows(result, "twin_refused"), [])
        self.assertTrue(any(i["code"] == "response_schema" and i["affects_completion"]
                            for i in result["issues"]))

    def test_a_refused_twin_is_a_possible_suppression_on_a_reported_cluster(self):
        sha = self.focus_sha("C001")
        provider = replay.ReplayProvider(self.table, edit=self.refuse([(sha, "twin")]))
        result, _ = self.run_case("C001", provider=provider)
        self.assertEqual([f["start_line"] for f in result["findings"]], [1])
        self.assertEqual(result["possible_suppression"],
                         {"flagged": True, "windows": 1, "overlaps_support": True})

    def test_a_refused_twin_is_a_possible_suppression_on_a_cleared_cluster(self):
        sha = self.focus_sha("C001")
        refused = self.refuse([(sha, "twin")])

        def edit(request_sha, answers, scoped):
            refused(request_sha, answers, scoped)
            if request_sha == sha:
                answers["verify"]["noul"] = Decimal("0.10")
        result, _ = self.run_case("C001", provider=replay.ReplayProvider(self.table, edit=edit))
        self.assertEqual(result["tile_sieve"]["clusters"][0]["decision"], "clear")
        self.assertEqual(result["findings"], [])
        self.assertEqual(result["possible_suppression"],
                         {"flagged": True, "windows": 1, "overlaps_support": True})

    def test_a_run_without_a_refusal_is_not_a_possible_suppression(self):
        for cid in ("C001", "C029"):
            with self.subTest(case=cid):
                self.assertEqual(self.results[cid]["possible_suppression"],
                                 {"flagged": False, "windows": 0, "overlaps_support": False})

    def test_a_refused_screening_answer_leaves_the_look_unassessed(self):
        tile = self.cases["C001"]["tiles"][0]["sha256"]
        provider = replay.ReplayProvider(self.table, edit=self.refuse([(tile, "need_ctx")]))
        result, _ = self.run_case("C001", provider=provider)
        self.assertIs(result["tile_sieve"]["looks_detail"][0]["assessed"], False)
        self.assertEqual((result["findings"], result["status"]), ([], "incomplete"))
        self.assertEqual(result["coverage"]["assessed_lines"], 0)
        self.assertEqual(result["calls_attempted"], 1)

    # -- judge controls, context and budgets -----------------------------------------------
    def test_a_control_failure_on_a_look_is_incomplete_with_judge_control_failed(self):
        tile = self.cases["C001"]["tiles"][0]["sha256"]
        provider = replay.ReplayProvider(self.table, edit=control_flipper({tile}))
        result, _ = self.run_case("C001", provider=provider)
        self.assertEqual((result["findings"], result["status"]), ([], "incomplete"))
        self.assertEqual(result["controls"]["requests_failed"], 1)
        self.assertTrue(any(i["code"] == "judge_control_failed" and i["affects_completion"]
                            for i in result["issues"]))
        self.assertEqual(result["calls_attempted"], 1)

    def test_a_control_failure_on_a_focus_request_is_incomplete(self):
        provider = replay.ReplayProvider(self.table,
                                         edit=control_flipper({self.focus_sha("C001")}))
        result, _ = self.run_case("C001", provider=provider)
        cluster = result["tile_sieve"]["clusters"][0]
        self.assertEqual((cluster["decision"], cluster["E"]), ("unmeasured", None))
        self.assertEqual((result["findings"], result["status"]), ([], "incomplete"))
        self.assertTrue(any(i["code"] == "judge_control_failed" and i["range"] == [1, 2]
                            for i in result["issues"]))

    def test_need_ctx_keeps_the_findings_and_makes_the_scan_incomplete(self):
        tile = self.cases["C001"]["tiles"][0]["sha256"]

        def edit(sha, answers, scoped):
            if sha == tile:
                answers["need_ctx"]["noul"] = Decimal("0.9")
        result, _ = self.run_case("C001", provider=replay.ReplayProvider(self.table, edit=edit))
        self.assertEqual(result["status"], "incomplete")
        self.assertEqual([f["start_line"] for f in result["findings"]], [1])
        self.assertEqual(result["findings"][0]["limitations"], ["missing-context"])
        self.assertEqual(result["handoff"]["findings"][0]["limitations"], ["missing-context"])
        self.assertEqual(result["tile_sieve"]["looks_detail"][0]["need_context"], "0.9")

    def test_need_ctx_at_exactly_the_threshold_is_unresolved_and_just_below_is_not(self):
        tile = self.cases["C001"]["tiles"][0]["sha256"]
        self.assertEqual(fusion.load_thresholds("openai").tau_ctx, 0.5)
        for value, unresolved in ((Decimal("0.5"), True), (Decimal("0.4999"), False)):
            def edit(sha, answers, scoped, value=value):
                if sha == tile:
                    answers["need_ctx"]["noul"] = value
            with self.subTest(need_ctx=str(value)):
                result, _ = self.run_case(
                    "C001", provider=replay.ReplayProvider(self.table, edit=edit))
                codes = [i["code"] for i in result["issues"]]
                self.assertEqual("context_unresolved" in codes, unresolved)
                self.assertEqual(result["status"], "incomplete" if unresolved else "complete")
                self.assertEqual([f["start_line"] for f in result["findings"]], [1])

    def test_max_calls_one_leaves_the_flagged_cluster_unmeasured(self):
        result, provider = self.run_case("C001", config=Config(search_policy="tile-sieve-beta",
                                                               max_calls=1))
        self.assertEqual(len(provider.sent), 1)
        self.assertEqual(result["calls_attempted"], 1)
        self.assertEqual((result["findings"], result["status"]), ([], "incomplete"))
        self.assertEqual(result["tile_sieve"]["clusters"][0]["decision"], "unmeasured")
        self.assertTrue(any(i["code"] == "call_budget_exhausted" and i["affects_completion"]
                            for i in result["issues"]))

    def test_max_questions_stops_the_focus_request(self):
        result, provider = self.run_case("C001", config=Config(search_policy="tile-sieve-beta",
                                                               max_questions=12))
        self.assertEqual(len(provider.sent), 1)
        self.assertEqual(result["status"], "incomplete")
        self.assertTrue(any(i["code"] == "question_budget_exhausted" for i in result["issues"]))

    def test_max_cost_stops_the_scan_before_the_first_call(self):
        provider = replay.ReplayProvider(self.table, model_spec=OPENAI_SPEC)
        result, _ = self.run_case("C001", provider=provider, max_cost=Decimal("0.0000001"))
        self.assertEqual(provider.sent, [])
        self.assertEqual(result["status"], "incomplete")
        self.assertEqual(result["calls_attempted"], 0)
        self.assertEqual(result["stop_reason"], "cost_budget_exhausted")
        self.assertTrue(any(i["code"] == "cost_budget_exhausted" and i["affects_completion"]
                            for i in result["issues"]))

    def test_max_cost_can_stop_the_scan_between_the_look_and_the_focus_request(self):
        provider = replay.ReplayProvider(self.table, model_spec=OPENAI_SPEC)
        # A budget that covers the look's bound but not the spend so far plus the focus's.
        result, _ = self.run_case("C001", provider=provider, max_cost=Decimal("0.0007"))
        self.assertEqual(len(provider.sent), 1)
        self.assertEqual(result["status"], "incomplete")
        self.assertEqual(result["stop_reason"], "cost_budget_exhausted")
        self.assertEqual(result["tile_sieve"]["clusters"][0]["decision"], "unmeasured")
        self.assertTrue(any(i["code"] == "cost_budget_exhausted" for i in result["issues"]))

    def test_an_unfittable_focus_request_is_an_incomplete_scan(self):
        error = plan.PlanError("focus_unfittable", {"K": [1, 2]})
        with mock.patch.object(plan.Planner, "focus", side_effect=error):
            result, provider = self.run_case("C001")
        self.assertEqual(len(provider.sent), 1)
        self.assertEqual((result["findings"], result["status"]), ([], "incomplete"))
        self.assertEqual(result["tile_sieve"]["clusters"][0]["decision"], "unmeasured")
        self.assertIsNone(result["tile_sieve"]["clusters"][0]["focus_sha256"])
        self.assertEqual([(i["code"], i["range"], i["phase"], i["affects_completion"])
                          for i in result["issues"]],
                         [("tile_sieve_focus_unfittable", [1, 2], "ts-focus", True)])

    def test_the_replay_judge_fails_on_a_request_it_does_not_know(self):
        provider = replay.ReplayProvider({})
        result, _ = self.run_case("C001", provider=provider)
        self.assertEqual(len(provider.unknown), 1)
        self.assertEqual(provider.unknown, provider.sent)
        self.assertEqual((result["findings"], result["status"]), ([], "incomplete"))

    def test_a_request_that_differs_from_the_plan_is_an_integrity_failure(self):
        real = plan.Planner.whole_tile

        def altered(self, look):
            request = real(self, look)
            return dataclasses.replace(request, sha256="0" * 64)
        with mock.patch.object(plan.Planner, "whole_tile", altered):
            with self.assertRaises(plan.IntegrityError):
                self.run_case("C001")

    def test_a_flagged_region_with_no_localization_mass_reports_the_whole_region(self):
        sha = self.focus_sha("C001")

        def edit(request_sha, answers, scoped):
            if request_sha == sha:
                for name in ("loc_a", "loc_b"):
                    answers[name] = {"type": "choice", "choice": "none",
                                     "confidence": Decimal("1"),
                                     "probabilities": {"L1-2": Decimal("0"),
                                                       "none": Decimal("1"),
                                                       "unlocalized": Decimal("0")}}
        result, _ = self.run_case("C001", provider=replay.ReplayProvider(self.table, edit=edit))
        cluster = result["tile_sieve"]["clusters"][0]
        self.assertEqual((cluster["runs"], cluster["runs_fell_back_to_K"]), ([[1, 2]], True))
        self.assertEqual([(f["start_line"], f["end_line"]) for f in result["findings"]], [(1, 2)])

    # -- the handoff -----------------------------------------------------------------------
    def test_the_handoff_text_names_the_search(self):
        text = format_handoff(self.results["C001"]["handoff"])
        self.assertIn("\nSEARCH: tile-sieve-beta whole-file\n", text)
        self.assertLess(text.index("SCAN:"), text.index("SEARCH:"))
        self.assertLess(text.index("SEARCH:"), text.index("F1 |"))


class ScriptedJudge:
    """A judge for synthetic files: it flags the lines in *bugs* wherever they are asked about.

    It answers every Tile Sieve question by its name and kind, with relation and requirement
    scores set by the caller, and it answers the judge controls correctly."""

    identity = ProviderIdentity("offline-scripted-judge", synthetic=True)

    def __init__(self, bugs=(), *, relation="0.9", requirement="0.8", refuse=(), verify="0.95",
                 need_ctx="0.02"):
        self.bugs = set(bugs)
        self.need_ctx = Decimal(need_ctx)
        self.relation, self.requirement = Decimal(relation), Decimal(requirement)
        self.refuse = set(refuse)
        self.verify = Decimal(verify)
        self.sent: list[str] = []

    def require_available(self):
        return None

    def check_sensitive(self, *values):
        return None

    def close(self):
        return None

    def hit(self, a, b):
        return any(a <= line <= b for line in self.bugs)

    @staticmethod
    def choice(q, pick):
        keys = list(q["criteria"])
        rest = [key for key in keys if key != pick]
        spare = "none" if "none" in rest else rest[0]
        return {"type": "choice", "choice": pick, "confidence": Decimal("0.8"),
                "probabilities": {key: (Decimal("0.9") if key == pick else
                                        Decimal("0.1") if key == spare else Decimal("0"))
                                  for key in keys}}

    def answer(self, qid, q):
        spans = spans_in(q["instructions"])
        target = (spans[0].start, spans[0].end) if spans else (0, 0)
        if q["type"] == "choice":
            cells = [(s.start, s.end) for s in spans_in(" ".join(q["criteria"]))]
            if qid.startswith("req"):
                return self.choice(q, next(k for k in q["criteria"] if k.startswith("R")))
            if qid.startswith("lens"):
                return self.choice(q, "none")
            hit = next((f"L{a}-{b}" for a, b in cells if self.hit(a, b)), "none")
            return self.choice(q, hit)
        if qid.startswith(("leaf_", "block_")):
            value = "0.99" if self.hit(*target) else "0.02"
        elif qid == "verify":
            value = str(self.verify) if self.hit(*target) else "0.02"
        elif qid == "twin":
            value = "0.03" if self.hit(*target) else "0.97"
        elif qid.startswith("lens_"):
            value = "0.9" if self.hit(*target) else "0.05"
        elif qid.startswith("rel_"):
            value = str(self.relation)
        elif qid.startswith("reqm_"):
            value = str(self.requirement)
        elif qid == "need_ctx":
            value = str(self.need_ctx)
        else:
            value = "0.02"
        return {"type": "noul", "noul": Decimal(value)}

    def answers_for(self, state, questions):
        """(answers, refusals) for one request."""
        answers, scoped = {}, {}
        for qid, q in questions.items():
            if qid in self.refuse:
                scoped[qid] = "question_refused"
            elif is_control(qid):
                answers[qid] = {"type": "noul",
                                "noul": Decimal(str(control_answer(q, state)["noul"]))}
            else:
                answers[qid] = self.answer(qid, q)
        return answers, scoped

    def decide(self, request):
        data = json.loads(request.payload)
        self.sent.append(hashlib.sha256(request.payload).hexdigest())
        answers, scoped = self.answers_for(data["state"], data["questions"])
        return ProviderResponse(answers, {"input_tokens": 10, "output_tokens": 0}, scoped=scoped)


class SecondRequestRefuses(ScriptedJudge):
    """A ScriptedJudge that refuses questions on chosen requests only.

    ``refuse_by_request`` maps a request's position (0 is the first) to the question names
    refused there; the keywords *refuse_at* and *refuse* set the one entry."""

    def __init__(self, *args, refuse_at=1, refuse=(), **kwargs):
        super().__init__(*args, **kwargs)
        self.refuse_by_request = {refuse_at: set(refuse)}
        self.seen = 0

    def answers_for(self, state, questions):
        self.refuse = self.refuse_by_request.get(self.seen, set())
        self.seen += 1
        return super().answers_for(state, questions)


class CustomGateway:
    """A gateway that is not a ValidatedGateway and names no judge (a library caller's own)."""

    provider_id = "custom-test-gateway"
    model_id = None
    synthetic = True
    rounding_places = None

    def __init__(self, scripted):
        self.scripted = scripted

    def evaluate(self, state, questions, *, metadata):
        answers, scoped = self.scripted.answers_for(state, questions)
        assert not scoped
        return protocol.validate_answer_objects(answers, questions)


FILLER = "\n".join(f"def filler_{i}(x):\n    return x + {i}\n" for i in range(12))
SAMPLE = ('def scale(value, factor):\n    """Scale a value by a factor."""\n'
          '    return value * factor\n\n\n' + FILLER +
          '\n\ndef total(items, factor):\n    out = 0\n    for item in items:\n'
          '        out += scale(item, factor)\n    return out\n')
SAMPLE_SPEC = "total returns the sum of the scaled items.\nscale multiplies by the factor.\n"


class PartnerJudge(ScriptedJudge):
    """A ScriptedJudge whose relation score depends on the partner it is asked about.

    *partners* maps the first line of the candidate evidence to its score."""

    def __init__(self, *args, partners, **kwargs):
        super().__init__(*args, **kwargs)
        self.partners = partners

    def answer(self, qid, q):
        if qid.startswith("rel_"):
            first = int(re.search(r"evidence lines (\d+) through", q["instructions"]).group(1))
            return {"type": "noul", "noul": Decimal(self.partners[first])}
        return super().answer(qid, q)


#: Three definitions (lines 1-2, 5-6 and 9-10), all read by the last function.
PARTNERS = ('def alpha(x):\n    return x + 1\n\n\ndef beta(x):\n    return x * 2\n\n\n'
            'def gamma(x):\n    return x - 3\n\n\n' + FILLER +
            '\n\ndef combine(x):\n    a = alpha(x)\n    b = beta(a)\n    return gamma(b)\n')


class SyntheticFileTests(unittest.TestCase):
    """Files that are not in the catalog, judged by a script."""

    def scan(self, judge, text=SAMPLE, spec=SAMPLE_SPEC, config=TILE_SIEVE, **options):
        source = Source.from_text(text, "sample.py")
        spec_source = Source.from_text(spec, "requirement.txt") if spec else None
        with tempfile.TemporaryDirectory() as temp:
            options.setdefault("retry_policy", RetryPolicy.none())
            gateway = ValidatedGateway(judge, Path(temp) / "receipts", **options)
            try:
                return scan(source, gateway, config, spec=spec_source,
                            context_scope="declared_standalone")
            finally:
                gateway.close()

    def test_a_planted_defect_is_found_with_its_partner_and_requirement(self):
        n = len(SAMPLE.splitlines())
        result = self.scan(ScriptedJudge(bugs={n - 2}))
        self.assertEqual(result["status"], "complete")
        self.assertEqual(result["tile_sieve"]["looks"], 2)
        (finding,) = result["findings"]
        self.assertLessEqual(finding["start_line"], n - 2)
        self.assertGreaterEqual(finding["end_line"], n - 2)
        self.assertEqual(finding["read_with"]["status"], "selected")
        self.assertEqual(finding["read_with"]["ranges"], [[1, 3]])
        self.assertEqual(finding["read_with"]["refs"], [{"file": None, "range": [1, 3]}])
        self.assertEqual(finding["relevant_requirement"]["status"], "selected")
        self.assertEqual(finding["relevant_requirement"]["ranges"], [[1, 2]])
        self.assertEqual(finding["relevant_requirement"]["refs"],
                         [{"file": "SPEC", "range": [1, 2]}])
        row = result["handoff"]["findings"][0]
        self.assertEqual(row["read_with"]["ranges"], [[1, 3]])
        self.assertEqual(row["relevant_requirement"]["ranges"], [[1, 2]])
        self.assertEqual(row["assessment"], "focus-supported")
        # One handoff, no extra calls: the requests are the looks plus one focus request.
        self.assertEqual(result["calls_attempted"], 3)
        self.assertEqual({r["phase"] for r in result["requests"]},
                         {"ts-screen-l0", "ts-screen-l1", "ts-focus"})

    def test_weak_relation_and_requirement_scores_name_nothing(self):
        n = len(SAMPLE.splitlines())
        result = self.scan(ScriptedJudge(bugs={n - 2}, relation="0.74", requirement="0.49"))
        (finding,) = result["findings"]
        self.assertEqual(finding["read_with"]["status"], "not-identified")
        self.assertEqual(finding["relevant_requirement"]["status"], "not-identified")
        self.assertEqual(result["handoff"]["findings"][0]["read_with"]["ranges"], [])

    def test_relation_and_requirement_scores_at_exactly_their_floors_name_their_targets(self):
        n = len(SAMPLE.splitlines())
        self.assertEqual((fusion.load_thresholds("openai").tau_rel, tile_sieve.REQUIREMENT_MIN),
                         (0.75, 0.5))
        result = self.scan(ScriptedJudge(bugs={n - 2}, relation="0.75", requirement="0.5"))
        (finding,) = result["findings"]
        self.assertEqual(finding["read_with"]["status"], "selected")
        self.assertEqual(finding["read_with"]["ranges"], [[1, 3]])
        self.assertEqual(finding["relevant_requirement"]["status"], "selected")
        self.assertEqual(finding["relevant_requirement"]["ranges"], [[1, 2]])
        below = self.scan(ScriptedJudge(bugs={n - 2}, relation="0.7499", requirement="0.4999"))
        self.assertEqual(below["findings"][0]["read_with"]["status"], "not-identified")
        self.assertEqual(below["findings"][0]["relevant_requirement"]["status"],
                         "not-identified")

    def test_a_flagged_cell_touching_the_core_only_at_an_edge_is_support(self):
        def look(index, *rows):
            return types.SimpleNamespace(
                assessed=True, request=types.SimpleNamespace(looks=[index], sha256=f"sha{index}"),
                rows=[{"cell": cell, "flag": flag, "why": ["leaf"]} for cell, flag in rows])
        cluster = types.SimpleNamespace(core=(5, 8))
        looks = [look(0, ((1, 4), True), ((1, 5), True), ((2, 6), False), ((8, 10), True),
                      ((9, 10), True)),
                 types.SimpleNamespace(assessed=False, request=None, rows=[])]
        got = tile_sieve.TileSieve._flag_support(cluster, looks)
        self.assertEqual([row["cell"] for row in got], [[1, 5], [8, 10]])
        self.assertEqual([(row["origin"], row["look"], row["request_sha256"]) for row in got],
                         [("tile_screen", 0, "sha0")] * 2)

    def test_without_a_specification_the_requirement_is_not_supplied(self):
        n = len(SAMPLE.splitlines())
        result = self.scan(ScriptedJudge(bugs={n - 2}), spec=None)
        self.assertEqual(result["findings"][0]["relevant_requirement"]["status"], "not-supplied")
        self.assertEqual(result["specification_mode"], "inferred")

    def test_two_far_apart_defects_are_two_clusters_and_two_findings(self):
        text = "\n".join(f"def fn_{i}(x):\n    return x * {i}\n" for i in range(30))
        result = self.scan(ScriptedJudge(bugs={2, 55}), text=text, spec=None)
        self.assertEqual(result["status"], "complete")
        clusters = result["tile_sieve"]["clusters"]
        self.assertEqual(len(clusters), 2)
        self.assertEqual([f["finding_id"] for f in result["findings"]], ["F1", "F2"])
        self.assertTrue(all(c["decision"] == "report" for c in clusters))

    def test_a_clean_file_has_no_cluster_and_no_focus_request(self):
        result = self.scan(ScriptedJudge(bugs=()))
        self.assertEqual((result["findings"], result["status"]), ([], "complete"))
        self.assertEqual(result["tile_sieve"]["clusters"], [])
        self.assertEqual(result["calls_attempted"], 2)
        self.assertEqual(result["coverage"]["all_lines_assessed"], True)

    def test_a_refusal_of_a_screening_answer_is_reported_not_hidden(self):
        result = self.scan(ScriptedJudge(bugs=(), refuse={"need_ctx"}))
        self.assertEqual(result["status"], "incomplete")
        self.assertEqual(result["coverage"]["assessed_lines"], 0)
        self.assertTrue(all(not d["assessed"] for d in result["tile_sieve"]["looks_detail"]))

    def test_one_look_unassessed_and_the_other_assessed_is_incomplete_without_coverage(self):
        n = len(SAMPLE.splitlines())
        self.assertGreater(n, 8)
        result = self.scan(SecondRequestRefuses(bugs={n - 2}, refuse_at=1, refuse={"need_ctx"}))
        self.assertEqual([d["assessed"] for d in result["tile_sieve"]["looks_detail"]],
                         [True, False])
        self.assertEqual(result["coverage"]["assessed_lines"], 0)
        self.assertIs(result["coverage"]["all_lines_assessed"], False)
        self.assertEqual(result["status"], "incomplete")
        # The assessed look still flags the planted line and its focus request decides.
        (finding,) = result["findings"]
        self.assertLessEqual(finding["start_line"], n - 2)
        self.assertGreaterEqual(finding["end_line"], n - 2)

    def test_a_refused_twin_on_one_cluster_does_not_excuse_a_refused_verify_on_another(self):
        text = "\n".join(f"def fn_{i}(x):\n    return x * {i}\n" for i in range(30))
        judge = SecondRequestRefuses(bugs={2, 55})
        # Requests 0 and 1 are the looks; 2 and 3 are the focus requests of the two clusters.
        judge.refuse_by_request = {2: {"twin"}, 3: {"verify"}}
        result = self.scan(judge, text=text, spec=None)
        first, second = result["tile_sieve"]["clusters"]
        self.assertEqual((first["decision"], first["twin_refused"]), ("report", True))
        self.assertEqual((second["decision"], second["twin_refused"]), ("unmeasured", False))
        self.assertEqual(result["status"], "incomplete")
        self.assertEqual([f["finding_id"] for f in result["findings"]], ["F1"])
        notes = [(i["range"], i["affects_completion"]) for i in result["issues"]
                 if i["code"] == "twin_refused"]
        self.assertEqual(notes, [(first["K"], False)])
        refused = {tuple(i["range"]): i["affects_completion"] for i in result["issues"]
                   if i["code"] == "question_refused"}
        self.assertEqual(refused, {tuple(first["K"]): False, tuple(second["K"]): True})

    def test_a_custom_gateway_uses_the_openai_set_and_says_it_was_not_declared(self):
        n = len(SAMPLE.splitlines())
        source = Source.from_text(SAMPLE, "sample.py")
        spec = Source.from_text(SAMPLE_SPEC, "requirement.txt")
        judge = ScriptedJudge(bugs={n - 2})
        result = scan(source, CustomGateway(judge), TILE_SIEVE, spec=spec,
                      context_scope="declared_standalone")
        block = result["tile_sieve"]
        self.assertEqual((block["thresholds_set"], block["judge_declared"]), ("openai", False))
        self.assertEqual(result["provider"], "custom-test-gateway")
        self.assertEqual(result["status"], "complete")
        (finding,) = result["findings"]
        self.assertLessEqual(finding["start_line"], n - 2)
        self.assertGreaterEqual(finding["end_line"], n - 2)
        self.assertNotIn("judge", result)

    def test_the_relation_path_reports_a_cluster_below_its_bar(self):
        n = len(SAMPLE.splitlines())
        # Not strong (the leaf scores 0.99 and the floor is 1), and E = 0.847 is below the
        # 0.95 bar; the partner relation reaches tau_rel and E is above tau_gray.
        with patched_thresholds(strong_cell="1", tau_rep_points=[[200, "0.95"]]):
            reported = self.scan(ScriptedJudge(bugs={n - 2}, verify="0.6", relation="0.9"))
            cleared = self.scan(ScriptedJudge(bugs={n - 2}, verify="0.6", relation="0.5"))
        cluster = reported["tile_sieve"]["clusters"][0]
        self.assertEqual((cluster["strong"], cluster["bar"], cluster["decision"]),
                         (False, "tau_rep", "report"))
        self.assertEqual(float(cluster["relation_max"]), 0.9)
        self.assertEqual(len(reported["findings"]), 1)
        self.assertEqual(cleared["tile_sieve"]["clusters"][0]["decision"], "clear")
        self.assertEqual((cleared["findings"], cleared["status"]), ([], "complete"))

    def test_partners_are_read_strongest_first_and_cut_to_the_display_limit(self):
        n = len(PARTNERS.splitlines())
        self.assertEqual(tile_sieve.DISPLAY_REFS, 2)
        result = self.scan(PartnerJudge(bugs={n - 1}, partners={1: "0.85", 5: "0.8", 9: "0.95"}),
                           text=PARTNERS)
        (finding,) = result["findings"]
        read = finding["read_with"]
        self.assertEqual(read["status"], "selected")
        # The strongest two are shown, in descending score; the weakest is only counted.
        self.assertEqual(read["ranges"], [[9, 10], [1, 2]])
        self.assertEqual(read["refs"], [{"file": None, "range": [9, 10]},
                                        {"file": None, "range": [1, 2]}])
        self.assertEqual(read["additional_count"], 1)
        self.assertEqual(read["all_ranges"], [[9, 10], [1, 2], [5, 6]])
        self.assertEqual(read["all_refs"], [{"file": None, "range": pair}
                                            for pair in ([9, 10], [1, 2], [5, 6])])
        self.assertEqual(read["candidates_assessed"], 3)
        row = result["handoff"]["findings"][0]["read_with"]
        self.assertEqual(row["ranges"], [[9, 10], [1, 2]])
        self.assertEqual(row["additional_count"], 1)

    def test_partners_below_the_floor_are_assessed_but_not_listed(self):
        n = len(PARTNERS.splitlines())
        result = self.scan(PartnerJudge(bugs={n - 1}, partners={1: "0.9", 5: "0.7499", 9: "0.8"}),
                           text=PARTNERS)
        read = result["findings"][0]["read_with"]
        self.assertEqual(read["all_ranges"], [[1, 2], [9, 10]])
        self.assertEqual((read["additional_count"], read["candidates_assessed"]), (0, 3))

    def test_partners_with_equal_scores_are_ordered_by_position(self):
        n = len(PARTNERS.splitlines())
        result = self.scan(PartnerJudge(bugs={n - 1}, partners={1: "0.9", 5: "0.9", 9: "0.9"}),
                           text=PARTNERS)
        read = result["findings"][0]["read_with"]
        self.assertEqual(read["all_ranges"], [[1, 2], [5, 6], [9, 10]])
        self.assertEqual(read["ranges"], [[1, 2], [5, 6]])
        self.assertEqual(read["additional_count"], 1)

    def test_the_selection_breaks_a_score_tie_by_span_length_then_start(self):
        # Direct, on the cluster shapes the engine hands it: equal scores order by the
        # shorter span first, then by the earlier start.
        def cluster(*rows):
            return types.SimpleNamespace(
                request=types.SimpleNamespace(roles={
                    qid: {"role": "relation", "partner": partner} for qid, partner, _ in rows}),
                answers={qid: {"noul": score} for qid, _, score in rows})
        owners = [cluster(("a", (10, 19), "0.9"), ("b", (4, 6), "0.9"), ("c", (1, 3), "0.9"),
                          ("d", (20, 30), "0.95"), ("e", (40, 41), "0.5"))]
        ranges, assessed = tile_sieve.TileSieve._selected(owners, "relation", "partner", 0.75)
        self.assertEqual(ranges, [[20, 30], [1, 3], [4, 6], [10, 19]])
        self.assertEqual(assessed, 5)

    def test_a_partner_named_by_several_clusters_keeps_its_highest_score(self):
        # Two owner clusters of one merged finding name the partner (1, 3); the strongest
        # answer ranks it, whichever cluster comes first, and every answer is counted.
        def cluster(*rows):
            return types.SimpleNamespace(
                request=types.SimpleNamespace(roles={
                    qid: {"role": "relation", "partner": partner} for qid, partner, _ in rows}),
                answers={qid: {"noul": score} for qid, _, score in rows})
        strong = cluster(("a", (1, 3), "0.95"))
        weak = cluster(("b", (1, 3), "0.8"), ("c", (10, 12), "0.9"))
        for owners in ([strong, weak], [weak, strong]):
            ranges, assessed = tile_sieve.TileSieve._selected(owners, "relation", "partner", 0.75)
            self.assertEqual(ranges, [[1, 3], [10, 12]])
            self.assertEqual(assessed, 3)

    def test_handoff_assessment_reads_a_finished_tile_sieve_search(self):
        n = len(SAMPLE.splitlines())
        source = Source.from_text(SAMPLE, "sample.py")
        with tempfile.TemporaryDirectory() as temp:
            gateway = ValidatedGateway(ScriptedJudge(bugs={n - 2}), Path(temp) / "receipts",
                                       retry_policy=RetryPolicy.none())
            try:
                search = Search(source, gateway, TILE_SIEVE, None,
                                context_scope="declared_standalone")
                result = search.run()
            finally:
                gateway.close()
        (finding,) = result["findings"]
        target = Span(finding["start_line"], finding["end_line"])
        self.assertTrue(search.tile_sieve.active)
        self.assertEqual(handoff.assessment(search, target), "focus-supported")
        self.assertEqual(handoff.assessment(search, target), finding["assessment"])

    def test_the_planned_looks_are_what_the_planner_builds(self):
        source = Source.from_text(SAMPLE, "sample.py")
        spec = Source.from_text(SAMPLE_SPEC, "requirement.txt")
        planned = plan.plan_whole_file(source, spec)
        judge = ScriptedJudge(bugs=())
        self.scan(judge)
        self.assertEqual(judge.sent, [request.sha256 for request in planned.looks])


class LegacyJudge:
    """A judge for the legacy-v1 questions: it flags the lines in *bugs* with the offline fixture."""

    identity = ProviderIdentity("offline-legacy-judge", synthetic=True)

    def __init__(self, bugs=()):
        self.fixture = FixtureProvider(list(bugs))
        self.sent: list[str] = []

    def require_available(self):
        return None

    def check_sensitive(self, *values):
        return None

    def close(self):
        return None

    def decide(self, request):
        data = json.loads(request.payload)
        self.sent.append(hashlib.sha256(request.payload).hexdigest())
        return ProviderResponse(
            {qid: self.fixture.answer(qid, q, data["state"])
             for qid, q in data["questions"].items()},
            {"input_tokens": 10, "output_tokens": 0})


class FallbackTests(unittest.TestCase):
    """A file that does not fit one request is scanned by legacy-v1, and the report says so."""

    @classmethod
    def setUpClass(cls):
        from tests.test_tile_sieve_plan import spec_source, synthetic

        cls.runs = {}
        for policy in ("legacy-v1", "tile-sieve-beta"):
            judge = LegacyJudge([(200, 201)])
            with tempfile.TemporaryDirectory() as temp:
                gateway = ValidatedGateway(judge, Path(temp) / "receipts",
                                           retry_policy=RetryPolicy.none())
                try:
                    config = Config(search_policy=policy, width=200, min_width=100,
                                    max_depth=1, max_calls=400)
                    result = scan(synthetic(1000), gateway, config, spec=spec_source(),
                                  context_scope="declared_standalone")
                finally:
                    gateway.close()
            cls.runs[policy] = (result, judge.sent)

    def test_the_requests_and_findings_are_legacy_identical(self):
        legacy, legacy_sent = self.runs["legacy-v1"]
        tile, tile_sent = self.runs["tile-sieve-beta"]
        self.assertGreater(len(legacy_sent), 10)
        self.assertEqual(tile_sent, legacy_sent)
        self.assertEqual(tile["findings"], legacy["findings"])
        self.assertEqual(tile["status"], legacy["status"])

    def test_the_report_differs_only_in_schema_policy_block_and_handoff_header(self):
        legacy, _ = self.runs["legacy-v1"]
        tile = copy.deepcopy(self.runs["tile-sieve-beta"][0])
        self.assertEqual((legacy["schema_version"], tile["schema_version"]), (7, 9))
        tile["schema_version"] = 7
        self.assertEqual(tile["configuration"].pop("search_policy"), "tile-sieve-beta")
        self.assertEqual(legacy["configuration"].pop("search_policy"), "legacy-v1")
        block = tile.pop("tile_sieve")
        self.assertEqual(tile["handoff"].pop("schema_version"), 6)
        self.assertEqual(legacy["handoff"].pop("schema_version"), 4)
        self.assertEqual(tile["handoff"].pop("search"),
                         {"policy": "tile-sieve-beta", "mode": "legacy-fallback",
                          "policy_run": "legacy-v1", "reason": block["reason"]})
        self.assertEqual(json.dumps(tile), json.dumps(legacy))

    def test_the_block_names_the_reason_and_the_caps(self):
        block = self.runs["tile-sieve-beta"][0]["tile_sieve"]
        self.assertEqual(block["mode"], "legacy-fallback")
        self.assertEqual(block["policy_run"], "legacy-v1")
        self.assertEqual(block["reason"], "state_bytes")
        self.assertEqual(block["caps"], {"max_questions": 64, "max_request_bytes": 24064,
                                         "max_state_bytes": 15872})
        self.assertGreater(block["detail"]["bytes"], block["detail"]["limit"])
        self.assertEqual(set(block), {"version", "mode", "policy_run", "reason", "detail",
                                      "caps"})

    def test_the_handoff_text_says_what_ran(self):
        text = format_handoff(self.runs["tile-sieve-beta"][0]["handoff"])
        self.assertIn("\nSEARCH: tile-sieve-beta -> legacy-v1 (state_bytes)\n", text)

    def test_the_engine_and_the_planner_agree_on_the_fallback(self):
        from tests.test_tile_sieve_plan import spec_source, synthetic
        found = plan.plan_whole_file(synthetic(1000), spec_source())
        block = self.runs["tile-sieve-beta"][0]["tile_sieve"]
        self.assertIsInstance(found, plan.Fallback)
        self.assertEqual((found.reason, found.detail), (block["reason"], block["detail"]))

    def test_an_empty_file_falls_back_too(self):
        source = Source.from_text("", "empty.py")
        with tempfile.TemporaryDirectory() as temp:
            gateway = ValidatedGateway(LegacyJudge(), Path(temp) / "receipts",
                                       retry_policy=RetryPolicy.none())
            try:
                result = scan(source, gateway, TILE_SIEVE, context_scope="declared_standalone")
            finally:
                gateway.close()
        self.assertEqual(result["tile_sieve"]["reason"], "empty_file")
        self.assertEqual(result["schema_version"], 9)


class PolicyIsolationTests(unittest.TestCase):
    """Nothing changes for the other policies."""

    def test_a_legacy_scan_has_no_tile_sieve_block_and_schema_7(self):
        source = Source.from_text("def f(x):\n    return x\n", "tiny.py")
        with tempfile.TemporaryDirectory() as temp:
            gateway = ValidatedGateway(LegacyJudge(), Path(temp) / "receipts",
                                       retry_policy=RetryPolicy.none())
            try:
                result = scan(source, gateway, Config(), context_scope="declared_standalone")
            finally:
                gateway.close()
        self.assertEqual(result["schema_version"], 7)
        self.assertEqual(result["handoff"]["schema_version"], 4)
        self.assertNotIn("tile_sieve", result)
        self.assertNotIn("search", result["handoff"])
        self.assertNotIn("SEARCH:", format_handoff(result["handoff"]))


class VersionMappingTests(unittest.TestCase):
    def test_compact_report_maps_every_schema_to_its_handoff(self):
        from decision_bug_hunter.handoff import compact_report
        base = {"findings": [], "source": {}, "specification": None, "specification_mode": "inferred",
                "scan_status": "complete", "handoff_status": "complete", "status": "complete"}
        for schema, handoff in ((7, 4), (8, 5), (9, 6)):
            self.assertEqual(compact_report({**base, "schema_version": schema})["schema_version"],
                             handoff)

    def test_the_search_block_appears_only_with_a_tile_sieve_block(self):
        from decision_bug_hunter.handoff import compact_report
        base = {"findings": [], "source": {}, "specification": None, "specification_mode": "inferred",
                "scan_status": "complete", "handoff_status": "complete", "status": "complete",
                "schema_version": 9}
        self.assertNotIn("search", compact_report(base))
        block = {"mode": "whole-file", "policy_run": "tile-sieve-beta"}
        self.assertEqual(compact_report({**base, "tile_sieve": block})["search"],
                         {"policy": "tile-sieve-beta", "mode": "whole-file",
                          "policy_run": "tile-sieve-beta"})


class ProtocolSanityTests(unittest.TestCase):
    def test_the_engine_envelope_is_the_planner_envelope(self):
        # The engine asks under RequestEnvelope(policy, 64, 24576); the planner's caps are
        # the margins below it, so a planned request is always admissible to the gateway.
        self.assertEqual((plan.MAX_QUESTIONS, plan.ENVELOPE_BYTES),
                         (protocol.MAX_QUESTIONS, protocol.MAX_REQUEST_BYTES))
        self.assertLess(plan.MAX_REQUEST_BYTES, plan.ENVELOPE_BYTES)


if __name__ == "__main__":
    unittest.main()
