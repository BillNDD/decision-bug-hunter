"""The Tile Sieve whole-file planner: byte equality with the pilot, caps and fallbacks.

Every request is built offline. The pilot fixtures hold the sha256 of every request the
pilot sent on the 34-case catalog and of its planted-file focus requests, so equal hashes
mean equal bytes. Nothing here opens a socket; importing ``tests`` installs the guard.
"""
import contextlib
import dataclasses
import hashlib
import importlib
import inspect
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock
import warnings

from decision_bug_hunter import protocol
from decision_bug_hunter import questions
from decision_bug_hunter import tile_sieve_index as tindex
from decision_bug_hunter import tile_sieve_plan as plan
from decision_bug_hunter.core import Source, Span
from decision_bug_hunter.repository import ProjectEntry, ProjectIndex
from tests import network_guard

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "tests" / "fixtures" / "tile_sieve"
EVAL = ROOT / "tools" / "eval"
SCOPES = {"standalone": "declared_standalone", "project": "project", "isolate": "owner_isolated"}
#: The bench's synthetic file generator and spec, copied so these tests need no tools directory.
SYNTH_SPEC = ("Every function returns the documented value for all valid inputs. "
              "Counters are inclusive of their upper bound. "
              "Constants are informational and carry no behavioral requirement.\n")


def tool(name):
    if str(EVAL) not in sys.path:
        sys.path.insert(0, str(EVAL))
    return importlib.import_module(name)


def synthetic_text(n):
    lines, i = [], 0
    while len(lines) < n:
        i += 1
        lines.extend([f"def helper_{i:05d}(value, limit={i % 97 + 3}):",
                      f"    \"\"\"Return value scaled by {i % 13 + 2}, bounded by limit.\"\"\"",
                      f"    scaled = value * {i % 13 + 2}",
                      "    if scaled >= limit:",
                      "        return limit",
                      "    return scaled",
                      ""])
    lines = lines[:n]
    for frac, size in ((0.2, 1), (0.5, 2), (0.8, 1)):
        start = max(1, int(n * frac))
        for k in range(size):
            lines[start - 1 + k] = f"    return scaled + {k + 1}  # planted off-by-one"
    return "\n".join(lines) + "\n"


def synthetic(n):
    return Source.from_text(synthetic_text(n), f"synthetic_{n}.py")


def spec_source(text=SYNTH_SPEC):
    return Source.from_text(text, "requirement.txt")


def assert_within_caps(test, request):
    test.assertLessEqual(request.nq, 64)
    test.assertLessEqual(len(request.wire), 24064)
    test.assertLessEqual(request.state_bytes, 15872)
    test.assertEqual(hashlib.sha256(request.wire).hexdigest(), request.sha256)


class NoNetworkTests(unittest.TestCase):
    def test_the_suite_runs_under_the_network_guard(self):
        self.assertTrue(network_guard.active())


@unittest.skipUnless(EVAL.is_dir() and FIXTURES.is_dir(), "catalog tools or fixtures absent")
class CatalogEquivalenceTests(unittest.TestCase):
    """The 34 catalog cases, materialized as run_catalog does, planned and compared to the pilot."""

    @classmethod
    def setUpClass(cls):
        cls.fixture = json.loads((FIXTURES / "e4_catalog.json").read_text(encoding="utf-8"))
        cls.cases = {c["id"]: c for c in cls.fixture["cases"]}
        catalog, run_catalog = tool("catalog"), tool("run_catalog")
        cls.tmp = tempfile.TemporaryDirectory()
        cls.addClassCleanup(cls.tmp.cleanup)
        cls.planners, cls.plans = {}, {}
        for case in catalog.cases():
            base = Path(cls.tmp.name) / case["id"]
            base.mkdir()
            argv, out = run_catalog.materialize(case, base)
            subject = Path(argv[0])
            spec_path = Path(argv[argv.index("--spec-file") + 1])
            source = Source.read(subject)
            spec = Source.read(spec_path, max_bytes=8192, max_lines=2000)
            entries = ()
            if case["scope"] == "project":
                entries = ProjectIndex.read(base / "scanned", primary_path=subject,
                                            exclude_paths=(out, spec_path)).entries
            planner = plan.Planner(source, spec, entries, SCOPES[case["scope"]])
            cls.planners[case["id"]] = planner
            cls.plans[case["id"]] = planner.plan()

    def test_fixture_is_the_pilots_catalog(self):
        self.assertEqual(len(self.cases), 34)
        self.assertEqual(self.fixture["summary"]["distinct_tile_requests"], 39)
        self.assertEqual(self.fixture["summary"]["focus_requests"], 17)

    def test_inputs_match_the_pilots_bytes(self):
        for cid, case in self.cases.items():
            planner = self.planners[cid]
            self.assertEqual(planner.source.sha256, case["subject"]["sha256"], cid)
            self.assertEqual(planner.n, case["n"], cid)
            self.assertEqual(planner.source.name, case["name"], cid)

    def test_every_case_fits_in_one_request(self):
        for cid, found in self.plans.items():
            self.assertIsInstance(found, plan.WholeFilePlan, cid)

    def test_36_distinct_tile_requests_are_the_fixtures_minus_look_one_of_the_short_files(self):
        planned, fixture_shas, skipped = set(), set(), set()
        for cid, case in self.cases.items():
            expected = set()
            for tile in case["tiles"]:
                fixture_shas.add(tile["sha256"])
                if case["n"] <= 8 and tile["looks"] == [1]:
                    skipped.add(cid)
                else:
                    expected.add(tile["sha256"])
            got = {request.sha256 for request in self.plans[cid].looks}
            self.assertEqual(got, expected, cid)
            planned |= got
        self.assertEqual(len(fixture_shas), 39)
        self.assertEqual(len(planned), 36)
        self.assertEqual(skipped, {"C008", "C013", "C014"})

    def test_tile_questions_bytes_and_roles_equal_the_fixture(self):
        for cid, case in self.cases.items():
            by_sha = {t["sha256"]: t for t in case["tiles"]}
            for request in self.plans[cid].looks:
                tile = by_sha[request.sha256]
                label = f"{cid} {request.sha256[:8]}"
                self.assertEqual(request.nq, tile["questions"], label)
                self.assertEqual(len(request.wire), tile["request_bytes"], label)
                self.assertEqual(request.state_bytes, tile["state_bytes"], label)
                self.assertEqual(request.roles, tile["meta"]["roles"], label)
                self.assertEqual(request.meta["cells"], tile["meta"]["cells"], label)
                self.assertEqual(request.meta["display"], tile["meta"]["display"], label)
                self.assertEqual(request.meta["spec_passages"], tile["meta"]["spec_passages"], label)

    def test_looks_served(self):
        for cid, case in self.cases.items():
            found = self.plans[cid]
            n = case["n"]
            if n <= 8:
                self.assertEqual(len(found.looks), 1, cid)
                self.assertEqual(found.looks[0].looks, (0, 1), cid)
                self.assertEqual(found.looks[0].meta["looks"], [0, 1], cid)
            else:
                self.assertEqual([r.looks for r in found.looks], [(0,), (1,)], cid)
            for look in (0, 1):
                self.assertIn(look, found.request_for_look(look).looks, cid)

    def test_files_of_up_to_4_lines_are_byte_identical_to_the_pilot(self):
        short = [cid for cid, case in self.cases.items() if case["n"] <= 4]
        self.assertEqual(len(short), 29)
        for cid in short:
            tiles = self.cases[cid]["tiles"]
            self.assertEqual([t["looks"] for t in tiles], [[0, 1]], cid)
            self.assertEqual(self.plans[cid].looks[0].sha256, tiles[0]["sha256"], cid)

    def test_a_longer_short_file_reads_once_and_serves_both_looks(self):
        # C013 has 6 lines: the pilot asked it twice, the planner once.
        found = self.plans["C013"]
        self.assertEqual(found.n, 6)
        self.assertEqual(len(found.looks), 1)
        self.assertEqual(found.looks[0].sha256, self.cases["C013"]["tiles"][0]["sha256"])
        # look 1 can still be built on request and is a different request
        planner = self.planners["C013"]
        self.assertEqual(planner.whole_tile(1).sha256, self.cases["C013"]["tiles"][1]["sha256"])

    def test_focus_requests_equal_the_fixtures_17(self):
        seen = 0
        for cid, case in self.cases.items():
            planner = self.planners[cid]
            for row in case["focus"]:
                request = planner.focus(row["K"])
                seen += 1
                label = f"{cid} {row['K']}"
                self.assertEqual(request.sha256, row["sha256"], label)
                self.assertEqual(request.nq, row["questions"], label)
                self.assertEqual(len(request.wire), row["request_bytes"], label)
                self.assertEqual(request.state_bytes, row["state_bytes"], label)
                self.assertEqual(request.roles, row["roles"], label)
                self.assertEqual(request.meta["truncation"], row["meta"]["truncation"], label)
                self.assertEqual(request.meta["partners"], row["meta"]["partners"], label)
                self.assertEqual(request.meta["display"], row["meta"]["display"], label)
        self.assertEqual(seen, 17)

    def test_no_request_exceeds_a_cap(self):
        for cid, case in self.cases.items():
            for request in self.plans[cid].looks:
                assert_within_caps(self, request)
            for row in case["focus"]:
                assert_within_caps(self, self.planners[cid].focus(row["K"]))

    def test_project_cases_carry_every_other_project_file_in_full(self):
        planner = self.planners["C025"]
        self.assertEqual([e.relpath for e in planner.related], ["prices.py"])
        state = self.plans["C025"].looks[0].state
        related = state["related_sources"]
        self.assertEqual([r["file"] for r in related], ["prices.py"])
        self.assertEqual(list(related[0]), ["file", "source_sha256", "start_line", "end_line", "lines"])
        self.assertEqual(related[0]["start_line"], 1)
        self.assertEqual(related[0]["end_line"], len(related[0]["lines"]))
        self.assertEqual(state["context_scope"], "project")


@unittest.skipUnless(FIXTURES.is_dir(), "fixtures absent")
class PlantedFocusTests(unittest.TestCase):
    """The pilot's E2 focus requests on three 535-line planted files, built with the recorded
    need_context flag and lens order. They have def-use partners and relation questions."""

    @classmethod
    def setUpClass(cls):
        cls.fixture = json.loads((FIXTURES / "e2_builders.json").read_text(encoding="utf-8"))

    def planner_for(self, rec):
        source = Source.read(FIXTURES / rec["path"])
        self.assertEqual(source.sha256, rec["sha256"])
        source = dataclasses.replace(source, name=rec["name"])
        spec = Source.from_text(rec["spec_text"], "requirement.txt")
        self.assertEqual(spec.sha256, rec["spec_sha256"])
        return plan.Planner(source, spec)

    def test_recorded_focus_requests_give_the_recorded_shas(self):
        rows = 0
        for rec in self.fixture["files"]:
            planner = self.planner_for(rec)
            self.assertEqual(planner.n, rec["n"])
            for row in rec["focus"]:
                request = planner.focus(row["K"], need_ctx=row["tile_ctx"]["need_ctx"],
                                        lens_order=row["lens_order"])
                rows += 1
                label = f"{rec['id']} {row['K']}"
                self.assertEqual(request.sha256, row["sha256"], label)
                self.assertEqual(request.nq, row["questions"], label)
                self.assertEqual(len(request.wire), row["request_bytes"], label)
                self.assertEqual(request.state_bytes, row["state_bytes"], label)
                self.assertEqual(request.roles, row["roles"], label)
                assert_within_caps(self, request)
        self.assertEqual(rows, 3)

    def test_partners_and_relations_were_exercised(self):
        for rec in self.fixture["files"]:
            planner = self.planner_for(rec)
            row = rec["focus"][0]
            request = planner.focus(row["K"], need_ctx=row["tile_ctx"]["need_ctx"],
                                    lens_order=row["lens_order"])
            self.assertTrue(request.meta["partners"], rec["id"])
            relations = [q for q in request.roles if q.startswith("rel_")]
            self.assertTrue(relations, rec["id"])
            self.assertEqual(len(relations), len(request.meta["partners"][:3]), rec["id"])
            self.assertEqual(request.state["evidence_coordinates"][0]["file"], rec["name"])
            lens_names = [q[len("lens_"):] for q in request.roles if q.startswith("lens_")]
            self.assertEqual(lens_names, row["lens_order"])

    def test_a_planted_file_does_not_fit_one_request(self):
        for rec in self.fixture["files"]:
            found = self.planner_for(rec).plan()
            self.assertIsInstance(found, plan.Fallback)
            self.assertEqual(found.reason, "state_bytes")


class FallbackTests(unittest.TestCase):
    def test_200_lines_fit_with_both_looks(self):
        found = plan.plan_whole_file(synthetic(200), spec_source())
        self.assertIsInstance(found, plan.WholeFilePlan)
        self.assertEqual([len(r.wire) for r in found.looks], [23038, 23097])
        self.assertEqual([r.looks for r in found.looks], [(0,), (1,)])
        for request in found.looks:
            assert_within_caps(self, request)

    def test_220_lines_exceed_the_request_cap(self):
        found = plan.plan_whole_file(synthetic(220), spec_source())
        self.assertEqual(found, plan.Fallback("request_bytes", {"bytes": 24493, "limit": 24064}))

    def test_300_lines_would_split_into_batches(self):
        found = plan.plan_whole_file(synthetic(300), spec_source())
        self.assertIsInstance(found, plan.Fallback)
        self.assertEqual(found.reason, "split_into_batches")
        self.assertGreater(found.detail["batches"], 1)

    def test_an_empty_file_is_empty_file(self):
        empty = Source.from_text("", "empty.py")
        self.assertEqual(plan.plan_whole_file(empty), plan.Fallback("empty_file", {}))
        with self.assertRaises(plan.Overflow) as caught:
            plan.Planner(empty).whole_tile(0)
        self.assertEqual(caught.exception.reason, "empty_file")

    def test_a_128_file_project_overflows_the_state(self):
        entries = tuple(ProjectEntry(f"module_{i:03d}.py", Source.from_text("value = 1\n" * 30, "m.py"))
                        for i in range(128))
        source = Source.from_text("def run():\n    return 1\n", "run.py")
        found = plan.plan_whole_file(source, None, entries, "project")
        self.assertIsInstance(found, plan.Fallback)
        self.assertEqual(found.reason, "state_bytes")
        self.assertGreater(found.detail["bytes"], found.detail["limit"])
        self.assertEqual(found.detail["limit"], 15872)

    def test_a_huge_file_is_refused_without_building_its_state(self):
        text = "x = 1\n" * 200000
        found = plan.plan_whole_file(Source.from_text(text, "big.py"))
        self.assertIsInstance(found, plan.Fallback)
        self.assertEqual(found.reason, "state_bytes")
        self.assertTrue(found.detail["at_least"])

    def test_a_state_just_over_the_cap_is_exact(self):
        # 24 lines of 640 bytes: the lines alone stay under the cheap floor, the placed state does not
        text = "".join(f"v{i} = '{'a' * 630}'\n" for i in range(24))
        found = plan.plan_whole_file(Source.from_text(text, "wide.py"))
        self.assertIsInstance(found, plan.Fallback)
        self.assertEqual(found.reason, "state_bytes")
        self.assertGreater(found.detail["bytes"], 15872)
        self.assertNotIn("at_least", found.detail)

    def test_a_state_of_exactly_the_cap_fits_and_one_byte_more_does_not(self):
        fits = plan.plan_whole_file(Source.from_text("x = '" + "a" * 14969 + "'\n", "a.py"))
        self.assertIsInstance(fits, plan.WholeFilePlan)
        self.assertEqual([r.state_bytes for r in fits.looks], [15872])
        over = plan.plan_whole_file(Source.from_text("x = '" + "a" * 14970 + "'\n", "a.py"))
        self.assertEqual(over, plan.Fallback("state_bytes", {"bytes": 15873, "limit": 15872}))

    def test_the_floor_refuses_only_above_the_cap(self):
        # one line whose entry is exactly the cap: the floor lets it through (the exact check then
        # reports the real size); one more byte is refused by the floor alone
        exact = Source.from_text("a" * 15851 + "\n", "a.py")
        planner = plan.Planner(exact)
        self.assertEqual(planner._floor_bytes(True), 15872)
        found = plan.plan_whole_file(exact)
        self.assertEqual(found.reason, "state_bytes")
        self.assertNotIn("at_least", found.detail)
        over = plan.plan_whole_file(Source.from_text("a" * 15852 + "\n", "a.py"))
        self.assertEqual(over, plan.Fallback("state_bytes", {"bytes": 15873, "limit": 15872,
                                                             "at_least": True}))

    def test_a_request_of_exactly_the_byte_cap_fits_and_one_byte_more_does_not(self):
        pack = plan.load_tile_sieve_pack()
        policy = plan.Planner(synthetic(3)).policy

        def build(extra):
            # 30 questions that carry *extra* spare bytes of wording between them
            qs = {}
            for i in range(30):
                question = plan.leaf_q(pack, Span(1, 1))
                spare = min(extra, 600)
                extra -= spare
                qs[f"q{i}"] = dict(question, instructions=question["instructions"] + "x" * spare)
            return plan.assemble(self.minimal_state(), qs, policy)

        base = len(build(0)[0])
        wire = build(24064 - base)[0]
        self.assertEqual(len(wire), 24064)
        with self.assertRaises(plan.Overflow) as caught:
            build(24064 - base + 1)
        self.assertEqual(caught.exception.reason, "request_bytes")
        self.assertEqual(caught.exception.detail, {"bytes": 24065, "limit": 24064})

    def test_a_batch_of_exactly_64_questions_fits_and_65_do_not(self):
        pack = plan.load_tile_sieve_pack()
        policy = plan.Planner(synthetic(3)).policy

        def build(count):
            qs = {f"q{i}": plan.leaf_q(pack, Span(1, 1)) for i in range(count)}
            return plan.assemble(self.minimal_state(), qs, policy)

        full = build(62)                    # the two canaries make 64
        self.assertEqual(full[5], 64)
        with self.assertRaises(plan.Overflow) as caught:
            build(63)
        self.assertEqual((caught.exception.reason, caught.exception.detail),
                         ("split_into_batches", {"batches": 2}))

    @staticmethod
    def encoded_floor(*groups):
        # what the state really carries per line, encoded the way the wire encodes it, plus the comma
        return sum(len(json.dumps({"line": i, "text": t}, ensure_ascii=False,
                                  separators=(",", ":")).encode("utf-8")) + 1
                   for lines in groups for i, t in enumerate(lines, 1))

    def test_the_cheap_floor_is_the_encoded_lines_and_never_above_the_real_state(self):
        mixed = ["plain ascii line", "café 日本語", 'quote " and back' + chr(92) + "slash",
                 "tab\tcontrol\x01end", "", "x = 1"] * 3
        helper = ProjectEntry("util.py", Source.from_text("\n".join(mixed[:5]) + "\n", "util.py"))
        for entries in ((), (helper,)):
            source = Source.from_text("\n".join(mixed) + "\n", "mixed.py")
            planner = plan.Planner(source, None, entries, "project" if entries else "declared_standalone")
            related = [e.source.lines for e in entries]
            self.assertEqual(planner._floor_bytes(True), self.encoded_floor(source.lines, *related))
            self.assertEqual(planner._floor_bytes(False), self.encoded_floor(*related))
            self.assertLessEqual(planner._floor_bytes(True), planner.whole_tile(0).state_bytes)
            self.assertLessEqual(planner._floor_bytes(False), planner.focus((2, 3)).state_bytes)
        # the sum stops at the first line past a limit
        first = self.encoded_floor(source.lines[:1])
        self.assertEqual(planner._floor_bytes(True, first - 1), first)
        self.assertLess(first, planner._floor_bytes(True))
        self.assertEqual(planner._floor_bytes(True, first), self.encoded_floor(source.lines[:2]))   # not at it

    def test_a_focus_request_is_refused_by_the_floor_when_the_related_sources_alone_overflow(self):
        entries = tuple(ProjectEntry(f"module_{i:03d}.py", Source.from_text("value = 1\n" * 30, "m.py"))
                        for i in range(128))
        source = Source.from_text("def run():\n    return 1\n", "run.py")
        planner = plan.Planner(source, None, entries, "project")
        with mock.patch.object(plan.Planner, "_focus_once", side_effect=AssertionError("built")):
            with self.assertRaises(plan.PlanError) as caught:
                planner.focus((1, 2))
        self.assertEqual(caught.exception.reason, "focus_unfittable")
        self.assertEqual(caught.exception.detail, {"K": [1, 2], "overflow": "state_bytes"})
        self.assertIsNone(planner._index)               # the index was never built
        found = plan.plan_whole_file(source, None, entries, "project")
        self.assertTrue(found.detail["at_least"])

    @staticmethod
    def minimal_state(**changes):
        state = {"source_sha256": "0" * 64, "file": "a.py", "total_lines": 1,
                 "excerpts": [], "specification": {"mode": "inferred", "lines": []},
                 "context_scope": "declared_standalone"}
        state.update(changes)
        return state

    def assemble(self, state, qs):
        return plan.assemble(state, qs, plan.Planner(synthetic(3)).policy)

    def refusal(self, state, qs):
        with self.assertRaises(plan.Overflow) as caught:
            self.assemble(state, qs)
        return caught.exception

    def test_more_questions_than_one_batch_holds_split_into_batches(self):
        pack = plan.load_tile_sieve_pack()
        qs = {f"q{i}": plan.leaf_q(pack, Span(1, 1)) for i in range(70)}
        refused = self.refusal(self.minimal_state(), qs)
        self.assertEqual(refused.reason, "split_into_batches")
        self.assertEqual(refused.detail, {"batches": 2})

    def test_a_question_larger_than_the_request_is_question_too_large(self):
        wide = {"type": "choice", "instructions": "Pick one option.",
                "criteria": {f"opt{i:03d}": "x" * 200 for i in range(255)}}
        self.assertEqual(self.refusal(self.minimal_state(), {"wide": wide}).reason,
                         "question_too_large")

    def test_a_state_without_a_declared_scope_cannot_carry_the_canaries(self):
        state = self.minimal_state()
        del state["context_scope"]
        pack = plan.load_tile_sieve_pack()
        self.assertEqual(self.refusal(state, {"q": plan.leaf_q(pack, Span(1, 1))}).reason,
                         "canaries_do_not_fit")

    def test_a_state_over_the_cap_is_state_bytes_with_the_exact_size(self):
        pack = plan.load_tile_sieve_pack()
        state = self.minimal_state(file="a" * 16000)
        refused = self.refusal(state, {"q": plan.leaf_q(pack, Span(1, 1))})
        self.assertEqual(refused.reason, "state_bytes")
        self.assertGreater(refused.detail["bytes"], 16000)
        self.assertEqual(refused.detail["limit"], 15872)
        self.assertNotIn("at_least", refused.detail)

    def test_the_question_cap_is_checked_again_after_packing(self):
        pack = plan.load_tile_sieve_pack()
        names = [f"q{i}" for i in range(63)] + ["ctl_00000001", "ctl_00000002"]
        batch = {name: plan.leaf_q(pack, Span(1, 1)) for name in names}
        packed = [(batch, None, b"{}")]
        with mock.patch.object(questions, "prepared_question_batches", lambda *a, **k: iter(packed)):
            refused = self.refusal(self.minimal_state(), {"q": plan.leaf_q(pack, Span(1, 1))})
        self.assertEqual(refused.reason, "too_many_questions")
        self.assertEqual(refused.detail, {"questions": 65, "limit": 64})

    def test_a_request_over_the_byte_cap_reports_both_numbers(self):
        found = plan.plan_whole_file(synthetic(220), spec_source())
        self.assertEqual((found.detail["bytes"], found.detail["limit"]), (24493, 24064))

    def test_a_provider_refusal_is_a_provider_code(self):
        bad = {"q": {"type": "noul", "instructions": "x", "criteria": {"true": "a"}}}
        self.assertEqual(self.refusal(self.minimal_state(), bad).reason, "provider_invalid_request")

    def test_fallback_reasons_are_the_documented_codes(self):
        self.assertEqual(set(plan.FALLBACK_REASONS),
                         {"request_bytes", "state_bytes", "too_many_questions", "split_into_batches",
                          "canaries_do_not_fit", "question_too_large", "empty_file"})


class SingleLookTests(unittest.TestCase):
    def source(self, n):
        return Source.from_text("".join(f"value_{i} = {i}\n" for i in range(n)), "small.py")

    def test_look_one_is_planned_only_above_eight_lines(self):
        for n in range(1, 13):
            found = plan.plan_whole_file(self.source(n), spec_source())
            self.assertIsInstance(found, plan.WholeFilePlan, n)
            if n <= 8:
                self.assertEqual(len(found.looks), 1, n)
                self.assertEqual(found.looks[0].looks, (0, 1), n)
            else:
                self.assertEqual(len(found.looks), 2, n)
                self.assertNotEqual(found.looks[0].sha256, found.looks[1].sha256, n)

    def test_up_to_four_lines_the_two_looks_are_the_same_bytes(self):
        for n in range(1, 5):
            planner = plan.Planner(self.source(n), spec_source())
            self.assertEqual(planner.whole_tile(0).wire, planner.whole_tile(1).wire, n)
        planner = plan.Planner(self.source(5), spec_source())
        self.assertNotEqual(planner.whole_tile(0).wire, planner.whole_tile(1).wire)

    def test_identical_looks_are_merged(self):
        planner = plan.Planner(self.source(20), spec_source())
        first = planner.whole_tile(0)
        with mock.patch.object(plan.Planner, "whole_tile", lambda self, look: first):
            found = planner.plan()
        self.assertEqual(len(found.looks), 1)
        self.assertEqual(found.looks[0].looks, (0, 1))

    def test_an_invalid_look_is_refused(self):
        planner = plan.Planner(self.source(3))
        for look in (-1, 2, "0"):
            with self.assertRaises(ValueError):
                planner.whole_tile(look)

    def test_request_for_an_unplanned_look_is_refused(self):
        found = plan.plan_whole_file(self.source(3))
        with self.assertRaises(ValueError):
            found.request_for_look(2)


class IntegrityTests(unittest.TestCase):
    def test_a_reencode_mismatch_raises_integrity_error_not_a_fallback(self):
        source = synthetic(30)
        with mock.patch.object(protocol, "encode_request", lambda state, qs=None: b"{}"):
            with self.assertRaises(plan.IntegrityError):
                plan.plan_whole_file(source, spec_source())
            with self.assertRaises(plan.IntegrityError):
                plan.Planner(source, spec_source()).focus((3, 5))

    def test_integrity_error_is_neither_an_overflow_nor_a_plan_error(self):
        self.assertFalse(issubclass(plan.IntegrityError, (plan.Overflow, plan.PlanError)))
        self.assertFalse(issubclass(plan.Overflow, plan.PlanError))


class SurfaceTests(unittest.TestCase):
    def test_no_stage_two_symbol_is_exported(self):
        for module in (plan, tindex):
            for name in dir(module):
                self.assertNotIn("stage2", name.lower(), f"{module.__name__}.{name}")
                self.assertNotIn("stage_2", name.lower(), f"{module.__name__}.{name}")
        for name in dir(plan.Planner):
            self.assertNotIn("stage2", name.lower(), name)
        self.assertNotIn("stage2", inspect.getsource(plan).lower())

    def test_the_planner_takes_no_judge_or_route(self):
        self.assertEqual(list(inspect.signature(plan.plan_whole_file).parameters),
                         ["source", "spec_source", "project_entries", "context_scope"])
        self.assertEqual(list(inspect.signature(plan.Planner.__init__).parameters),
                         ["self", "source", "spec_source", "project_entries", "context_scope"])

    def test_caps_are_openai_directs_whatever_the_route(self):
        self.assertEqual((plan.MAX_QUESTIONS, plan.ENVELOPE_BYTES, plan.MAX_REQUEST_BYTES,
                          plan.MAX_STATE_BYTES), (64, 24576, 24064, 15872))

    def test_planning_is_independent_of_the_active_state_layout(self):
        source = synthetic(40)
        reference = plan.plan_whole_file(source, spec_source())
        with questions.using_state_layout("v2"):
            other = plan.plan_whole_file(source, spec_source())
            focus = plan.Planner(source, spec_source()).focus((10, 14))
        self.assertEqual([r.sha256 for r in other.looks], [r.sha256 for r in reference.looks])
        self.assertEqual(focus.sha256, plan.Planner(source, spec_source()).focus((10, 14)).sha256)

    def test_planning_is_deterministic(self):
        source = synthetic(120)
        again = [plan.plan_whole_file(source, spec_source()) for _ in range(2)]
        self.assertEqual([r.wire for r in again[0].looks], [r.wire for r in again[1].looks])

    def test_requests_do_not_depend_on_the_hash_seed(self):
        code = chr(10).join([
            "from decision_bug_hunter import tile_sieve_plan as p",
            "from decision_bug_hunter.core import Source",
            "text = ''.join(f'def f{i}(a):' + chr(10) + f'    return g{i % 7}(a) + h{i % 5}(a)' + chr(10)",
            "               for i in range(40))",
            "pl = p.Planner(Source.from_text(text, 'm.py'))",
            "print(pl.whole_tile(0).sha256, pl.whole_tile(1).sha256, pl.focus((30, 33)).sha256)",
        ])
        outputs = set()
        for seed in ("1", "2", "3"):
            env = dict(os.environ, PYTHONHASHSEED=seed, PYTHONPATH=str(ROOT))
            result = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True,
                                    env=env, cwd=ROOT, timeout=120)
            self.assertEqual(result.returncode, 0, result.stderr)
            outputs.add(result.stdout)
        self.assertEqual(len(outputs), 1)


class StateAndQuestionTests(unittest.TestCase):
    def plan_for(self, n, **kw):
        return plan.Planner(synthetic(n), spec_source(), **kw)

    def test_state_keys_follow_the_pilots_order(self):
        request = self.plan_for(70).whole_tile(0)
        self.assertEqual(list(request.state), ["policy", "source_sha256", "file", "total_lines",
                                               "excerpts", "specification", "context_scope"])
        self.assertEqual(list(request.state["specification"]), ["mode", "lines"])
        self.assertEqual(request.state["specification"]["mode"], "provided")
        self.assertEqual(request.state["total_lines"], 70)
        self.assertEqual(request.state["excerpts"][0]["start_line"], 1)
        self.assertEqual(request.state["excerpts"][0]["end_line"], 70)

    def test_related_sources_and_evidence_follow_the_specification(self):
        source = Source.from_text("def a():\n    return b()\n", "a.py")
        helper = ProjectEntry("util/b.py", Source.from_text("def b():\n    return 1\n", "b.py"))
        request = plan.Planner(source, None, (helper,), "project").focus((1, 2))
        self.assertEqual(list(request.state), ["policy", "source_sha256", "file", "total_lines",
                                               "excerpts", "specification", "related_sources",
                                               "context_scope"])
        self.assertEqual(request.state["specification"], {"mode": "inferred", "lines": []})
        self.assertEqual(request.state["related_sources"][0]["file"], "util/b.py")
        pair = Source.from_text("def a():\n    return 1\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n"
                                "\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\ndef c():\n    return a()\n",
                                "c.py")
        shown = plan.Planner(pair).focus((49, 50))
        self.assertEqual(list(shown.state)[-1], "evidence_coordinates")
        self.assertEqual(shown.meta["partners"], [[1, 2, "def a"]])

    def test_every_project_file_but_the_primary_is_related_in_index_order(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            for name, body in (("main.py", "import util\n"), ("zeta.py", "Z = 1\n"),
                               ("alpha.py", "A = 1\n"), ("util.py", "U = 1\n")):
                (root / name).write_text(body, encoding="utf-8")
            primary = Source.read(root / "main.py")
            index = ProjectIndex.read(root, primary_path=root / "main.py")
            self.assertEqual([e.relpath for e in index.entries], ["alpha.py", "util.py", "zeta.py"])
            # the index already leaves the primary out; a caller that passes it anyway gets it dropped
            extra = ProjectEntry("main.py", primary)
            twin = ProjectEntry("again.py", Source.read(root / "main.py"))
            entries = (index.entries[0], extra, index.entries[1], twin, index.entries[2])
            planner = plan.Planner(primary, None, entries, "project")
            self.assertEqual([e.relpath for e in planner.related], ["alpha.py", "util.py", "zeta.py"])
            request = planner.whole_tile(0)
            self.assertEqual([r["file"] for r in request.state["related_sources"]],
                             ["alpha.py", "util.py", "zeta.py"])

    def test_no_project_files_means_no_related_sources_key(self):
        request = self.plan_for(20).whole_tile(0)
        self.assertNotIn("related_sources", request.state)

    def test_mode_a_rich_question_order(self):
        request = self.plan_for(70).whole_tile(0)
        order = [q for q in request.questions if not questions.CONTROL_NAME.fullmatch(q)]
        self.assertEqual(order, ["leaf_L1-16", "leaf_L17-32", "leaf_L33-48", "leaf_L49-64", "leaf_L65-70",
                                 "block_L1-48", "block_L49-70", "need_ctx", "gran",
                                 "lens_functional", "lens_contract", "lens_boundary", "lens_state",
                                 "lens_integration", "req"])
        self.assertEqual(len(request.questions), len(order) + 2)
        controls = [q for q in request.questions if questions.CONTROL_NAME.fullmatch(q)]
        self.assertEqual(sorted(request.roles[q]["role"] for q in controls), ["must_false", "must_true"])
        # look 1 shifts every grid
        second = self.plan_for(70).whole_tile(1)
        self.assertEqual(second.meta["cells"]["leaf"],
                         [[1, 8], [9, 24], [25, 40], [41, 56], [57, 70]])
        self.assertEqual(second.meta["cells"]["block"], [[1, 24], [25, 70]])
        self.assertEqual(second.meta["cells"]["gran"][0], [1, 4])

    def test_requirement_question_only_when_passages_were_kept(self):
        without = plan.Planner(synthetic(30)).whole_tile(0)
        self.assertNotIn("req", without.questions)
        self.assertEqual(without.state["specification"], {"mode": "inferred", "lines": []})
        with_spec = self.plan_for(30).whole_tile(0)
        self.assertIn("req", with_spec.questions)
        criteria = with_spec.questions["req"]["criteria"]
        self.assertEqual(list(criteria)[-1], "none")
        self.assertEqual(criteria["none"],
                         "No supplied specification passage is a relevant requirement for this target.")

    def test_the_policy_is_placed_once_in_state_and_stripped_from_questions(self):
        request = self.plan_for(30).whole_tile(0)
        policy = request.state["policy"]
        self.assertTrue(policy)
        for qid, question in request.questions.items():
            self.assertNotIn(policy, question["instructions"], qid)

    def test_focus_question_order(self):
        request = self.plan_for(70).focus((20, 31))
        order = [q for q in request.questions if not questions.CONTROL_NAME.fullmatch(q)]
        self.assertEqual(order[:2], ["loc_a", "loc_b"])
        self.assertEqual(order[2:4], ["verify", "twin"])
        self.assertEqual(order[4:9], [f"lens_{n}" for n in plan.LENS_NAMES])
        self.assertEqual(order[-2:], ["need_ctx", "multiple"])
        self.assertTrue(all(q.startswith(("reqm_", "rel_")) for q in order[9:-2]))
        self.assertEqual(request.meta["K"], [20, 31])
        self.assertEqual(request.meta["display"], [4, 47])

    def test_focus_clips_to_the_file_and_honors_the_lens_order(self):
        planner = self.plan_for(30)
        request = planner.focus((25, 99), lens_order=["state", "functional", "contract", "boundary",
                                                      "integration"])
        self.assertEqual(request.meta["K"], [25, 30])
        self.assertEqual(request.meta["display"], [9, 30])
        lenses = [q for q in request.roles if q.startswith("lens_")]
        self.assertEqual(lenses, ["lens_state", "lens_functional", "lens_contract", "lens_boundary",
                                  "lens_integration"])
        with self.assertRaises(ValueError):
            planner.focus((40, 50))


class TruncationTests(unittest.TestCase):
    """The focus ladder: partners, partner lines, spec, halo, optional questions. The expected
    shas were also produced by the pilot's planner on the same inputs."""

    @staticmethod
    def heavy_lines():
        lines = []
        for i in range(6):
            lines.append(f"def helper_{i}(x):")
            lines.extend(f"    y{j} = x + {j}  # " + "p" * 300 for j in range(29))
        lines.append("def target(x):")
        lines.extend(f"    x = helper_{i}(x)" for i in range(6))
        lines.append("    return x")
        return lines

    def test_the_first_setting_is_untrimmed_and_the_ladder_only_trims(self):
        ladder = plan._truncation_settings(3)
        self.assertEqual(ladder[0], {"partners": 3, "partner_cap": None, "spec": 1536, "linked": False,
                                     "halo": 16, "relations": 3, "lenses": 5})
        self.assertEqual([s["partners"] for s in ladder[:3]], [3, 2, 1])
        self.assertEqual([s["partner_cap"] for s in ladder[3:6]], [24, 12, 6])
        self.assertEqual(ladder[-1], {"partners": 0, "partner_cap": 6, "spec": 96, "linked": True,
                                      "halo": 0, "relations": 1, "lenses": 3})
        self.assertEqual(len(plan._truncation_settings(0)), 1 + 3 + 1 + 1 + 1)
        # no rung widens the halo or restores anything
        for before, after in zip(ladder, ladder[1:]):
            self.assertLessEqual(after["partners"], before["partners"])
            self.assertLessEqual(after["halo"], before["halo"])
            self.assertLessEqual(after["spec"], before["spec"])
            self.assertLessEqual(after["relations"], before["relations"])
            self.assertLessEqual(after["lenses"], before["lenses"])
        self.assertTrue(all(s["halo"] <= 16 for s in ladder))

    def test_an_overfull_request_is_trimmed_to_fit(self):
        lines = self.heavy_lines()
        source = Source.from_text("\n".join(lines) + "\n", "mod.py")
        request = plan.Planner(source).focus((len(lines) - 8, len(lines)))
        self.assertEqual(request.sha256,
                         "4b5cf338db3364f7482d8c278d26a3c7a5fa44f7670dc21c58581b6ec9952b1a")
        self.assertEqual(request.meta["truncation"]["partner_cap"], 24)
        self.assertEqual(request.meta["truncation"]["partners"], 1)
        self.assertEqual(request.meta["partners"], [[121, 144, "def helper_4"]])
        assert_within_caps(self, request)

    @staticmethod
    def wide_source(width):
        lines = (["def alpha_total(x):"]
                 + [f"    value_{i} = alpha_total(x) + {i}  # " + "p" * width for i in range(58)]
                 + ["    return x"])
        return Source.from_text("\n".join(lines) + "\n", "m.py")

    WIDE_SPEC = "\n\n".join(
        f"Rule {i}: the alpha total value must stay within the documented limit for case {i}. "
        + "Totals are inclusive of the upper bound. " * 2 for i in range(14)) + "\n"

    def test_a_request_that_stays_too_big_descends_the_spec_and_halo_rungs(self):
        # (line width, settings that fit, nq, sha256), all taken from the pilot's planner
        rungs = [
            (320, {"spec": 768, "linked": False, "halo": 16, "relations": 3, "lenses": 5}, 15,
             "6abc3441201c24c11c3e47b04bba8a9b2b5cc69ebb759652ff491fe071422cf2"),
            (340, {"spec": 384, "linked": True, "halo": 16, "relations": 3, "lenses": 5}, 15,
             "d1681ff0333fa5ec35719617e273e61792e99ec47e2c88fd3a5e064d7ce63d38"),
            (350, {"spec": 192, "linked": True, "halo": 16, "relations": 3, "lenses": 5}, 14,
             "5740bb879a80f743d64d57007024459363ad89ee0abc0d4903d2e9278022b873"),
            (360, {"spec": 192, "linked": True, "halo": 8, "relations": 3, "lenses": 5}, 14,
             "7a8e233f6f8be1e4200aaf722ad6992e05a5d42c65261e28a7448adcbb106dff"),
            (700, {"spec": 96, "linked": True, "halo": 0, "relations": 1, "lenses": 3}, 11,
             "5631d73b7d80b8d243e49091cd0efb275c224afe468c2e6e0f0569a03b9c4018"),
        ]
        for width, settings, nq, sha in rungs:
            request = plan.Planner(self.wide_source(width), spec_source(self.WIDE_SPEC)).focus((25, 28))
            self.assertEqual(request.meta["truncation"],
                             dict(settings, partners=0, partner_cap=None), width)
            self.assertEqual(request.nq, nq, width)
            self.assertEqual(request.sha256, sha, width)
            assert_within_caps(self, request)

    def test_nearest_definitions_stand_in_only_when_context_was_needed(self):
        source = Source.from_text("def first(x):\n    return x + 1\n\ndef second(y):\n    return y * 2\n\n"
                                  "def third(z):\n    return z - 1\n", "mod.py")
        planner = plan.Planner(source)
        off = planner.focus((4, 5))
        on = planner.focus((4, 5), need_ctx=True)
        self.assertEqual(off.meta["partners"], [])
        self.assertEqual(off.sha256, "9c314e009b2fea2e220e4133780d5ee5845cf7a5b952c1841acc32bdfc6e81f6")
        self.assertEqual(on.meta["partners"], [[7, 8, "def third"], [1, 2, "def first"]])
        self.assertEqual(on.sha256, "3a66ec50fe4263be28a178087be37c670564008b9abd92abdd0ca4313bdb5ced")
        self.assertTrue(on.meta["need_ctx_tile"])
        self.assertFalse(off.meta["need_ctx_tile"])

    def test_a_region_that_cannot_fit_even_bare_is_a_plan_error(self):
        source = Source.from_text("a = '" + "z" * 20000 + "'\nb = 1\nc = 2\n", "mod.py")
        with self.assertRaises(plan.PlanError) as caught:
            plan.Planner(source).focus((1, 3))
        self.assertEqual(caught.exception.reason, "focus_unfittable")
        self.assertEqual(caught.exception.detail["K"], [1, 3])
        # the whole-file look is refused as well, with a fallback rather than an error
        self.assertEqual(plan.plan_whole_file(source).reason, "state_bytes")


class GridTests(unittest.TestCase):
    def test_cells_are_clipped_and_owned_by_their_first_line(self):
        self.assertEqual([c.id for c in plan.cells_owned(70, 16, 0, 1, 70)],
                         ["L1-16", "L17-32", "L33-48", "L49-64", "L65-70"])
        self.assertEqual([c.id for c in plan.cells_owned(70, 16, 8, 1, 70)],
                         ["L1-8", "L9-24", "L25-40", "L41-56", "L57-70"])
        self.assertEqual([c.id for c in plan.cells_owned(70, 8, 4, 1, 70)][:3],
                         ["L1-4", "L5-12", "L13-20"])
        self.assertEqual(plan.cells_owned(70, 16, 0, 20, 40)[0], plan.Cell(33, 48))
        self.assertEqual(plan.cells_owned(0, 16, 0, 1, 10), [])
        self.assertEqual(plan.cells_owned(10, 16, 0, 5, 4), [])

    def test_every_line_belongs_to_one_cell_per_grid_and_look(self):
        for n in (1, 2, 7, 8, 9, 16, 17, 47, 48, 49, 70, 95, 200):
            for look in (0, 1):
                _offset, a, b, g = plan.PHASES[look]
                for period, phase in ((plan.LEAF, a), (plan.BLOCK, b), (plan.GRAN, g)):
                    cells = plan.cells_owned(n, period, phase, 1, n)
                    covered = [line for c in cells for line in range(c.start, c.end + 1)]
                    self.assertEqual(covered, list(range(1, n + 1)), (n, look, period))
                    for line in range(1, n + 1):
                        c = plan.cell_containing(n, period, phase, line)
                        self.assertIn(c, cells)
                        self.assertTrue(c.start <= line <= c.end)

    def test_local_cells(self):
        self.assertEqual([(c.start, c.end) for c in plan.local_cells(1, 10, 4)],
                         [(1, 4), (5, 8), (9, 10)])
        self.assertEqual([(c.start, c.end) for c in plan.local_cells(1, 10, 4, 2)],
                         [(1, 2), (3, 6), (7, 10)])
        self.assertEqual([(c.start, c.end) for c in plan.local_cells(5, 5, 4, 2)], [(5, 5)])

    def test_the_two_phases_are_the_pilots(self):
        self.assertEqual(plan.PHASES, ((0, 0, 0, 0), (72, 8, 24, 4)))
        self.assertEqual((plan.LEAF, plan.BLOCK, plan.GRAN), (16, 48, 8))


class PackTests(unittest.TestCase):
    def test_the_merged_pack_keeps_question_pack_and_adds_the_wording(self):
        base, base_sha = questions.load_pack()
        merged = plan.load_tile_sieve_pack()
        for key, value in base.items():
            self.assertEqual(merged[key], value, key)
        self.assertEqual(merged["version"], base["version"])
        self.assertEqual(set(merged) - set(base),
                         {"rank_granule", "rank_requirement", "multiple", "requirement_none"})
        self.assertEqual(base_sha, "ce602fcdea0b37d25410f39f075e3470445671af7e64c8910904416b29cdd0d2")

    def test_the_pack_hash_is_the_shipped_files(self):
        path = ROOT / "decision_bug_hunter" / "tile_sieve_pack.json"
        self.assertEqual(plan.tile_sieve_pack_sha256(), hashlib.sha256(path.read_bytes()).hexdigest())

    def test_a_malformed_pack_file_is_refused(self):
        with mock.patch.object(plan, "files") as files:
            files.return_value.joinpath.return_value.read_bytes.return_value = b'{"version": "x"}'
            with self.assertRaises(ValueError):
                plan.load_tile_sieve_pack()

    def test_the_granule_question_offers_none_and_unlocalized(self):
        request = plan.Planner(synthetic(30), spec_source()).whole_tile(0)
        criteria = request.questions["gran"]["criteria"]
        self.assertEqual(list(criteria)[-2:], ["none", "unlocalized"])
        self.assertEqual(list(criteria)[0], "L1-8")


class IndexTests(unittest.TestCase):
    PYTHON = ("LIMIT = 10\n"
              "\n"
              "def scale(value):\n"
              "    \"\"\"Scale a value.\"\"\"\n"
              "    return value * LIMIT\n"
              "\n"
              "class Box:\n"
              "    def open(self):\n"
              "        return scale(1)\n")

    def test_python_outline_and_uses(self):
        index = tindex.CodeIndex(self.PYTHON.splitlines(), "mod.py")
        self.assertEqual([(d.name, d.kind, d.start, d.end) for d in index.defs],
                         [("LIMIT", "var", 1, 1), ("scale", "def", 3, 5), ("Box", "class", 7, 9),
                          ("open", "def", 8, 9)])
        self.assertEqual(index.defs_of("scale")[0].doc, "Scale a value.")
        self.assertEqual(index.uses_of("scale"), [9])
        self.assertEqual(index.idents_in(3, 5), {"LIMIT": 1, "value": 1})

    def test_partners_are_definitions_used_and_uses_of_definitions(self):
        index = tindex.CodeIndex(self.PYTHON.splitlines(), "mod.py")
        used = index.partners(9, 9, 0)
        self.assertEqual(used, [(6, Span(3, 5), "def scale")])
        defined = index.partners(3, 5, 0)
        self.assertEqual(defined, [(2, Span(1, 1), "def LIMIT"), (4, Span(8, 9), "use scale")])
        capped = index.partners(9, 9, 0, max_lines=2)
        self.assertEqual(capped, [])
        self.assertEqual(index.partners(9, 9, 20), [])          # everything is inside the halo

    def test_a_python_file_that_does_not_parse_uses_the_regex_index(self):
        broken = "def ok(x):\n    return x +\n\nfunction other() {\n  ok(1)\n}\n"
        index = tindex.CodeIndex(broken.splitlines(), "bad.py")
        self.assertEqual([d.name for d in index.defs], ["ok", "other"])
        self.assertTrue(index.uses_of("ok"))

    @staticmethod
    def escape_lines():
        # a valid file whose string has an invalid escape sequence; the backslash is built here so
        # that this test file itself compiles without a warning. The comment names a function: the
        # ast index does not count it as a use, the regex index does.
        return ["import re", "", "def target(x):", "    return x", "",
                'PATTERN = re.compile("' + chr(92) + 'd+")', "# target is only named in a comment"]

    def test_an_invalid_escape_neither_warns_nor_changes_the_index(self):
        lines = self.escape_lines()
        for action in ("default", "always", "error"):
            with warnings.catch_warnings(record=True) as seen:
                warnings.simplefilter(action)
                index = tindex.CodeIndex(lines, "mod.py")
            self.assertEqual(seen, [], action)
            self.assertEqual(index.uses_of("target"), [], action)       # still the ast index
        for action in ("default", "always"):
            with warnings.catch_warnings(), contextlib.redirect_stderr(io.StringIO()) as err:
                warnings.simplefilter(action)
                tindex.CodeIndex(lines, "mod.py")
            self.assertEqual(err.getvalue(), "", action)

    def test_request_bytes_do_not_depend_on_the_warning_filters(self):
        source = Source.from_text("\n".join(self.escape_lines()) + "\n", "mod.py")
        shas = {}
        for action in ("default", "error"):
            with warnings.catch_warnings(), contextlib.redirect_stderr(io.StringIO()) as err:
                warnings.simplefilter(action)
                planner = plan.Planner(source)
                shas[action] = (planner.whole_tile(0).sha256, planner.whole_tile(1).sha256,
                                planner.focus((3, 4)).sha256)
            self.assertEqual(err.getvalue(), "", action)
        self.assertEqual(shas["error"], shas["default"])

    def test_a_parser_stack_overflow_uses_the_regex_index(self):
        deep = ["def f():", "    return " + "-" * 7000 + "1"]
        index = tindex.CodeIndex(deep, "deep.py")        # a MemoryError in ast.parse on CPython
        self.assertEqual([d.name for d in index.defs], ["f"])
        found = plan.plan_whole_file(Source.from_text("\n".join(deep) + "\n", "deep.py"))
        self.assertIsInstance(found, plan.WholeFilePlan)
        # whatever the interpreter does with that line, a MemoryError from the parser is not fatal
        calls = []

        def refuse(*args, **kwargs):
            calls.append(args)
            raise MemoryError

        with mock.patch.object(tindex.ast, "parse", refuse):
            regex = tindex.CodeIndex(self.PYTHON.splitlines(), "mod.py")
        self.assertEqual(len(calls), 1)
        self.assertEqual([d.name for d in regex.defs], ["LIMIT", "scale", "Box", "open"])
        self.assertTrue(regex.uses_of("scale"))

    def test_other_languages_use_the_regex_index(self):
        js = "MAX_ITEMS = 4;\nfunction pick(a) {\n  return a + MAX_ITEMS;\n}\n\nfunction run() {\n  pick(1);\n}\n"
        index = tindex.CodeIndex(js.splitlines(), "x.js")
        self.assertEqual([(d.name, d.start, d.end) for d in index.defs],
                         [("MAX_ITEMS", 1, 1), ("pick", 2, 4), ("run", 6, 8)])
        self.assertEqual(index.uses_of("MAX_ITEMS"), [1, 3])
        self.assertEqual([lab for _d, _s, lab in index.partners(7, 7, 0)], ["def pick"])

    def test_nearest_definitions(self):
        index = tindex.CodeIndex(["def a():", "    pass", "", "def b():", "    pass", "", "def c():", "    pass"],
                                 "m.py")
        found = tindex.nearest_defs(index, 4, 5)
        self.assertEqual([(s.start, s.end, lab) for _d, s, lab in found], [(7, 8, "def c"), (1, 2, "def a")])

    def test_nearest_definitions_cut_a_long_definition_to_forty_lines(self):
        # expected values from the pilot's index on the same lines
        lines = (["def big():"] + [f"    v{i} = {i}" for i in range(44)]
                 + ["", "def small():", "    return 1", "", "def other():", "    return 2"])
        index = tindex.CodeIndex(lines, "m.py")
        for region, expected in (((47, 48), [(2, 50, 51, "def other"), (46, 1, 40, "def big")]),
                                 ((52, 53), [(2, 50, 51, "def other"), (5, 47, 48, "def small")])):
            found = tindex.nearest_defs(index, *region)
            self.assertEqual([(d, s.start, s.end, lab) for d, s, lab in found], expected, region)

    SPAN_SOURCE = (["def alpha():", "    return 1", "", "def beta():", "    return alpha()",
                    "def rec(n):", "    return rec(n - 1) if n else 0", "    # tail"]
                   + ["pad = 0"] * 30 + ["x = alpha() + beta()"] + ["pad2 = 0"] * 5 + ["y = rec(3)"])

    def test_use_sites_that_share_a_span_keep_the_first_definition(self):
        # expected values from the pilot's index on the same lines
        index = tindex.CodeIndex(self.SPAN_SOURCE, "m.py")
        for halo, expected in ((0, [(1, 4, 6, "use alpha"), (35, 38, 40, "use alpha")]),
                               (2, [(35, 38, 40, "use alpha")])):
            found = index.partners(1, 4, halo, 80, 40)
            self.assertEqual([(d, s.start, s.end, lab) for d, s, lab in found], expected, halo)
        both = index.partners(4, 5, 0, 80, 40)
        self.assertEqual([(d, s.start, s.end, lab) for d, s, lab in both],
                         [(3, 1, 2, "def alpha"), (34, 38, 40, "use beta")])

    def test_a_use_inside_the_definitions_own_body_is_not_a_partner(self):
        index = tindex.CodeIndex(self.SPAN_SOURCE, "m.py")
        for region in ((6, 6), (6, 7)):
            found = index.partners(region[0], region[1], 0, 80, 40)
            self.assertEqual([(s.start, s.end, lab) for _d, s, lab in found], [(44, 45, "use rec")], region)

    def test_spec_slice_budget_is_inclusive(self):
        text = "alpha beta total rule"
        cost = len(json.dumps({"line": 1, "text": text}, separators=(",", ":")).encode("utf-8")) + 1
        fits, kept = tindex.spec_slice([text], ["alpha"], 2 + cost)
        self.assertEqual(fits, [{"line": 1, "text": text}])
        self.assertEqual([(p.start, p.end) for p in kept], [(1, 1)])
        self.assertEqual(tindex.spec_slice([text], ["alpha"], 2 + cost - 1), ([], []))
        # a second passage that brings the total to exactly the budget is kept; one byte less drops it
        lines = ["alpha one", "", "alpha two"]
        total = 2 + sum(len(json.dumps({"line": i, "text": lines[i - 1]},
                                       separators=(",", ":")).encode("utf-8")) + 1 for i in (1, 3))
        for budget, expected in ((total, [1, 3]), (total - 1, [1])):
            entries, kept = tindex.spec_slice(lines, ["alpha"], budget)
            self.assertEqual([e["line"] for e in entries], expected, budget)
            self.assertEqual([p.start for p in kept], expected, budget)

    def test_an_oversize_first_passage_stops_at_the_first_line_that_does_not_fit(self):
        # expected values from the pilot's spec_slice on the same lines: the long second line ends
        # the cut, so the short lines after it are left out
        lines = ["alpha one", "x" * 300, "alpha two", "alpha three", "", "alpha four"]
        for budget, expected_lines, expected_kept in ((120, [1, 6], [(1, 4), (6, 6)]),
                                                      (200, [1, 6], [(1, 4), (6, 6)]),
                                                      (400, [1, 2, 3], [(1, 4)])):
            entries, kept = tindex.spec_slice(lines, ["alpha"], budget)
            self.assertEqual([e["line"] for e in entries], expected_lines, budget)
            self.assertEqual([(p.start, p.end) for p in kept], expected_kept, budget)

    def test_spec_passages_are_blocks_and_windows(self):
        lines = ["first paragraph", "continues", "", "second paragraph"] + [f"long {i}" for i in range(10)]
        found = tindex.spec_passages(lines)
        self.assertEqual([(p.start, p.end) for p in found], [(1, 2), (4, 11), (7, 14)])
        self.assertEqual(tindex.spec_passages([]), [])

    def test_spec_slice_takes_the_best_passages_whole_within_the_budget(self):
        lines = ["unrelated notes here", "", "the scale limit applies to value", "",
                 "another unrelated sentence"]
        entries, kept = tindex.spec_slice(lines, ["scale", "limit"], 1536)
        self.assertEqual([e["line"] for e in entries], [1, 3, 5])
        self.assertEqual(entries[1], {"line": 3, "text": "the scale limit applies to value"})
        small, kept_small = tindex.spec_slice(lines, ["scale", "limit"], 90)
        self.assertEqual([e["line"] for e in small], [3])
        self.assertEqual([(p.start, p.end) for p in kept_small], [(3, 3)])
        self.assertEqual(tindex.spec_slice([], ["x"], 100), ([], []))

    def test_spec_slice_linked_only_cuts_to_the_sentences_that_share_a_word(self):
        lines = ["alpha unrelated", "the scale limit rule", "omega unrelated"]
        entries, kept = tindex.spec_slice(lines, ["scale"], 1536, linked_only=True)
        self.assertEqual([e["line"] for e in entries], [2])
        self.assertEqual([(p.start, p.end) for p in kept], [(1, 3)])
        none_linked, _ = tindex.spec_slice(lines, ["zzz"], 1536, linked_only=True)
        self.assertEqual([e["line"] for e in none_linked], [1])

    def test_a_single_passage_larger_than_the_budget_keeps_the_lines_that_fit(self):
        lines = [f"line number {i} of one long passage" for i in range(20)]
        entries, kept = tindex.spec_slice(lines, [], 200)
        self.assertTrue(0 < len(entries) < 20)
        self.assertEqual([e["line"] for e in entries], list(range(1, len(entries) + 1)))
        self.assertEqual(len(kept), 1)

    def test_words_split_identifiers(self):
        self.assertEqual(tindex.words("parseHTTPRequest v2 an"), {"parse", "http", "request"})
        self.assertEqual(tindex.ident_words(["max_items", "x"]), {"max", "items"})


if __name__ == "__main__":
    unittest.main()
