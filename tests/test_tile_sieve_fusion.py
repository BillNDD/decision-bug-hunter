"""Tile Sieve fusion: the pilot's decisions replayed from recorded answers, the 8C report rule,
both screening variants and the per-judge threshold file.

Everything is offline. The E4 fixture holds the answers the pilot recorded on the 34-case
catalog and what the pilot decided from them; the E2 fixture holds the focus clusters the report
rule was fitted on. Answers are turned into ``Decimal`` objects as the gateway returns them.
"""
import dataclasses
import hashlib
import importlib.util
import json
from decimal import Decimal
from fractions import Fraction
from pathlib import Path
import tomllib
import unittest

from decision_bug_hunter import judges
from decision_bug_hunter import tile_sieve_fusion as F

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "tests" / "fixtures" / "tile_sieve"
THRESHOLDS = ROOT / "decision_bug_hunter" / "tile_sieve_thresholds.json"
#: A file of at most this many lines is read once (look 1 is not asked).
SINGLE_LOOK_MAX_LINES = 8


def load_json(name):
    return json.loads((FIXTURES / name).read_text(encoding="utf-8"))


def gateway(answers):
    """Recorded plain answers as the validated gateway returns them: ``Decimal`` probabilities."""
    out = {}
    for qid, a in answers.items():
        if a["type"] == "noul":
            out[qid] = {"type": "noul", "noul": Decimal(a["noul"])}
        else:
            out[qid] = {"type": "choice", "choice": a["choice"],
                        "probabilities": {k: Decimal(v) for k, v in a["probabilities"].items()},
                        "confidence": Decimal(a["confidence"])}
    return out


def pair(cell):
    return tuple(cell)


def flagged_cells(rows):
    return sorted(pair(r["cell"]) for r in rows if r["flag"])


class Fixtures(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.e4 = load_json("e4_catalog.json")
        cls.e2 = load_json("e2_decisions.json")
        cls.ts = F.load_thresholds("openai")


class ThresholdFileTests(unittest.TestCase):
    def raw(self):
        return THRESHOLDS.read_bytes()

    def data(self):
        return json.loads(self.raw())

    def test_openai_set_holds_the_pilot_values(self):
        ts = F.load_thresholds("openai")
        self.assertEqual(ts.judge, "openai")
        self.assertEqual(ts.screening_rule, "pilot-full")
        self.assertEqual(ts.weights, (1.0, 0.0, 0.0, 0.0))
        self.assertEqual((ts.tau_s, ts.tau_c, ts.tau_block, ts.tau_lens, ts.tau_none),
                         (0.96, 0.96, 0.96, 0.96, 0.04))
        self.assertEqual(ts.tau_leaf, 0.85)
        self.assertEqual(ts.strong_cell, 0.96)
        self.assertEqual((ts.tau_ctx, ts.tau_mult), (0.5, 0.5))
        self.assertEqual(ts.e_weights, (1.0, 2.0, 0.0))
        self.assertEqual((ts.tau_strong, ts.tau_gray, ts.tau_rel), (0.39, 0.39, 0.75))
        self.assertEqual(ts.tau_rep_points, ((200, 0.54), (1000, 0.71), (5000, 0.81)))
        self.assertIn("pilot 2026-10-10", ts.basis)

    def test_values_equal_the_floats_the_pilot_used(self):
        pilot = load_json("e4_catalog.json")["thresholds"]
        ts = F.load_thresholds("openai")
        self.assertEqual(ts.weights, tuple(pilot["weights"]))
        self.assertEqual(ts.e_weights, tuple(pilot["e_weights"]))
        for name in ("tau_s", "tau_c", "tau_block", "tau_lens", "tau_none", "tau_ctx", "tau_mult",
                     "tau_gray", "tau_rel"):
            self.assertEqual(getattr(ts, name), pilot[name], name)
        self.assertEqual(ts.tau_rep_points, tuple(tuple(p) for p in pilot["tau_rep_points"]))
        self.assertEqual(ts.tau_strong, pilot["tau_gray"])

    def test_values_come_from_float_of_the_decimal_string(self):
        ts = F.load_thresholds("openai")
        self.assertEqual(ts.tau_gray, float("0.39"))
        self.assertEqual(repr(ts.tau_gray), "0.39")
        self.assertEqual(ts.tau_strong.hex(), float("0.39").hex())
        self.assertEqual(ts.tau_leaf.hex(), float("0.85").hex())

    def test_the_shipped_screening_rule_is_the_pilot_rule(self):
        self.assertEqual(self.data()["judges"]["openai"]["screening_rule"], "pilot-full")
        self.assertEqual(F.load_thresholds("openai").screening_rule, "pilot-full")
        self.assertEqual(self.data()["judges"]["openai"]["leaf_only"], {"tau_leaf": "0.85"})

    def test_microsoft_has_no_set_and_is_refused(self):
        # Owner decision 12A: the Microsoft judge cannot meet the Tile Sieve gate,
        # so the beta ships no Microsoft threshold set and the loader refuses it.
        self.assertEqual(set(self.data()["judges"]), {"openai"})
        with self.assertRaises(LookupError) as caught:
            F.load_thresholds("microsoft")
        self.assertEqual(str(caught.exception), "tile_sieve_uncalibrated")

    def test_an_unknown_judge_is_uncalibrated(self):
        # unhashable names must be refused as uncalibrated, not raise a TypeError
        for judge in ("nobody", "", "OpenAI", None, 3, ("openai",), ["openai"], {"openai": 1}):
            with self.subTest(judge=judge), self.assertRaises(LookupError) as caught:
                F.load_thresholds(judge)
            self.assertEqual(str(caught.exception), "tile_sieve_uncalibrated")

    def test_every_judge_in_the_file_is_a_known_judge(self):
        self.assertLessEqual(set(self.data()["judges"]), set(judges.JUDGES))

    def test_sha256_is_the_digest_of_the_shipped_bytes(self):
        self.assertEqual(F.thresholds_sha256(), hashlib.sha256(self.raw()).hexdigest())
        self.assertEqual(len(F.thresholds_sha256()), 64)

    def test_file_is_lf_only_and_ends_with_one_newline(self):
        raw = self.raw()
        self.assertNotIn(b"\r", raw)
        self.assertTrue(raw.endswith(b"}\n"))
        self.assertFalse(raw.endswith(b"\n\n"))
        raw.decode("utf-8")

    def test_loading_twice_gives_equal_sets(self):
        self.assertEqual(F.load_thresholds("openai"), F.load_thresholds("openai"))
        with self.assertRaises(dataclasses.FrozenInstanceError):
            F.load_thresholds("openai").tau_gray = 0.0

    def test_as_dict_is_plain_json(self):
        shown = F.load_thresholds("openai").as_dict()
        self.assertEqual(json.loads(json.dumps(shown)), shown)
        self.assertEqual(shown["tau_rep_points"], [[200, 0.54], [1000, 0.71], [5000, 0.81]])
        self.assertEqual(shown["screening_rule"], "pilot-full")

    def parse(self, mutate):
        data = self.data()
        mutate(data)
        return F.parse_thresholds(json.dumps(data).encode("utf-8"), "openai")

    def assertRejected(self, mutate):
        with self.assertRaises(ValueError) as caught:
            self.parse(mutate)
        self.assertEqual(str(caught.exception), "invalid_tile_sieve_thresholds")

    def test_the_unmutated_file_parses(self):
        self.assertEqual(self.parse(lambda d: None), F.load_thresholds("openai"))

    def test_a_malformed_file_is_rejected(self):
        def entry(d):
            return d["judges"]["openai"]

        cases = {
            "wrong version": lambda d: d.update(version="tile-sieve-thresholds/2"),
            "extra top key": lambda d: d.update(extra=1),
            "no judges key": lambda d: d.pop("judges"),
            "judges empty": lambda d: d.update(judges={}),
            "judges a list": lambda d: d.update(judges=[]),
            "bad judge name": lambda d: d["judges"].update({"Bad Name": entry(d)}),
            "entry not a dict": lambda d: d["judges"].update(openai=[]),
            "missing entry key": lambda d: entry(d).pop("tau_rel"),
            "extra entry key": lambda d: entry(d).update(tau_extra="0.5"),
            "stage2 key comes back": lambda d: entry(d).update(tau_stage2="0.5"),
            "empty basis": lambda d: entry(d).update(basis="  "),
            "basis not a string": lambda d: entry(d).update(basis=1),
            "unknown screening rule": lambda d: entry(d).update(screening_rule="orphan-only"),
            "screening rule case": lambda d: entry(d).update(screening_rule="Pilot-Full"),
            "screening rule not a string": lambda d: entry(d).update(screening_rule=None),
            "number instead of string": lambda d: entry(d).update(tau_gray=0.39),
            "decimal with a space": lambda d: entry(d).update(tau_gray="0.39 "),
            "decimal with a sign": lambda d: entry(d).update(tau_gray="+0.39"),
            "exponent": lambda d: entry(d).update(tau_gray="3.9e-1"),
            "bare dot": lambda d: entry(d).update(tau_gray=".39"),
            "trailing dot": lambda d: entry(d).update(tau_gray="1."),
            "leading zero": lambda d: entry(d).update(tau_gray="00.39"),
            "comma": lambda d: entry(d).update(tau_gray="0,39"),
            "nan": lambda d: entry(d).update(tau_gray="nan"),
            "above one": lambda d: entry(d).update(tau_rel="1.01"),
            "negative": lambda d: entry(d).update(tau_rel="-0.1"),
            "huge digit string": lambda d: entry(d).update(tau_rel="0." + "9" * 40),
            "strong cell above one": lambda d: entry(d).update(strong_cell="1.5"),
            "pilot_full missing key": lambda d: entry(d)["pilot_full"].pop("tau_none"),
            "pilot_full extra key": lambda d: entry(d)["pilot_full"].update(tau_x="0.5"),
            "pilot_full threshold above one": lambda d: entry(d)["pilot_full"].update(tau_s="2"),
            "weights wrong length": lambda d: entry(d)["pilot_full"].update(weights=["1.0"]),
            "weights too long": lambda d: entry(d)["pilot_full"].update(
                weights=["1.0", "0", "0", "0", "0"]),
            "weight just above the cap": lambda d: entry(d)["pilot_full"].update(
                weights=["16.0001", "0", "0", "0"]),
            "e_weights too long": lambda d: entry(d).update(e_weights=["1.0", "2.0", "0", "0"]),
            "threshold just above one": lambda d: entry(d).update(tau_gray="1.0000000001"),
            "weights all zero": lambda d: entry(d)["pilot_full"].update(
                weights=["0", "0.0", "0", "0"]),
            "weights not a list": lambda d: entry(d)["pilot_full"].update(weights="1.0"),
            "weight too large": lambda d: entry(d)["pilot_full"].update(
                weights=["17", "0", "0", "0"]),
            "leaf_only missing": lambda d: entry(d).pop("leaf_only"),
            "leaf_only extra key": lambda d: entry(d)["leaf_only"].update(tau_x="0.5"),
            "tau_leaf above one": lambda d: entry(d)["leaf_only"].update(tau_leaf="1.2"),
            "e_weights wrong length": lambda d: entry(d).update(e_weights=["1.0", "2.0"]),
            "e_weights all zero": lambda d: entry(d).update(e_weights=["0", "0", "0"]),
            "verify weight zero": lambda d: entry(d).update(e_weights=["0", "2.0", "1.0"]),
            "points not a list": lambda d: entry(d).update(tau_rep_points="200"),
            "points empty": lambda d: entry(d).update(tau_rep_points=[]),
            "points too many": lambda d: entry(d).update(
                tau_rep_points=[[n, "0.5"] for n in range(1, 18)]),
            "point not a pair": lambda d: entry(d).update(tau_rep_points=[[200, "0.54", 1]]),
            "points not increasing": lambda d: entry(d).update(
                tau_rep_points=[[1000, "0.71"], [200, "0.54"]]),
            "points repeat n": lambda d: entry(d).update(
                tau_rep_points=[[200, "0.54"], [200, "0.60"]]),
            "point n zero": lambda d: entry(d).update(tau_rep_points=[[0, "0.54"]]),
            "point n a string": lambda d: entry(d).update(tau_rep_points=[["200", "0.54"]]),
            "point n a float": lambda d: entry(d).update(tau_rep_points=[[200.0, "0.54"]]),
            "point n a bool": lambda d: entry(d).update(tau_rep_points=[[True, "0.54"]]),
            "point tau a number": lambda d: entry(d).update(tau_rep_points=[[200, 0.54]]),
            "point tau above one": lambda d: entry(d).update(tau_rep_points=[[200, "1.1"]]),
        }
        for name, mutate in cases.items():
            with self.subTest(name):
                self.assertRejected(mutate)

    def test_a_threshold_of_exactly_one_or_zero_and_a_weight_at_the_cap_are_valid(self):
        def edit(d):
            d["judges"]["openai"]["tau_gray"] = "1"
            d["judges"]["openai"]["tau_rel"] = "1.0"
            d["judges"]["openai"]["tau_ctx"] = "0"
            d["judges"]["openai"]["pilot_full"]["weights"] = ["16", "0", "0", "0.5"]

        ts = self.parse(edit)
        self.assertEqual((ts.tau_gray, ts.tau_rel, ts.tau_ctx), (1.0, 1.0, 0.0))
        self.assertEqual(ts.weights, (16.0, 0.0, 0.0, 0.5))

    def test_a_defect_in_any_judge_entry_refuses_the_file(self):
        def add_broken(d):
            broken = json.loads(json.dumps(d["judges"]["openai"]))
            broken["tau_rel"] = "9"
            d["judges"]["microsoft"] = broken

        self.assertRejected(add_broken)

    def test_a_second_valid_entry_is_served_and_the_first_still_loads(self):
        data = self.data()
        second = json.loads(json.dumps(data["judges"]["openai"]))
        second["screening_rule"] = "leaf-only"
        second["strong_cell"] = "0.9"
        data["judges"]["microsoft"] = second
        raw = json.dumps(data).encode("utf-8")
        self.assertEqual(F.parse_thresholds(raw, "microsoft").screening_rule, "leaf-only")
        self.assertEqual(F.parse_thresholds(raw, "microsoft").strong_cell, 0.9)
        self.assertEqual(F.parse_thresholds(raw, "openai").screening_rule, "pilot-full")
        with self.assertRaises(LookupError):
            F.parse_thresholds(raw, "foundry")

    def test_not_json_and_not_utf8_are_rejected(self):
        raw = self.raw()
        # b"[" * 100000 is the nesting that raises RecursionError inside the JSON scanner
        # (b"{" * 100000 already fails as a syntax error)
        for bad in (b"", b"{", b"[]", b"null", b"\xff\xfe" + raw, raw + b"x", raw.replace(b"0.39", b"NaN", 1),
                    b"{" * 100000, b"[" * 100000):
            with self.subTest(bad=bad[:20]), self.assertRaises(ValueError) as caught:
                F.parse_thresholds(bad, "openai")
            self.assertEqual(str(caught.exception), "invalid_tile_sieve_thresholds")

    def test_duplicate_keys_are_rejected(self):
        text = self.raw().decode("utf-8").replace('"tau_rel": "0.75",',
                                                  '"tau_rel": "0.75", "tau_rel": "0.5",', 1)
        self.assertNotEqual(text, self.raw().decode("utf-8"))
        with self.assertRaises(ValueError):
            F.parse_thresholds(text.encode("utf-8"), "openai")

    def test_the_file_is_package_data_and_listed_for_the_distribution_check(self):
        with (ROOT / "pyproject.toml").open("rb") as handle:
            data = tomllib.load(handle)
        declared = data["tool"]["setuptools"]["package-data"]["decision_bug_hunter"]
        self.assertIn("tile_sieve_thresholds.json", declared)
        path = ROOT / "tools" / "check_distribution.py"
        spec = importlib.util.spec_from_file_location("dbh_check_distribution_for_fusion", path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        self.assertIn("decision_bug_hunter/tile_sieve_thresholds.json", module.WHEEL_RESOURCES)
        self.assertIn("decision_bug_hunter/tile_sieve_pack.json", module.WHEEL_RESOURCES)
        self.assertIn("tile_sieve_thresholds.json", path.read_text(encoding="utf-8").split(
            "code = (")[1])


class TauRepTests(Fixtures):
    def test_clamped_at_and_below_the_first_point(self):
        for n in (0, 1, 8, 199, 200):
            self.assertEqual(self.ts.tau_rep(n), 0.54, n)

    def test_interpolated_in_log_n_and_rounded_to_four_places(self):
        self.assertEqual(self.ts.tau_rep(300), 0.5828)
        self.assertEqual(self.ts.tau_rep(1000), 0.71)
        self.assertEqual(self.ts.tau_rep(2000), 0.7531)
        self.assertEqual(self.ts.tau_rep(5000), 0.81)

    def test_clamped_at_and_above_the_last_point(self):
        for n in (5000, 5001, 10 ** 6):
            self.assertEqual(self.ts.tau_rep(n), 0.81, n)

    def test_the_bar_never_falls_as_the_file_grows(self):
        bars = [self.ts.tau_rep(n) for n in range(1, 6001, 7)]
        self.assertEqual(bars, sorted(bars))

    def test_module_function_matches_the_method(self):
        for n in (1, 200, 300, 1000, 9000):
            self.assertEqual(F.tau_rep(n, self.ts), self.ts.tau_rep(n))

    def test_a_single_point_set_is_flat(self):
        one = dataclasses.replace(self.ts, tau_rep_points=((100, 0.5),))
        self.assertEqual([one.tau_rep(n) for n in (1, 100, 5000)], [0.5, 0.5, 0.5])


# -- synthetic looks --------------------------------------------------------------------------

def decimal_noul(value):
    return {"type": "noul", "noul": Decimal(str(value))}


def decimal_choice(probabilities):
    return {"type": "choice", "choice": max(probabilities, key=lambda k: probabilities[k]),
            "probabilities": {k: Decimal(str(v)) for k, v in probabilities.items()},
            "confidence": Decimal("0.5")}


LEAVES = ((1, 16), (17, 32))
BLOCKS = ((1, 32),)
GRANULES = ((1, 8), (9, 16), (17, 24), (25, 32))
LENS = ("functional", "contract", "boundary", "state", "integration")


def synthetic_look(leaf=("0.1", "0.1"), block="0.1", gran=("0.1", "0.1", "0.1", "0.1"),
                   gran_none="0.5", lens=None, need_ctx="0.0", leaves=LEAVES, grans=GRANULES,
                   blocks=BLOCKS):
    """(meta, answers, features) of a 32-line look. *lens* maps a lens name to its block mass."""
    roles = {"ctl_a": {"role": "must_true"}, "ctl_b": {"role": "must_false"}}
    answers = {"ctl_a": decimal_noul("0.99"), "ctl_b": decimal_noul("0.01")}
    for cell, value in zip(leaves, leaf):
        roles[f"leaf_L{cell[0]}-{cell[1]}"] = {"role": "leaf", "cell": list(cell)}
        answers[f"leaf_L{cell[0]}-{cell[1]}"] = decimal_noul(value)
    for cell in blocks:
        roles[f"block_L{cell[0]}-{cell[1]}"] = {"role": "block", "cell": list(cell)}
        answers[f"block_L{cell[0]}-{cell[1]}"] = decimal_noul(block)
    roles["need_ctx"] = {"role": "need_ctx"}
    answers["need_ctx"] = decimal_noul(need_ctx)
    roles["gran"] = {"role": "gran", "cells": [list(g) for g in grans]}
    distribution = {f"L{g[0]}-{g[1]}": v for g, v in zip(grans, gran)}
    distribution["none"] = gran_none
    distribution["unlocalized"] = "0.0"
    answers["gran"] = decimal_choice(distribution)
    for name in LENS:
        roles[f"lens_{name}"] = {"role": "lens", "lens": name, "cells": [list(b) for b in blocks]}
        mass = (lens or {}).get(name, "0.0")
        rest = str(Decimal("1") - Decimal(mass))
        answers[f"lens_{name}"] = decimal_choice(
            {**{f"L{b[0]}-{b[1]}": mass for b in blocks}, "none": rest, "unlocalized": "0.0"})
    meta = {"core": [1, 32], "roles": roles,
            "cells": {"leaf": [list(c) for c in leaves], "block": [list(b) for b in blocks],
                      "gran": [list(g) for g in grans]}}
    return meta, answers, F.tile_features(meta, answers)


class SynthesizedLookTests(Fixtures):
    def flags(self, feat, rule="pilot-full"):
        ts = dataclasses.replace(self.ts, screening_rule=rule)
        return F.flag_tile(feat, ts)

    def test_quiet_look_flags_nothing(self):
        _meta, _answers, feat = synthetic_look()
        self.assertEqual(flagged_cells(self.flags(feat)), [])
        self.assertEqual(flagged_cells(self.flags(feat, "leaf-only")), [])

    def test_leaf_at_096_is_flagged_and_095_is_not(self):
        for value, expected in (("0.96", [(1, 16)]), ("0.95", []), ("0.9601", [(1, 16)])):
            with self.subTest(value=value):
                _m, _a, feat = synthetic_look(leaf=(value, "0.1"))
                rows = self.flags(feat)
                self.assertEqual(flagged_cells(rows), expected)
                if expected:
                    self.assertEqual(rows[0]["why"], ["z"])

    def test_granule_at_096_flags_the_leaves_it_overlaps(self):
        for value, expected in (("0.96", [(1, 16)]), ("0.95", [])):
            with self.subTest(value=value):
                none = str(Decimal(1) - Decimal(value))
                _m, _a, feat = synthetic_look(gran=(value, "0.0", "0.0", "0.0"), gran_none=none)
                rows = self.flags(feat)
                self.assertEqual(flagged_cells(rows), expected)
                if expected:
                    self.assertEqual(rows[0]["why"], ["granule"])

    def test_orphan_block_flags_every_leaf_when_no_leaf_is_flagged(self):
        _m, _a, feat = synthetic_look(block="0.96")
        rows = self.flags(feat)
        self.assertEqual(flagged_cells(rows), [(1, 16), (17, 32)])
        self.assertTrue(all(r["why"] == ["orphan_block"] for r in rows))
        _m, _a, feat = synthetic_look(block="0.95")
        self.assertEqual(flagged_cells(self.flags(feat)), [])

    def test_orphan_block_is_silent_when_a_leaf_inside_is_flagged(self):
        _m, _a, feat = synthetic_look(leaf=("0.97", "0.1"), block="0.99")
        rows = self.flags(feat)
        self.assertEqual(flagged_cells(rows), [(1, 16)])
        self.assertNotIn("orphan_block", rows[1]["why"])

    def test_orphan_lens_mass_flags_the_block(self):
        _m, _a, feat = synthetic_look(lens={"state": "0.96"})
        rows = self.flags(feat)
        self.assertEqual(flagged_cells(rows), [(1, 16), (17, 32)])
        _m, _a, feat = synthetic_look(lens={"state": "0.95"})
        self.assertEqual(flagged_cells(self.flags(feat)), [])

    def test_orphan_none_fires_only_with_no_flagged_leaf(self):
        grans = ("0.1", "0.1", "0.4", "0.37")
        _m, _a, feat = synthetic_look(gran=grans, gran_none="0.03")
        rows = self.flags(feat)
        # the top two granules lie in the second leaf; the first leaf is untouched
        self.assertEqual(flagged_cells(rows), [(17, 32)])
        self.assertEqual(rows[1]["why"], ["orphan_none"])
        _m, _a, feat = synthetic_look(leaf=("0.97", "0.1"), gran=grans, gran_none="0.03")
        rows = self.flags(feat)
        self.assertEqual(flagged_cells(rows), [(1, 16)])
        self.assertNotIn("orphan_none", rows[1]["why"])
        # the rule is strict: a none mass of exactly tau_none does not fire
        _m, _a, feat = synthetic_look(gran=("0.1", "0.1", "0.4", "0.36"), gran_none="0.04")
        self.assertEqual(flagged_cells(self.flags(feat)), [])

    def test_orphan_none_takes_the_top_two_granules_wherever_they_lie(self):
        # the top two granules, (9,16) at 0.4 and (17,24) at 0.37, lie in different leaves
        _m, _a, feat = synthetic_look(gran=("0.1", "0.4", "0.37", "0.1"), gran_none="0.03")
        rows = self.flags(feat)
        self.assertEqual(flagged_cells(rows), [(1, 16), (17, 32)])
        self.assertEqual([r["why"] for r in rows], [["orphan_none"], ["orphan_none"]])
        # a third granule does not count: the granules at 0.1 lie in the leaf that is hit anyway,
        # so move the top two into the first leaf and the third into the second
        _m, _a, feat = synthetic_look(gran=("0.4", "0.37", "0.2", "0.0"), gran_none="0.03")
        self.assertEqual(flagged_cells(self.flags(feat)), [(1, 16)])

    def test_tail_cells_without_an_owned_leaf_become_rows_of_their_own(self):
        # the leaves cover lines 1-16 only, the granule question also names 17-24
        _m, _a, feat = synthetic_look(leaf=("0.1",), leaves=((1, 16),),
                                      gran=("0.1", "0.1", "0.96", "0.0"), gran_none="0.04",
                                      grans=GRANULES, blocks=((1, 16),))
        rows = self.flags(feat)
        tails = [r for r in rows if r.get("tail")]
        self.assertEqual([(r["cell"], r["why"]) for r in tails], [((17, 24), ["granule_tail"])])
        self.assertEqual(tails[0]["z"], 0.96)
        self.assertEqual(tails[0]["comps"], {})
        self.assertEqual(flagged_cells(rows), [(17, 24)])
        self.assertEqual([r["cell"] for r in rows], sorted(r["cell"] for r in rows))

    def test_block_tail_row(self):
        _m, _a, feat = synthetic_look(leaf=("0.1",), leaves=((1, 16),), block="0.97",
                                      gran=("0.1", "0.1", "0.1", "0.1"), grans=((1, 8), (9, 16)),
                                      blocks=((1, 16), (17, 32)))
        rows = self.flags(feat)
        self.assertIn(((17, 32), ["block_tail"]),
                      [(r["cell"], r["why"]) for r in rows if r.get("tail")])
        tail = next(r for r in rows if r.get("tail"))
        self.assertEqual((tail["z"], tail["comps"]), (0.97, {}))

    def test_leaf_only_flags_at_085_and_not_below(self):
        for value, expected in (("0.85", [(1, 16)]), ("0.8499", []), ("0.8501", [(1, 16)]),
                                ("0.96", [(1, 16)])):
            with self.subTest(value=value):
                _m, _a, feat = synthetic_look(leaf=(value, "0.1"))
                rows = self.flags(feat, "leaf-only")
                self.assertEqual(flagged_cells(rows), expected)
                if expected:
                    self.assertEqual(rows[0]["why"], ["z"])

    def test_pilot_full_does_not_flag_a_leaf_at_085(self):
        _m, _a, feat = synthetic_look(leaf=("0.85", "0.1"))
        self.assertEqual(flagged_cells(self.flags(feat)), [])

    def test_leaf_only_has_no_granule_orphan_block_lens_none_or_tail_rule(self):
        for kwargs in ({"gran": ("0.99", "0.0", "0.0", "0.0"), "gran_none": "0.01"},
                       {"block": "0.99"}, {"lens": {"state": "0.99"}},
                       {"gran": ("0.1", "0.1", "0.4", "0.37"), "gran_none": "0.03"}):
            with self.subTest(kwargs=kwargs):
                _m, _a, feat = synthetic_look(**kwargs)
                self.assertEqual(flagged_cells(self.flags(feat, "leaf-only")), [])
        _m, _a, feat = synthetic_look(leaf=("0.1",), leaves=((1, 16),), block="0.97",
                                      gran=("0.97", "0.0", "0.97", "0.0"), gran_none="0.01",
                                      blocks=((1, 16), (17, 32)))
        rows = self.flags(feat, "leaf-only")
        self.assertEqual(flagged_cells(rows), [])
        self.assertFalse(any(r.get("tail") for r in rows))

    def test_a_missing_leaf_answer_is_never_a_flag(self):
        meta, answers, _feat = synthetic_look(leaf=("0.99", "0.99"))
        del answers["leaf_L1-16"]
        feat = F.tile_features(meta, answers)
        self.assertIsNone(feat["leaf"][(1, 16)])
        for rule in ("pilot-full", "leaf-only"):
            self.assertEqual(flagged_cells(self.flags(feat, rule)), [(17, 32)])

    def test_flag_tile_dispatches_on_the_set(self):
        _m, _a, feat = synthetic_look(leaf=("0.9", "0.1"))
        full = F.flag_tile(feat, self.ts)
        leaf = F.flag_tile(feat, dataclasses.replace(self.ts, screening_rule="leaf-only"))
        self.assertEqual(flagged_cells(full), [])
        self.assertEqual(flagged_cells(leaf), [(1, 16)])
        self.assertEqual(F.flag_tile_pilot_full(feat, self.ts), full)
        self.assertEqual(F.flag_tile_leaf_only(feat, self.ts), F.flag_tile(
            feat, dataclasses.replace(self.ts, screening_rule="leaf-only")))
        with self.assertRaises(ValueError):
            F.flag_tile(feat, dataclasses.replace(self.ts, screening_rule="anything"))

    def test_fused_score_is_the_weighted_max(self):
        comp = {"leaf": 0.5, "blk": 0.8, "gran": None, "lens": 0.9}
        self.assertEqual(F.fuse_z(comp, (1.0, 0.0, 0.0, 0.0)), 0.5)
        self.assertEqual(F.fuse_z(comp, (1.0, 1.0, 1.0, 0.0)), 0.8)
        self.assertEqual(F.fuse_z(comp, (0.0, 0.0, 1.0, 0.0)), None)
        self.assertEqual(F.fuse_z(comp, (0.5, 0.0, 0.0, 1.0)), 0.9)

    # The shipped weights are (1, 0, 0, 0): the block, granule and lens components never reach the
    # fused score. A set with other weights relies on them, so they are pinned here by hand.

    @staticmethod
    def hand_features(leaf=(0.2, 0.1), block=0.8, gran=(0.6, 0.3, 0.05, 0.05), lens=None):
        """Features of the 32-line look built directly, without answers."""
        lens = {"state": 0.25, "contract": 0.35} if lens is None else lens
        return {"leaf": dict(zip(LEAVES, leaf)), "block": {(1, 32): block},
                "gran": dict(zip(GRANULES, gran)), "gran_none": 0.5, "gran_unloc": 0.0,
                "lens": {name: {"blocks": {(1, 32): mass}, "none": 0.0, "unloc": 0.0}
                         for name, mass in lens.items()},
                "need_ctx": 0.0, "core": [1, 32],
                "cells": {"leaf": [list(c) for c in LEAVES], "block": [list(b) for b in BLOCKS],
                          "gran": [list(g) for g in GRANULES]}}

    def assertComps(self, got, leaf, blk, gran, lens):
        self.assertEqual(got["leaf"], leaf)
        for name, want in (("blk", blk), ("gran", gran), ("lens", lens)):
            if want is None:
                self.assertIsNone(got[name], name)
            else:
                self.assertAlmostEqual(got[name], want, places=12, msg=name)

    def test_components_of_a_leaf_by_hand(self):
        comps = F.leaf_components(self.hand_features())
        # first leaf: the top-2 granules (1,8) at 0.6 and (9,16) at 0.3 both lie in it, so the
        # weighted share is 1 + 0.3 / 0.6 = 1.5, clipped to 1; block 0.8 * 1; granule mass
        # 0.6 + 0.3; lens mass is the larger of the two lens scores 0.25 and 0.35 (the block
        # covers the whole leaf)
        self.assertComps(comps[(1, 16)], 0.2, 0.8, 0.9, 0.35)
        # second leaf: neither top-2 granule touches it (block 0), granules (17,24), (25,32) give
        # 0.05 + 0.05, and the same lens mass as the block covers this leaf too
        self.assertComps(comps[(17, 32)], 0.1, 0.0, 0.1, 0.35)

    def test_the_top_two_granules_are_ranked_by_mass_and_only_two_count(self):
        # p(g) / p(top) weights the second granule; a third granule adds nothing
        feat = self.hand_features(block=1.0, gran=(0.2, 0.2, 0.4, 0.2))
        comps = F.leaf_components(feat)
        # top granule (17,24) at 0.4, then a tie at 0.2 broken by position: (1,8)
        self.assertComps(comps[(1, 16)], 0.2, 0.5, 0.4, 0.35)
        self.assertComps(comps[(17, 32)], 0.1, 1.0, 0.6, 0.35)

    def test_a_granule_counts_in_a_block_from_half_of_its_lines(self):
        # block (1,12): granule (9,16) shares exactly 4 of its 8 lines with it and counts
        feat = {"leaf": {(9, 16): 0.0}, "block": {(1, 12): 0.9},
                "gran": {(1, 8): 0.2, (9, 16): 0.4},
                "gran_none": 0.0, "gran_unloc": 0.0, "lens": {}, "need_ctx": 0.0, "core": [1, 16],
                "cells": {"leaf": [[9, 16]], "block": [[1, 12]], "gran": [[1, 8], [9, 16]]}}
        self.assertAlmostEqual(F.leaf_components(feat)[(9, 16)]["blk"], 0.9, places=12)
        feat["gran"] = {(1, 8): 0.2, (9, 16): 0.4, (13, 20): 0.9}   # 0 of 8 lines: ignored
        self.assertAlmostEqual(F.leaf_components(feat)[(9, 16)]["blk"], 0.9, places=12)
        feat["gran"] = {(1, 8): 0.2, (9, 24): 0.4}                 # 4 of 16 lines: ignored
        self.assertAlmostEqual(F.leaf_components(feat)[(9, 16)]["blk"], 0.0, places=12)

    def test_components_are_clipped_to_one(self):
        feat = self.hand_features(block=0.8, gran=(0.9, 0.9, 0.0, 0.0))
        feat["lens"]["state"]["blocks"] = {(1, 16): 0.8, (1, 32): 0.8}
        # blk: the share 1 + 1 is clipped to 1 before it multiplies the block score 0.8;
        # gran 0.9 + 0.9 and lens 0.8 + 0.8 are clipped to 1
        self.assertComps(F.leaf_components(feat)[(1, 16)], 0.2, 0.8, 1.0, 1.0)
        # two blocks over the leaf add up to 0.8 + 0.8, clipped to 1
        feat["block"] = {(1, 32): 0.8, (1, 16): 0.8}
        feat["cells"]["block"] = [[1, 32], [1, 16]]
        self.assertComps(F.leaf_components(feat)[(1, 16)], 0.2, 1.0, 1.0, 1.0)

    def test_missing_signals_leave_their_components_none(self):
        feat = self.hand_features()
        feat["block"], feat["gran"], feat["lens"] = {}, {}, {}
        comps = F.leaf_components(feat)[(1, 16)]
        self.assertComps(comps, 0.2, None, None, None)
        feat["block"] = {(1, 32): None}
        self.assertEqual(F.leaf_components(feat)[(1, 16)]["blk"], 0.0)

    def test_the_fused_score_and_the_flags_follow_other_weights(self):
        feat = self.hand_features()
        no_leaf = dataclasses.replace(self.ts, weights=(0.0, 1.0, 1.0, 1.0), tau_s=0.5)
        rows = F.flag_tile_pilot_full(feat, no_leaf)
        self.assertEqual([(r["cell"], r["flag"], r["why"]) for r in rows],
                         [((1, 16), True, ["z"]), ((17, 32), False, [])])
        self.assertAlmostEqual(rows[0]["z"], 0.9, places=12)       # max of 0.8, 0.9, 0.35
        self.assertAlmostEqual(rows[1]["z"], 0.35, places=12)      # max of 0.0, 0.1, 0.35
        weighted = dataclasses.replace(self.ts, weights=(2.0, 0.5, 0.5, 0.5), tau_s=0.4)
        rows = F.flag_tile_pilot_full(feat, weighted)
        self.assertAlmostEqual(rows[0]["z"], 0.45, places=12)      # max of 0.4, 0.4, 0.45, 0.175
        self.assertAlmostEqual(rows[1]["z"], 0.2, places=12)       # max of 0.2, 0.0, 0.05, 0.175
        self.assertEqual([r["flag"] for r in rows], [True, False])
        # at the shipped weights the same look has only the leaf in z
        rows = F.flag_tile_pilot_full(feat, self.ts)
        self.assertEqual([r["z"] for r in rows], [0.2, 0.1])
        self.assertEqual([r["flag"] for r in rows], [False, False])

    def test_need_context_is_read_from_the_look(self):
        _m, _a, feat = synthetic_look(need_ctx="0.5")
        self.assertEqual(feat["need_ctx"], 0.5)
        self.assertGreaterEqual(feat["need_ctx"], self.ts.tau_ctx)
        _m, _a, feat = synthetic_look(need_ctx="0.4999")
        self.assertLess(feat["need_ctx"], self.ts.tau_ctx)

    def test_canary_rule(self):
        meta, answers, _feat = synthetic_look()
        self.assertTrue(F.canaries_pass(meta, answers)[0])
        answers["ctl_a"] = decimal_noul("0.89")
        passed, detail = F.canaries_pass(meta, answers)
        self.assertFalse(passed)
        self.assertEqual(detail["ctl_a"], {"role": "must_true", "p": 0.89, "passed": False})
        answers["ctl_a"] = decimal_noul("0.90")
        self.assertTrue(F.canaries_pass(meta, answers)[0])
        answers["ctl_b"] = decimal_noul("0.11")
        self.assertFalse(F.canaries_pass(meta, answers)[0])
        answers["ctl_b"] = decimal_noul("0.10")
        self.assertTrue(F.canaries_pass(meta, answers)[0])
        del answers["ctl_b"]
        self.assertFalse(F.canaries_pass(meta, answers)[0])
        self.assertEqual(F.canaries_pass({"roles": {"q": {"role": "verify"}}}, {}), (False, {}))


class StrengthTests(Fixtures):
    def strong(self, feat, rule="pilot-full", core=(1, 16)):
        ts = dataclasses.replace(self.ts, screening_rule=rule)
        return F.cluster_strength({"core": core, "K": core}, [feat], ts)

    def test_leaf_at_096_is_strong_and_095_is_not(self):
        for value, expected in (("0.96", True), ("0.95", False), ("0.9599", False), ("1.0", True)):
            with self.subTest(value=value):
                _m, _a, feat = synthetic_look(leaf=(value, "0.1"))
                self.assertIs(self.strong(feat), expected)

    def test_granule_at_096_is_strong_and_095_is_not(self):
        for value, expected in (("0.96", True), ("0.95", False)):
            with self.subTest(value=value):
                _m, _a, feat = synthetic_look(gran=(value, "0.0", "0.0", "0.0"), gran_none="0.04")
                self.assertIs(self.strong(feat), expected)

    def test_strength_reads_the_scores_whatever_the_screening_variant(self):
        for value, expected in (("0.96", True), ("0.95", False)):
            _m, _a, feat = synthetic_look(leaf=(value, "0.1"))
            self.assertIs(self.strong(feat, "pilot-full"), expected)
            self.assertIs(self.strong(feat, "leaf-only"), expected)
        _m, _a, feat = synthetic_look(gran=("0.97", "0.0", "0.0", "0.0"), gran_none="0.03")
        self.assertIs(self.strong(feat, "leaf-only"), True)

    def test_only_members_count(self):
        _m, _a, feat = synthetic_look(leaf=("0.1", "0.99"), gran=("0.1", "0.1", "0.1", "0.1"))
        self.assertIs(self.strong(feat, core=(1, 16)), False)
        self.assertIs(self.strong(feat, core=(17, 32)), True)
        self.assertIs(self.strong(feat, core=(10, 20)), True)
        self.assertEqual(F.cluster_peak((1, 16), [feat]), 0.1)

    def test_padding_does_not_make_a_cluster_strong(self):
        # core (9,16) is padded to (5,20); the granule at 0.97 lies in 17-24, so it reaches only
        # the padding and no member of the cluster
        _m, _a, feat = synthetic_look(gran=("0.0", "0.0", "0.97", "0.0"), gran_none="0.03")
        cluster = F.make_clusters_ex([(9, 16)], 32)[0]
        self.assertEqual((cluster["core"], cluster["K"]), ((9, 16), (5, 20)))
        for rule in ("pilot-full", "leaf-only"):
            with self.subTest(rule=rule):
                self.assertIs(self.strong(feat, rule, core=cluster["core"]), False)
                ts = dataclasses.replace(self.ts, screening_rule=rule)
                self.assertIs(F.cluster_strength(cluster, [feat], ts), False)
        self.assertEqual(F.cluster_peak(cluster, [feat]), 0.1)
        self.assertEqual(F.cluster_peak((9, 24), [feat]), 0.97)
        # the same for a leaf: (17,32) is not a member of the core (1,16)
        _m, _a, feat = synthetic_look(leaf=("0.1", "0.99"))
        self.assertIs(self.strong(feat, core=(1, 16)), False)

    def test_any_look_can_make_a_cluster_strong(self):
        _m, _a, quiet = synthetic_look()
        _m, _a, loud = synthetic_look(leaf=("0.98", "0.1"))
        self.assertIs(F.cluster_strength((1, 16), [quiet, loud], self.ts), True)
        self.assertIs(F.cluster_strength((1, 16), [quiet, quiet], self.ts), False)
        self.assertIs(F.cluster_strength((1, 16), [], self.ts), False)

    def test_a_missing_leaf_answer_does_not_count(self):
        meta, answers, _feat = synthetic_look(leaf=("0.99", "0.1"))
        del answers["leaf_L1-16"]
        feat = F.tile_features(meta, answers)
        self.assertIs(self.strong(feat), False)

    def test_a_bare_core_pair_and_a_cluster_dict_agree(self):
        _m, _a, feat = synthetic_look(leaf=("0.99", "0.1"))
        cluster = F.make_clusters_ex([(1, 16)], 32)[0]
        self.assertEqual(F.cluster_strength(cluster, [feat], self.ts),
                         F.cluster_strength(cluster["core"], [feat], self.ts))


class ClusterTests(unittest.TestCase):
    def test_gap_of_eight_merges_and_nine_splits(self):
        self.assertEqual(F.make_clusters([(1, 16), (25, 40)], 100), [(1, 44)])
        self.assertEqual(F.make_clusters([(1, 16), (26, 40)], 100), [(1, 20), (22, 44)])

    def test_pieces_are_capped_at_48_lines_and_padded_by_four(self):
        out = F.make_clusters_ex([(11, 100)], 200)
        self.assertEqual([c["core"] for c in out], [(11, 55), (56, 100)])
        self.assertEqual([c["K"] for c in out], [(7, 59), (52, 104)])
        self.assertEqual(F.make_clusters_ex([(1, 48)], 200)[0]["core"], (1, 48))
        self.assertEqual(len(F.make_clusters_ex([(1, 48)], 200)), 1)

    def test_a_run_over_the_cap_is_cut_into_the_fewest_nearly_even_pieces(self):
        # 49 lines are two pieces of 25 and 24, not one of 49 and not 24, 24 and 1
        out = F.make_clusters_ex([(1, 49)], 200)
        self.assertEqual([c["core"] for c in out], [(1, 25), (26, 49)])
        self.assertEqual([c["K"] for c in out], [(1, 29), (22, 53)])
        # 100 lines are three pieces of 34, 34 and 32
        out = F.make_clusters_ex([(1, 100)], 200)
        self.assertEqual([c["core"] for c in out], [(1, 34), (35, 68), (69, 100)])
        # 97 lines are three pieces of 33, 33 and 31 starting at 4
        out = F.make_clusters_ex([(4, 100)], 200)
        self.assertEqual([c["core"] for c in out], [(4, 36), (37, 69), (70, 100)])
        self.assertEqual((F.CLUSTER_GAP, F.CLUSTER_MAX, F.CLUSTER_PAD), (8, 48, 4))

    def test_padding_is_clipped_to_the_file(self):
        self.assertEqual(F.make_clusters([(1, 2)], 3), [(1, 3)])
        self.assertEqual(F.make_clusters([(97, 100)], 100), [(93, 100)])

    def test_unsorted_and_overlapping_intervals_are_united(self):
        self.assertEqual(F.make_clusters([(33, 48), (1, 16), (9, 24)], 200), [(1, 52)])
        self.assertEqual(F.make_clusters([], 10), [])


class FocusRuleTests(Fixtures):
    def decide(self, e, strong=False, relation=0.0, n=100):
        return F.focus_decision({"relation": relation}, e, n, strong, self.ts)

    def test_strong_cluster_reports_at_039_and_clears_at_03899(self):
        self.assertEqual(self.decide(0.39, strong=True), "report")
        self.assertEqual(self.decide(0.3899, strong=True), "clear")
        self.assertEqual(self.decide(0.39000000000000007, strong=True), "report")
        self.assertEqual(self.decide(0.38999999999999996, strong=True), "clear")

    def test_other_cluster_reports_at_tau_rep(self):
        self.assertEqual(self.decide(0.54), "report")
        self.assertEqual(self.decide(0.5399), "clear")
        self.assertEqual(self.decide(0.39), "clear")

    def test_tau_rep_is_taken_at_the_files_own_line_count(self):
        self.assertEqual(self.decide(0.6, n=200), "report")
        self.assertEqual(self.decide(0.6, n=300), "report")      # 0.5828
        self.assertEqual(self.decide(0.6, n=1000), "clear")      # 0.71
        self.assertEqual(self.decide(0.71, n=1000), "report")
        self.assertEqual(self.decide(0.6, n=1), "report")
        self.assertEqual(self.decide(0.6, n=1000, strong=True), "report")

    def test_relation_path_at_075_and_039(self):
        self.assertEqual(self.decide(0.39, relation=0.75), "report")
        self.assertEqual(self.decide(0.39, relation=0.7499), "clear")
        self.assertEqual(self.decide(0.3899, relation=0.99), "clear")
        self.assertEqual(self.decide(0.5, relation=1.0, n=1000), "report")
        self.assertEqual(self.decide(0.2, relation=1.0), "clear")

    def test_no_score_is_unmeasured_whatever_the_cluster(self):
        for strong in (True, False):
            self.assertEqual(F.focus_decision({"relation": 1.0}, None, 100, strong, self.ts),
                             "unmeasured")

    def test_decisions_are_only_report_clear_or_unmeasured(self):
        seen = {self.decide(e / 100, strong=s, relation=r)
                for e in range(0, 101, 3) for s in (True, False) for r in (0.0, 0.8)}
        self.assertEqual(seen, {"report", "clear"})
        self.assertNotIn("stage2", [name for name in dir(F) if "stage" in name])

    def test_the_bar_names_and_values(self):
        self.assertEqual(F.report_bar(True, 5000, self.ts), ("strong", 0.39))
        self.assertEqual(F.report_bar(False, 100, self.ts), ("tau_rep", 0.54))
        self.assertEqual(F.report_bar(False, 300, self.ts), ("tau_rep", 0.5828))

    def test_a_set_with_different_strong_and_gray_bars(self):
        ts = dataclasses.replace(self.ts, tau_strong=0.5, tau_gray=0.3)
        self.assertEqual(F.report_bar(True, 5000, ts), ("strong", 0.5))
        self.assertEqual(F.report_bar(False, 5000, ts), ("tau_rep", 0.81))

        def decide(e, strong, relation=0.0, n=100):
            return F.focus_decision({"relation": relation}, e, n, strong, ts)

        # a strong cluster needs tau_strong, not tau_gray
        self.assertEqual(decide(0.5, True), "report")
        self.assertEqual(decide(0.4999, True), "clear")
        self.assertEqual(decide(0.4, True), "clear")
        # the relation path starts at tau_gray, whatever the cluster
        self.assertEqual(decide(0.3, True, relation=0.75), "report")
        self.assertEqual(decide(0.2999, True, relation=0.75), "clear")
        self.assertEqual(decide(0.3, False, relation=0.75), "report")
        self.assertEqual(decide(0.3, False, relation=0.7499), "clear")
        self.assertEqual(decide(0.5, False), "clear")

    def test_focus_score_accumulates_in_the_pilot_order(self):
        # B20: (1.0 * 0.01 + 2.0 * (1 - 0.42)) / 3.0, summed term by term
        p = {"verify": 0.01, "twin": 0.42, "lens": 0.0}
        e = F.fuse_e(p, self.ts)
        self.assertEqual(e, 0.39000000000000007)
        self.assertGreater(e, 0.39)
        self.assertEqual(F.focus_decision({"relation": 0.46}, e, 680, True, self.ts), "report")

    def test_focus_score_weights_and_missing_terms(self):
        base = {"verify": 0.5, "twin": 0.25, "lens": 1.0}
        self.assertEqual(F.fuse_e(base, self.ts), (1.0 * 0.5 + 2.0 * 0.75) / 3.0)
        self.assertIsNone(F.fuse_e(dict(base, verify=None), self.ts))
        self.assertEqual(F.fuse_e(dict(base, twin=None), self.ts), 0.5)
        lens = dataclasses.replace(self.ts, e_weights=(1.0, 2.0, 1.0))
        self.assertEqual(F.fuse_e(base, lens), ((1.0 * 0.5 + 2.0 * 0.75) + 1.0 * 1.0) / 4.0)

    def test_a_third_term_accumulates_left_to_right_on_every_interpreter(self):
        # 1.0 * 0.67 + 2.0 * (1 - 0.31) + 1.0 * 0.61 summed term by term is 2.6599999999999997;
        # the compensated built-in sum() of Python 3.12 and later gives 2.66, the naive sum() of
        # 3.11 the first value. The score must not depend on the interpreter.
        lens = dataclasses.replace(self.ts, e_weights=(1.0, 2.0, 1.0))
        e = F.fuse_e({"verify": 0.67, "twin": 0.31, "lens": 0.61}, lens)
        self.assertEqual(e.hex(), (2.6599999999999997 / 4.0).hex())
        self.assertEqual(e, 0.6649999999999999)
        self.assertNotEqual(e, 0.665)
        # a missing twin leaves its term and weight out, in the same order
        e = F.fuse_e({"verify": 0.67, "twin": None, "lens": 0.61}, lens)
        self.assertEqual(e, (1.0 * 0.67 + 1.0 * 0.61) / 2.0)

    def test_a_missing_verify_is_never_scored_from_the_twin_alone(self):
        self.assertIsNone(F.fuse_e({"verify": None, "twin": 0.0, "lens": 1.0}, self.ts))


def focus_meta(with_twin=True, with_relation=True):
    roles = {"ctl_a": {"role": "must_true"}, "ctl_b": {"role": "must_false"},
             "loc_a": {"role": "loc_a", "cells": [[1, 4], [5, 8]]},
             "loc_b": {"role": "loc_b", "cells": [[1, 2], [3, 6], [7, 8]]},
             "verify": {"role": "verify"}, "multiple": {"role": "multiple"},
             "need_ctx": {"role": "need_ctx"},
             "lens_state": {"role": "lens", "lens": "state"},
             "lens_contract": {"role": "lens", "lens": "contract"},
             "reqm_R1-1": {"role": "requirement", "passage": [1, 1]}}
    if with_twin:
        roles["twin"] = {"role": "twin"}
    if with_relation:
        roles["rel_a"] = {"role": "relation"}
        roles["rel_b"] = {"role": "relation"}
    return {"roles": roles}


def focus_answers(verify="0.5", twin="0.25", relation=("0.3", "0.6"), multiple="0.0"):
    answers = {"ctl_a": decimal_noul("0.99"), "ctl_b": decimal_noul("0.01"),
               "verify": decimal_noul(verify), "multiple": decimal_noul(multiple),
               "need_ctx": decimal_noul("0.0"), "lens_state": decimal_noul("0.7"),
               "lens_contract": decimal_noul("0.2"), "reqm_R1-1": decimal_noul("0.9"),
               "loc_a": decimal_choice({"L1-4": "0.9", "L5-8": "0.05", "none": "0.05",
                                        "unlocalized": "0.0"}),
               "loc_b": decimal_choice({"L1-2": "0.1", "L3-6": "0.85", "L7-8": "0.0",
                                       "none": "0.05", "unlocalized": "0.0"})}
    if twin is not None:
        answers["twin"] = decimal_noul(twin)
    if relation:
        answers["rel_a"] = decimal_noul(relation[0])
        answers["rel_b"] = decimal_noul(relation[1])
    return answers


class FocusScoreTests(Fixtures):
    def test_scores_collect_the_maxima_by_role(self):
        p, e = F.focus_scores(focus_meta(), focus_answers(), self.ts)
        self.assertEqual(p["verify"], 0.5)
        self.assertEqual(p["twin"], 0.25)
        self.assertEqual(p["lens"], 0.7)
        self.assertEqual(p["relation"], 0.6)
        self.assertEqual(p["requirement"], 0.9)
        self.assertEqual(p["multiple"], 0.0)
        self.assertEqual(p["need_ctx"], 0.0)
        self.assertIs(p["twin_refused"], False)
        self.assertEqual(e, F.fuse_e(p, self.ts))
        self.assertEqual(e, (1.0 * 0.5 + 2.0 * (1 - 0.25)) / 3.0)

    def test_a_refused_twin_decides_on_verify_alone_and_is_noted(self):
        answers = focus_answers(verify="0.45", twin=None)
        p, e = F.focus_scores(focus_meta(), answers, self.ts)
        self.assertIsNone(p["twin"])
        self.assertIs(p["twin_refused"], True)
        self.assertEqual(e, 0.45)
        self.assertEqual(F.focus_decision(p, e, 200, False, self.ts), "clear")
        self.assertEqual(F.focus_decision(p, e, 200, True, self.ts), "report")

    def test_a_request_that_never_asked_the_twin_is_not_a_refusal(self):
        p, _e = F.focus_scores(focus_meta(with_twin=False), focus_answers(twin=None), self.ts)
        self.assertIs(p["twin_refused"], False)

    def test_a_missing_verify_is_unmeasured(self):
        answers = focus_answers()
        del answers["verify"]
        p, e = F.focus_scores(focus_meta(), answers, self.ts)
        self.assertIsNone(e)
        self.assertEqual(F.focus_decision(p, e, 100, True, self.ts), "unmeasured")

    def test_no_relation_leaves_the_relation_score_at_zero(self):
        p, _e = F.focus_scores(focus_meta(with_relation=False), focus_answers(relation=()),
                               self.ts)
        self.assertEqual(p["relation"], 0.0)

    def test_the_relation_path_decides_from_the_scores(self):
        answers = focus_answers(verify="0.3", twin="0.5", relation=("0.75", "0.2"))
        p, e = F.focus_scores(focus_meta(), answers, self.ts)
        self.assertEqual(p["relation"], 0.75)
        self.assertGreaterEqual(e, 0.39)
        self.assertLess(e, 0.54)
        self.assertEqual(F.focus_decision(p, e, 200, False, self.ts), "report")


class RunTests(Fixtures):
    def test_runs_average_the_two_menus_and_keep_the_top_one(self):
        meta, answers = focus_meta(), focus_answers()
        p, _e = F.focus_scores(meta, answers, self.ts)
        # line masses: 1-2 (0.9 + 0.1) / 2 = 0.5, 3-4 (0.9 + 0.85) / 2 = 0.875, 5-6 below one half
        self.assertEqual(F.report_runs(answers, meta, p, self.ts), ([(1, 4)], 1))
        self.assertEqual(F.combined_runs(answers, meta, 1, roles=("loc_a",)), ([(1, 4)], 1))
        self.assertEqual(F.combined_runs(answers, meta, 1, roles=("loc_b",)), ([(3, 6)], 1))

    def test_up_to_three_runs_when_multiple_reaches_tau_mult(self):
        meta = {"roles": {"loc_a": {"role": "loc_a", "cells": [[1, 2], [5, 6], [9, 10], [13, 14]]},
                          "loc_b": {"role": "loc_b", "cells": [[1, 2], [5, 6], [9, 10], [13, 14]]}}}
        both = {"L1-2": "0.2", "L5-6": "0.2", "L9-10": "0.2", "L13-14": "0.2", "none": "0.2",
                "unlocalized": "0.0"}
        answers = {"loc_a": decimal_choice(both), "loc_b": decimal_choice(both)}
        # each line has mass 0.2, below one half: nothing qualifies
        self.assertEqual(F.combined_runs(answers, meta, 3), ([], 0))
        sharp = {"L1-2": "0.5", "L5-6": "0.5", "L9-10": "0.0", "L13-14": "0.0", "none": "0.0",
                 "unlocalized": "0.0"}
        answers = {"loc_a": decimal_choice(sharp), "loc_b": decimal_choice(sharp)}
        one, total = F.report_runs(answers, meta, {"multiple": 0.49}, self.ts)
        self.assertEqual((len(one), total), (1, 2))
        two, total = F.report_runs(answers, meta, {"multiple": 0.5}, self.ts)
        self.assertEqual((sorted(two), total), ([(1, 2), (5, 6)], 2))
        self.assertEqual(F.report_runs(answers, meta, {"multiple": None}, self.ts)[0], one)

    def four_runs(self):
        """Four runs of equal peak and total mass: every line carries 0.4 from the wide option,
        and the four short options lift their lines to 0.55 in both menus."""
        cells = [[1, 14], [1, 2], [5, 6], [9, 10], [13, 14]]
        meta = {"roles": {"loc_a": {"role": "loc_a", "cells": cells},
                          "loc_b": {"role": "loc_b", "cells": cells}}}
        menu = {"L1-14": "0.4", "L1-2": "0.15", "L5-6": "0.15", "L9-10": "0.15", "L13-14": "0.15",
                "none": "0.0", "unlocalized": "0.0"}
        return meta, {"loc_a": decimal_choice(menu), "loc_b": decimal_choice(menu)}

    def test_report_runs_keeps_the_top_one_or_the_top_three_of_four(self):
        meta, answers = self.four_runs()
        # runs of equal peak and total mass are ordered by position, lowest first
        every = [(1, 2), (5, 6), (9, 10), (13, 14)]
        self.assertEqual(F.combined_runs(answers, meta, 4), (every, 4))
        self.assertEqual(F.combined_runs(answers, meta, 3), (every[:3], 4))
        self.assertEqual(F.combined_runs(answers, meta, 2), (every[:2], 4))
        self.assertEqual(F.report_runs(answers, meta, {"multiple": 0.49}, self.ts), ([(1, 2)], 4))
        self.assertEqual(F.report_runs(answers, meta, {"multiple": 0.5}, self.ts), (every[:3], 4))
        self.assertEqual(F.report_runs(answers, meta, {"multiple": 1.0}, self.ts), (every[:3], 4))
        self.assertEqual(F.report_runs(answers, meta, {"multiple": None}, self.ts), ([(1, 2)], 4))
        self.assertEqual(F.report_runs(answers, meta, {}, self.ts), ([(1, 2)], 4))

    def test_a_run_ranked_by_mass_comes_before_an_earlier_run(self):
        meta, answers = self.four_runs()
        # lift the third run: 9-10 now carries 0.2 more in the first menu
        answers["loc_a"] = decimal_choice({"L1-14": "0.4", "L1-2": "0.1", "L5-6": "0.1",
                                           "L9-10": "0.4", "L13-14": "0.0", "none": "0.0",
                                           "unlocalized": "0.0"})
        runs, total = F.combined_runs(answers, meta, 3)
        # masses: lines 1-2 and 5-6 (0.5 + 0.55) / 2 = 0.525, lines 9-10 (0.8 + 0.55) / 2 = 0.675;
        # 13-14 (0.4 + 0.55) / 2 = 0.475 does not qualify
        self.assertEqual((runs, total), ([(9, 10), (1, 2), (5, 6)], 3))

    def test_hidden_mass_of_one_half_gives_no_run_so_the_cluster_itself_is_reported(self):
        meta = {"roles": {"loc_a": {"role": "loc_a", "cells": [[1, 4]]},
                          "loc_b": {"role": "loc_b", "cells": [[1, 4]]}}}
        # 0.5 on the cell, 0.5 hidden: the line mass 0.5 would pass, the hidden mass blocks it
        answers = {"loc_a": decimal_choice({"L1-4": "0.5", "none": "0.5", "unlocalized": "0.0"}),
                   "loc_b": decimal_choice({"L1-4": "0.5", "none": "0.4", "unlocalized": "0.1"})}
        self.assertEqual(F.combined_runs(answers, meta, 1), ([], 0))
        runs, _total = F.report_runs(answers, meta, {"multiple": 0.0}, self.ts)
        K = (1, 4)
        self.assertEqual(runs or [K], [K])
        answers["loc_a"] = decimal_choice({"L1-4": "0.51", "none": "0.49", "unlocalized": "0.0"})
        answers["loc_b"] = decimal_choice({"L1-4": "0.51", "none": "0.49", "unlocalized": "0.0"})
        self.assertEqual(F.combined_runs(answers, meta, 1), ([(1, 4)], 1))

    def test_hidden_mass_counts_undisplayed_probability(self):
        meta = {"roles": {"loc_a": {"role": "loc_a", "cells": [[1, 4]]}}}
        answers = {"loc_a": decimal_choice({"L1-4": "0.5", "none": "0.0", "unlocalized": "0.0"})}
        self.assertEqual(F.combined_runs(answers, meta, 1), ([], 0))

    def test_line_mass_is_exact(self):
        meta = {"roles": {"loc_a": {"role": "loc_a", "cells": [[1, 4]]},
                          "loc_b": {"role": "loc_b", "cells": [[1, 4]]}}}
        # 0.5 in one menu and 0.49999999998 in the other average to just under one half
        meta["roles"]["loc_a"]["cells"] = meta["roles"]["loc_b"]["cells"] = [[1, 4], [5, 8]]
        answers = {"loc_a": decimal_choice({"L1-4": "0.5", "L5-8": "0.4", "none": "0.1",
                                            "unlocalized": "0.0"}),
                   "loc_b": decimal_choice({"L1-4": "0.49999999998", "L5-8": "0.40000000002",
                                            "none": "0.1", "unlocalized": "0.0"})}
        self.assertEqual(F.combined_runs(answers, meta, 1), ([], 0))
        answers["loc_b"] = decimal_choice({"L1-4": "0.5", "L5-8": "0.4", "none": "0.1",
                                           "unlocalized": "0.0"})
        self.assertEqual(F.combined_runs(answers, meta, 1), ([(1, 4)], 1))
        self.assertEqual(F.combined_runs(answers, meta, 1, roles=("loc_a",)), ([(1, 4)], 1))
        self.assertEqual(F.combined_runs(answers, meta, 1, roles=("loc_c",)), ([], 0))

    def test_probabilities_are_read_as_the_printed_decimals_not_as_binary_floats(self):
        meta = {"roles": {"loc_a": {"role": "loc_a", "cells": [[1, 4], [5, 8]]},
                          "loc_b": {"role": "loc_b", "cells": [[1, 4], [5, 8]]}}}
        # 0.3 and 0.7 average to exactly one half; as binary floats they would fall just short
        answers = {"loc_a": decimal_choice({"L1-4": "0.3", "L5-8": "0.7", "none": "0.0",
                                            "unlocalized": "0.0"}),
                   "loc_b": decimal_choice({"L1-4": "0.7", "L5-8": "0.3", "none": "0.0",
                                            "unlocalized": "0.0"})}
        self.assertEqual(F.combined_runs(answers, meta, 1), ([(1, 8)], 1))
        recorded = {"loc_a": {"probabilities": {"L1-4": "0.3", "L5-8": "0.7", "none": "0.0"}},
                    "loc_b": {"probabilities": {"L1-4": "0.7", "L5-8": "0.3", "none": "0.0"}}}
        self.assertEqual(F.combined_runs(recorded, meta, 1), ([(1, 8)], 1))

    def test_no_menu_gives_no_run(self):
        self.assertEqual(F.combined_runs({}, {"roles": {"loc_a": {"role": "loc_a", "cells": [[1, 2]]}}}, 1),
                         ([], 0))

    def test_runs_rank_by_peak_then_total_then_position(self):
        meta = {"roles": {"loc_a": {"role": "loc_a", "cells": [[1, 2], [4, 5], [7, 9]]}}}
        answers = {"loc_a": decimal_choice({"L1-2": "0.5", "L4-5": "0.6", "L7-9": "0.5",
                                            "none": "0.0", "unlocalized": "0.0"})}
        # raw masses: 0.6 on 4-5, 0.5 on 1-2 and on 7-9 (same peak; 7-9 has more total mass)
        self.assertEqual(F.combined_runs(answers, meta, 3)[0], [(4, 5), (7, 9), (1, 2)])
        self.assertEqual(F.combined_runs(answers, meta, 0)[0], [])

    def test_gateway_decimal_and_exact_fraction_agree(self):
        meta = {"roles": {"loc_a": {"role": "loc_a", "cells": [[1, 4]]}}}
        answers = {"loc_a": decimal_choice({"L1-4": "0.5", "none": "0.1", "unlocalized": "0.0"})}
        self.assertEqual(F.combined_runs(answers, meta, 1),
                         F.combined_runs({"loc_a": {"probabilities": {"L1-4": 0.5, "none": 0.1,
                                                                    "unlocalized": 0.0}}}, meta, 1))
        self.assertEqual(Fraction(str(Decimal("0.1"))), Fraction(1, 10))

    def test_reconcile_merges_at_half_of_the_smaller_interval(self):
        self.assertEqual(F.reconcile([(1, 10), (6, 14)]), [(1, 14)])      # overlap 5 of 9
        self.assertEqual(F.reconcile([(1, 10), (7, 14)]), [(1, 14)])      # overlap 4 of 8: half
        self.assertEqual(F.reconcile([(1, 10), (8, 14)]), [(1, 10), (8, 14)])   # overlap 3 of 7
        self.assertEqual(F.reconcile([(1, 10), (6, 13)]), [(1, 13)])      # overlap 5 of 8
        self.assertEqual(F.reconcile([(1, 4), (6, 9)]), [(1, 4), (6, 9)])
        self.assertEqual(F.reconcile([(20, 30), (1, 10), (5, 12)]), [(1, 12), (20, 30)])
        self.assertEqual(F.reconcile([]), [])

    def test_reconcile_unites_in_order_of_position_whatever_the_input_order(self):
        # in the given order (6,8), (9,15), (7,16), the last one joins (6,8) and leaves (9,15)
        # standing inside it; by position (9,15) is united with the others after (7,16)
        self.assertEqual(F.reconcile([(6, 8), (9, 15), (7, 16)]), [(6, 16)])
        self.assertEqual(F.reconcile([(7, 16), (9, 15), (6, 8)]), [(6, 16)])
        self.assertEqual(F.reconcile([(9, 15), (7, 16), (6, 8)]), [(6, 16)])
        # the result is sorted by position
        self.assertEqual(F.reconcile([(40, 50), (20, 30), (1, 4)]), [(1, 4), (20, 30), (40, 50)])


# -- replays ----------------------------------------------------------------------------------

class E4ReplayTests(Fixtures):
    """The recorded pilot answers of the catalog, read by the shipped code."""

    def tiles_of(self, case):
        """{look: (tile, features)} under 8C: look 1 is not asked for a file of at most 8 lines."""
        out = {}
        for tile in case["tiles"]:
            for look in tile["looks"]:
                if look == 1 and case["n"] <= SINGLE_LOOK_MAX_LINES and 0 not in tile["looks"]:
                    continue
                answers = gateway(tile["answers"])
                out[look] = (tile, F.tile_features(tile["meta"], answers))
        return out

    def flagged_by_look(self, case, rule=None):
        ts = self.ts if rule is None else dataclasses.replace(self.ts, screening_rule=rule)
        return {look: flagged_cells(F.flag_tile(feat, ts))
                for look, (_tile, feat) in self.tiles_of(case).items()}

    def clusters(self, case, rule=None):
        flagged = self.flagged_by_look(case, rule)
        return F.make_clusters_ex([c for cells in flagged.values() for c in cells], case["n"])

    def test_every_tile_flags_exactly_as_the_pilot_did(self):
        tiles = [(c, t) for c in self.e4["cases"] for t in c["tiles"]]
        self.assertEqual(len(tiles), 39)
        count = 0
        for case, tile in tiles:
            feat = F.tile_features(tile["meta"], gateway(tile["answers"]))
            rows = F.flag_tile(feat, self.ts)
            got = [{"cell": list(r["cell"]), "flag": r["flag"], "why": r["why"], "z": r["z"]}
                   for r in rows]
            self.assertEqual(got, tile["flags"], tile["id"])
            self.assertEqual(feat["need_ctx"], tile["need_ctx"], tile["id"])
            self.assertEqual(F.canaries_pass(tile["meta"], gateway(tile["answers"]))[0],
                             tile["canaries_pass"], tile["id"])
            count += sum(r["flag"] for r in rows)
        self.assertEqual(count, 20)

    def test_twenty_leaf_flags_by_the_leaf_score_and_the_granule_and_no_orphan(self):
        why = []
        for case in self.e4["cases"]:
            for tile in case["tiles"]:
                rows = F.flag_tile(F.tile_features(tile["meta"], gateway(tile["answers"])), self.ts)
                self.assertFalse(any(r.get("tail") for r in rows), tile["id"])
                why.extend(tuple(r["why"]) for r in rows if r["flag"])
        self.assertEqual(len(why), 20)
        self.assertEqual(sorted(set(why)), [("z",), ("z", "granule")])
        self.assertEqual(why.count(("z",)), 16)
        self.assertEqual(why.count(("z", "granule")), 4)

    def test_flagged_cells_per_look_equal_the_fixture(self):
        for case in self.e4["cases"]:
            expected = case["expected_outcome"]["flagged_by_look"]
            got = self.flagged_by_look(case)
            self.assertIn(0, got, case["id"])
            for look, cells in got.items():
                self.assertEqual(cells, [pair(c) for c in expected[str(look)]], (case["id"], look))
            if case["n"] > SINGLE_LOOK_MAX_LINES:
                self.assertEqual(sorted(got), [0, 1], case["id"])
            else:
                self.assertEqual(sorted(got), [0, 1] if case["n"] <= 4 else [0], case["id"])

    def test_need_context_equals_the_fixture(self):
        for case in self.e4["cases"]:
            fired = any(feat["need_ctx"] is not None and feat["need_ctx"] >= self.ts.tau_ctx
                        for _tile, feat in self.tiles_of(case).values())
            self.assertIs(fired, case["expected_outcome"]["need_ctx"], case["id"])

    def test_clusters_equal_the_fixture_with_look_one_skipped_for_short_files(self):
        total = 0
        for case in self.e4["cases"]:
            got = [{"K": c["K"], "core": c["core"]} for c in self.clusters(case)]
            expected = [{"K": pair(c["K"]), "core": pair(c["core"])}
                        for c in case["expected_outcome"]["clusters"]]
            self.assertEqual(got, expected, case["id"])
            total += len(got)
        self.assertEqual(total, 17)

    def test_seventeen_clusters_and_all_strong(self):
        count = 0
        for case in self.e4["cases"]:
            feats = [feat for _tile, feat in self.tiles_of(case).values()]
            for cluster in self.clusters(case):
                count += 1
                self.assertIs(F.cluster_strength(cluster, feats, self.ts), True, case["id"])
        self.assertEqual(count, 17)

    def test_focus_scores_decisions_runs_and_findings_equal_the_fixture(self):
        reported = 0
        for case in self.e4["cases"]:
            feats = [feat for _tile, feat in self.tiles_of(case).values()]
            by_k = {pair(item["K"]): item for item in case["focus"]}
            self.assertEqual(len(by_k), len(case["focus"]), case["id"])
            findings = []
            for cluster in self.clusters(case):
                item = by_k.pop(cluster["K"])
                answers = gateway(item["answers"])
                p, e = F.focus_scores(item["meta"], answers, self.ts)
                self.assertEqual(e, item["E"], (case["id"], cluster["K"]))
                self.assertEqual(p["verify"], item["scores"]["verify"])
                self.assertEqual(p["twin"], item["scores"]["twin"])
                self.assertEqual(p["relation"], item["scores"]["relation_max"])
                self.assertEqual(p["lens"], item["scores"]["lens_max"])
                self.assertEqual(p["requirement"], item["scores"]["requirement_max"])
                self.assertEqual(p["multiple"], item["scores"]["multiple"])
                self.assertEqual(p["need_ctx"], item["scores"]["need_ctx"])
                self.assertIs(p["twin_refused"], False)
                self.assertIs(F.canaries_pass(item["meta"], answers)[0], item["canaries_pass"])
                strong = F.cluster_strength(cluster, feats, self.ts)
                self.assertEqual(self.ts.tau_rep(case["n"]), item["tau_rep"])
                decision = F.focus_decision(p, e, case["n"], strong, self.ts)
                self.assertEqual(decision, item["decision"], (case["id"], cluster["K"]))
                if decision != "report":
                    continue
                reported += 1
                runs, _total = F.report_runs(answers, item["meta"], p, self.ts)
                self.assertEqual(runs, [pair(r) for r in item["runs"]])
                findings.extend(runs or [cluster["K"]])
            self.assertEqual(by_k, {}, case["id"])
            self.assertEqual(F.reconcile(findings),
                             [pair(f) for f in case["expected_outcome"]["findings"]], case["id"])
        self.assertEqual(reported, 17)

    def test_the_weak_second_bug_of_c029_reports_at_the_file_length_bar(self):
        case = next(c for c in self.e4["cases"] if c["id"] == "C029")
        item = next(f for f in case["focus"] if pair(f["K"]) == (53, 70))
        p, e = F.focus_scores(item["meta"], gateway(item["answers"]), self.ts)
        self.assertAlmostEqual(e, 0.587, places=3)
        self.assertEqual(F.focus_decision(p, e, 70, True, self.ts), "report")
        self.assertEqual(F.focus_decision(p, e, 1000, False, self.ts), "clear")

    def test_leaf_only_at_085_finds_the_same_seventeen_clusters(self):
        total = 0
        for case in self.e4["cases"]:
            got = [{"K": c["K"], "core": c["core"]} for c in self.clusters(case, "leaf-only")]
            expected = [{"K": pair(c["K"]), "core": pair(c["core"])}
                        for c in case["expected_outcome"]["clusters"]]
            self.assertEqual(got, expected, case["id"])
            total += len(got)
        self.assertEqual(total, 17)

    def test_leaf_only_flags_no_more_than_the_pilot_rule_on_the_catalog(self):
        for case in self.e4["cases"]:
            for tile in case["tiles"]:
                feat = F.tile_features(tile["meta"], gateway(tile["answers"]))
                full = set(flagged_cells(F.flag_tile_pilot_full(feat, self.ts)))
                leaf = set(flagged_cells(F.flag_tile_leaf_only(feat, self.ts)))
                self.assertLessEqual(leaf, full, tile["id"])

    def test_the_pilot_screening_variants_on_the_fixture_tiles(self):
        full = leaf = 0
        for case in self.e4["cases"]:
            for tile in case["tiles"]:
                feat = F.tile_features(tile["meta"], gateway(tile["answers"]))
                rows = F.flag_tile_pilot_full(feat, self.ts)
                full += sum(r["flag"] for r in rows)
                self.assertFalse(any(w.startswith("orphan") for r in rows for w in r["why"]))
                leaf += sum(r["flag"] for r in F.flag_tile_leaf_only(feat, self.ts))
        self.assertEqual(full, 20)
        self.assertGreaterEqual(leaf, 16)

    def test_raising_the_leaf_bar_moves_nothing_but_the_flag(self):
        # the pilot rule at its own 0.96 bar: lowering it to 0.95 changes no catalog cluster
        lower = dataclasses.replace(self.ts, tau_s=0.95)
        for case in self.e4["cases"]:
            for tile in case["tiles"]:
                feat = F.tile_features(tile["meta"], gateway(tile["answers"]))
                self.assertEqual(flagged_cells(F.flag_tile(feat, lower)),
                                 flagged_cells(F.flag_tile(feat, self.ts)), tile["id"])


#: The clusters (file, K) of the E2 fixture that rule 8C reports at decision_n = 200: 15 of the
#: 21 true ones and 2 of the 15 clean ones. Pinned by name, so that a swap of one reported and
#: one missed cluster cannot pass on the counts.
E2_REPORTED_TRUE = frozenset({
    ("p-B01-recordset", (549, 588)), ("p-B02-recordset", (557, 580)),
    ("p-B03-recordset", (549, 588)), ("p-B07-logstats", (165, 188)),
    ("p-B08-logstats", (381, 412)), ("p-B09-logstats", (381, 412)),
    ("p-B11-logstats", (485, 508)), ("p-B12-logstats", (213, 268)),
    ("p-B14-job_scheduler", (557, 596)), ("p-B20-workflow_engine", (565, 596)),
    ("p-B24-workflow_engine", (621, 676)), ("p-B31-polygeom", (165, 200)),
    ("p-B36-polygeom", (653, 691)), ("p-B45-patchkit", (429, 460)),
    ("p-B47-patchkit", (285, 316))})
E2_REPORTED_CLEAN = frozenset({("c1-linediff", (365, 388)), ("c4-textfmt", (413, 436))})


class E2ReplayTests(Fixtures):
    """The 8C decision on the 36 answered E2 focus clusters and the 6 with a refused twin."""

    def scored(self, row):
        p = {"verify": row["verify"], "twin": row["twin"], "twin_refused": row["twin_refused"],
             "lens": 0.0, "relation": row["relation_max"]}
        return p, F.fuse_e(p, self.ts)

    def test_expected_counts_at_decision_n_200(self):
        expected = self.e2["expected_8c_openai"]
        self.assertEqual(expected["decision_n"], 200)
        tally = {"true": [0, 0], "clean": [0, 0]}
        for row in self.e2["clusters"]:
            p, e = self.scored(row)
            self.assertEqual(e, row["E"], (row["file"], row["K"]))
            decision = F.focus_decision(p, e, expected["decision_n"], row["strong"], self.ts)
            self.assertIn(decision, ("report", "clear"))
            tally[row["label"]][0] += decision == "report"
            tally[row["label"]][1] += 1
        self.assertEqual(tally["true"], [expected["true_reported"], expected["true_total"]])
        self.assertEqual(tally["clean"], [expected["clean_reported"], expected["clean_total"]])
        self.assertEqual(tally["true"], [15, 21])
        self.assertEqual(tally["clean"], [2, 15])

    def test_each_cluster_is_decided_as_pinned(self):
        reported = {"true": set(), "clean": set()}
        for row in self.e2["clusters"]:
            p, e = self.scored(row)
            if F.focus_decision(p, e, 200, row["strong"], self.ts) == "report":
                reported[row["label"]].add((row["file"], tuple(row["K"])))
        self.assertEqual(reported["true"], E2_REPORTED_TRUE)
        self.assertEqual(reported["clean"], E2_REPORTED_CLEAN)
        self.assertEqual(len({(r["file"], tuple(r["K"])) for r in self.e2["clusters"]}), 36)

    def test_the_two_clean_clusters_that_report(self):
        reported = []
        for row in self.e2["clusters"]:
            p, e = self.scored(row)
            if row["label"] == "clean" and F.focus_decision(p, e, 200, row["strong"], self.ts) == "report":
                reported.append((row["file"], tuple(row["K"]), row["strong"]))
        self.assertEqual(reported, [("c1-linediff", (365, 388), True), ("c4-textfmt", (413, 436), False)])

    def test_the_six_refused_twins_are_cleared_on_verify_alone(self):
        rows = self.e2["twin_refused_clusters"]
        self.assertEqual(len(rows), 6)
        for row in rows:
            self.assertIsNone(row["twin"])
            self.assertTrue(row["twin_refused"])
            p, e = self.scored(row)
            self.assertEqual(e, row["verify"], (row["file"], row["K"]))
            self.assertEqual(e, row["E"])
            self.assertEqual(F.focus_decision(p, e, 200, row["strong"], self.ts), "clear")
        self.assertEqual(self.e2["expected_8c_openai"]["refused_twins_cleared"], 6)

    def test_no_cluster_is_left_unmeasured(self):
        rows = self.e2["clusters"] + self.e2["twin_refused_clusters"]
        for row in rows:
            _p, e = self.scored(row)
            self.assertIsNotNone(e)
        self.assertEqual(self.e2["expected_8c_openai"]["unmeasured"], 0)

    def test_workflow_engine_b20_reports_at_039000000000000007(self):
        row = next(r for r in self.e2["clusters"] if r["file"] == "p-B20-workflow_engine")
        p, e = self.scored(row)
        self.assertEqual(e, 0.39000000000000007)
        self.assertTrue(row["strong"])
        self.assertEqual(F.focus_decision(p, e, 200, True, self.ts), "report")
        # a non-strong cluster at that score is below its bar
        self.assertEqual(F.focus_decision(p, e, 200, False, self.ts), "clear")

    def test_a_refused_twin_that_is_strong_reports_from_039(self):
        row = {"verify": 0.39, "twin": None, "twin_refused": True, "relation_max": 0.0}
        p, e = self.scored(row)
        self.assertEqual(F.focus_decision(p, e, 200, True, self.ts), "report")
        self.assertEqual(F.focus_decision(p, e, 200, False, self.ts), "clear")

    def test_deciding_at_each_files_own_n_never_reports_more_than_n_200(self):
        for row in self.e2["clusters"]:
            p, e = self.scored(row)
            own = F.focus_decision(p, e, row["n"], row["strong"], self.ts)
            at200 = F.focus_decision(p, e, 200, row["strong"], self.ts)
            self.assertFalse(own == "report" and at200 != "report", (row["file"], row["K"]))


class ModuleTests(unittest.TestCase):
    def test_module_imports_in_a_fresh_interpreter_before_the_engine(self):
        import subprocess
        import sys
        # The engine reads the thresholds from this module, so this module must not import the
        # engine at load time: importing it first must work, leave the engine unloaded, and still
        # let the run functions (which import the engine's helpers when called) work.
        runs = ("meta = {'roles': {'loc_a': {'role': 'loc_a', 'cells': [[1, 4]]}}}; "
                "answers = {'loc_a': {'probabilities': {'L1-4': '0.9', 'none': '0.1'}}}; "
                "assert F.combined_runs(answers, meta, 1) == ([(1, 4)], 1)")
        codes = (
            "import sys; import decision_bug_hunter.tile_sieve_fusion as F; "
            "assert 'decision_bug_hunter.engine' not in sys.modules; " + runs +
            "; assert 'decision_bug_hunter.engine' in sys.modules",
            "import decision_bug_hunter.engine; import decision_bug_hunter.tile_sieve_fusion as F; "
            + runs)
        for code in codes:
            # no -I: the checkout under test is found through the working directory
            result = subprocess.run([sys.executable, "-c", code], cwd=ROOT,
                                    capture_output=True, text=True, timeout=120)
            self.assertEqual(result.returncode, 0, result.stderr)

    def test_the_module_does_no_network_or_process_work(self):
        source = (ROOT / "decision_bug_hunter" / "tile_sieve_fusion.py").read_text(encoding="utf-8")
        for word in ("socket", "urllib", "http.client", "subprocess", "os.environ", "getenv",
                     "time.time", "datetime", "random"):
            self.assertNotIn(word, source, word)


if __name__ == "__main__":
    unittest.main()
