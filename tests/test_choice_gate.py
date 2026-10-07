"""Revision-3 WP-15: choice gate, localization menus and rounding caps.

The localization gate defaults to "mass" (the maintainer's decision after
the live development-suite comparison); every other option defaults to its
legacy value. The pinned scenarios pass choice_gate="legacy" explicitly, so
the legacy values still reproduce the pre-WP-15 request bytes and reports
exactly.
"""
from decimal import Decimal
from fractions import Fraction
import hashlib
import json
from pathlib import Path
import unittest
from unittest.mock import patch

from decision_bug_hunter import __main__ as cli
from decision_bug_hunter.core import (CHOICE_GATES, DEFAULT_CHOICE_GATE, Config,
                                      LEGACY_CHOICE_OPTIONS, Span, contiguous_candidates)
from decision_bug_hunter.engine import (Search, choice_mass_diffuse, choice_option_cap,
                                        half_quantum, hidden_choice_mass, line_overlap_mass,
                                        mass_gate_runs)
from decision_bug_hunter.questions import load_pack, screening, singleton_candidates
from tests.support import FixtureProvider, scan, source

OBSERVED = Path(__file__).parent / "fixtures" / "openrouter" / "observed" / "2026-10-06"
H2 = half_quantum(2)


def observed_where(name):
    data = json.loads((OBSERVED / f"{name}.json").read_text(encoding="utf-8"),
                      parse_float=Decimal)
    return data["body"]["answers"]["where"]


def identity_answer(probabilities, chosen):
    """A choice whose confidence follows chance_normalized_p1 (observed on Luna)."""
    k = len(probabilities)
    p1 = Fraction(probabilities[chosen])
    confidence = (p1 - Fraction(1, k)) / (1 - Fraction(1, k))
    return {"type": "choice", "choice": chosen, "probabilities": probabilities,
            "confidence": Decimal(confidence.numerator) / Decimal(confidence.denominator)}


class Diffuse(FixtureProvider):
    """Localize answers spread over every option containing line 5 (S10-like)."""

    def answer(self, qid, q, state):
        if qid == "where":
            keys = list(q["criteria"])
            probs = dict.fromkeys(keys, 0)
            hot = [k for k in keys if k.startswith("L")
                   and int(k[1:].split("-")[0]) <= 5 <= int(k.split("-")[1])]
            base = round(0.9 / len(hot), 2) if hot else 0
            total = 0
            for k in hot:
                probs[k] = base
                total += base
            probs["unlocalized"] = round(1 - total, 2)
            top = max(probs.values())
            best = next(k for k in keys if probs[k] == top)
            return {"type": "choice", "choice": best, "confidence": top,
                    "probabilities": probs}
        return super().answer(qid, q, state)


def canon(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, ensure_ascii=False,
                                     separators=(",", ":"), default=str).encode()).hexdigest()


def digests(provider, src, cfg, **kwargs):
    result = scan(src, provider, cfg, **kwargs)
    wire = hashlib.sha256(json.dumps(provider.requests, ensure_ascii=False,
                                     separators=(",", ":")).encode()).hexdigest()
    return wire, canon(result)


def strict_fixture(bugs):
    provider = FixtureProvider(bugs)
    provider.rounding_places = None
    return provider


# (wire sha256, report sha256) produced by the pre-WP-15 code (HEAD a433ddb).
PRE_WP15 = {
    "legacy": ("9167966d6236347cb1e6adb2aa74a074cc2f70ee8b4ee90445349867874fdf2c",
               "5bd981a5e7f62f8d8ace5527c2f7aa9569d5857c476ef0daeff93ac95064221b"),
    "scoped": ("87a1e144a9fa8091483d51444d0f2322bd0a3bca2342674f304de830b0793547",
               "2ed0e562958e8572206b45b2a7ce6cf8313e714ffb915b518bf9d6d6b74a8984"),
    "legacy_spec": ("6ea616a06a7ca2f9b09a9075048137b1f6364af880541f239861719a43c5288f",
                    "03f1a1e00c28034de0cb5d78897de7f51ca2114655a55ec6d66a53c57a70140f"),
    "strict": ("9167966d6236347cb1e6adb2aa74a074cc2f70ee8b4ee90445349867874fdf2c",
               "b14fbd7b844f5e9b09d4436c38eda6b21747606f7cf086bce838b59004e728a9"),
    "diffuse": ("68d29fc9c1cffd8beedd0906b2e57cf6907f657ecd59f547f719af152237b9e4",
                "f5e431bc9a0052c1f931960ad577f64eab8cb91259f173efb926c35e88943213"),
    "diffuse_scoped": ("d511a984037bfc71d57cce884733fc99024fd6c4e651c8ad23d6dda9211fbfb2",
                       "ad5af6e57d364dd266f946a55cd0b643ef383bb14e7ca2e6f25c64bb54aa779e"),
    "context": ("f03aedf2ba74bfc05dbf84b5afcaa7d33a7588659c93ba84318d5a3e240c56fa",
                "549c4bd6487b810a441d8ed258446e903e5ee4074b4de7894821135823e0bea3"),
}


def scenarios(**options):
    """The pinned scenarios; *options* adds Config fields to every run.

    The pins predate the judge controls (WP-14) and the mass-gate default,
    so the scenarios run with canaries off and choice_gate "legacy", which
    must reproduce those bytes exactly.
    """
    options = {"canaries": "off", "choice_gate": "legacy", **options}
    scoped = {"search_policy": "scoped-v2-beta"}
    return {
        "legacy": (FixtureProvider([(5, 5)]), source(30), Config(whole_file=False, **options), {}),
        "scoped": (FixtureProvider([(5, 5)]), source(30),
                   Config(whole_file=False, **scoped, **options), {}),
        "legacy_spec": (FixtureProvider([(5, 5), (40, 41)]), source(60), Config(**options),
                        {"spec": "Line five must be correct.\nLines forty must hold."}),
        "strict": (strict_fixture([(5, 5)]), source(30), Config(whole_file=False, **options), {}),
        "diffuse": (Diffuse([(5, 5)]), source(24), Config(whole_file=False, **options), {}),
        "diffuse_scoped": (Diffuse([(5, 5)]), source(24),
                           Config(whole_file=False, **scoped, **options), {}),
        "context": (FixtureProvider([(30, 30)], need_packet=70), source(100),
                    Config(whole_file=False, **options), {}),
    }


def search_for(gateway, lines=20, **options):
    return Search(source(lines), gateway, Config(**options), None)


class Gateway:
    """Attributes the engine reads from a gateway; no evaluate needed here."""

    def __init__(self, rounding_places=None, display_places=None):
        self.rounding_places = rounding_places
        self.display_places = display_places


class DefaultsTests(unittest.TestCase):
    def test_legacy_gate_reproduces_pre_wp15_requests_and_reports_byte_for_byte(self):
        for name, (provider, src, cfg, kwargs) in scenarios().items():
            with self.subTest(name):
                self.assertEqual(digests(provider, src, cfg, **kwargs), PRE_WP15[name])

    def test_explicit_legacy_values_reproduce_the_pins(self):
        explicit = dict(LEGACY_CHOICE_OPTIONS, choice_mass=Decimal("0.50"))
        for name, (provider, src, cfg, kwargs) in scenarios(**explicit).items():
            with self.subTest(name):
                self.assertEqual(digests(provider, src, cfg, **kwargs), PRE_WP15[name])
        # Only the gate default moved; the other WP-15 options keep their
        # legacy values.
        self.assertEqual(Config(), Config(**dict(LEGACY_CHOICE_OPTIONS, choice_gate="mass")))

    def test_default_gate_is_mass(self):
        self.assertEqual(DEFAULT_CHOICE_GATE, "mass")
        self.assertIn("legacy", CHOICE_GATES)
        self.assertEqual(Config().choice_gate, "mass")
        self.assertEqual(Config().choice_mass, Decimal("0.5"))
        self.assertEqual(LEGACY_CHOICE_OPTIONS["choice_gate"], "legacy")
        # The report configuration records the gate; choice_mass at 0.5 and
        # the other options at their legacy values stay omitted.
        recorded = Config().as_dict()
        self.assertEqual(recorded["choice_gate"], "mass")
        self.assertFalse({"choice_mass", "localization_menu", "choice_rounding_caps"}
                         & set(recorded))
        self.assertNotIn("choice_gate", Config(choice_gate="legacy").as_dict())

    def test_default_scan_uses_the_mass_gate_and_records_it(self):
        legacy = scan(source(24), Diffuse([(5, 5)]),
                      Config(whole_file=False, choice_gate="legacy"))
        default = scan(source(24), Diffuse([(5, 5)]), Config(whole_file=False))
        mass = scan(source(24), Diffuse([(5, 5)]), Config(whole_file=False, choice_gate="mass"))
        self.assertEqual(default["configuration"]["choice_gate"], "mass")
        self.assertNotIn("choice_gate", legacy["configuration"])
        self.assertEqual(canon(default), canon(mass))
        self.assertNotEqual(canon(default), canon(legacy))
        events = [e for e in default["events"] if e["phase"] == "localize"]
        self.assertTrue(events)
        self.assertEqual(events[0]["gate"], "mass")

    def test_caps_without_rounding_profile_change_nothing(self):
        provider, src, cfg, _ = scenarios(choice_rounding_caps=True)["strict"]
        wire, _ = digests(provider, src, cfg)
        self.assertEqual(wire, PRE_WP15["strict"][0])

    def test_legacy_configuration_omits_wp15_keys_and_records_others(self):
        self.assertFalse(set(LEGACY_CHOICE_OPTIONS)
                         & set(Config(choice_gate="legacy").as_dict()))
        recorded = Config(choice_gate="mass", choice_mass=Decimal("0.6"),
                          localization_menu="singletons", choice_rounding_caps=True).as_dict()
        self.assertEqual({k: recorded[k] for k in LEGACY_CHOICE_OPTIONS},
                         {"choice_gate": "mass", "choice_mass": "0.6",
                          "localization_menu": "singletons", "choice_rounding_caps": True})

    def test_config_validation(self):
        for bad in ({"choice_gate": "prefix"}, {"choice_gate": None},
                    {"localization_menu": "lines"}, {"choice_mass": 0},
                    {"choice_mass": Decimal("1.01")}, {"choice_mass": "0.5"},
                    {"choice_mass": float("nan")}, {"choice_rounding_caps": 1}):
            with self.subTest(bad), self.assertRaises(ValueError):
                Config(**bad)
        self.assertEqual(Config(choice_mass=1).choice_mass, Decimal(1))

    def test_cli_flags_parse_with_mass_gate_default(self):
        args = cli.parser().parse_args(["x.py"])
        self.assertEqual((args.choice_gate, args.choice_mass, args.localization_menu,
                          args.choice_rounding_caps), ("mass", Decimal("0.5"), "intervals", False))
        self.assertEqual(args.choice_gate, Config().choice_gate)
        self.assertEqual(args.choice_mass, Config().choice_mass)
        args = cli.parser().parse_args(["x.py", "--choice-gate", "legacy"])
        self.assertEqual(args.choice_gate, "legacy")
        args = cli.parser().parse_args(["x.py", "--choice-gate", "mass", "--choice-mass", "0.6",
                                        "--localization-menu", "singletons",
                                        "--choice-rounding-caps"])
        self.assertEqual((args.choice_gate, args.choice_mass, args.localization_menu,
                          args.choice_rounding_caps), ("mass", Decimal("0.6"), "singletons", True))
        for bad in (["--choice-gate", "prefix"], ["--localization-menu", "lines"]):
            with self.subTest(bad), patch("sys.stderr"), self.assertRaises(SystemExit):
                cli.parser().parse_args(["x.py", *bad])


class MassGateTests(unittest.TestCase):
    def test_mass_gate_per_line_overlap_lower_bound(self):
        # S10 (k = 212, planted bug at line 5): exactly one span, L4-5.
        where = observed_where("S10")
        options = {s.id: s for s in contiguous_candidates(Span(1, 20))}
        self.assertEqual(len(where["probabilities"]), 212)
        mass = line_overlap_mass(where, options, H2)
        self.assertEqual((mass[3], mass[4], mass[5], mass[6]),
                         (Fraction("0.485"), Fraction("0.525"), Fraction("0.565"),
                          Fraction("0.225")))
        runs, qualifying, hidden = mass_gate_runs(where, options, Decimal("0.5"), H2, 3)
        self.assertEqual((runs, qualifying, hidden), ([Span(4, 5)], 1, Fraction("0.03")))
        # The engine reaches the same span through the OpenRouter display
        # precision (2 places) when no rounding profile is set; legacy
        # returns nothing because min(0.27, 0.27) < 0.5.
        search = search_for(Gateway(display_places=2), choice_gate="mass")
        selected, fields = search.mass_selection(where, list(options.values()), 3)
        self.assertEqual(selected, [Span(4, 5)])
        self.assertEqual(fields, {"gate": "mass", "mass_selected": ["L4-5"],
                                  "qualifying_runs": 1, "hidden_mass": "0.03"})
        self.assertEqual(search.gated_candidates(where, list(options.values()), 3), [])

    def test_s10b_singletons_mass_and_legacy_agree(self):
        where = observed_where("S10b")
        singles = [Span(i, i) for i in range(1, 19)]
        search = search_for(Gateway(display_places=2), choice_gate="mass")
        self.assertEqual(search.mass_selection(where, singles, 3)[0], [Span(5, 5)])
        self.assertEqual(search.gated_candidates(where, singles, 3), [Span(5, 5)])

    def test_gate_menu_size_invariant(self):
        # The same 0.6 of mass on line 5, offered as one singleton option or
        # spread over every nested interval containing it. Under the observed
        # identity the legacy gate needs p1 >= 0.5 + 0.5/k, which depends on k;
        # the mass gate selects line 5 in both menus.
        target = Span(1, 20)
        singles = singleton_candidates(target)
        flat = dict.fromkeys([s.id for s in singles] + ["none", "unlocalized"], Decimal(0))
        flat["L5-5"], flat["unlocalized"] = Decimal("0.6"), Decimal("0.4")
        nested_options = contiguous_candidates(target)
        nested = dict.fromkeys([s.id for s in nested_options] + ["none", "unlocalized"],
                               Decimal(0))
        nested["L5-5"] = Decimal("0.42")
        nested["L4-6"] = Decimal("0.18")
        nested["unlocalized"] = Decimal("0.4")
        search = search_for(Gateway(display_places=2), choice_gate="mass")
        flat_answer = identity_answer(flat, "L5-5")
        nested_answer = identity_answer(nested, "L5-5")
        self.assertEqual(search.mass_selection(flat_answer, singles, 3)[0], [Span(5, 5)])
        self.assertEqual(search.mass_selection(nested_answer, nested_options, 3)[0], [Span(5, 5)])
        self.assertEqual(search.gated_candidates(flat_answer, singles, 3), [Span(5, 5)])
        self.assertEqual(search.gated_candidates(nested_answer, nested_options, 3), [])
        # Legacy boundary under the identity: p1 = 0.5 + 0.5/k passes, less fails.
        for k in (4, 22, 212):
            p1 = Fraction(1, 2) + Fraction(1, 2 * k)
            confidence = (p1 - Fraction(1, k)) / (1 - Fraction(1, k))
            self.assertEqual(min(confidence, p1), Fraction(1, 2))

    def test_hidden_mass_blocks_gate(self):
        options = {s.id: s for s in singleton_candidates(Span(1, 4))}

        def answer(**values):
            probs = dict.fromkeys(list(options) + ["none", "unlocalized"], Decimal(0))
            probs.update({k.replace("_", "-"): Decimal(v) for k, v in values.items()})
            return {"type": "choice", "choice": max(probs, key=lambda k: probs[k]),
                    "confidence": Decimal("0.5"), "probabilities": probs}
        blocked = answer(L2_2="0.5", none="0.3", unlocalized="0.2")
        self.assertEqual(mass_gate_runs(blocked, options, Decimal("0.4"), H2, 3)[0], [])
        passing = answer(L2_2="0.51", none="0.29", unlocalized="0.2")
        self.assertEqual(mass_gate_runs(passing, options, Decimal("0.5"), H2, 3)[0],
                         [Span(2, 2)])
        # Undisplayed mass (rounding profiles allow sum(v) < 1) counts as hidden.
        missing = answer(L2_2="0.55", none="0.2", unlocalized="0.05")
        self.assertEqual(hidden_choice_mass(missing), Fraction("0.45"))
        self.assertEqual(mass_gate_runs(missing, options, Decimal("0.5"), H2, 3)[0],
                         [Span(2, 2)])
        lost = answer(L2_2="0.5", none="0.2", unlocalized="0.05")
        self.assertEqual(hidden_choice_mass(lost), Fraction("0.5"))
        self.assertEqual(mass_gate_runs(lost, options, Decimal("0.4"), H2, 3), ([], 0, Fraction("0.5")))
        # On a singleton menu the gate is v - h >= threshold.
        edge = answer(L2_2="0.505", none="0.495")
        self.assertEqual(mass_gate_runs(edge, options, Decimal("0.5"), H2, 3)[0], [Span(2, 2)])
        under = answer(L2_2="0.504", none="0.496")
        self.assertEqual(mass_gate_runs(under, options, Decimal("0.5"), H2, 3)[0], [])

    def test_runs_ranked_and_limited_by_beam(self):
        options = {s.id: s for s in contiguous_candidates(Span(1, 10))}
        probs = dict.fromkeys(list(options) + ["none", "unlocalized"], Decimal(0))
        probs.update({"L1-9": Decimal("0.55"), "L2-2": Decimal("0.2"), "L8-8": Decimal("0.25")})
        answer = {"type": "choice", "choice": "L1-9", "confidence": Decimal("0.4"),
                  "probabilities": probs}
        runs, qualifying, _ = mass_gate_runs(answer, options, Decimal("0.5"), H2, 3)
        # Lines 1-9 all carry 0.545 (line 2: 0.74, line 8: 0.79): one run.
        self.assertEqual((runs, qualifying), ([Span(1, 9)], 1))
        runs, qualifying, _ = mass_gate_runs(answer, options, Decimal("0.7"), H2, 1)
        self.assertEqual((runs, qualifying), ([Span(8, 8)], 2))
        runs, _, _ = mass_gate_runs(answer, options, Decimal("0.7"), H2, 3)
        self.assertEqual(runs, [Span(8, 8), Span(2, 2)])

    def test_half_quantum_precedence(self):
        answer = {"confidence": Decimal("0.5"),
                  "probabilities": {"a": Decimal("0.125"), "b": Decimal("0.875")}}
        self.assertEqual(search_for(Gateway(3, 2)).gate_half_quantum(answer), half_quantum(3))
        self.assertEqual(search_for(Gateway(None, 2)).gate_half_quantum(answer), half_quantum(2))
        self.assertEqual(search_for(Gateway()).gate_half_quantum(answer), half_quantum(3))

    def test_engine_mass_gate_localizes_diffuse_menu(self):
        legacy = scan(source(24), Diffuse([(5, 5)]),
                      Config(whole_file=False, choice_gate="legacy"))
        provider = Diffuse([(5, 5)])
        mass = scan(source(24), provider, Config(whole_file=False, choice_gate="mass"))
        legacy_events = [e for e in legacy["events"] if e["phase"] == "localize"]
        mass_events = [e for e in mass["events"] if e["phase"] == "localize"]
        self.assertTrue(legacy_events)
        self.assertNotIn("gate", legacy_events[0])
        first = mass_events[0]
        self.assertEqual((first["target"], first["choice"], first["gate"]),
                         ("L1-12", "unlocalized", "mass"))
        self.assertEqual(first["mass_selected"], ["L5-6"])
        self.assertEqual(first["hidden_mass"], "0.2")
        self.assertIn([5, 6], [r["target"] for r in mass["rechecks"]])
        self.assertNotIn([5, 6], [r["target"] for r in legacy["rechecks"]])
        # One menu per target under the mass gate: no shrunken re-ask.
        self.assertEqual(len([e for e in mass_events if e["target"] == "L1-12"]), 1)
        self.assertEqual(mass["configuration"]["choice_gate"], "mass")

    def test_mass_gate_ignored_under_scoped_policy(self):
        base = Diffuse([(5, 5)])
        legacy = scan(source(24), base, Config(whole_file=False, search_policy="scoped-v2-beta",
                                               choice_gate="legacy"))
        gated = Diffuse([(5, 5)])
        result = scan(source(24), gated, Config(whole_file=False, search_policy="scoped-v2-beta",
                                               choice_gate="mass"))
        self.assertEqual(gated.requests, base.requests)
        self.assertFalse(any("gate" in e for e in result["events"]))
        # The default gate is mass: scoped requests and findings equal the
        # legacy gate's; only the recorded configuration differs.
        default = Diffuse([(5, 5)])
        defaulted = scan(source(24), default,
                         Config(whole_file=False, search_policy="scoped-v2-beta"))
        self.assertEqual(default.requests, base.requests)
        self.assertEqual(defaulted["findings"], legacy["findings"])
        self.assertEqual(defaulted["configuration"]["choice_gate"], "mass")
        self.assertNotIn("choice_gate", legacy["configuration"])


class MenuTests(unittest.TestCase):
    def test_singleton_menu_k_le_22(self):
        pack, _ = load_pack()
        for size in range(1, 21):
            with self.subTest(size):
                singles = singleton_candidates(Span(3, 2 + size))
                self.assertEqual(singles, [Span(i, i) for i in range(3, 3 + size)])
        with self.assertRaises(ValueError):
            singleton_candidates(Span(1, 21))
        search = search_for(Gateway(), lines=40, localization_menu="singletons")
        options, menu = search.localization_menu(Span(1, 20))
        self.assertEqual((len(options) + 2, menu), (22, "singletons"))
        self.assertEqual(search_for(Gateway(), lines=40).localization_menu(Span(1, 20))[1],
                         "intervals")

    def test_engine_singleton_menu_scan(self):
        provider = FixtureProvider([(5, 5)])
        result = scan(source(30), provider, Config(whole_file=False,
                                                   localization_menu="singletons"))
        wheres = [r["questions"]["where"] for r in provider.requests
                  if "where" in r["questions"]]
        self.assertTrue(wheres)
        for where in wheres:
            ids = [k for k in where["criteria"] if k not in ("none", "unlocalized")]
            self.assertLessEqual(len(where["criteria"]), 22)
            self.assertTrue(all(k.split("-")[0][1:] == k.split("-")[1] for k in ids))
        self.assertIn((5, 5), {(f["start_line"], f["end_line"]) for f in result["findings"]})
        events = [e for e in result["events"] if e["phase"] == "localize"]
        self.assertTrue(all(e["menu"] == "singletons" for e in events))

    def test_scoped_singleton_recovery_uses_target_subdivision(self):
        provider = Diffuse([(5, 5)])
        result = scan(source(24), provider, Config(whole_file=False, search_policy="scoped-v2-beta",
                                                   localization_menu="singletons"))
        wheres = [r["questions"]["where"] for r in provider.requests if "where" in r["questions"]]
        self.assertTrue(wheres)
        self.assertTrue(all(len(w["criteria"]) <= 22 for w in wheres))
        self.assertEqual(result["configuration"]["localization_menu"], "singletons")


class RoundingCapTests(unittest.TestCase):
    def test_option_cap_values(self):
        self.assertEqual([choice_option_cap(n) for n in (2, 3, 8)], [25, 250, 25000000])
        self.assertIsNone(search_for(Gateway(2), choice_rounding_caps=False).option_cap())
        self.assertIsNone(search_for(Gateway(None), choice_rounding_caps=True).option_cap())
        self.assertEqual(search_for(Gateway(2), choice_rounding_caps=True).option_cap(), 25)

    def test_rank_page_cap_when_rounding_set(self):
        def rank_sizes(**options):
            provider = FixtureProvider([(5, 5)])
            scan(source(48), provider, Config(whole_file=False, min_width=3, **options))
            return [len(q["criteria"]) for r in provider.requests
                    for qid, q in r["questions"].items() if qid.startswith("rank_")]
        uncapped = rank_sizes()
        capped = rank_sizes(choice_rounding_caps=True)
        self.assertGreater(max(uncapped), 25)
        self.assertLessEqual(max(capped), 25)
        self.assertEqual(sum(n - 2 for n in capped), sum(n - 2 for n in uncapped))
        pack, _ = load_pack()
        targets = [Span(1, i) for i in range(1, 60)]
        pages = [q for qid, q in screening(pack, Span(1, 60), targets, bug_lenses=False,
                                           max_page=23).items() if qid.startswith("rank_")]
        self.assertEqual([len(q["criteria"]) for q in pages], [25, 25, 15])
        with self.assertRaises(ValueError):
            screening(pack, Span(1, 60), targets, max_page=201)

    def test_interval_menu_over_cap_falls_back_to_singletons(self):
        capped = search_for(Gateway(2), lines=40, choice_rounding_caps=True)
        self.assertEqual(capped.localization_menu(Span(1, 12))[1], "singletons-capped")
        self.assertEqual(capped.localization_menu(Span(1, 6))[1], "intervals")  # 21 + 2 <= 25
        wide = search_for(Gateway(3), lines=40, choice_rounding_caps=True)
        self.assertEqual(wide.localization_menu(Span(1, 20))[1], "intervals")  # 212 <= 250
        provider = FixtureProvider([(5, 5)])
        result = scan(source(30), provider, Config(whole_file=False, choice_rounding_caps=True))
        events = [e for e in result["events"] if e["phase"] == "localize"]
        self.assertTrue(events)
        self.assertTrue(all(e["menu"] == "singletons-capped" for e in events))
        for r in provider.requests:
            for q in r["questions"].values():
                if q["type"] == "choice":
                    self.assertLessEqual(len(q["criteria"]) * H2, Fraction(1, 8))

    def test_context_picker_capped(self):
        def picker_sizes(**options):
            provider = FixtureProvider([(30, 30)], need_packet=200)
            scan(source(240, text="x"), provider,
                 Config(whole_file=False, width=12, min_width=12, max_depth=0,
                        max_context_packets=40, **options))
            return [len(r["questions"]["context_where"]["criteria"])
                    for r in provider.requests if "context_where" in r["questions"]]
        uncapped, capped = picker_sizes(), picker_sizes(choice_rounding_caps=True)
        self.assertGreater(max(uncapped), 25)
        self.assertLessEqual(max(capped), 25)
        self.assertEqual(sum(n - 2 for n in capped), sum(n - 2 for n in uncapped))

    def test_diffuse_flag_k0_correction(self):
        def answer(values):
            probs = {f"o{i}": Decimal(v) for i, v in enumerate(values)}
            return {"type": "choice", "choice": "o0", "confidence": Decimal("0.5"),
                    "probabilities": probs}
        # 20 options shown as 0 may each hide up to h = 0.005: a missing 0.09
        # is explained by k0 * h = 0.10 and is not diffuse.
        self.assertFalse(choice_mass_diffuse(answer(["0.91"] + ["0"] * 20), 2))
        # Without the k0 correction the same deficit would exceed 4h*sqrt(1/3).
        self.assertTrue(choice_mass_diffuse(answer(["0.91"]), 2))
        # Positive options allow 4h * sqrt(k+/3): k+ = 3 allows 0.02.
        self.assertFalse(choice_mass_diffuse(answer(["0.5", "0.3", "0.18"]), 2))
        self.assertTrue(choice_mass_diffuse(answer(["0.5", "0.3", "0.179"]), 3))
        self.assertFalse(choice_mass_diffuse(answer(["0.5", "0.5"]), 2))

    def test_diffuse_counted_only_under_caps(self):
        def run(**options):
            provider = Diffuse([(5, 5)])
            return scan(source(24), provider, Config(whole_file=False, **options))
        plain = run()
        self.assertNotIn("choice_mass_diffuse", plain["judge_diagnostics"])
        self.assertFalse(any("choice_mass_diffuse" in r for r in plain["requests"]))
        capped = run(choice_rounding_caps=True)
        self.assertEqual(capped["judge_diagnostics"]["choice_mass_diffuse"], 0)
        rows = [r for r in capped["requests"] if r["status"] == "validated"]
        self.assertTrue(rows)
        self.assertTrue(all(r["choice_mass_diffuse"] == [] for r in rows))


if __name__ == "__main__":
    unittest.main()
