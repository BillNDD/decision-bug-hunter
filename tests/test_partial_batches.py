"""Answer-level defects and partial batches (ADR-3, ADR-4(2) and (4), ADR-7(1)).

Offline only: a scripted provider behind the real ValidatedGateway, or
scripted sockets behind the real OpenRouter adapter. Passing these
establishes local accounting of refusals and malformed answers; it says
nothing about how often the live judge refuses.
"""
from decimal import Decimal
import json
import math
from pathlib import Path
import tempfile
import unittest

from decision_bug_hunter import engine as engine_module
from decision_bug_hunter import openrouter
from decision_bug_hunter.core import Config, Source, Span
from decision_bug_hunter.engine import (Search, clopper_pearson,
                                        confidence_identity_violation)
from decision_bug_hunter.hosted import ModelSpec
from decision_bug_hunter.openrouter import OpenRouterProvider
from decision_bug_hunter.protocol import (ANSWER_SCOPED_CODES, ERROR_CODES, QUESTION,
                                          ProviderError, validate_answer_objects,
                                          validate_answer_objects_scoped)
from decision_bug_hunter.providers import (ProviderIdentity, ProviderResponse, RetryPolicy,
                                           ValidatedGateway)
from tests.fakes import FakeClock, Reply, ScriptedHTTPS
from tests.support import FixtureProvider, openrouter_body, spans_in

KEY = "offline-partial-batch-sentinel-credential-7c2e"
CHOICE = {"type": "choice", "instructions": "Which interval is strongest?",
          "criteria": {"L1-1": "lines 1 through 1", "L2-2": "lines 2 through 2",
                       "none": "No supported suspicion."}}
GOOD_CHOICE = {"type": "choice", "choice": "L1-1", "confidence": Decimal("0.85"),
               "probabilities": {"L1-1": Decimal("0.9"), "L2-2": Decimal("0.05"),
                                 "none": Decimal("0.05")}}
NOUL = {"type": "noul", "noul": Decimal("0.4")}
LUNA = ModelSpec("offline-luna", price_in_per_mtok=Decimal("0.10"),
                 price_out_upper_per_mtok=Decimal("0"),
                 confidence_identity="chance_normalized_p1")


def nouls(count):
    return {f"q{i:02d}": QUESTION for i in range(count)}


class DefectProvider:
    """A DecisionProvider answering from the fixture, then applying defects.

    ``refuse(qid)`` marks questions the provider declines; ``mutate(answers,
    scoped, questions)`` may corrupt answers or add adapter-scoped defects.
    ``spec`` is exposed as ``model_spec`` (the confidence identity).
    """

    identity = ProviderIdentity("offline-defects", synthetic=True)

    def __init__(self, bugs=(), *, refuse=None, mutate=None, spec=None):
        self.fixture = FixtureProvider(bugs)
        self.refuse = refuse
        self.mutate = mutate
        self.requests = []
        if spec is not None:
            self.model_spec = spec

    def require_available(self):
        return None

    def check_sensitive(self, *values):
        return None

    def decide(self, request):
        data = json.loads(request.payload)
        self.requests.append(data)
        questions = data["questions"]
        answers, scoped = {}, {}
        for qid, q in questions.items():
            if self.refuse is not None and self.refuse(qid):
                scoped[qid] = "question_refused"
            elif spans_in(q["instructions"]):
                answers[qid] = self.fixture.answer(qid, q, data["state"])
            else:
                answers[qid] = (dict(NOUL) if q["type"] == "noul" else
                                {"type": "choice", "choice": next(iter(q["criteria"])),
                                 "confidence": 1,
                                 "probabilities": {k: int(i == 0) for i, k in
                                                   enumerate(q["criteria"])}})
        if self.mutate is not None:
            self.mutate(answers, scoped, questions)
        return ProviderResponse(answers, {"input_tokens": 10, "output_tokens": 0},
                                scoped=scoped)

    def close(self):
        return None


class Base(unittest.TestCase):
    def gateway(self, provider, **kwargs):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        kwargs.setdefault("retry_policy", RetryPolicy.none())
        gateway = ValidatedGateway(provider, Path(tmp.name) / "receipts", **kwargs)
        self.addCleanup(gateway.close)
        return gateway

    def search(self, provider, lines=3, **config):
        source = Source.from_text("\n".join(f"line {i}" for i in range(1, lines + 1)),
                                  "a.txt")
        gateway = provider if not hasattr(provider, "decide") else self.gateway(provider)
        return Search(source, gateway, Config(**config), None,
                      context_scope="declared_standalone")

    def receipt(self, gateway):
        return json.loads(Path(gateway.last_receipt).read_text(encoding="utf-8"))


class ScopedValidatorTests(unittest.TestCase):
    def test_codes_registered(self):
        self.assertEqual(ANSWER_SCOPED_CODES, {"question_refused", "response_vector_missing",
                                               "response_distribution",
                                               "choice_argmax_mismatch"})
        self.assertLessEqual(ANSWER_SCOPED_CODES, ERROR_CODES)
        self.assertEqual(ProviderError("question_refused").code, "question_refused")

    def test_scoped_validator_partial_and_atomic_unchanged(self):
        questions = {"a": QUESTION, "where": CHOICE, "b": QUESTION}
        bad_mass = {**GOOD_CHOICE, "probabilities": {"L1-1": Decimal("0.9"),
                                                     "L2-2": Decimal("0.2"),
                                                     "none": Decimal("0")}}
        answers, defects = validate_answer_objects_scoped(
            {"a": NOUL, "where": bad_mass, "b": NOUL}, questions)
        self.assertEqual(set(answers), {"a", "b"})
        self.assertEqual(defects, {"where": "response_distribution"})
        with self.assertRaises(ProviderError) as caught:
            validate_answer_objects({"a": NOUL, "where": bad_mass, "b": NOUL}, questions)
        self.assertEqual(caught.exception.code, "response_distribution")
        # A refusal reported by the adapter: exactly the other names remain.
        answers, defects = validate_answer_objects_scoped(
            {"a": NOUL, "where": GOOD_CHOICE}, questions, None, {"b": "question_refused"})
        self.assertEqual((set(answers), defects), ({"a", "where"}, {"b": "question_refused"}))
        answers, defects = validate_answer_objects_scoped(
            {"a": NOUL, "where": GOOD_CHOICE}, questions, None, ["b"])
        self.assertEqual(defects, {"b": "question_refused"})

    def test_scoped_validator_batch_level_cases(self):
        questions = {"a": QUESTION, "where": CHOICE}
        cases = [
            (({"a": NOUL}, {}), "response_schema"),                       # missing name
            (({"a": NOUL, "where": GOOD_CHOICE, "x": NOUL}, {}), "response_schema"),
            (({"a": NOUL, "where": GOOD_CHOICE}, {"a": "question_refused"}),
             "response_schema"),                                          # refused yet answered
            (({}, {"a": "question_refused", "where": "question_refused"}),
             "response_refused"),                                         # refusal cap
            (({"where": GOOD_CHOICE}, {"a": "response_vector_missing"}),
             "response_schema"),                                          # vector on a noul
            (({"where": GOOD_CHOICE}, {"a": "response_distribution"}),
             "response_schema"),                                          # not an adapter code
            (({"a": NOUL, "where": GOOD_CHOICE}, {"zz": "question_refused"}),
             "response_schema"),
            (({"a": {**NOUL, "extra": 1}, "where": GOOD_CHOICE}, {}), "response_schema"),
            (({"a": {"type": "choice"}, "where": GOOD_CHOICE}, {}), "response_schema"),
            (({"a": {**NOUL, "noul": 1.5}, "where": GOOD_CHOICE}, {}), "response_probability"),
            (({"a": {**NOUL, "noul": float("nan")}, "where": GOOD_CHOICE}, {}),
             "response_probability"),
            (({"a": NOUL, "where": {**GOOD_CHOICE, "choice": 3}}, {}), "response_schema"),
            (({"a": NOUL, "where": {**GOOD_CHOICE, "probabilities": [1]}}, {}),
             "response_schema"),
            (({"a": NOUL, "where": {**GOOD_CHOICE, "confidence": 2}}, {}),
             "response_probability"),
            # Out-of-range values stay batch-level even with wrong keys.
            (({"a": NOUL, "where": {**GOOD_CHOICE, "probabilities": {"L1-1": 7}}}, {}),
             "response_probability"),
            (({"a": NOUL, "where": GOOD_CHOICE}, "a"), "response_schema"),
        ]
        for (answers, scoped), code in cases:
            with self.subTest(code=code, answers=answers, scoped=scoped):
                with self.assertRaises(ProviderError) as caught:
                    validate_answer_objects_scoped(answers, questions, None, scoped)
                self.assertEqual(caught.exception.code, code)


class RefusalTests(Base):
    def test_refusal_accepts_rest_of_batch_one_http_call(self):
        # The acceptance case: 1 refusal among 17 answers through the real
        # OpenRouter adapter gives 16 judgments, 1 limitation and 1 call.
        questions = nouls(17)
        answers = {qid: {"type": "noul", "noul": Decimal("0.3")} for qid in questions}
        body = json.loads(openrouter_body(answers))
        body["answers"]["q07"] = {"type": "refusal"}
        raw = json.dumps(body).encode()
        script = ScriptedHTTPS([Reply(status=200, body=raw, headers=[
            ("Content-Type", "application/json"), ("Content-Length", str(len(raw)))])],
            clock=FakeClock(), host=openrouter.HOST)
        provider = OpenRouterProvider(KEY, environ={},
                                      exchange=script.exchange(openrouter.HOST,
                                                               openrouter.PATH))
        search = self.search(provider)
        result = search.ask({"file": "a.txt", "total_lines": 3, "excerpts": []}, questions,
                            Span(1, 3), "test")
        self.assertEqual(len(result), 16)
        self.assertNotIn("q07", result)
        self.assertEqual(len(script.requests), 1)
        self.assertEqual((search.calls, search.validated_questions), (1, 16))
        self.assertEqual(search.issues, [{"code": "question_refused", "range": [1, 3],
                                          "phase": "test", "affects_completion": True}])
        self.assertEqual(search.trace[0]["status"], "validated_partial")
        self.assertEqual(search.trace[0]["scoped"], {"q07": "question_refused"})
        self.assertEqual(search.failed_requests, {})
        receipt = self.receipt(search.gw)
        self.assertEqual((receipt["status"], receipt["scoped"]),
                         ("validated_partial", {"q07": "question_refused"}))
        quality = search.answer_quality()
        self.assertEqual(quality["refusals"]["refused"], 1)
        self.assertEqual(quality["refusals"]["answers"], 17)
        self.assertEqual(quality["answer_defects"]["by_code"], {"question_refused": 1})

    def test_refusal_never_reasked_on_cache_hit(self):
        provider = DefectProvider(refuse=lambda qid: qid == "b")
        search = self.search(provider)
        state = {"file": "a.txt", "total_lines": 3, "excerpts": []}
        first = search.ask(state, {"a": QUESTION, "b": QUESTION}, Span(1, 3), "one")
        again = search.ask(state, {"a": QUESTION, "b": QUESTION}, Span(2, 3), "two")
        self.assertEqual(set(first), {"a"})
        self.assertEqual(again, first)
        self.assertEqual(len(provider.requests), 1)
        self.assertEqual(search.cache_hits, 1)
        self.assertEqual([(i["code"], i["range"], i["phase"]) for i in search.issues],
                         [("question_refused", [1, 3], "one"),
                          ("question_refused", [2, 3], "two")])
        phases = [e["phase"] for e in search.events]
        self.assertEqual(phases, ["judgment_reuse"])
        # Counted once: the cache hit is not a second answer.
        self.assertEqual(search.answer_defects, {"question_refused": 1})

    def test_two_refusals_whole_batch(self):
        provider = DefectProvider(refuse=lambda qid: qid in {"a", "b"})
        search = self.search(provider)
        state = {"file": "a.txt", "total_lines": 3, "excerpts": []}
        result = search.ask(state, {"a": QUESTION, "b": QUESTION, "c": QUESTION},
                            Span(1, 3), "t")
        self.assertEqual(result, {})
        self.assertEqual([i["code"] for i in search.issues], ["response_refused"])
        (pin,) = search.failed_requests.values()
        self.assertEqual(pin, {"code": "response_refused", "permanent": True})
        receipt = self.receipt(search.gw)
        self.assertEqual((receipt["status"], receipt["error"], receipt["scoped"]),
                         ("failed", "response_refused", None))

    def test_refused_screen_window_unreviewed(self):
        refused = "screen_L1-3"
        provider = DefectProvider(refuse=lambda qid: qid == refused)
        search = self.search(provider, lines=3, bug_lenses=False)
        result = search.run()
        (row,) = [o for o in result["windows"] if o["window_id"] == "L1-3"]
        self.assertEqual(row["status"], "unreviewed")
        self.assertIsNone(row["score"])
        refusals = [i for i in result["issues"] if i["code"] == "question_refused"]
        self.assertEqual(refusals, [{"code": "question_refused", "range": [1, 3],
                                     "phase": "screen", "affects_completion": True}])
        self.assertEqual(result["status"], "incomplete")
        self.assertEqual(result["refusals"]["refused"], 1)
        self.assertEqual(result["refusals"]["method"], "clopper-pearson")
        self.assertEqual(result["answer_defects"]["total"], 1)


class CoverageTests(Base):
    def test_lens_only_window_unreviewed(self):
        # The screen of L1-3 is refused; its lenses survive, keep their scores
        # and still route drilling, but the window is not reviewed.
        provider = DefectProvider(bugs=[(2, 2)], refuse=lambda qid: qid == "screen_L1-3")
        search = self.search(provider, lines=3)
        result = search.run()
        rows = [o for o in result["windows"] if o["window_id"] == "L1-3"
                and "screen" not in o["judgments"]]
        self.assertTrue(rows)
        for row in rows:
            self.assertEqual(row["status"], "unreviewed")
            self.assertEqual(row["score"], "0.95")
            self.assertTrue(set(row["judgments"]) <= set(engine_module.LENS_KINDS))
        self.assertIn(Span(1, 3), search.action_targets)
        self.assertFalse(result["coverage"]["all_lines_assessed"])
        # Unreviewed windows never count as assessed coverage.
        scored = [o for o in result["windows"] if o["status"] == "scored"]
        self.assertTrue(all("screen" in o["judgments"] for o in scored))
        self.assertEqual(result["status"], "incomplete")

    def test_custom_gateway_stays_atomic(self):
        class PartialGateway:
            """A custom gateway claiming a defect and returning a partial batch."""

            last_defects = {"b": "question_refused"}

            def evaluate(self, state, questions, *, metadata):
                return {"a": dict(NOUL)}

        search = self.search(PartialGateway())
        result = search.ask({"file": "a.txt", "total_lines": 3, "excerpts": []},
                            {"a": QUESTION, "b": QUESTION}, Span(1, 3), "t")
        self.assertEqual(result, {})
        self.assertEqual([i["code"] for i in search.issues], ["response_schema"])
        self.assertEqual(search.answer_defects, {})


class DistributionTests(Base):
    def test_mass_failure_scoped_to_answer(self):
        # Acceptance: a response_distribution on rank_0 keeps every noul.
        def break_rank(answers, scoped, questions):
            rank = answers["rank_0"]
            rank["probabilities"] = dict.fromkeys(rank["probabilities"], 0)
            rank["probabilities"][next(iter(rank["probabilities"]))] = 0.5
            rank["probabilities"]["none"] = 0.7
            rank["choice"] = "none"

        provider = DefectProvider(bugs=[(2, 2)], mutate=break_rank)
        search = self.search(provider, lines=3)
        group = search.view(Span(1, 3), [Span(1, 1), Span(2, 2), Span(3, 3)],
                            {}, search.state_for(Span(1, 3)), "initial")
        (sent,) = provider.requests
        nouls_sent = {qid for qid, q in sent["questions"].items() if q["type"] == "noul"}
        row = search.trace[0]
        self.assertEqual(row["status"], "validated_partial")
        self.assertEqual(row["scoped"], {"rank_0": "response_distribution"})
        self.assertEqual(set(row["answers"]), nouls_sent)
        self.assertEqual(group["scores"][Span(2, 2)], Decimal("0.95"))
        self.assertEqual(group["priority"], [])
        (issue,) = [i for i in search.issues if i["code"] == "response_distribution"]
        self.assertFalse(issue["affects_completion"])
        quality = search.answer_quality()
        self.assertEqual(quality["answer_defects"],
                         {"total": 1, "by_code": {"response_distribution": 1},
                          "choice_routing": 1})

    def test_argmax_mismatch_scoped_and_counted(self):
        def flip(answers, scoped, questions):
            answers["where"]["choice"] = "none"

        provider = DefectProvider(mutate=flip)
        search = self.search(provider)
        state = {"file": "a.txt", "total_lines": 3, "excerpts": []}
        result = search.ask(state, {"exists": QUESTION, "where": CHOICE}, Span(1, 3), "t")
        self.assertEqual(set(result), {"exists"})
        self.assertEqual(search.answer_defects, {"choice_argmax_mismatch": 1})
        self.assertEqual(search.choice_answers, 1)
        self.assertEqual(search.issues, [{"code": "choice_argmax_mismatch", "range": [1, 3],
                                          "phase": "t", "affects_completion": False}])
        self.assertEqual(search.answer_quality()["banners"], [])
        # The banner needs a rate above 2% of at least 50 choice answers.
        for count, mismatches, banner in ((50, 1, False), (50, 2, True), (49, 49, False),
                                          (100, 3, True)):
            with self.subTest(count=count, mismatches=mismatches):
                search.choice_answers = count
                search.answer_defects = {"choice_argmax_mismatch": mismatches}
                self.assertEqual("judge_inconsistent" in search.answer_quality()["banners"],
                                 banner)

    def test_vector_missing_scoped(self):
        def drop_vector(answers, scoped, questions):
            del answers["where"]
            scoped["where"] = "response_vector_missing"

        provider = DefectProvider(mutate=drop_vector)
        search = self.search(provider)
        state = {"file": "a.txt", "total_lines": 3, "excerpts": []}
        result = search.ask(state, {"exists": QUESTION, "where": CHOICE}, Span(1, 3), "t")
        self.assertEqual(set(result), {"exists"})
        self.assertEqual(search.issues, [{"code": "response_vector_missing",
                                          "range": [1, 3], "phase": "t",
                                          "affects_completion": False}])
        self.assertEqual(search.answer_quality()["answer_defects"]["choice_routing"], 1)
        self.assertEqual(self.receipt(search.gw)["scoped"],
                         {"where": "response_vector_missing"})

    def test_scoped_defects_never_trip_breaker(self):
        def flip(answers, scoped, questions):
            answers["where"]["choice"] = "none"

        provider = DefectProvider(refuse=lambda qid: qid == "b", mutate=flip)
        gateway = self.gateway(provider)
        for sequence in range(1, 8):
            answers = gateway.evaluate({"file": "a.txt", "n": sequence},
                                       {"a": QUESTION, "b": QUESTION, "where": CHOICE},
                                       metadata={"sequence": sequence, "phase": "t"})
            self.assertEqual(set(answers), {"a"})
            self.assertEqual(gateway.last_defects, {"b": "question_refused",
                                                    "where": "choice_argmax_mismatch"})
        self.assertIsNone(gateway.stop_reason)
        self.assertEqual(set(gateway.breaker.streaks.values()), {0})
        self.assertEqual(gateway.retries, 0)
        self.assertEqual(len(provider.requests), 7)


class SuppressionTests(Base):
    def test_possible_suppression_two_windows_or_supported_overlap(self):
        search = self.search(DefectProvider(), lines=10)
        quality = search.answer_quality()["possible_suppression"]
        self.assertEqual(quality, {"flagged": False, "windows": 0, "overlaps_support": False})
        search.suppressed = {(1, 2)}
        self.assertFalse(search.answer_quality()["possible_suppression"]["flagged"])
        search.support = {Span(2, 4): [{"origin": "screen"}]}
        self.assertEqual(search.answer_quality()["possible_suppression"],
                         {"flagged": True, "windows": 1, "overlaps_support": True})
        search.support = {Span(5, 6): [{"origin": "screen"}]}
        search.suppressed = {(1, 2), (8, 9)}
        self.assertEqual(search.answer_quality()["possible_suppression"],
                         {"flagged": True, "windows": 2, "overlaps_support": False})
        # Refused window questions and moderated requests both feed it.
        provider = DefectProvider(refuse=lambda qid: qid in {"screen_L1-1"})
        search = self.search(provider, lines=10)
        search.ask({"file": "a.txt", "total_lines": 10, "excerpts": []},
                   {"screen_L1-1": QUESTION, "screen_L3-3": QUESTION}, Span(1, 5), "t")
        self.assertEqual(search.suppressed, {(1, 1)})
        moderated = DefectProvider()
        moderated.decide = lambda request: (_ for _ in ()).throw(
            ProviderError("provider_moderated"))
        search2 = self.search(moderated, lines=10)
        search2.suppressed = {(1, 1)}
        search2.ask({"file": "a.txt", "total_lines": 10, "excerpts": []},
                    {"q": QUESTION}, Span(6, 9), "t")
        self.assertEqual(search2.suppressed, {(1, 1), (6, 9)})
        self.assertTrue(search2.answer_quality()["possible_suppression"]["flagged"])

    def test_clopper_pearson_interval(self):
        self.assertIsNone(clopper_pearson(0, 0))
        low, high = clopper_pearson(0, 10)
        self.assertEqual(low, 0.0)
        self.assertAlmostEqual(high, 1 - 0.025 ** (1 / 10), places=5)
        low, high = clopper_pearson(10, 10)
        self.assertAlmostEqual(low, 0.025 ** (1 / 10), places=5)
        self.assertEqual(high, 1.0)
        # Published value for 1 of 17: [0.0015, 0.2869].
        low, high = clopper_pearson(1, 17)
        self.assertAlmostEqual(low, 0.0015, places=4)
        self.assertAlmostEqual(high, 0.2869, places=4)
        # Symmetry, and a large n stays fast and finite.
        a, b = clopper_pearson(3, 40)
        c, d = clopper_pearson(37, 40)
        self.assertAlmostEqual(a, 1 - d, places=5)
        self.assertAlmostEqual(b, 1 - c, places=5)
        low, high = clopper_pearson(5000, 64000)
        self.assertTrue(0 < low < 5000 / 64000 < high < 1)
        self.assertTrue(all(math.isfinite(x) for x in (low, high)))
        with self.assertRaises(ValueError):
            clopper_pearson(3, 2)


class DiagnosticTests(Base):
    def test_confidence_identity_violation_counted(self):
        def answer(p1, confidence, k=2):
            rest = (Decimal(1) - Decimal(p1)) / (k - 1)
            probs = {f"o{i}": (Decimal(p1) if i == 0 else rest) for i in range(k)}
            return {"type": "choice", "choice": "o0", "probabilities": probs,
                    "confidence": Decimal(confidence)}

        # S10: p1 0.27 over 212 options displayed confidence 0.27.
        s10 = {"type": "choice", "choice": "o0", "confidence": Decimal("0.27"),
               "probabilities": {"o0": Decimal("0.27"), **{f"o{i}": Decimal("0")
                                                           for i in range(1, 212)}}}
        self.assertFalse(confidence_identity_violation(s10, 2))
        self.assertFalse(confidence_identity_violation(answer("1", "1"), 2))
        self.assertFalse(confidence_identity_violation(answer("0.9", "0.8"), 2))
        self.assertFalse(confidence_identity_violation(answer("0.9", "0.81"), 2))
        self.assertTrue(confidence_identity_violation(answer("0.9", "0.9"), 2))
        self.assertTrue(confidence_identity_violation(answer("0.95", "0.5"), 2))
        # Without a display precision, the answer's own places are used.
        self.assertTrue(confidence_identity_violation(answer("0.9", "0.85"), None))

        def skew(answers, scoped, questions):
            answers["where"].update(confidence=0.4)

        provider = DefectProvider(mutate=skew, spec=LUNA)
        search = self.search(provider)
        self.assertEqual(search.gw.confidence_identity, "chance_normalized_p1")
        self.assertEqual(search.gw.display_places, 2)
        for n in range(3):
            state = {"file": "a.txt", "total_lines": 3, "excerpts": [], "n": n}
            search.ask(state, {"where": CHOICE}, Span(1, 3), "t")
        quality = search.answer_quality()
        self.assertEqual(quality["judge_diagnostics"]["confidence_identity_checked"], 3)
        self.assertEqual(quality["judge_diagnostics"]["confidence_identity_violations"], 3)
        self.assertEqual(quality["banners"], ["judge_semantics_changed"])
        # A route without a known identity is never checked.
        search = self.search(DefectProvider(mutate=skew))
        search.ask({"file": "a.txt", "excerpts": []}, {"where": CHOICE}, Span(1, 3), "t")
        quality = search.answer_quality()["judge_diagnostics"]
        self.assertIsNone(quality["confidence_identity"])
        self.assertEqual(quality["confidence_identity_checked"], 0)

    def test_report_uncalibrated_object_and_support_paths(self):
        provider = DefectProvider(bugs=[(2, 2)])
        result = self.search(provider, lines=4).run()
        self.assertEqual(result["calibration"], {"status": "uncalibrated", "profile_id": None})
        self.assertTrue(result["findings"])
        for finding in result["findings"]:
            origins = sorted({row["origin"] for row in finding["support"]})
            self.assertEqual(finding["support_paths"], origins)
        self.assertIn("direct_recheck", result["findings"][0]["support_paths"])
        for field in ("answer_defects", "refusals", "possible_suppression",
                      "judge_diagnostics", "banners"):
            self.assertIn(field, result)
        self.assertEqual(result["banners"], [])
        json.dumps(result)


if __name__ == "__main__":
    unittest.main()
