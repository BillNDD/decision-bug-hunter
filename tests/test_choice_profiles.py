"""Local limitation vocabulary, explicit profiles and validator parity."""
import unittest

from decision_bug_hunter import handoff
from decision_bug_hunter.__main__ import parser


class TestLimitationVocabulary(unittest.TestCase):
    def test_response_distribution_has_precise_label(self):
        self.assertEqual(handoff.LIMITS["response_distribution"],
                         "choice-distribution-invalid")

    def test_generic_fallback_is_not_used_for_distributions(self):
        self.assertNotEqual(
            handoff.LIMITS.get("response_distribution", "evaluation-failed"),
            "evaluation-failed")


class TestChoiceProfileDefault(unittest.TestCase):
    def test_default_rounding_profile_is_strict(self):
        args = parser().parse_args(["x.py"])
        self.assertIsNone(args.choice_rounding_places)
        self.assertFalse(args.strict_choice_mass)

    def test_strict_flag_selects_exact_mass(self):
        args = parser().parse_args(["x.py", "--strict-choice-mass"])
        self.assertTrue(args.strict_choice_mass)

    def test_explicit_places_kept(self):
        args = parser().parse_args(["x.py", "--choice-rounding-places", "3"])
        self.assertEqual(args.choice_rounding_places, 3)


class GatewayParityTests(unittest.TestCase):
    """Object and local JSON fixture validation enforce the same rules."""

    def question(self):
        return {"type": "choice", "instructions": "Pick.", "criteria":
                {"a": "option a", "b": "option b"}}

    def codes(self, answer, places=None):
        import json as _json
        from decision_bug_hunter.protocol import (CONTRACT_VERSION, ProviderError, validate_answer_objects,
                                    validate_answers)
        questions = {"q": self.question()}
        raw = _json.dumps({"contract": CONTRACT_VERSION, "answers": {"q": answer},
                           "usage": {"input_tokens": 1, "output_tokens": 1}}
                          ).encode("utf-8")
        out = []
        for fn in (lambda: validate_answers(raw, questions, "", places),
                   lambda: validate_answer_objects({"q": answer}, questions,
                                                   places)):
            try:
                fn()
                out.append("accepted")
            except ProviderError as exc:
                out.append(exc.code)
        return out

    def test_object_and_local_json_validation_are_identical(self):
        cases = {
            "argmax_mismatch": {"type": "choice", "choice": "a",
                                "probabilities": {"a": 0.6, "b": 0.9},
                                "confidence": 1},
            "mass_1_80": {"type": "choice", "choice": "a",
                          "probabilities": {"a": 0.9, "b": 0.9},
                          "confidence": 1},
            "missing_option": {"type": "choice", "choice": "a",
                               "probabilities": {"a": 0.5},
                               "confidence": 1},
            "out_of_range": {"type": "choice", "choice": "a",
                             "probabilities": {"a": 1.5, "b": 0.0},
                             "confidence": 1},
            "choice_not_in_criteria": {"type": "choice", "choice": "z",
                                       "probabilities": {"a": 1, "b": 0},
                                       "confidence": 1},
        }
        for label, answer in cases.items():
            with self.subTest(case=label):
                local_json, objects = self.codes(answer)
                self.assertNotEqual(local_json, "accepted")
                self.assertEqual(local_json, objects)

    def test_valid_profiles_accepted_by_both_paths(self):
        for places in (None, 2):
            with self.subTest(places=places):
                local_json, objects = self.codes(
                    {"type": "choice", "choice": "b",
                     "probabilities": {"a": 0.4, "b": 0.6},
                     "confidence": 1}, places)
                self.assertEqual(local_json, "accepted")
                self.assertEqual(objects, "accepted")


if __name__ == "__main__":
    unittest.main()
