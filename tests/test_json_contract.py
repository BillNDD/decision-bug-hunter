"""Exact local JSON validation; no service schema is asserted."""
from decimal import Decimal
import json
import unittest
from decision_bug_hunter import protocol

KEY = "offline-sentinel-credential-9e91"
STATE = {"file": "example.txt", "context": {"text": "sample"}}

def response(token="0.82", **extra):
    data = {"contract": protocol.CONTRACT_VERSION,
            "answers": {"q": {"type": "noul", "noul": 0}},
            "usage": {"input_tokens": 100, "output_tokens": 1}}
    data.update(extra)
    return json.dumps(data).replace('"noul": 0', '"noul": ' + token).encode()

class JsonContractTests(unittest.TestCase):
    def assert_code(self, code, function, *args):
        with self.assertRaises(protocol.ProviderError) as caught:
            function(*args)
        self.assertEqual(caught.exception.code, code)
        self.assertIsNone(caught.exception.__cause__)
        self.assertIsNone(caught.exception.__context__)

    def test_fixed_envelope_and_byte_budget(self):
        wire = protocol.encode_request(STATE)
        body = json.loads(wire)
        self.assertEqual(set(body), {"contract", "state", "questions"})
        self.assertEqual(body["contract"], "dbh-judge-v1")
        self.assertEqual(body["questions"], {"q": protocol.QUESTION})
        self.assertEqual(body["state"], STATE)
        self.assertNotIn(b'\n', wire)
        self.assert_code("request_too_large", protocol.encode_request,
                         {"text": "\u6f22" * 6000})

    def test_non_json_and_nonfinite_request_rejected(self):
        circular = []
        circular.append(circular)
        cases = [[], {"bad": float("nan")}, {"bad": {1, 2}},
                 {1: "not a JSON key"}, {"bad": "\ud800"}, {"bad": circular}]
        for case in cases:
            with self.subTest(case=type(case)):
                self.assert_code("invalid_request", protocol.encode_request, case)

    def test_integer_decimal_and_threshold_tokens_remain_exact(self):
        for token in ("0", "1", "1.0", "0.59999999999999999999", "1e-400"):
            score, usage = protocol.validate_response(response(token))
            self.assertIs(type(score), Decimal)
            self.assertEqual(score, Decimal(token))
            self.assertEqual(usage["input_tokens"], 100)
        below, _ = protocol.validate_response(response("0.59999999999999999999"))
        self.assertLess(below, Decimal("0.60"))

    def test_invalid_probability_tokens_rejected(self):
        for token in ("true", "false", "null", '"0.82"', "[]", "{}",
                      "-1e-400", "1.00000000000000000001", "2", "-1",
                      "1e-1001", "0." + "1" * 128):
            with self.subTest(token=token[:32]):
                self.assert_code("response_probability", protocol.validate_response,
                                 response(token))
        for token in ("NaN", "Infinity", "-Infinity"):
            self.assert_code("response_invalid_json", protocol.validate_response,
                             response(token))

    def test_strict_diagnostics(self):
        protocol.validate_response(response(diagnostics={}))
        protocol.validate_response(response(diagnostics={k: False for k in protocol.DIAGNOSTICS}))
        for name in protocol.DIAGNOSTICS:
            self.assert_code("response_truncated", protocol.validate_response,
                             response(diagnostics={name: True}))
            for value in (1, "true", None, [], {}):
                self.assert_code("response_schema", protocol.validate_response,
                                 response(diagnostics={name: value}))
        self.assert_code("response_schema", protocol.validate_response,
                         response(diagnostics={"future_truncation": False}))

    def test_schema_contract_and_usage_changes_rejected(self):
        for contract in ("dbh-judge-v2", "dbh-latest", "dbh-judge-\u0661", 1):
            self.assert_code("response_model", protocol.validate_response,
                             response(contract=contract))
        for usage in ({"input_tokens": True, "output_tokens": 1},
                      {"input_tokens": -1, "output_tokens": 1},
                      {"input_tokens": 1.0, "output_tokens": 1},
                      {"input_tokens": 1, "output_tokens": 1, "total_tokens": 2}):
            self.assert_code("response_usage", protocol.validate_response,
                             response(usage=usage))
        for answers in ({}, {"another": {"type": "noul", "noul": 1}},
                        {"q": {"type": "choice", "choice": "yes"}},
                        {"q": {"type": "noul", "noul": 1, "why": "text"}}):
            self.assert_code("response_schema", protocol.validate_response,
                             response(answers=answers))
        self.assert_code("response_schema", protocol.validate_response,
                         response(new_envelope_field=1))

    def test_malformed_duplicate_and_sensitive_responses_do_not_chain(self):
        for raw in (b'{"secret":', b'\xff', b'{}{}', b'{"x":1,"x":2}'):
            self.assert_code("response_invalid_json", protocol.validate_response, raw)
        raw = response(diagnostics={"unexpected": KEY})
        self.assert_code("response_sensitive", protocol.validate_response, raw, KEY)
        escaped = raw.replace(KEY.encode(), rb'\u006f' + KEY[1:].encode())
        self.assert_code("response_sensitive", protocol.validate_response, escaped, KEY)
        self.assert_code("response_too_large", protocol.validate_response,
                         b" " * (protocol.MAX_RESPONSE_BYTES + 1))
