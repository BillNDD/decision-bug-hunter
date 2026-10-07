"""Catalog runner scoring and summary (tools/eval), fully offline.

Only ``judge`` and ``summarize`` are exercised, on hand-built reports; the
CLI is never run and nothing touches the network. Skips when tools/eval is
absent, as in an sdist that prunes it.
"""
from contextlib import redirect_stdout
import importlib
import io
import json
from pathlib import Path
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
EVAL = ROOT / "tools" / "eval"


def tool(name):
    if str(EVAL) not in sys.path:
        sys.path.insert(0, str(EVAL))
    return importlib.import_module(name)


def report(*, spend=None, findings=(), status="complete", usage=None):
    """A minimal b1-shaped report with the fields judge() reads."""
    return {"status": status, "calls_attempted": 3, "provider": "openrouter",
            "model": "openai/gpt-6-luna-decisions",
            "usage": usage if usage is not None else {"input_tokens": 1200, "output_tokens": 0},
            "spend": spend, "issues": [],
            "handoff": {"findings": [{"suspect": list(span)} for span in findings]}}


@unittest.skipUnless(EVAL.is_dir(), "tools/eval absent")
class CatalogSpendTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.run_catalog = tool("run_catalog")
        cases = {case["id"]: case for case in tool("catalog").cases()}
        cls.defect, cls.clear = cases["C001"], cases["C002"]

    def test_judge_records_provider_reported_usd(self):
        judge = self.run_catalog.judge
        row = judge(self.clear, report(spend={"provider_reported_usd": "0.000846",
                                              "estimated_usd": "0.0009"}), 0)
        self.assertEqual(row["provider_reported_usd"], "0.000846")
        self.assertTrue(row["location_pass"])
        for spend in (None, {}, {"provider_reported_usd": None},
                      {"provider_reported_usd": 0.0008}, {"provider_reported_usd": "1e-4"},
                      {"provider_reported_usd": "-0.1"}, "0.1"):
            self.assertIsNone(judge(self.clear, report(spend=spend), 0)["provider_reported_usd"],
                              spend)
        self.assertIsNone(judge(self.clear, None, 2)["provider_reported_usd"])

    def test_summary_sums_provider_reported_cost_not_usage(self):
        judge = self.run_catalog.judge
        rows = []
        for case, rep, code in (
                (self.defect, report(spend={"provider_reported_usd": "0.0123"},
                                     findings=[(1, 2)]), 1),
                (self.clear, report(spend={"provider_reported_usd": "0.0323"},
                                    usage={"input_tokens": 10, "output_tokens": 0,
                                           "cost_usd": 9.5}), 0),
                (self.clear, report(spend=None, usage={"input_tokens": 5, "cost_usd": 7}), 0)):
            row = judge(case, rep, code)
            row.update(id=case["id"], family=case["family"], expected=case["expected"],
                       exit_code=code, elapsed_s=0.1, stderr_tail=[])
            rows.append(row)
        with tempfile.TemporaryDirectory() as temp:
            out = Path(temp)
            (out / "results.json").write_text(json.dumps(
                {"catalog_revision": "test", "cli_args": [], "cases": rows}), encoding="utf-8")
            with redirect_stdout(io.StringIO()):
                self.run_catalog.summarize(out)
            summary = (out / "summary.md").read_text(encoding="utf-8")
        self.assertIn("Provider-reported cost: $0.0446 (1 case(s) without a provider-reported "
                      "cost).", summary)
        self.assertIn("Input tokens: 1215.", summary)
        self.assertNotIn("16.5", summary)

    def test_summary_without_unknown_cases_has_no_note(self):
        row = self.run_catalog.judge(self.clear, report(spend={"provider_reported_usd": "0"}), 0)
        row.update(id="C002", family=self.clear["family"], expected="clear", exit_code=0,
                   elapsed_s=0.1, stderr_tail=[])
        with tempfile.TemporaryDirectory() as temp:
            out = Path(temp)
            (out / "results.json").write_text(json.dumps(
                {"catalog_revision": "test", "cli_args": ["--state-layout", "v2"],
                 "cases": [row]}), encoding="utf-8")
            with redirect_stdout(io.StringIO()):
                self.run_catalog.summarize(out)
            summary = (out / "summary.md").read_text(encoding="utf-8")
        self.assertIn("Provider-reported cost: $0.", summary)
        self.assertNotIn("without a provider-reported cost", summary)
        self.assertIn("`--state-layout v2`", summary)


if __name__ == "__main__":
    unittest.main()
