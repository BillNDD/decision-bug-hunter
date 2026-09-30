"""The public library and README require an explicit context scope."""
from pathlib import Path
import unittest
from decision_bug_hunter.core import Source
from tests.support import FixtureProvider

class DocumentationTests(unittest.TestCase):
    def test_library_scope_contract_has_no_implicit_default(self):
        from decision_bug_hunter.core import scan as public_scan
        with self.assertRaises(ValueError):
            public_scan(Source.from_text("x"), FixtureProvider())
        readme = Path(__file__).resolve().parents[1].joinpath("README.md").read_text(encoding="utf-8")
        self.assertIn("mandatory in both the CLI and library", " ".join(readme.split()))
