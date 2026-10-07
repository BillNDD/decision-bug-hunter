"""The public documentation matches the CLI, the error taxonomy and the directives."""
from decimal import Decimal
from pathlib import Path, PurePath
import re
import unittest

from decision_bug_hunter import __version__
from decision_bug_hunter.__main__ import parser
from decision_bug_hunter.core import Source
from decision_bug_hunter.protocol import ERROR_CODES
from tests.support import FixtureProvider

ROOT = Path(__file__).resolve().parents[1]
#: Public documents that ship in the sdist; only PROVENANCE.md may name the
#: project DBH started from.
PUBLIC_DOCS = ("README.md", "CHANGELOG.md", "SECURITY.md", ".env.example",
               "docs/VALIDATION.md", "docs/RELEASE_GATES.md", "docs/PROVIDER_CONTRACT.md")
#: Host path fragments that must never reach a public document (assembled at
#: runtime so this file does not contain them either).
HOST_PATHS = ("c:/" + "users", "c:\\" + "users", "codex" + "temp")
FLAG_ROW = re.compile(r"^\| `(--[a-z0-9-]+)`")


def read(name):
    return ROOT.joinpath(name).read_text(encoding="utf-8")


def flat(text):
    return " ".join(text.split())


def flag_rows(text):
    """{flag: default cell} for the README's flags-and-defaults table."""
    rows = {}
    section = text.split("## Flags and defaults", 1)[1].split("\n## ", 1)[0]
    for line in section.splitlines():
        match = FLAG_ROW.match(line)
        if match:
            cells = [cell.strip() for cell in line.strip().strip("|").split("|")]
            rows[match.group(1)] = cells[1].strip("`")
    return rows


def default_matches(action, cell):
    default = action.default
    if default is None:
        return cell.startswith(("unset", "required"))
    if default is False and action.nargs == 0:
        return cell == "off"
    if isinstance(default, PurePath):
        return cell == default.as_posix()
    if isinstance(default, Decimal):
        return cell == str(default)
    if isinstance(default, float):
        return float(cell) == default
    if isinstance(default, int):
        return cell == str(default)
    return cell == default


class DocumentationTests(unittest.TestCase):
    def test_library_scope_contract_has_no_implicit_default(self):
        from decision_bug_hunter.core import scan as public_scan
        with self.assertRaises(ValueError):
            public_scan(Source.from_text("x"), FixtureProvider())
        readme = read("README.md")
        self.assertIn("mandatory in both the CLI and library", flat(readme))

    def test_every_readme_scan_example_names_a_route(self):
        commands = [line.strip() for line in read("README.md").splitlines()
                    if line.strip().startswith("decision-bug-hunter ")
                    and "--help" not in line]
        self.assertGreaterEqual(len(commands), 5)
        for command in commands:
            with self.subTest(command):
                self.assertRegex(command, r"--provider (openai|openrouter)\b")
                self.assertIn("--scope ", command)

    def test_readme_flag_table_lists_every_option_with_its_default(self):
        rows = flag_rows(read("README.md"))
        options = {action.option_strings[0] if action.option_strings[0].startswith("--")
                   else action.option_strings[-1]: action
                   for action in parser()._actions if action.option_strings}
        options.pop("--help")
        self.assertEqual(set(rows), set(options))
        for flag, action in options.items():
            with self.subTest(flag):
                self.assertTrue(default_matches(action, rows[flag]), rows[flag])

    def test_readme_covers_routes_failure_and_cost_controls(self):
        readme = flat(read("README.md"))
        for needle in ("OPENAI_API_KEY", "OPENROUTER_API_KEY", "DBH_PROVIDER",
                       "NEED_USER_INPUT provider", "provider_unavailable",
                       '"data_collection":"deny"', "--no-retry", "--max-cost",
                       "cost_budget_exhausted", "question_refused", "response_refused",
                       "--canaries off", "19 percent", "secret_detected",
                       "--allow-secrets", "provider_stopped", "1800",
                       "https://github.com/BillNDD/decision-bug-hunter",
                       "not held out", "## Evidence and limits"):
            with self.subTest(needle):
                self.assertIn(needle, readme)
        self.assertNotIn("no automatic retry", readme.lower())

    def test_public_docs_are_decisions_only_and_standalone(self):
        for name in PUBLIC_DOCS:
            text = read(name).lower()
            with self.subTest(name):
                for word in ("jev", "typesafe", "comparison_only", "cross-judge"):
                    self.assertNotIn(word, text)
                for path in HOST_PATHS:
                    self.assertNotIn(path, text)

    def test_provenance_names_the_port_and_the_exclusions(self):
        provenance = flat(read("docs/PROVENANCE.md"))
        for needle in ("standalone repository", "tools/eval/catalog.py", "MIT",
                       "Excluded: the Jev endpoint, the Jev model"):
            with self.subTest(needle):
                self.assertIn(needle, provenance)

    def test_provider_contract_lists_exactly_the_error_codes(self):
        contract = read("docs/PROVIDER_CONTRACT.md")
        section = contract.split("## Error codes", 1)[1].split("\n## ", 1)[0]
        listed = set(re.findall(r"^\| `([a-z_]+)` \|", section, re.M))
        self.assertEqual(listed, set(ERROR_CODES))

    def test_security_policy_names_both_keys_and_injection(self):
        security = flat(read("SECURITY.md"))
        for needle in ("OPENAI_API_KEY", "OPENROUTER_API_KEY", "## Prompt injection",
                       "secret_detected", '"data_collection":"deny"', "cf-ray"):
            with self.subTest(needle):
                self.assertIn(needle, security)

    def test_changelog_has_one_unreleased_entry_for_this_version(self):
        headings = re.findall(r"^## (.+)$", read("CHANGELOG.md"), re.M)
        self.assertEqual(headings, [f"{__version__} (unreleased)"])

    def test_relative_links_in_public_docs_resolve(self):
        for name in (*PUBLIC_DOCS, "docs/PROVENANCE.md"):
            base = ROOT.joinpath(name).parent
            for target in re.findall(r"\]\(([^)#]+)(?:#[^)]*)?\)", read(name)):
                if "://" in target:
                    continue
                with self.subTest(name=name, target=target):
                    self.assertTrue(base.joinpath(target).exists())


if __name__ == "__main__":
    unittest.main()
