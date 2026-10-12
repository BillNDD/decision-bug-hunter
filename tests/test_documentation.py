"""The public documentation matches the CLI, the error taxonomy and the directives."""
from decimal import Decimal
from pathlib import Path, PurePath
import re
import unittest

from decision_bug_hunter import __version__
from decision_bug_hunter.__main__ import parser
from decision_bug_hunter.core import Source
from decision_bug_hunter.judges import JUDGES
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
                self.assertRegex(command, r"--judge (openai|microsoft)\b")
                self.assertRegex(command, r"--provider (openai|openrouter|foundry)\b")
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

    def test_readme_says_a_fitting_file_gets_one_or_two_whole_file_looks(self):
        # A file of 8 lines or fewer, or whose two looks come out identical, gets one look.
        text = flat(read("README.md"))
        self.assertIn("is read in one or two whole-file looks, then each flagged region", text)
        self.assertNotIn("read in two looks", text)

    def test_readme_quotes_the_microsoft_notice_and_the_judge_choice_text(self):
        readme = read("README.md")
        section = readme.split("## Choosing a judge", 1)[1].split("\n## ", 1)[0]
        self.assertIn(JUDGES["microsoft"].notice, section)
        self.assertIsNone(JUDGES["openai"].notice)
        self.assertIn("experimental", section)
        self.assertIn("(judge microsoft)", section)
        # The first NEED_USER_INPUT judge text, with the README's line wraps joined.
        text = flat(readme)
        for judge in JUDGES.values():
            route_names = " | ".join(route.selector for route in judge.routes)
            self.assertIn(f"routes {route_names})", text)
        self.assertIn("NEED_USER_INPUT judge_route: microsoft routes: openrouter | foundry",
                      text)

    def test_readme_covers_routes_failure_and_cost_controls(self):
        readme = flat(read("README.md"))
        for needle in ("OPENAI_API_KEY", "OPENROUTER_API_KEY", "DBH_PROVIDER",
                       "DBH_JUDGE", "AZURE_API_KEY", "AZURE_ENTRA_TOKEN",
                       "DBH_FOUNDRY_ENDPOINT", "DBH_FOUNDRY_DEPLOYMENT",
                       "NEED_USER_INPUT judge:", "NEED_USER_INPUT judge_route",
                       "NEED_USER_INPUT foundry_endpoint", "NEED_USER_INPUT foundry_auth",
                       "invalid_judge", "endpoint_invalid", "not yet verified live",
                       "## Choosing a judge",
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

    def test_public_docs_have_no_placeholders(self):
        for name in (*PUBLIC_DOCS, "docs/PROVENANCE.md"):
            text = read(name)
            with self.subTest(name):
                self.assertNotIn("PENDING", text)
                self.assertNotIn("**Pending.**", text)

    def test_release_evaluation_is_recorded(self):
        validation = flat(read("docs/VALIDATION.md"))
        gates = read("docs/RELEASE_GATES.md")
        gate8 = next(line for line in gates.splitlines() if line.startswith("| 8 |"))
        self.assertIn("Satisfied (development suite only)", gate8)
        for needle in ("451,412", "683,136", "$0.0451", "$0.0683", "$0.0025",
                       "449,566", "$0.0450", "1,199,357", "$0.1200", "about $1.16",
                       "445,685", "654,342", "1,100,027", "about $0.11", "about $1.27"):
            with self.subTest(needle):
                self.assertIn(needle, validation)
        self.assertIn("about $1.27", gates)
        self.assertIn("Final evaluation at the release code", flat(read("README.md")))

    def test_mass_gate_default_is_documented_with_its_evidence(self):
        from decision_bug_hunter.core import DEFAULT_CHOICE_GATE, Config
        self.assertEqual(DEFAULT_CHOICE_GATE, "mass")
        self.assertEqual(Config().choice_gate, "mass")
        self.assertEqual(Config().state_layout, "v1")
        readme = flat(read("README.md"))
        evidence = readme.split("## Evidence and limits", 1)[1]
        shipped = evidence.split("Shipped defaults", 1)[1].split("Final evaluation", 1)[0]
        self.assertIn("`--choice-gate mass`, state layout v1, canaries on", shipped)
        for row in ("| Defective programs detected | 15/16 | 15/16 | 16/16 | 14/16 |",
                    "| Individual defects covered | 16/17 | 17/17 | 17/17 | 17/17 |",
                    "| Corrected controls clear | 16/16 | 16/16 | 16/16 | 16/16 |",
                    "| Missing evidence marked incomplete | 1/2 | 1/2 | 0/2 | 1/2 |",
                    "| Entire cases | 32/34 | 32/34 | 32/34 | 31/34 |",
                    "| Calls / cost | 214 / $0.0450 | 312 / $0.0683 | 211 / about $0.045 "
                    "(estimated) | 296 / about $0.065 (estimated) |"):
            with self.subTest(row):
                self.assertIn(row, shipped)
        variants = evidence.split("Measured variants", 1)[1]
        self.assertIn("| legacy-v1 + `--choice-gate legacy` | 31/34 |", variants)
        self.assertIn("211 calls, $0.0451", variants)
        self.assertIn("Reverses the mass-gate gain", variants)
        validation = flat(read("docs/VALIDATION.md"))
        self.assertIn("### Default decisions", validation)
        self.assertIn("`--state-layout v2` stays opt-in", validation)
        changelog = flat(read("CHANGELOG.md"))
        self.assertIn("`--choice-gate` (default `mass`)", changelog)
        # No commit hashes in the public docs (the history is rewritten
        # before publishing).
        for name in PUBLIC_DOCS:
            with self.subTest(name):
                self.assertIsNone(re.search(r"commit `[0-9a-f]{7,40}`", read(name)))

    def test_openai_direct_route_is_documented_as_live_verified(self):
        # tools/smoke is repository-only and pruned from the sdist (MANIFEST.in).
        smoke_readme = "tools/smoke/README.md"
        smoke_present = ROOT.joinpath(smoke_readme).is_file()
        names = ["README.md", "docs/PROVIDER_CONTRACT.md", "docs/VALIDATION.md"]
        if smoke_present:
            names.append(smoke_readme)
        for name in names:
            text = flat(read(name))
            with self.subTest(name):
                for stale in ("has not been exercised live", "No live request has been made",
                              "has not been run against the live service",
                              "pinned only by offline fixtures built"):
                    self.assertNotIn(stale, text)
        gates = read("docs/RELEASE_GATES.md")
        for number in (2, 5, 6):
            row = next(line for line in gates.splitlines()
                       if line.startswith(f"| {number} |"))
            with self.subTest(gate=number):
                self.assertIn("both routes", row)
        validation = flat(read("docs/VALIDATION.md"))
        for needle in ("### OpenAI-direct smoke findings", "76 answers", "`x-request-id` on all 5",
                       "`http_rejected`"):
            with self.subTest(needle):
                self.assertIn(needle, validation)
        if smoke_present:
            self.assertIn("about $0.002", flat(read(smoke_readme)))

    def test_readme_cost_bounds_match_the_code(self):
        from decision_bug_hunter import openrouter
        from decision_bug_hunter.providers import attempt_cost_bound
        spec = openrouter.ROUTE.models[0]
        full = attempt_cost_bound(spec.max_envelope_bytes, spec.max_questions,
                                  spec.price_in_per_mtok, spec.price_out_upper_per_mtok)
        wire = attempt_cost_bound(openrouter.MAX_BODY_BYTES,
                                  spec.state_placement_max_questions,
                                  spec.price_in_per_mtok, spec.price_out_upper_per_mtok)
        readme = flat(read("README.md"))
        self.assertEqual(round(full, 4), Decimal("0.0029"))
        self.assertIn("about $0.0029 for a full 24 KiB, 64-question request", readme)
        self.assertEqual(round(wire, 3), Decimal("0.008"))
        self.assertIn("about $0.007 to $0.008 at the 64 KiB wire cap", readme)
        self.assertEqual(round(wire * 1000), 8)
        self.assertIn("at most about $8", readme)

    def test_library_use_names_policy_placement_for_make_provider(self):
        import inspect
        from decision_bug_hunter.providers import make_provider
        self.assertIn("policy_placement", inspect.signature(make_provider).parameters)
        section = read("README.md").split("## Library use", 1)[1]
        library = flat(section.split("\n## ", 1)[0])
        self.assertIn("pass the same `policy_placement=` to `make_provider(...)`", library)

    def test_changelog_describes_rather_than_diffs(self):
        changelog = flat(read("CHANGELOG.md"))
        for phrase in ("Reports gain", "new codes include"):
            with self.subTest(phrase):
                self.assertNotIn(phrase, changelog)

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
