"""The public documentation matches the CLI, the error taxonomy and the directives."""
from decimal import Decimal
import json
from pathlib import Path, PurePath
import re
import tomllib
import unittest

from decision_bug_hunter import __version__
from decision_bug_hunter.__main__ import parser
from decision_bug_hunter.core import Source
from decision_bug_hunter.hosted import CREDENTIAL_VARIABLES
from decision_bug_hunter.judges import JUDGES
from decision_bug_hunter.protocol import ERROR_CODES
from tests.support import FixtureProvider

ROOT = Path(__file__).resolve().parents[1]
#: Public documents that ship in the sdist; only PROVENANCE.md may name the
#: project DBH started from.
PUBLIC_DOCS = ("README.md", "CHANGELOG.md", "SECURITY.md", ".env.example",
               "docs/VALIDATION.md", "docs/RELEASE_GATES.md", "docs/PROVIDER_CONTRACT.md",
               "docs/performance.md", "tools/eval/README.md")
#: Host path fragments that must never reach a public document (assembled at
#: runtime so this file does not contain them either).
HOST_PATHS = ("c:/" + "users", "c:\\" + "users", "codex" + "temp")
FLAG_ROW = re.compile(r"^\| `(--[a-z0-9-]+)`")
#: The README's first paragraph, word for word.
OPENING = ("A super-fast sanity check for LLM-written code, not a full bug checker. The OpenAI "
           "Decisions model answers closed questions about a file and DBH flags suspect line "
           "ranges in seconds, for about a tenth of a cent per small file. Tested live through "
           "both OpenAI and OpenRouter.")
#: pyproject.toml's keywords, exactly.
KEYWORDS = ["llm", "ai-generated-code", "sanity-check", "code-review", "openai",
            "decisions-api", "openrouter", "python"]


def read(name):
    return ROOT.joinpath(name).read_text(encoding="utf-8")


def flat(text):
    return " ".join(text.split())


def table_rows(text):
    """{first cell: [other cells]} for the rows of the markdown tables in *text*."""
    rows = {}
    for line in text.splitlines():
        if line.startswith("| ") and not line.startswith("| ---"):
            cells = [cell.strip() for cell in line.strip().strip("|").split("|")]
            rows[cells[0]] = cells[1:]
    return rows


def section(text, heading):
    """The text under *heading* (a line starting with ``#``) up to the next heading of
    the same or a higher level; a ``#`` line inside a code fence is not a heading."""
    level = len(heading) - len(heading.lstrip("#"))
    lines, fenced, inside = [], False, False
    for line in text.splitlines():
        if line.startswith("```"):
            fenced = not fenced
        if inside and not fenced and re.match(r"#{1,%d} " % level, line):
            break
        if inside:
            lines.append(line)
        elif line == heading:
            inside = True
    return "\n".join(lines)


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

    def test_env_example_lists_every_variable_the_cli_reads_with_empty_values(self):
        values = {}
        for line in read(".env.example").splitlines():
            if line and not line.startswith("#"):
                name, _, value = line.partition("=")
                values[name] = value
        self.assertEqual(
            set(values),
            {"DBH_JUDGE", "DBH_PROVIDER", "DBH_FOUNDRY_ENDPOINT", "DBH_FOUNDRY_DEPLOYMENT",
             *CREDENTIAL_VARIABLES, "OPENAI_ORG_ID", "OPENAI_PROJECT_ID"})
        self.assertEqual(set(values.values()), {""})
        text = flat(read(".env.example"))
        for needle in ("not yet verified live", "microsoft/microsoft-decision-1",
                       "openai/gpt-6-luna-decisions", "NEED_USER_INPUT judge"):
            with self.subTest(needle):
                self.assertIn(needle, text)

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

    def test_readme_opens_with_the_sanity_check_and_the_beta_paragraph(self):
        paragraphs = read("README.md").split("\n\n")
        self.assertEqual(paragraphs[0], "# Decision Bug Hunter")
        self.assertEqual(paragraphs[1], OPENING)
        beta = flat(paragraphs[2])
        for needle in ("experimental beta", "decision models only", "OpenAI Decisions",
                       "Microsoft-Decision-1", "experimental", "`--judge`"):
            with self.subTest(needle):
                self.assertIn(needle, beta)

    def test_package_metadata_matches_the_opening(self):
        project = tomllib.loads(read("pyproject.toml"))["project"]
        self.assertEqual(project["keywords"], KEYWORDS)
        description = project["description"]
        self.assertTrue(description.startswith("A fast sanity check for LLM-written code"))
        self.assertIn("not a full bug checker", description)
        self.assertIn("decision models", description)
        self.assertNotIn("Bounded first-pass", description)

    def test_no_public_document_claims_a_single_supported_model(self):
        for name in PUBLIC_DOCS:
            text = flat(read(name)).lower()
            with self.subTest(name):
                for stale in ("supports no other model", "no other model is supported",
                              "decisions-only", "its one judge", "one judge, the openai"):
                    self.assertNotIn(stale, text)

    def test_public_docs_have_no_placeholders_scratch_paths_or_todo_markers(self):
        for name in (*PUBLIC_DOCS, "docs/PROVENANCE.md"):
            text = read(name)
            with self.subTest(name):
                self.assertIsNone(re.search(r"\b(TODO|TBD|FIXME|XXX)\b", text))
                self.assertNotIn("scratchpad", text.lower())

    def test_every_need_user_input_field_is_documented(self):
        source = ROOT.joinpath("decision_bug_hunter", "__main__.py").read_text(encoding="utf-8")
        fields = set(re.findall(r'(?:need_user_input|FoundryInputNeeded)\(\s*"([a-z_]+)"',
                                source))
        self.assertEqual(fields, {"project_scope", "project_root", "conflicting_options",
                                  "judge", "provider", "judge_route", "foundry_endpoint",
                                  "foundry_deployment", "foundry_auth"})
        readme = flat(read("README.md"))
        for field in sorted(fields):
            with self.subTest(field):
                self.assertIn(f"NEED_USER_INPUT {field}", readme)

    def test_readme_documents_the_foundry_setup_commands(self):
        text = read("README.md")
        foundry = section(text, "### Microsoft Foundry")
        flat_foundry = flat(foundry)
        self.assertIn("not yet verified live", flat_foundry)
        for command in ("az login", "az cognitiveservices account create",
                        "az cognitiveservices account deployment create",
                        '--model-name "Microsoft-Decision-1" --model-format Microsoft',
                        "--sku-name GlobalStandard",
                        "az cognitiveservices account show",
                        "az cognitiveservices account keys list",
                        "az account get-access-token --resource "
                        "https://cognitiveservices.azure.com",
                        "--judge microsoft --provider foundry --scope standalone"):
            with self.subTest(command):
                self.assertIn(command, foundry)
        for variable in ("DBH_FOUNDRY_ENDPOINT", "DBH_FOUNDRY_DEPLOYMENT", "AZURE_API_KEY",
                         "AZURE_ENTRA_TOKEN"):
            with self.subTest(variable):
                self.assertIn(variable, foundry)

    def test_foundry_documentation_matches_the_adapter(self):
        from decision_bug_hunter import foundry
        contract = flat(read("docs/PROVIDER_CONTRACT.md"))
        route = flat(section(read("docs/PROVIDER_CONTRACT.md"), "## Route 4: Microsoft Foundry "
                             "(`--judge microsoft --provider foundry`)"))
        self.assertFalse(foundry.VERIFIED_LIVE)
        self.assertIn("not yet verified live", route)
        for family in foundry.ENDPOINT_FAMILIES:
            with self.subTest(family):
                self.assertIn(f"<resource>.{family}", route)
        self.assertIn(foundry.PATH, route)
        for variable in (foundry.API_KEY_VARIABLE, foundry.TOKEN_VARIABLE,
                         foundry.DEPLOYMENT_VARIABLE):
            with self.subTest(variable):
                self.assertIn(variable, route)
                self.assertIn(variable, flat(read("README.md")))
        for variable in (foundry.API_KEY_VARIABLE, foundry.TOKEN_VARIABLE):
            self.assertIn(variable, flat(read("SECURITY.md")))
        self.assertEqual(foundry.TEMPLATE.price_in_per_mtok, Decimal("0.042"))
        self.assertIn("$0.042 per million", route)
        for name in ("prompt_tokens", "completion_tokens", "input_tokens", "output_tokens",
                     "usage_shape", "endpoint_invalid"):
            with self.subTest(name):
                self.assertIn(name, route)
        # Every status code the adapter can return has a cell in the status table.
        table = table_rows(read("docs/PROVIDER_CONTRACT.md"))
        codes = {foundry.status_code(status) for status in (302, 400, 401, 402, 403, 404, 408,
                                                              413, 422, 429, 503, 524, 529)}
        cells = " ".join(" ".join(cells) for cells in table.values())
        for code in sorted(codes):
            with self.subTest(code):
                self.assertIn(f"`{code}`", cells)
        self.assertIn("| Status | OpenAI direct | OpenRouter | Foundry |", contract)

    def test_microsoft_results_agree_between_the_documents(self):
        readme = read("README.md")
        validation = read("docs/VALIDATION.md")
        judge = section(readme, "## Choosing a judge")
        shipped = readme.split("## Evidence and limits", 1)[1].split("Shipped defaults", 1)[1]
        chosen = table_rows(judge)
        evidence = table_rows(shipped.split("Final evaluation", 1)[0])
        self.assertEqual(chosen["Defective programs detected"][0], "13/16")
        self.assertEqual(chosen["Individual defects covered"][0], "14/17")
        self.assertEqual(chosen["Corrected controls clear"][0], "14/16")
        self.assertEqual(chosen["Missing evidence marked incomplete"][0], "1/2")
        self.assertEqual(chosen["Entire cases"][0], "28/34")
        self.assertEqual(chosen["Calls / cost"][0], "182 / $0.0107")
        # The OpenAI columns are the shipped-defaults table's OpenRouter and OpenAI-direct
        # legacy-v1 columns.
        for label in ("Defective programs detected", "Individual defects covered",
                      "Corrected controls clear", "Missing evidence marked incomplete",
                      "Entire cases", "Calls / cost"):
            with self.subTest(label):
                self.assertEqual(chosen[label][1], evidence[label][0])
                self.assertEqual(chosen[label][2], evidence[label][2])
        # VALIDATION.md repeats the same figures.
        table = table_rows(section(validation, "### Microsoft-Decision-1 on OpenRouter"))
        for label, theirs in (("Defective programs detected", "Defective programs detected"),
                              ("Individual defects covered", "Individual defects covered"),
                              ("Corrected controls clear", "Corrected controls clear"),
                              ("Missing evidence marked incomplete",
                               "Missing evidence incomplete"),
                              ("Entire cases", "Entire cases")):
            with self.subTest(label=label):
                self.assertEqual(table[theirs], chosen[label])
        self.assertEqual(table["Calls"][0], "182")
        self.assertEqual(table["Input tokens"][0], "254,661")
        self.assertEqual(table["Cost"][0], "$0.0107")
        flat_readme = flat(readme)
        for needle in ("171 of the 182 requests", "about 10^-10",
                       "six request formats for the screening questions and three for the "
                       "verification questions", "the limit looks like the model, not the "
                       "request design", "27 of 34 (12 of 16 defective programs, 14 of 16 clean "
                       "files)"):
            with self.subTest(needle):
                self.assertIn(needle, flat_readme)
        flat_validation = flat(validation)
        for needle in ("$0.2143", "85 of 86", "21 to 23 of 40", "0.80 to 0.93", "0.55, 0.59 and 0.63",
                       "best pooled AUC was 0.60 against a bar of 0.65", "171 of the 182",
                       "1,225 Microsoft receipts"):
            with self.subTest(needle):
                self.assertIn(needle, flat_validation)

    def test_tile_sieve_documentation_matches_the_code_and_the_golden_file(self):
        from decision_bug_hunter.__main__ import SearchPolicyRefused, require_calibrated_judge
        from decision_bug_hunter.tile_sieve_fusion import load_thresholds
        from decision_bug_hunter.tile_sieve_plan import MAX_REQUEST_BYTES, MAX_STATE_BYTES
        readme = read("README.md")
        tile = section(readme, "## Tile Sieve (beta)")
        flat_tile = flat(tile)
        # The refusal text is the code's, and the documents quote it.
        with self.assertRaises(SearchPolicyRefused) as refused:
            require_calibrated_judge("tile-sieve-beta", "microsoft")
        message = f"invalid_search_configuration: {refused.exception.detail}"
        self.assertEqual(refused.exception.detail,
                         "tile-sieve-beta has no calibrated thresholds for judge microsoft")
        for name in ("README.md", "CHANGELOG.md", "tools/eval/README.md"):
            with self.subTest(name):
                self.assertIn(message, flat(read(name)))
        # One threshold set, the OpenAI judge's, and the numbers the README gives for it.
        shipped = json.loads(ROOT.joinpath("decision_bug_hunter",
                                           "tile_sieve_thresholds.json").read_text("utf-8"))
        self.assertEqual(set(shipped["judges"]), {"openai"})
        with self.assertRaises(LookupError):
            load_thresholds("microsoft")
        thresholds = load_thresholds("openai")
        for value in (thresholds.strong_cell, thresholds.tau_strong, thresholds.tau_rel,
                      thresholds.tau_rep(200)):
            with self.subTest(value=value):
                self.assertIn(f"{value:g}", flat_tile)
        self.assertIn(f"{MAX_REQUEST_BYTES:,} bytes", flat_tile)
        self.assertIn(f"{MAX_STATE_BYTES:,} bytes of state", flat_tile)
        for needle in ("one or two whole-file looks", "Rule 8C", "There is no second stage",
                       "`legacy-fallback`", "about 0.30", "`thresholds_sha256`",
                       "`\"judge_declared\": false`", "36 tile requests",
                       "optimistic", "not held-out evidence", "beta"):
            with self.subTest(needle):
                self.assertIn(needle, flat_tile)
        # The catalog figures: the two Tile Sieve runs and the legacy-v1 columns beside them.
        table = table_rows(tile)
        self.assertEqual(table["Defective programs detected"],
                         ["16/16", "15/16", "16/16", "15/16"])
        self.assertEqual(table["Individual defects covered"],
                         ["17/17", "16/17", "17/17", "16/17"])
        self.assertEqual(table["Corrected controls clear"],
                         ["16/16", "16/16", "16/16", "16/16"])
        self.assertEqual(table["Missing evidence marked incomplete"],
                         ["2/2", "2/2", "0/2", "1/2"])
        self.assertEqual(table["Entire cases"], ["34/34", "33/34", "32/34", "32/34"])
        self.assertEqual(table["Entire cases, strict"], ["32/34", "31/34", "32/34", "32/34"])
        self.assertEqual(table["Calls"], ["53", "52", "211", "214"])
        self.assertEqual(table["Input tokens"], ["153,561", "148,640", "445,685", "449,566"])
        evidence = table_rows(readme.split("## Evidence and limits", 1)[1]
                              .split("Shipped defaults", 1)[1].split("Final evaluation", 1)[0])
        for label in ("Defective programs detected", "Individual defects covered",
                      "Corrected controls clear", "Missing evidence marked incomplete",
                      "Entire cases"):
            with self.subTest(label):
                self.assertEqual(table[label][2], evidence[label][2])
                self.assertEqual(table[label][3], evidence[label][0])
        validation = table_rows(section(read("docs/VALIDATION.md"),
                                        "### Tile Sieve on the catalog"))
        for label, cells in table.items():
            if label != "Cost":
                with self.subTest(label=label):
                    self.assertEqual(validation[label.replace("marked incomplete", "incomplete")],
                                     cells)
        # The costs differ only in precision: the README rounds the estimates.
        self.assertEqual(table["Cost"], ["about $0.015 (estimated)", "$0.0149",
                                         "about $0.045 (estimated)", "$0.0450"])
        self.assertEqual(validation["Cost"], ["about $0.0154 (estimated)", "$0.0149",
                                              "about $0.0446 (estimated)", "$0.0450"])
        # The offline benchmark makes the same 53 requests: 36 looks and 17 focus requests.
        golden = json.loads(read("tools/bench/golden.json"))["scenarios"]["catalog-tile-sieve"]
        phases = golden["exact"]["rounds_by_phase"]
        self.assertEqual(golden["exact"]["provider_calls"], 53)
        self.assertEqual(phases["ts-screen-l0"] + phases["ts-screen-l1"], 36)
        self.assertEqual(phases["ts-focus"], 17)
        flat_validation = flat(read("docs/VALIDATION.md"))
        self.assertIn("53 requests: 36 whole-file looks", flat_validation)
        self.assertIn("and 17 focus requests", flat_validation)

    def test_performance_table_matches_the_golden_file(self):
        golden = json.loads(read("tools/bench/golden.json"))["scenarios"]
        rows = {}
        for line in read("docs/performance.md").splitlines():
            cells = [cell.strip() for cell in line.strip().strip("|").split("|")]
            if line.startswith("| ") and cells[0] in golden:
                rows[cells[0]] = [int(cell.replace(",", "")) for cell in cells[1:]]
        self.assertEqual(set(rows), set(golden))
        for name, row in rows.items():
            exact = golden[name]["exact"]
            with self.subTest(name):
                self.assertEqual([row[0], row[1], row[2], row[3], row[4], row[5], row[9]],
                                 [golden[name]["jobs"], exact["provider_calls"],
                                  exact["questions_total"], exact["envelope_bytes_total"],
                                  exact["rounds_as_executed"], exact["critical_path_upper"],
                                  exact["receipt_writes"]])
        for name in ("catalog-tile-sieve", "catalog-4-tile-sieve", "synth-200-tile-sieve",
                     "synth-1000-tile-sieve", "catalog-4-microsoft"):
            with self.subTest(scenario=name):
                self.assertIn(f"`{name}`", read("docs/performance.md"))
        tile = golden["catalog-tile-sieve"]["exact"]
        self.assertIn(f"{tile['provider_calls']} provider calls, {tile['questions_total']} "
                      f"questions and {tile['envelope_bytes_total']:,}",
                      flat(read("docs/performance.md")))

    def test_release_gates_cover_the_second_judge_and_tile_sieve(self):
        gates = read("docs/RELEASE_GATES.md")
        rows = {number: next(line for line in gates.splitlines()
                             if line.startswith(f"| {number} |")) for number in (12, 13, 14, 15)}
        self.assertIn("Verified live and published as experimental, below the full-judge bar",
                      rows[12])
        self.assertIn("This is not a pass.", rows[12])
        self.assertIn("28/34", rows[12])
        self.assertIn("**Open.**", rows[13])
        self.assertIn("not yet verified live", rows[13])
        self.assertIn("Satisfied", rows[14])
        self.assertIn("34/34", rows[14])
        self.assertIn("33/34", rows[14])
        self.assertIn("Not offered", rows[15])
        new_evidence = flat(gates.split("## Changes that require new evidence", 1)[1])
        self.assertIn("tile_sieve_thresholds.json", new_evidence)
        self.assertIn("A new judge or model needs its own allow-list entry", new_evidence)

    def test_security_policy_covers_the_azure_credentials(self):
        security = flat(read("SECURITY.md"))
        for needle in ("AZURE_API_KEY", "AZURE_ENTRA_TOKEN", "DBH_FOUNDRY_ENDPOINT",
                       "by its exact value", "no pattern for an Azure resource key",
                       "short-lived", "never acquires or refreshes", "`http_unauthorized`",
                       "`--judge microsoft --provider foundry`", "Azure for `--judge microsoft`",
                       "refused wherever its unaltered text appears",
                       "matches the key's text as configured",
                       "an escaped or encoded form (JSON `\\u` escapes, base64 or hex)",
                       "a byte-order mark, a zero-width character, an unbalanced quote, "
                       "a `Bearer ` prefix or backticks", "Keep keys out of the files you scan"):
            with self.subTest(needle):
                self.assertIn(needle, security)
        self.assertNotIn("never be sent to OpenAI or OpenRouter", security)
        flat_readme = flat(read("README.md"))
        for needle in ("so the unaltered key is refused wherever it appears, on every route",
                       "Keep keys out of the files you scan"):
            with self.subTest(needle):
                self.assertIn(needle, flat_readme)

    def test_concurrency_is_not_a_public_setting(self):
        for name in ("README.md", "CHANGELOG.md", "docs/PROVIDER_CONTRACT.md", "docs/VALIDATION.md"):
            with self.subTest(name):
                self.assertNotIn("--concurrency", read(name))
        known = flat(read("docs/RELEASE_GATES.md").split("## Known issues", 1)[1])
        for needle in ("Request concurrency is not exposed in 0.1.0b1",
                       "do not inherit context variables",
                       "`max_in_flight` is not checked against the provider's `max_connections`",
                       "latches `cost_budget_exhausted`"):
            with self.subTest(needle):
                self.assertIn(needle, known)

    def test_changelog_describes_the_second_judge_and_tile_sieve(self):
        changelog = flat(read("CHANGELOG.md"))
        for needle in ("### Judges and routes", "### Tile Sieve (beta)", "**experimental**",
                       "`NEED_USER_INPUT judge`", "`invalid_judge`", "`endpoint_invalid`",
                       "not yet verified live", "28 of 34 cases against 32 of 34",
                       "tile_sieve_thresholds.json", "9 (tile-sieve-beta)", "handoff schema 4, 5 and 6",
                       "53 calls through OpenAI direct and 33 of 34 with 52 calls"):
            with self.subTest(needle):
                self.assertIn(needle, changelog)

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
