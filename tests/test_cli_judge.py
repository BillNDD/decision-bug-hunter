"""Judge and route selection on the command line, fully offline.

The CLI chooses a decision model (``--judge``), then a route to it
(``--provider``), then checks the pair, the model and the route's own options,
all inside ``cli.make_provider`` and all before the source is read or any
output exists. These tests pin that order, the exact NEED_USER_INPUT texts, the
experimental notice of the Microsoft judge and that no credential value or
Foundry endpoint is ever printed. No socket is opened and no real key is read.
"""
import argparse
from contextlib import redirect_stderr, redirect_stdout
import io
from pathlib import Path
import shutil
import tempfile
import unittest
from unittest.mock import patch

from decision_bug_hunter import __main__ as cli
from decision_bug_hunter.core import Source
from decision_bug_hunter.decisions import DecisionsProvider
from decision_bug_hunter.foundry import FoundryProvider
from decision_bug_hunter.handoff import compact_report
from decision_bug_hunter.openrouter import OpenRouterProvider
from decision_bug_hunter.protocol import ProviderError
from tests.support import clean_provider_env

OPENAI_KEY = "offline-openai-sentinel-credential-1a2b"
OPENROUTER_KEY = "offline-openrouter-sentinel-credential-3c4d"
AZURE_KEY = "offline-azure-sentinel-credential-5e6f"
ENTRA_TOKEN = "offline-entra-sentinel-credential-7a8b"
ENDPOINT_HOST = "dbh-fixture-resource.services.ai.azure.com"
ENDPOINT = "https://" + ENDPOINT_HOST
DEPLOYMENT = "dbh-fixture-deployment"
SECRETS = (OPENAI_KEY, OPENROUTER_KEY, AZURE_KEY, ENTRA_TOKEN, ENDPOINT_HOST)
NOTICE = ("Note: Microsoft-Decision-1 support is experimental: in DBH's validation it "
          "finds fewer bugs than OpenAI Decisions (README: Choosing a judge).")
JUDGE_NEEDED = ("NEED_USER_INPUT judge: openai (OpenAI Decisions gpt-6-luna; routes openai | "
                "openrouter) | microsoft (Microsoft-Decision-1; routes openrouter | foundry)\n")
LUNA = "openai/gpt-6-luna-decisions"
MICROSOFT = "microsoft/microsoft-decision-1"
FOUNDRY = ["--foundry-endpoint", ENDPOINT, "--foundry-deployment", DEPLOYMENT]
EVERY_KEY = {"OPENAI_API_KEY": OPENAI_KEY, "OPENROUTER_API_KEY": OPENROUTER_KEY,
             "AZURE_API_KEY": AZURE_KEY, "AZURE_ENTRA_TOKEN": ENTRA_TOKEN}


def run_cli(argv, **environment):
    out, err = io.StringIO(), io.StringIO()
    with clean_provider_env(**environment), redirect_stdout(out), redirect_stderr(err):
        code = cli.main(argv)
    return code, out.getvalue(), err.getvalue()


def parsed(*argv):
    return cli.parser().parse_args(["target.py", "--scope", "standalone", *argv])


def report(*, status="complete", **extra):
    result = {
        "schema_version": 4, "source": {"name": "target.py", "sha256": "a" * 64},
        "specification": None, "scan_status": status, "handoff_status": "complete",
        "configuration": {}, "specification_mode": "inferred", "status": status,
        "calls_attempted": 1, "findings": [], "windows": [],
        "coverage": {"assessed_lines": 2}, "issues": [], **extra}
    result["handoff"] = compact_report(result)
    return result


class Temporary(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)
        self.target = self.root / "target.py"
        self.target.write_text("a = 1\nb = a / 0\n", encoding="utf-8")
        self.out = self.root / "out"

    def argv(self, *extra):
        return [str(self.target), "--scope", "standalone", "--output-dir", str(self.out),
                *extra]

    def run_cli(self, *extra, **environment):
        code, out, err = run_cli(self.argv(*extra), **environment)
        for secret in SECRETS:
            self.assertNotIn(secret, out + err)
        return code, out, err


class SelectionTests(Temporary):
    """Every refusal happens before any read or output."""

    def setUp(self):
        super().setUp()
        self.reader = patch.object(Source, "read", side_effect=AssertionError("source read"))
        self.read = self.reader.start()
        self.addCleanup(self.reader.stop)
        self.maker = patch.object(tempfile, "mkdtemp", side_effect=AssertionError("mkdtemp"))
        self.mkdtemp = self.maker.start()
        self.addCleanup(self.maker.stop)

    def refused(self, argv_extra, code, **environment):
        result, out, err = self.run_cli(*argv_extra, **environment)
        self.assertEqual((result, out), (code, ""))
        self.assertFalse(self.read.called)
        self.assertFalse(self.mkdtemp.called)
        self.assertFalse(self.out.exists())
        self.assertNotIn("experimental", err)
        return err

    def test_no_judge_asks_for_one_with_the_exact_text(self):
        for extra, environment in (([], {}), (["--provider", "openrouter"], EVERY_KEY),
                                   (["--provider", "foundry", *FOUNDRY], EVERY_KEY)):
            with self.subTest(extra=extra):
                self.assertEqual(self.refused(extra, 3, **environment), JUDGE_NEEDED)

    def test_scope_comes_before_the_judge_and_the_judge_before_the_route(self):
        code, _, err = run_cli([str(self.target), "--output-dir", str(self.out)])
        self.assertEqual(code, 3)
        self.assertIn("NEED_USER_INPUT project_scope", err)
        # An invalid route is not examined before the judge is known.
        err = self.refused([], 3, DBH_PROVIDER="bogus-route-sentinel")
        self.assertEqual(err, JUDGE_NEEDED)
        # A judge but no route asks for the route; a bad route is refused next.
        self.assertIn("NEED_USER_INPUT provider:", self.refused(["--judge", "openai"], 3))
        err = self.refused(["--judge", "openai"], 2, DBH_PROVIDER="bogus-route-sentinel")
        self.assertIn("Scan failed (invalid_provider).", err)
        # The route is checked before availability: no key is needed to be refused.
        self.assertIn("NEED_USER_INPUT judge_route", self.refused(
            ["--judge", "openai", "--provider", "foundry"], 3))

    def test_an_invalid_dbh_judge_is_refused_without_echo(self):
        for value in ("bogus-judge-sentinel", "OpenAI", "openai "):
            with self.subTest(value=value):
                err = self.refused([], 2, DBH_JUDGE=value, DBH_PROVIDER="openrouter",
                                   OPENROUTER_API_KEY=OPENROUTER_KEY)
                # Exactly the fixed text: the value is not part of it.
                self.assertEqual(err, "Scan failed (invalid_judge).\n"
                                      "DBH_JUDGE must be one of: openai, microsoft.\n")

    def test_the_flag_wins_over_dbh_judge(self):
        # A bad DBH_JUDGE is ignored when --judge is given.
        err = self.refused(["--judge", "openai", "--provider", "openai"], 2,
                           DBH_JUDGE="bogus-judge-sentinel")
        self.assertIn("Scan failed (provider_unavailable).", err)
        self.assertIn("Set OPENAI_API_KEY in the environment", err)
        # DBH_JUDGE alone selects the judge.
        err = self.refused(["--provider", "foundry"], 3, DBH_JUDGE="openai")
        self.assertIn("NEED_USER_INPUT judge_route: openai routes: openai | openrouter", err)
        # The flag overrides a different DBH_JUDGE.
        err = self.refused(["--judge", "microsoft", "--provider", "openai"], 3,
                           DBH_JUDGE="openai")
        self.assertIn("NEED_USER_INPUT judge_route: microsoft routes: openrouter | foundry", err)

    def test_the_openai_judge_without_a_route_keeps_todays_text(self):
        err = self.refused(["--judge", "openai"], 3)
        self.assertEqual(err, "NEED_USER_INPUT provider: openai | openrouter (set: none)\n")
        err = self.refused(["--judge", "openai"], 3, OPENROUTER_API_KEY=OPENROUTER_KEY)
        self.assertEqual(
            err, "NEED_USER_INPUT provider: openai | openrouter (set: OPENROUTER_API_KEY)\n")
        # The Azure credentials are not the OpenAI judge's: never listed for it.
        err = self.refused(["--judge", "openai"], 3, **EVERY_KEY)
        self.assertEqual(err, "NEED_USER_INPUT provider: openai | openrouter "
                              "(set: OPENAI_API_KEY, OPENROUTER_API_KEY)\n")

    def test_the_microsoft_judge_lists_only_its_own_routes_and_keys(self):
        err = self.refused(["--judge", "microsoft"], 3)
        self.assertEqual(err, "NEED_USER_INPUT provider: openrouter | foundry (set: none)\n")
        err = self.refused(["--judge", "microsoft"], 3, **EVERY_KEY)
        self.assertEqual(err, "NEED_USER_INPUT provider: openrouter | foundry "
                              "(set: OPENROUTER_API_KEY, AZURE_API_KEY, AZURE_ENTRA_TOKEN)\n")
        err = self.refused(["--judge", "microsoft"], 3, OPENAI_API_KEY=OPENAI_KEY)
        self.assertEqual(err, "NEED_USER_INPUT provider: openrouter | foundry (set: none)\n")

    def test_each_invalid_pair_is_a_judge_route_request(self):
        for judge, route, line in (
                ("openai", "foundry", "openai routes: openai | openrouter"),
                ("microsoft", "openai", "microsoft routes: openrouter | foundry")):
            with self.subTest(judge=judge, route=route):
                for extra in (["--judge", judge, "--provider", route],
                              ["--judge", judge, "--provider", route, "--model", "x-model"]):
                    err = self.refused(extra, 3, **EVERY_KEY)
                    self.assertEqual(err, f"NEED_USER_INPUT judge_route: {line}\n")
                err = self.refused(["--judge", judge], 3, DBH_PROVIDER=route, **EVERY_KEY)
                self.assertEqual(err, f"NEED_USER_INPUT judge_route: {line}\n")

    def test_an_invalid_dbh_provider_names_the_routes_of_the_judge(self):
        for judge, routes in (("openai", "openai, openrouter"),
                              ("microsoft", "openrouter, foundry")):
            with self.subTest(judge=judge):
                err = self.refused(["--judge", judge], 2, DBH_PROVIDER="bogus-route-sentinel")
                self.assertIn("Scan failed (invalid_provider).", err)
                self.assertIn(f"DBH_PROVIDER must be one of: {routes}.", err)
                self.assertNotIn("bogus-route-sentinel", err)

    def test_a_model_of_the_other_judge_is_invalid_request(self):
        for judge, route, model in (("openai", "openrouter", MICROSOFT),
                                    ("openai", "openai", MICROSOFT),
                                    ("openai", "openrouter", "gpt-6-luna"),
                                    ("microsoft", "openrouter", LUNA),
                                    ("microsoft", "openrouter", "gpt-6-luna"),
                                    ("microsoft", "openrouter", MICROSOFT + "-mini")):
            with self.subTest(judge=judge, route=route, model=model):
                err = self.refused(["--judge", judge, "--provider", route, "--model", model],
                                   2, **EVERY_KEY)
                self.assertIn("Scan failed (invalid_request).", err)
                self.assertNotIn(model, err)

    def test_the_microsoft_judge_accepts_its_own_model(self):
        err = self.refused(["--judge", "microsoft", "--provider", "openrouter",
                            "--model", MICROSOFT], 2)
        self.assertIn("Scan failed (provider_unavailable).", err)
        self.assertIn("Set OPENROUTER_API_KEY in the environment", err)

    def test_model_with_foundry_is_invalid_request_before_foundry_asks(self):
        # No endpoint and no deployment yet: the model check comes first.
        for extra in (["--model", MICROSOFT], ["--model", DEPLOYMENT, *FOUNDRY]):
            with self.subTest(extra=extra):
                err = self.refused(["--judge", "microsoft", "--provider", "foundry", *extra],
                                   2, AZURE_API_KEY=AZURE_KEY)
                self.assertIn("Scan failed (invalid_request).", err)

    def test_foundry_flags_belong_to_the_foundry_route(self):
        for route, judge in (("openrouter", "microsoft"), ("openrouter", "openai"),
                             ("openai", "openai")):
            for flag, value in (("--foundry-endpoint", ENDPOINT),
                                ("--foundry-deployment", DEPLOYMENT),
                                ("--foundry-auth", "api-key")):
                with self.subTest(route=route, flag=flag):
                    err = self.refused(["--judge", judge, "--provider", route, flag, value],
                                       2, **EVERY_KEY)
                    self.assertIn("Scan failed (invalid_request).", err)

    def test_openrouter_options_do_not_apply_to_foundry(self):
        for extra in (["--openrouter-zdr"], ["--openrouter-routing", "account-default"]):
            with self.subTest(extra=extra):
                err = self.refused(["--judge", "microsoft", "--provider", "foundry", *FOUNDRY,
                                    *extra], 2, AZURE_API_KEY=AZURE_KEY)
                self.assertIn("Scan failed (invalid_request).", err)

    def test_foundry_asks_for_a_missing_endpoint_then_deployment(self):
        base = ["--judge", "microsoft", "--provider", "foundry"]
        err = self.refused(base, 3, AZURE_API_KEY=AZURE_KEY)
        self.assertEqual(err, "NEED_USER_INPUT foundry_endpoint: provide --foundry-endpoint or "
                              "DBH_FOUNDRY_ENDPOINT (https://<resource>.services.ai.azure.com)\n")
        err = self.refused([*base, "--foundry-deployment", DEPLOYMENT], 3,
                           AZURE_API_KEY=AZURE_KEY)
        self.assertIn("NEED_USER_INPUT foundry_endpoint:", err)
        err = self.refused([*base, "--foundry-endpoint", ENDPOINT], 3, AZURE_API_KEY=AZURE_KEY)
        self.assertEqual(err, "NEED_USER_INPUT foundry_deployment: provide "
                              "--foundry-deployment or DBH_FOUNDRY_DEPLOYMENT\n")
        # The environment variables stand in for the flags, one by one.
        err = self.refused(base, 3, AZURE_API_KEY=AZURE_KEY, DBH_FOUNDRY_ENDPOINT=ENDPOINT)
        self.assertIn("NEED_USER_INPUT foundry_deployment:", err)
        err = self.refused(base, 3, AZURE_API_KEY=AZURE_KEY, DBH_FOUNDRY_DEPLOYMENT=DEPLOYMENT)
        self.assertIn("NEED_USER_INPUT foundry_endpoint:", err)

    def test_both_foundry_credentials_need_an_explicit_choice(self):
        err = self.refused(["--judge", "microsoft", "--provider", "foundry", *FOUNDRY], 3,
                           AZURE_API_KEY=AZURE_KEY, AZURE_ENTRA_TOKEN=ENTRA_TOKEN)
        self.assertTrue(err.startswith("NEED_USER_INPUT foundry_auth: "), err)
        self.assertIn("api-key | entra-token", err)

    def test_foundry_without_a_credential_is_unavailable_and_names_both_variables(self):
        err = self.refused(["--judge", "microsoft", "--provider", "foundry", *FOUNDRY], 2)
        self.assertIn("Scan failed (provider_unavailable).", err)
        self.assertIn("AZURE_API_KEY", err)
        self.assertIn("AZURE_ENTRA_TOKEN", err)
        # A key of another route does not make it available.
        err = self.refused(["--judge", "microsoft", "--provider", "foundry", *FOUNDRY], 2,
                           OPENROUTER_API_KEY=OPENROUTER_KEY, OPENAI_API_KEY=OPENAI_KEY)
        self.assertIn("Scan failed (provider_unavailable).", err)

    def test_an_invalid_endpoint_is_refused_without_echo(self):
        for endpoint in ("http://dbh-fixture-resource.services.ai.azure.com",
                         "https://dbh-fixture-resource.example.com",
                         ENDPOINT + "/api/projects/dbh-fixture-project",
                         ENDPOINT + ":8443", ENDPOINT + "?x=1",
                         "https://user:pw@" + ENDPOINT_HOST, "https://203.0.113.9"):
            with self.subTest(endpoint=endpoint):
                err = self.refused(["--judge", "microsoft", "--provider", "foundry",
                                    "--foundry-endpoint", endpoint,
                                    "--foundry-deployment", DEPLOYMENT], 2,
                                   AZURE_API_KEY=AZURE_KEY)
                self.assertIn("Scan failed (endpoint_invalid).", err)
                self.assertIn("services.ai.azure.com", err)
                for part in ("dbh-fixture-project", "8443", "user:pw", "203.0.113.9",
                             "example.com", "x=1"):
                    self.assertNotIn(part, err)

    def test_an_invalid_deployment_name_is_invalid_request(self):
        err = self.refused(["--judge", "microsoft", "--provider", "foundry",
                            "--foundry-endpoint", ENDPOINT,
                            "--foundry-deployment", "bad name/sentinel"], 2,
                           AZURE_API_KEY=AZURE_KEY)
        self.assertIn("Scan failed (invalid_request).", err)
        self.assertNotIn("sentinel", err)

    def test_the_flag_choices_are_closed(self):
        for extra in (["--judge", "google"], ["--foundry-auth", "password"],
                      ["--provider", "azure", "--judge", "microsoft"]):
            with self.subTest(extra=extra), self.assertRaises(SystemExit) as caught, \
                    redirect_stderr(io.StringIO()):
                cli.main(self.argv(*extra))
            self.assertEqual(caught.exception.code, 2)
        self.assertFalse(self.read.called)


class BuildTests(unittest.TestCase):
    """The factory builds the provider of the chosen pair, reading nothing else."""

    def build(self, *argv, **environment):
        args = parsed(*argv)
        with clean_provider_env(**environment):
            return cli.make_provider(args), args

    def test_each_valid_pair_builds_its_provider(self):
        provider, args = self.build("--judge", "openai", "--provider", "openai",
                                    OPENAI_API_KEY=OPENAI_KEY)
        self.assertIsInstance(provider, DecisionsProvider)
        self.assertEqual((args.selected_judge, args.selected_provider), ("openai", "openai"))
        for judge, model in (("openai", LUNA), ("microsoft", MICROSOFT)):
            with self.subTest(judge=judge):
                provider, args = self.build("--judge", judge, "--provider", "openrouter",
                                            OPENROUTER_API_KEY=OPENROUTER_KEY)
                self.assertIsInstance(provider, OpenRouterProvider)
                self.assertEqual(provider.identity.model, model)
                self.assertEqual(provider.model_spec.judge, judge)
                self.assertEqual(cli.judge_of_provider(provider), judge)
                self.assertEqual(args.selected_judge, judge)
        provider, args = self.build("--judge", "microsoft", "--provider", "foundry", *FOUNDRY,
                                    AZURE_API_KEY=AZURE_KEY)
        self.assertIsInstance(provider, FoundryProvider)
        self.assertEqual((provider.identity.model, cli.judge_of_provider(provider)),
                         (DEPLOYMENT, "microsoft"))
        self.assertEqual(args.selected_auth, "api-key")

    def test_the_models_default_to_the_judges_and_may_be_named(self):
        for judge, model in (("openai", LUNA), ("microsoft", MICROSOFT)):
            provider, _ = self.build("--judge", judge, "--provider", "openrouter",
                                     "--model", model, OPENROUTER_API_KEY=OPENROUTER_KEY)
            self.assertEqual(provider.identity.model, model)
        provider, _ = self.build("--judge", "openai", "--provider", "openai",
                                 "--model", "gpt-6-luna", OPENAI_API_KEY=OPENAI_KEY)
        self.assertEqual(provider.identity.model, "gpt-6-luna")

    def test_the_foundry_provider_holds_one_exchange(self):
        provider, _ = self.build("--judge", "microsoft", "--provider", "foundry", *FOUNDRY,
                                 AZURE_API_KEY=AZURE_KEY)
        try:
            self.assertIsNone(provider._pool)
        finally:
            provider.close()

    def test_foundry_auth_picks_the_header(self):
        both = {"AZURE_API_KEY": AZURE_KEY, "AZURE_ENTRA_TOKEN": ENTRA_TOKEN}
        base = ("--judge", "microsoft", "--provider", "foundry", *FOUNDRY)
        provider, args = self.build(*base, "--foundry-auth", "api-key", **both)
        self.assertEqual(provider.auth_headers(), {"api-key": AZURE_KEY})
        self.assertEqual(args.selected_auth, "api-key")
        provider, args = self.build(*base, "--foundry-auth", "entra-token", **both)
        self.assertEqual(provider.auth_headers(), {"Authorization": "Bearer " + ENTRA_TOKEN})
        self.assertEqual(args.selected_auth, "entra-token")
        # One variable set selects its mode without the flag.
        provider, args = self.build(*base, AZURE_ENTRA_TOKEN=ENTRA_TOKEN)
        self.assertEqual(provider.auth_headers(), {"Authorization": "Bearer " + ENTRA_TOKEN})
        self.assertEqual(args.selected_auth, "entra-token")
        provider, args = self.build(*base, AZURE_API_KEY=AZURE_KEY)
        self.assertEqual(provider.auth_headers(), {"api-key": AZURE_KEY})
        # An explicit mode whose credential is missing is unavailable, not inferred.
        provider, _ = self.build(*base, "--foundry-auth", "entra-token",
                                 AZURE_API_KEY=AZURE_KEY)
        with self.assertRaises(ProviderError) as caught:
            provider.require_available()
        self.assertEqual(caught.exception.code, "provider_unavailable")

    def test_the_environment_stands_in_for_the_foundry_flags_and_the_flag_wins(self):
        base = ("--judge", "microsoft", "--provider", "foundry")
        provider, _ = self.build(*base, AZURE_API_KEY=AZURE_KEY,
                                 DBH_FOUNDRY_ENDPOINT=ENDPOINT,
                                 DBH_FOUNDRY_DEPLOYMENT="env-deployment")
        self.assertEqual(provider.identity.model, "env-deployment")
        provider, _ = self.build(*base, "--foundry-deployment", "flag-deployment",
                                 AZURE_API_KEY=AZURE_KEY, DBH_FOUNDRY_ENDPOINT=ENDPOINT,
                                 DBH_FOUNDRY_DEPLOYMENT="env-deployment")
        self.assertEqual(provider.identity.model, "flag-deployment")

    def test_the_judge_comes_from_the_flag_else_the_environment(self):
        args = parsed("--provider", "openrouter")
        with clean_provider_env(DBH_JUDGE="microsoft", OPENROUTER_API_KEY=OPENROUTER_KEY):
            self.assertEqual(cli.make_provider(args).model_spec.judge, "microsoft")
        args = parsed("--judge", "openai", "--provider", "openrouter")
        with clean_provider_env(DBH_JUDGE="microsoft", OPENROUTER_API_KEY=OPENROUTER_KEY):
            self.assertEqual(cli.make_provider(args).model_spec.judge, "openai")

    def test_a_namespace_without_a_judge_is_refused(self):
        with clean_provider_env(), self.assertRaises(cli.JudgeChoiceNeeded):
            cli.make_provider(argparse.Namespace(provider="openai"))
        with clean_provider_env(), self.assertRaises(ProviderError) as caught:
            cli.make_provider(argparse.Namespace(judge="google", provider="openai"))
        self.assertEqual(caught.exception.code, "invalid_judge")

    def test_a_custom_provider_names_no_judge(self):
        self.assertIsNone(cli.judge_of_provider(object()))


class RunTests(Temporary):
    """The notice, the summary line and the hints of a run that reaches the scan."""

    def run_scan(self, *extra, result=None, **environment):
        with patch.object(cli, "scan", return_value=report() if result is None else result):
            return self.run_cli(*extra, **environment)

    def test_the_microsoft_judge_prints_the_notice_once_on_each_route(self):
        for extra, environment in (
                (["--judge", "microsoft", "--provider", "openrouter"],
                 {"OPENROUTER_API_KEY": OPENROUTER_KEY}),
                (["--judge", "microsoft", "--provider", "foundry", *FOUNDRY],
                 {"AZURE_API_KEY": AZURE_KEY}),
                (["--judge", "microsoft", "--provider", "foundry", *FOUNDRY],
                 {"AZURE_ENTRA_TOKEN": ENTRA_TOKEN})):
            with self.subTest(extra=extra[:4]):
                code, out, err = self.run_scan(*extra, **environment)
                self.assertEqual(code, 0, err)
                self.assertEqual(err.count(NOTICE), 1)
                self.assertEqual(err.count("experimental"), 1)
                lines = err.splitlines()
                # The notice precedes the run itself, and the run is named.
                self.assertLess(lines.index(NOTICE),
                                next(i for i, line in enumerate(lines)
                                     if line.startswith("Results run:")))
                self.assertIn("2/2 source lines assessed (judge microsoft).", err)
                # The output directory exists only now, and holds no secret.
                files = [item for item in self.out.rglob("*") if item.is_file()]
                self.assertTrue(files)
                for item in files:
                    for secret in SECRETS:
                        self.assertNotIn(secret, item.read_text(encoding="utf-8"))
                self._wipe()

    def _wipe(self):
        shutil.rmtree(self.out, ignore_errors=True)

    def test_the_openai_judge_prints_no_notice_and_keeps_its_summary(self):
        for route, environment in (("openai", {"OPENAI_API_KEY": OPENAI_KEY}),
                                   ("openrouter", {"OPENROUTER_API_KEY": OPENROUTER_KEY})):
            with self.subTest(route=route):
                code, out, err = self.run_scan("--judge", "openai", "--provider", route,
                                               **environment)
                self.assertEqual(code, 0, err)
                self.assertNotIn("experimental", err)
                self.assertNotIn("Microsoft", err)
                self.assertIn("1 call(s) attempted; 2/2 source lines assessed.", err)
                self._wipe()

    def test_a_refused_run_prints_no_notice(self):
        base = ["--judge", "microsoft"]
        for extra, environment, expected in (
                ([*base], {}, 3),
                ([*base, "--provider", "openai"], {"OPENAI_API_KEY": OPENAI_KEY}, 3),
                ([*base, "--provider", "openrouter"], {}, 2),
                ([*base, "--provider", "openrouter", "--model", LUNA],
                 {"OPENROUTER_API_KEY": OPENROUTER_KEY}, 2),
                ([*base, "--provider", "foundry"], {"AZURE_API_KEY": AZURE_KEY}, 3),
                ([*base, "--provider", "foundry", "--foundry-endpoint", "http://x.example",
                  "--foundry-deployment", DEPLOYMENT], {"AZURE_API_KEY": AZURE_KEY}, 2)):
            with self.subTest(extra=extra):
                code, out, err = self.run_scan(*extra, **environment)
                self.assertEqual((code, out), (expected, ""))
                self.assertNotIn("experimental", err)
                self.assertFalse(self.out.exists())

    def test_a_credential_in_the_source_refuses_the_run_before_the_notice(self):
        for label, text, extra, environment in (
                ("openrouter key", OPENROUTER_KEY,
                 ["--judge", "microsoft", "--provider", "openrouter"],
                 {"OPENROUTER_API_KEY": OPENROUTER_KEY}),
                ("azure key under the other judge", AZURE_KEY,
                 ["--judge", "microsoft", "--provider", "openrouter"],
                 {"OPENROUTER_API_KEY": OPENROUTER_KEY, "AZURE_API_KEY": AZURE_KEY}),
                ("azure key on the openai route", AZURE_KEY,
                 ["--judge", "openai", "--provider", "openai"],
                 {"OPENAI_API_KEY": OPENAI_KEY, "AZURE_API_KEY": AZURE_KEY}),
                ("entra token on openrouter", ENTRA_TOKEN,
                 ["--judge", "openai", "--provider", "openrouter"],
                 {"OPENROUTER_API_KEY": OPENROUTER_KEY, "AZURE_ENTRA_TOKEN": ENTRA_TOKEN}),
                ("openai key on foundry", OPENAI_KEY,
                 ["--judge", "microsoft", "--provider", "foundry", *FOUNDRY],
                 {"AZURE_API_KEY": AZURE_KEY, "OPENAI_API_KEY": OPENAI_KEY})):
            with self.subTest(label):
                self.target.write_text(f"token = {text!r}\n", encoding="utf-8")
                code, out, err = self.run_scan(*extra, **environment)
                self.assertEqual((code, out), (2, ""))
                self.assertIn("Scan failed (sensitive_input).", err)
                self.assertNotIn("experimental", err)
                self.assertFalse(self.out.exists())

    def test_a_refused_entra_token_suggests_refreshing_it(self):
        stopped = report(status="incomplete", stop_reason="http_unauthorized")
        extra = ["--judge", "microsoft", "--provider", "foundry", *FOUNDRY]
        code, out, err = self.run_scan(*extra, result=stopped, AZURE_ENTRA_TOKEN=ENTRA_TOKEN)
        self.assertEqual(code, 2)
        self.assertIn("Provider stopped (http_unauthorized);", err)
        self.assertIn("AZURE_ENTRA_TOKEN token was refused; it may have expired.", err)
        self._wipe()
        code, out, err = self.run_scan(*extra, result=stopped, AZURE_API_KEY=AZURE_KEY)
        self.assertEqual(code, 2)
        self.assertIn("Provider stopped (http_unauthorized);", err)
        self.assertNotIn("expired", err)


class FailureTextTests(unittest.TestCase):
    def failure(self, *args):
        err = io.StringIO()
        with redirect_stderr(err):
            code = cli.failure(*args)
        self.assertEqual(code, 2)
        return err.getvalue()

    def test_provider_unavailable_for_foundry_names_both_credentials(self):
        text = self.failure("provider_unavailable", "foundry")
        self.assertIn("Scan failed (provider_unavailable).", text)
        self.assertIn("AZURE_API_KEY (--foundry-auth api-key)", text)
        self.assertIn("AZURE_ENTRA_TOKEN (--foundry-auth entra-token)", text)
        self.assertIn("foundry route", text)

    def test_the_other_routes_keep_their_hints(self):
        self.assertIn("Set OPENAI_API_KEY in the environment to enable the openai route",
                      self.failure("provider_unavailable", "openai"))
        self.assertIn("Set OPENROUTER_API_KEY in the environment to enable the openrouter",
                      self.failure("provider_unavailable", "openrouter"))
        self.assertIn("(--provider openai)", self.failure("provider_unavailable"))

    def test_invalid_judge_and_endpoint_never_echo_a_value(self):
        text = self.failure("invalid_judge", None, "microsoft")
        self.assertEqual(text, "Scan failed (invalid_judge).\n"
                               "DBH_JUDGE must be one of: openai, microsoft.\n")
        text = self.failure("endpoint_invalid", "foundry", "microsoft")
        self.assertTrue(text.startswith("Scan failed (endpoint_invalid).\n"))
        self.assertNotIn("dbh-fixture", text)

    def test_an_unauthorized_entra_token_suggests_a_refresh(self):
        text = self.failure("http_unauthorized", "foundry", "microsoft", "entra-token")
        self.assertIn("AZURE_ENTRA_TOKEN", text)
        self.assertIn("never refreshes", text)
        for auth in ("api-key", None):
            self.assertEqual(self.failure("http_unauthorized", "foundry", "microsoft", auth),
                             "Scan failed (http_unauthorized).\n")

    def test_the_help_marks_foundry_not_yet_verified_live_and_the_judge_experimental(self):
        text = " ".join(cli.parser().format_help().split())
        self.assertIn("not yet verified live", text)
        self.assertIn("--judge {openai,microsoft}", text)
        self.assertIn("Microsoft-Decision-1, experimental", text)
        for flag in ("--foundry-endpoint", "--foundry-deployment", "--foundry-auth"):
            self.assertIn(flag, text)


if __name__ == "__main__":
    unittest.main()
