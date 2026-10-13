"""A configured key is protected by its core text: offline, fake values only.

A key pasted with a newline, a Windows variable with a trailing space or a
quoted key is not a header token, so it can never be sent, but its bare text
must still never leave the machine on another route. These tests drive the real
provider, gateway and exchange over a scripted origin and assert that nothing
is sent and nothing prints a value.
"""
from __future__ import annotations

from contextlib import redirect_stderr, redirect_stdout
import io
import json
from pathlib import Path
import tempfile
import unittest

from decision_bug_hunter import foundry, openrouter
from decision_bug_hunter.decisions import DecisionsProvider
from decision_bug_hunter import decisions, hosted, protocol
from decision_bug_hunter.hosted import CREDENTIAL_VARIABLES, configured_credentials
from decision_bug_hunter.foundry import FoundryProvider
from decision_bug_hunter.openrouter import OpenRouterProvider
from decision_bug_hunter.protocol import ProviderError, encode_request
from decision_bug_hunter.providers import ProviderRequest, RetryPolicy, ValidatedGateway
from tests import test_foundry
from tests.fakes import FakeClock, Reply, ScriptedHTTPS
from tests.support import openai_body, openrouter_body
from tests.test_openrouter import ANSWERS, METADATA, QUESTIONS, STATE, error_body, reply

OPENAI_SELECTED = "offline-openai-selected-key-3d51"
OPENROUTER_SELECTED = "offline-openrouter-selected-key-7a20"
#: The fake 32-hex shape of an Azure resource key, which no scanner recognizes.
CORE = "0f3c9a1b7e2d4c6a8b0e1f2a3c4d5e6f"
CORES = {
    "plain": CORE,
    "inner space": "0f3c9a1b7e2d4c6a 8b0e1f2a3c4d5e6f",
    "non-ascii": "0f3c9a1b7e2d4c6a“8b0e1f2aé3c4d5e6f",
}
#: The two halves of a key that holds a line break inside it.
HEAD = "0f3c9a1b7e2d4c6a"
TAIL = "8b0e1f2a3c4d5e6f"
FOUNDRY_KEY = "offline-azure-selected-key-5c18"
FOUNDRY_TOKEN = "offline.entra.selected-token-9e42"
#: Every character str.strip removes, found rather than listed.
WHITESPACE = tuple(chr(code) for code in range(0x110000) if chr(code).isspace())
#: How a core can arrive in a variable.
DECORATIONS = {
    "clean": "{}",
    "trailing space": "{} ",
    "trailing tab": "{}\t",
    "trailing CR": "{}\r",
    "trailing LF": "{}\n",
    "trailing CRLF": "{}\r\n",
    "leading space": " {}",
    "leading tab": "\t{}",
    "leading CR": "\r{}",
    "leading LF": "\n{}",
    "leading CRLF": "\r\n{}",
    "both sides": "\r\n \t{}\t \r\n",
    "double quotes": '"{}"',
    "single quotes": "'{}'",
    "quotes and newline": '"{}"\n',
    "padded quotes": " '{}' \r\n",
    "spaces inside quotes": '" {} "',
}


def decorate(label: str, core: str) -> str:
    return DECORATIONS[label].replace("{}", core)


def state_with(text: str, base: dict = STATE) -> dict:
    state = json.loads(json.dumps(base))
    state["excerpts"][0]["lines"][0]["text"] = text
    return state


def raw_reply(body: bytes, status: int = 200) -> Reply:
    return Reply(status=status, body=body, close_after=True, headers=[
        ("Content-Type", "application/json"), ("Content-Length", str(len(body)))])


class Rig:
    """One scripted origin, the selected route's provider over it and a gateway.

    ``route`` is None for the OpenAI and OpenRouter routes (the selected one is
    any route whose own variable is not the one tested) or ``"foundry"``, whose
    selected credential is the Azure variable that is not the one tested.
    """

    def __init__(self, test: unittest.TestCase, unselected: str, value: str, steps=(),
                 route: str | None = None) -> None:
        env = {unselected: value}
        self.base_state, self.questions, self.metadata = STATE, QUESTIONS, METADATA
        if route == "foundry":
            if unselected == "AZURE_API_KEY":
                env["AZURE_ENTRA_TOKEN"], auth = FOUNDRY_TOKEN, "entra-token"
            else:
                env["AZURE_API_KEY"], auth = FOUNDRY_KEY, "api-key"
            self.script = ScriptedHTTPS(list(steps), clock=FakeClock(), host=test_foundry.HOST)
            exchange = self.script.exchange(test_foundry.HOST, foundry.PATH)
            self.provider = FoundryProvider(environ=env, exchange=exchange, auth=auth,
                                            endpoint=test_foundry.ENDPOINT,
                                            deployment=test_foundry.DEPLOYMENT)
            self.base_state = test_foundry.STATE
            self.questions, self.metadata = test_foundry.QUESTIONS, test_foundry.METADATA
        elif unselected == "OPENROUTER_API_KEY":
            self.script = ScriptedHTTPS(list(steps), clock=FakeClock(), host=decisions.HOST)
            exchange = self.script.exchange(decisions.HOST, decisions.PATH)
            self.provider = DecisionsProvider(OPENAI_SELECTED, environ=env, exchange=exchange)
        else:
            self.script = ScriptedHTTPS(list(steps), clock=FakeClock(), host=openrouter.HOST)
            exchange = self.script.exchange(openrouter.HOST, openrouter.PATH)
            self.provider = OpenRouterProvider(OPENROUTER_SELECTED, environ=env,
                                               exchange=exchange)
        tmp = tempfile.TemporaryDirectory()
        test.addCleanup(tmp.cleanup)
        self.receipts = Path(tmp.name) / "receipts"
        self.gateway = ValidatedGateway(self.provider, self.receipts,
                                        retry_policy=RetryPolicy.none())
        test.addCleanup(self.gateway.close)

    def state_with(self, text: str) -> dict:
        return state_with(text, self.base_state)

    def evaluate(self, state=None):
        try:
            return self.gateway.evaluate(self.base_state if state is None else state,
                                         self.questions, metadata=self.metadata)
        except ProviderError as exc:
            return exc

    def receipt_text(self) -> str:
        return "".join(path.read_text(encoding="utf-8") for path in self.receipts.rglob("*.json"))

    def sent_nothing(self, test: unittest.TestCase) -> None:
        test.assertEqual(self.script.requests, [])
        test.assertEqual(self.script.connects, [])


def cases():
    """(unselected variable, core label, decoration label, value)."""
    for variable in CREDENTIAL_VARIABLES:
        for core_label, core in CORES.items():
            for label in DECORATIONS:
                yield variable, core_label, label, decorate(label, core)


class ConfiguredCredentialTests(unittest.TestCase):
    def test_every_variable_and_decoration_yields_its_core(self):
        for variable, core_label, label, value in cases():
            with self.subTest(variable=variable, core=core_label, decoration=label):
                found = configured_credentials({variable: value}, None)
                self.assertIn(CORES[core_label], found)
                self.assertEqual(len(found), len(set(found)))
                self.assertTrue(all(len(item) >= hosted._INACTIVE_MIN_LENGTH for item in found))

    def test_clean_values_are_unchanged(self):
        env = {"OPENAI_API_KEY": "offline-openai-clean-key-1111",
               "AZURE_API_KEY": CORE, "AZURE_ENTRA_TOKEN": "offline.entra.token-2222"}
        self.assertEqual(configured_credentials(env, None),
                         ("offline-openai-clean-key-1111", CORE, "offline.entra.token-2222"))
        self.assertEqual(configured_credentials(env, "offline-openai-clean-key-1111"),
                         ("offline-openai-clean-key-1111", CORE, "offline.entra.token-2222"))
        self.assertEqual(configured_credentials({}, None), ())
        self.assertEqual(configured_credentials({}, "active-key-value"), ("active-key-value",))

    def test_quoted_value_keeps_the_quoted_text_and_adds_the_core(self):
        found = configured_credentials({"AZURE_API_KEY": '"%s"' % CORE}, None)
        self.assertEqual(found, ('"%s"' % CORE, CORE))
        found = configured_credentials({"AZURE_API_KEY": " '%s'\r\n" % CORE}, None)
        self.assertEqual(found, (CORE,))
        # Only one matching pair comes off; mismatched quotes stay.
        self.assertEqual(configured_credentials({"AZURE_API_KEY": "\"%s'" % CORE}, None),
                         ("\"%s'" % CORE,))
        self.assertEqual(configured_credentials({"AZURE_API_KEY": "''%s''" % CORE}, None),
                         ("''%s''" % CORE, "'%s'" % CORE))

    def test_short_empty_and_non_string_values_are_not_credentials(self):
        env = {"OPENAI_API_KEY": "short\n", "OPENROUTER_API_KEY": "  \r\n\t",
               "AZURE_API_KEY": "", "AZURE_ENTRA_TOKEN": b"0123456789abcdef"}
        self.assertEqual(configured_credentials(env, None), ())  # type: ignore[arg-type]
        self.assertEqual(configured_credentials({"AZURE_API_KEY": "''"}, None), ())
        self.assertEqual(configured_credentials({"AZURE_API_KEY": "\"   \""}, None), ())

    def test_the_same_core_in_two_variables_is_listed_once(self):
        env = {"OPENAI_API_KEY": CORE, "AZURE_API_KEY": CORE + "\n", "OPENROUTER_API_KEY": ""}
        self.assertEqual(configured_credentials(env, CORE), (CORE,))

    def test_a_selected_key_with_whitespace_is_not_a_header_token(self):
        self.assertIsNone(hosted.token(CORE + "\n"))
        self.assertIsNone(hosted.token(" " + CORE))
        self.assertEqual(hosted.token(CORE), CORE)

    def test_every_whitespace_character_is_stripped_on_either_side(self):
        # ASCII and Unicode alike: vertical tab, form feed, the separators
        # U+001C-U+001F, U+0085, no-break space, em space, U+2028 and so on.
        self.assertIn("\x0b", WHITESPACE)
        self.assertIn("\x1f", WHITESPACE)
        self.assertIn("\xa0", WHITESPACE)
        self.assertIn(" ", WHITESPACE)
        for variable in CREDENTIAL_VARIABLES:
            for char in WHITESPACE:
                for value in (char + CORE, CORE + char, char * 3 + CORE + char * 2):
                    with self.subTest(variable=variable, char=hex(ord(char))):
                        self.assertEqual(configured_credentials({variable: value}, None), (CORE,))

    def test_a_whitespace_only_value_is_not_a_credential(self):
        for body in (" " * 8, "\n" * 9, " \r\n\t" * 4, " " * 8, "\x0b\x0c" * 5):
            for value in (body, '"%s"' % body, "'%s'\n" % body, ' "%s" ' % body):
                with self.subTest(value=value):
                    self.assertEqual(
                        configured_credentials({"AZURE_API_KEY": value, "OPENAI_API_KEY": value},
                                               None), ())

    def test_an_inner_line_break_adds_each_line(self):
        for variable in CREDENTIAL_VARIABLES:
            for glue in ("\n", "\r\n", "\r", "\n\n", " \n "):
                value = HEAD + glue + TAIL
                with self.subTest(variable=variable, glue=glue):
                    found = configured_credentials({variable: value}, None)
                    self.assertIn(HEAD, found)
                    self.assertIn(TAIL, found)
                    self.assertIn(value.strip(), found)
                    self.assertEqual(len(found), len(set(found)))
        found = configured_credentials({"AZURE_API_KEY": '"%s\r\n%s"\n' % (HEAD, TAIL)}, None)
        self.assertEqual(found, ('%s\r\n%s' % (HEAD, TAIL), HEAD, TAIL))
        # A line shorter than the minimum, or one that is blank, is not listed.
        found = configured_credentials({"AZURE_API_KEY": "short\n\n  \n" + HEAD}, None)
        self.assertEqual(found, ("short\n\n  \n" + HEAD, HEAD))
        self.assertEqual(configured_credentials({"AZURE_API_KEY": "tiny\nlines\nonly"}, None),
                         ("tiny\nlines\nonly",))


class OutgoingRefusalTests(unittest.TestCase):
    def test_a_source_line_with_the_bare_core_is_refused_before_any_send(self):
        for variable, core_label, label, value in cases():
            with self.subTest(variable=variable, core=core_label, decoration=label):
                rig = Rig(self, variable, value)
                core = CORES[core_label]
                outcome = rig.evaluate(state_with('AZURE_KEY = "%s"' % core))
                self.assertIsInstance(outcome, ProviderError)
                self.assertEqual(outcome.code, "sensitive_input")
                rig.sent_nothing(self)
                self.assertNotIn(core, rig.receipt_text())

    def test_every_part_of_the_state_is_checked(self):
        rig = Rig(self, "AZURE_API_KEY", CORE + "\r\n")
        questions = {"q": {**QUESTIONS["screen"], "instructions": "has " + CORE}}
        with self.assertRaises(ProviderError) as caught:
            rig.gateway.evaluate(STATE, questions, metadata=METADATA)
        self.assertEqual(caught.exception.code, "sensitive_input")
        with self.assertRaises(ProviderError) as caught:
            rig.provider.check_sensitive({"nested": [{"k": "x" + CORE + "y"}]})
        self.assertEqual(caught.exception.code, "sensitive_input")
        with self.assertRaises(ProviderError) as caught:
            rig.provider.check_sensitive(("t", {CORE: 1}))
        self.assertEqual(caught.exception.code, "sensitive_input")
        rig.provider.check_sensitive({"nested": ["clean text only"]})
        rig.sent_nothing(self)

    def test_the_encoded_request_body_is_checked_too(self):
        for variable, core_label, label, value in cases():
            if label not in ("clean", "trailing CRLF", "double quotes", "leading space"):
                continue
            with self.subTest(variable=variable, core=core_label, decoration=label):
                rig = Rig(self, variable, value)
                core = CORES[core_label]
                payload = encode_request(state_with("note " + core), QUESTIONS)
                with self.assertRaises(ProviderError) as caught:
                    rig.provider.decide(ProviderRequest(payload, 30.0))
                self.assertEqual(caught.exception.code, "sensitive_input")
                rig.sent_nothing(self)

    def test_every_whitespace_character_around_the_key_still_refuses_the_source(self):
        for variable in CREDENTIAL_VARIABLES:
            for char in WHITESPACE:
                with self.subTest(variable=variable, char=hex(ord(char))):
                    rig = Rig(self, variable, char + CORE + char)
                    outcome = rig.evaluate(rig.state_with("k = " + CORE))
                    self.assertIsInstance(outcome, ProviderError)
                    self.assertEqual(outcome.code, "sensitive_input")
                    rig.sent_nothing(self)

    def test_a_key_with_a_line_break_inside_is_refused_line_by_line(self):
        for variable in CREDENTIAL_VARIABLES:
            for glue in ("\n", "\r\n"):
                value = '"%s%s%s"\r\n' % (HEAD, glue, TAIL)
                for part in (HEAD, TAIL):
                    with self.subTest(variable=variable, glue=glue, part=part):
                        rig = Rig(self, variable, value)
                        outcome = rig.evaluate(rig.state_with("secret = " + part + " # x"))
                        self.assertIsInstance(outcome, ProviderError)
                        self.assertEqual(outcome.code, "sensitive_input")
                        rig.sent_nothing(self)
                        self.assertNotIn(part, rig.receipt_text())

    def test_a_quoted_whitespace_only_value_does_not_refuse_indented_source(self):
        for variable in CREDENTIAL_VARIABLES:
            for body in (" " * 8, "\n" * 9, "\t" * 8):
                with self.subTest(variable=variable, body=body):
                    good = (openai_body(ANSWERS) if variable == "OPENROUTER_API_KEY"
                            else openrouter_body(ANSWERS))
                    rig = Rig(self, variable, '"%s"' % body, [raw_reply(good)])
                    answers = rig.evaluate(rig.state_with(" " * 8 + "indented = 1"))
                    self.assertNotIsInstance(answers, ProviderError)
                    self.assertEqual(answers["screen"]["noul"], ANSWERS["screen"]["noul"])
                    self.assertEqual(len(rig.script.requests), 1)

    def test_a_clean_request_still_goes_out_with_a_decorated_unselected_key(self):
        rig = Rig(self, "AZURE_API_KEY", CORE + "\r\n",
                  [reply(openrouter_body(ANSWERS))])
        answers = rig.evaluate()
        self.assertEqual(answers["screen"]["noul"], ANSWERS["screen"]["noul"])
        (request,) = rig.script.requests
        self.assertNotIn(CORE.encode(), request.body)
        self.assertEqual(request.header("Authorization"), "Bearer " + OPENROUTER_SELECTED)


class ResponseRefusalTests(unittest.TestCase):
    def body(self, variable: str, **where) -> bytes:
        if variable == "OPENROUTER_API_KEY":
            return openai_body(ANSWERS, **where)
        return openrouter_body(ANSWERS, **where)

    def test_a_response_carrying_the_core_is_refused(self):
        for variable, core_label, label, value in cases():
            if label not in ("clean", "trailing CRLF", "leading tab", "single quotes",
                             "spaces inside quotes"):
                continue
            with self.subTest(variable=variable, core=core_label, decoration=label):
                core = CORES[core_label]
                payload = encode_request(STATE, QUESTIONS)
                for where in ({"id": core}, {"note": ["x", {"k": "pre " + core}]}):
                    rig = Rig(self, variable, value, [raw_reply(self.body(variable, **where))])
                    with self.assertRaises(ProviderError) as caught:
                        rig.provider.decide(ProviderRequest(payload, 30.0))
                    self.assertEqual(caught.exception.code, "response_sensitive")

    def test_an_escaped_core_in_a_response_is_refused(self):
        for variable, core_label, label, value in cases():
            if label not in ("clean", "trailing LF", "double quotes"):
                continue
            with self.subTest(variable=variable, core=core_label, decoration=label):
                core = CORES[core_label]
                escaped = "".join("\\u%04x" % ord(char) for char in core)
                body = self.body(variable, id="PLACEHOLDER").replace(
                    b'"PLACEHOLDER"', ('"%s"' % escaped).encode())
                self.assertNotIn(core.encode("utf-8"), body)
                rig = Rig(self, variable, value, [raw_reply(body)])
                with self.assertRaises(ProviderError) as caught:
                    rig.provider.decide(ProviderRequest(encode_request(STATE, QUESTIONS), 30.0))
                self.assertEqual(caught.exception.code, "response_sensitive")

    def test_a_json_escaped_inner_character_in_a_response_is_refused(self):
        core = 'abcd"efgh\\ijkl'
        for variable in ("AZURE_API_KEY", "OPENROUTER_API_KEY"):
            with self.subTest(variable=variable):
                body = json.dumps({"id": core}).encode()
                rig = Rig(self, variable, '"%s"\n' % core, [raw_reply(body)])
                with self.assertRaises(ProviderError) as caught:
                    rig.provider.decide(ProviderRequest(encode_request(STATE, QUESTIONS), 30.0))
                self.assertEqual(caught.exception.code, "response_sensitive")

    def test_an_error_body_carrying_the_core_is_withheld(self):
        for variable, core_label, label, value in cases():
            if label not in ("clean", "trailing CRLF", "double quotes"):
                continue
            with self.subTest(variable=variable, core=core_label, decoration=label):
                core = CORES[core_label]
                body = error_body(403, core)
                rig = Rig(self, variable, value, [raw_reply(body, 403)])
                outcome = rig.evaluate()
                self.assertIsInstance(outcome, ProviderError)
                receipt = json.loads(next(rig.receipts.rglob("*.json")).read_text("utf-8"))
                self.assertEqual(receipt["provider_error"], {"error_body": "withheld_sensitive"})
                self.assertNotIn(core, rig.receipt_text())

    def test_a_clean_response_passes_with_a_non_ascii_core_configured(self):
        core = CORES["non-ascii"]
        rig = Rig(self, "AZURE_API_KEY", core + "\n", [reply(openrouter_body(ANSWERS))])
        self.assertEqual(rig.evaluate()["screen"]["noul"], ANSWERS["screen"]["noul"])


def foundry_body(**where) -> bytes:
    data = json.loads(test_foundry.fixture("response_ok.json"))
    data.update(where)
    return json.dumps(data).encode()


class FoundryRouteTests(unittest.TestCase):
    """The same guarantees through the Foundry provider and its own gateway."""

    LABELS = ("clean", "trailing CRLF", "leading tab", "double quotes", "padded quotes",
              "spaces inside quotes", "both sides")

    def foundry_cases(self):
        for variable in CREDENTIAL_VARIABLES:
            for core_label, core in CORES.items():
                for label in self.LABELS:
                    yield variable, core_label, label, decorate(label, core)

    def test_a_source_line_with_the_bare_core_is_refused_before_any_send(self):
        for variable, core_label, label, value in self.foundry_cases():
            with self.subTest(variable=variable, core=core_label, decoration=label):
                rig = Rig(self, variable, value, route="foundry")
                core = CORES[core_label]
                outcome = rig.evaluate(rig.state_with('AZURE_KEY = "%s"' % core))
                self.assertIsInstance(outcome, ProviderError)
                self.assertEqual(outcome.code, "sensitive_input")
                rig.sent_nothing(self)
                self.assertNotIn(core, rig.receipt_text())

    def test_a_key_with_a_line_break_inside_is_refused_line_by_line(self):
        for variable in CREDENTIAL_VARIABLES:
            for part in (HEAD, TAIL):
                with self.subTest(variable=variable, part=part):
                    rig = Rig(self, variable, "%s\r\n%s\n" % (HEAD, TAIL), route="foundry")
                    outcome = rig.evaluate(rig.state_with("secret = " + part))
                    self.assertIsInstance(outcome, ProviderError)
                    self.assertEqual(outcome.code, "sensitive_input")
                    rig.sent_nothing(self)

    def test_every_whitespace_character_around_the_key_still_refuses_the_source(self):
        for variable in CREDENTIAL_VARIABLES:
            for char in WHITESPACE:
                with self.subTest(variable=variable, char=hex(ord(char))):
                    rig = Rig(self, variable, char + CORE + char, route="foundry")
                    outcome = rig.evaluate(rig.state_with("k = " + CORE))
                    self.assertEqual(getattr(outcome, "code", None), "sensitive_input")
                    rig.sent_nothing(self)

    def test_the_encoded_request_body_is_checked_too(self):
        for variable, core_label, label, value in self.foundry_cases():
            if label not in ("clean", "trailing CRLF", "double quotes"):
                continue
            with self.subTest(variable=variable, core=core_label, decoration=label):
                rig = Rig(self, variable, value, route="foundry")
                payload = encode_request(rig.state_with("note " + CORES[core_label]),
                                         rig.questions)
                with self.assertRaises(ProviderError) as caught:
                    rig.provider.decide(ProviderRequest(payload, 30.0))
                self.assertEqual(caught.exception.code, "sensitive_input")
                rig.sent_nothing(self)

    def test_a_response_carrying_the_core_is_refused(self):
        for variable, core_label, label, value in self.foundry_cases():
            if label not in ("clean", "trailing CRLF", "double quotes"):
                continue
            with self.subTest(variable=variable, core=core_label, decoration=label):
                core = CORES[core_label]
                for where in ({"id": core}, {"note": ["x", {"k": "pre " + core}]}):
                    rig = Rig(self, variable, value, [raw_reply(foundry_body(**where))],
                              route="foundry")
                    payload = encode_request(rig.base_state, rig.questions)
                    with self.assertRaises(ProviderError) as caught:
                        rig.provider.decide(ProviderRequest(payload, 30.0))
                    self.assertEqual(caught.exception.code, "response_sensitive")

    def test_an_escaped_core_in_a_response_is_refused(self):
        for variable, core_label, label, value in self.foundry_cases():
            if label not in ("clean", "trailing CRLF"):
                continue
            with self.subTest(variable=variable, core=core_label, decoration=label):
                core = CORES[core_label]
                escaped = "".join("\\u%04x" % ord(char) for char in core)
                body = foundry_body(id="PLACEHOLDER").replace(
                    b'"PLACEHOLDER"', ('"%s"' % escaped).encode())
                self.assertNotIn(core.encode("utf-8"), body)
                rig = Rig(self, variable, value, [raw_reply(body)], route="foundry")
                payload = encode_request(rig.base_state, rig.questions)
                with self.assertRaises(ProviderError) as caught:
                    rig.provider.decide(ProviderRequest(payload, 30.0))
                self.assertEqual(caught.exception.code, "response_sensitive")

    def test_an_error_body_carrying_the_core_is_withheld(self):
        for variable, core_label, label, value in self.foundry_cases():
            if label not in ("trailing CRLF", "double quotes"):
                continue
            with self.subTest(variable=variable, core=core_label, decoration=label):
                core = CORES[core_label]
                body = json.dumps({"error": {"code": "x", "message": "bad " + core}}).encode()
                rig = Rig(self, variable, value, [raw_reply(body, 401)], route="foundry")
                outcome = rig.evaluate()
                self.assertIsInstance(outcome, ProviderError)
                receipt = json.loads(next(rig.receipts.rglob("*.json")).read_text("utf-8"))
                self.assertEqual(receipt["provider_error"], {"error_body": "withheld_sensitive"})
                self.assertNotIn(core, rig.receipt_text())

    def test_a_clean_request_still_goes_out_with_a_decorated_unselected_key(self):
        for variable in CREDENTIAL_VARIABLES:
            with self.subTest(variable=variable):
                rig = Rig(self, variable, CORE + "\r\n",
                          [test_foundry.reply(test_foundry.fixture("response_ok.json"))],
                          route="foundry")
                outcome = rig.evaluate()
                self.assertNotIsInstance(outcome, ProviderError)
                (request,) = rig.script.requests
                self.assertNotIn(CORE.encode(), request.body)

    def test_a_selected_key_with_whitespace_is_unavailable_and_never_sent(self):
        for variable, auth in (("AZURE_API_KEY", "api-key"),
                               ("AZURE_ENTRA_TOKEN", "entra-token")):
            labels = [(label, decorate(label, FOUNDRY_KEY)) for label in DECORATIONS]
            labels += [("char %x" % ord(char), char + FOUNDRY_KEY + char) for char in WHITESPACE]
            labels.append(("inner space", "offline azure key"))
            for label, value in labels:
                if hosted.token(value) is not None:
                    # Quotes alone are printable ASCII: as today, such a value is the key.
                    continue
                with self.subTest(variable=variable, decoration=label):
                    script = ScriptedHTTPS([test_foundry.reply(
                        test_foundry.fixture("response_ok.json"))], clock=FakeClock(),
                        host=test_foundry.HOST)
                    exchange = script.exchange(test_foundry.HOST, foundry.PATH)
                    provider = FoundryProvider(
                        environ={variable: value}, exchange=exchange, auth=auth,
                        endpoint=test_foundry.ENDPOINT, deployment=test_foundry.DEPLOYMENT)
                    with self.assertRaises(ProviderError) as caught:
                        provider.require_available()
                    self.assertEqual(caught.exception.code, "provider_unavailable")
                    with tempfile.TemporaryDirectory() as tmp:
                        gateway = ValidatedGateway(provider, Path(tmp) / "r",
                                                   retry_policy=RetryPolicy.none())
                        self.addCleanup(gateway.close)
                        with self.assertRaises(ProviderError) as caught:
                            gateway.evaluate(test_foundry.STATE, test_foundry.QUESTIONS,
                                             metadata=test_foundry.METADATA)
                        self.assertEqual(caught.exception.code, "provider_unavailable")
                    self.assertEqual(script.requests, [])
                    self.assertEqual(script.connects, [])

    def test_the_selected_variables_own_core_is_protected_from_other_data(self):
        for variable, auth in (("AZURE_API_KEY", "api-key"),
                               ("AZURE_ENTRA_TOKEN", "entra-token")):
            with self.subTest(variable=variable):
                provider = FoundryProvider(
                    environ={variable: CORE + "\r\n"}, exchange=object(),  # type: ignore[arg-type]
                    auth=auth, endpoint=test_foundry.ENDPOINT,
                    deployment=test_foundry.DEPLOYMENT)
                with self.assertRaises(ProviderError) as caught:
                    provider.check_sensitive("line " + CORE)
                self.assertEqual(caught.exception.code, "sensitive_input")


class DecodeGateTests(unittest.TestCase):
    """The decoded walk and its ASCII gate stay correct for a non-ASCII core."""

    def check(self, raw: bytes, credentials, expected):
        for decode in (lambda: openrouter.decode_response(raw, QUESTIONS, credentials),
                       lambda: decisions.translate_response(raw, QUESTIONS, credentials),
                       lambda: foundry.decode_response(raw, QUESTIONS, credentials)):
            with self.assertRaises(ProviderError) as caught:
                decode()
            self.assertEqual(caught.exception.code, expected)

    def test_non_ascii_core_found_verbatim_or_escaped(self):
        core = CORES["non-ascii"]
        verbatim = json.dumps({"x": core}, ensure_ascii=False).encode("utf-8")
        escaped = json.dumps({"x": core}, ensure_ascii=True).encode("ascii")
        key_only = json.dumps({core: 1}, ensure_ascii=True).encode("ascii")
        for raw in (verbatim, escaped, key_only):
            with self.subTest(raw=raw[:20]):
                self.check(raw, (core,), "response_sensitive")
        self.assertNotIn(core.encode("utf-8"), escaped)

    def test_secret_in_finds_a_non_ascii_core_in_bytes_and_text(self):
        core = CORES["non-ascii"]
        self.assertTrue(protocol._secret_in(core, [("x" + core).encode("utf-8")]))
        self.assertTrue(protocol._secret_in(core, ["x" + core]))
        self.assertTrue(protocol._secret_in(core, [{"a": [b"..", core.encode("utf-8")]}]))
        self.assertFalse(protocol._secret_in(core, [b"plain ascii", "plain"]))
        self.assertFalse(protocol._secret_in(core, [b"\xff\xfe"]))
        # A lone surrogate in a key cannot match, and cannot raise.
        self.assertFalse(protocol._secret_in("ab\ud800cd", [b"abcd", "abcd"]))


class SelectedKeyTests(unittest.TestCase):
    def test_a_selected_key_with_whitespace_is_unavailable_and_never_sent(self):
        for label in DECORATIONS:
            value = decorate(label, "offline-openrouter-selected-key-7a20")
            if hosted.token(value) is not None:
                # Quotes alone are printable ASCII: as today, such a value is the key as it stands.
                continue
            with self.subTest(decoration=label):
                script = ScriptedHTTPS([reply(openrouter_body(ANSWERS))], clock=FakeClock(),
                                       host=openrouter.HOST)
                exchange = script.exchange(openrouter.HOST, openrouter.PATH)
                provider = OpenRouterProvider(
                    environ={"OPENROUTER_API_KEY": value}, exchange=exchange)
                with self.assertRaises(ProviderError) as caught:
                    provider.require_available()
                self.assertEqual(caught.exception.code, "provider_unavailable")
                with tempfile.TemporaryDirectory() as tmp:
                    gateway = ValidatedGateway(provider, Path(tmp) / "r",
                                               retry_policy=RetryPolicy.none())
                    self.addCleanup(gateway.close)
                    with self.assertRaises(ProviderError) as caught:
                        gateway.evaluate(STATE, QUESTIONS, metadata=METADATA)
                    self.assertEqual(caught.exception.code, "provider_unavailable")
                self.assertEqual(script.requests, [])
                self.assertEqual(script.connects, [])

    def test_the_openai_route_with_a_whitespace_key_is_unavailable(self):
        for value in ("offline-openai-selected-key-3d51\n", ' "offline-openai-key-3d51"',
                      "offline openai key"):
            with self.subTest(value=value):
                if value.startswith(' "'):
                    # Quotes are printable ASCII: this one is a header token with a space.
                    self.assertIsNone(hosted.token(value))
                provider = DecisionsProvider(environ={"OPENAI_API_KEY": value},
                                             exchange=object())  # type: ignore[arg-type]
                with self.assertRaises(ProviderError) as caught:
                    provider.require_available()
                self.assertEqual(caught.exception.code, "provider_unavailable")

    def test_the_selected_variables_own_core_is_protected_from_other_data(self):
        provider = OpenRouterProvider(environ={"OPENROUTER_API_KEY": CORE + "\r\n"},
                                      exchange=object())  # type: ignore[arg-type]
        with self.assertRaises(ProviderError) as caught:
            provider.check_sensitive("line " + CORE)
        self.assertEqual(caught.exception.code, "sensitive_input")

    def test_a_clean_selected_key_is_sent_exactly_as_before(self):
        script = ScriptedHTTPS([reply(openrouter_body(ANSWERS))], clock=FakeClock(),
                               host=openrouter.HOST)
        exchange = script.exchange(openrouter.HOST, openrouter.PATH)
        provider = OpenRouterProvider(environ={"OPENROUTER_API_KEY": OPENROUTER_SELECTED,
                                               "AZURE_API_KEY": CORE}, exchange=exchange)
        self.assertEqual(provider._credentials, (OPENROUTER_SELECTED, CORE))
        self.assertEqual(provider._api_key, OPENROUTER_SELECTED)


class NothingPrintsTests(unittest.TestCase):
    def test_no_value_is_printed_journaled_or_put_in_an_error(self):
        out, err = io.StringIO(), io.StringIO()
        seen = []
        with redirect_stdout(out), redirect_stderr(err):
            for variable, core_label, label, value in cases():
                if label not in ("clean", "trailing CRLF", "padded quotes", "both sides"):
                    continue
                core = CORES[core_label]
                rig = Rig(self, variable, value)
                outcome = rig.evaluate(state_with("k = " + core))
                self.assertIsInstance(outcome, ProviderError)
                seen.append((core, value, repr(outcome), str(outcome), outcome.code,
                             repr(getattr(outcome, "info", None)), rig.receipt_text()))
        text = out.getvalue() + err.getvalue()
        self.assertEqual(text, "")
        for core, value, *parts in seen:
            for part in parts:
                self.assertNotIn(core, part)
                self.assertNotIn(value, part)


if __name__ == "__main__":
    unittest.main()
