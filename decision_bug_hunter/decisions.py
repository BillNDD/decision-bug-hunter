"""OpenAI Decisions adapter for the documented ``POST /v1/decisions`` endpoint.

The endpoint, request and response shapes follow the public documentation of
2026-10-06 (public beta, model ``gpt-6-luna``). The adapter uses only the
standard library: one HTTPS request per local batch through
``exchange.HttpsExchange`` (one TLS context and at most one kept-alive
connection per provider, an absolute per-call deadline), no SDK, no retry,
no backoff, no redirect following, no proxy, no image input and no fallback
model. The credential is read from the environment once, at construction,
and never enters request bodies, receipts, reports or error text. HTTP error
bodies are never read or journaled.
"""
from __future__ import annotations

from collections.abc import Mapping
import json
import math
import os
import re
from typing import Any

from .exchange import ExchangeError, HttpsExchange
from .protocol import (CONTRACT_VERSION, MAX_RESPONSE_BYTES, ProviderError,
                       _constant, _decimal, _json, _pairs, _secret_in,
                       validate_questions)
from .providers import ProviderIdentity, ProviderRequest, ProviderResponse


PROVIDER_NAME = "openai-decisions"
MODEL = "gpt-6-luna"
HOST = "api.openai.com"
PORT = 443
PATH = "/v1/decisions"
CREDENTIAL_VARIABLE = "OPENAI_API_KEY"
ORGANIZATION_VARIABLE = "OPENAI_ORG_ID"
PROJECT_VARIABLE = "OPENAI_PROJECT_ID"
# Local bound on the translated body. The local envelope is at most 24 KiB;
# translation adds only names, type tags and the two predicate criteria.
MAX_BODY_BYTES = 64 * 1024
# Credentials and routing identifiers are single-line printable ASCII tokens.
_HEADER_TOKEN = re.compile(r"[!-~]{1,4096}\Z")
_PREDICATE_FORMAT = "{instructions}\nAnswer true if: {true}\nAnswer false if: {false}"
_STATUS_CODES = {401: "http_unauthorized", 403: "http_unauthorized",
                 429: "http_rate_limited"}


def _question(name: str, question: Mapping[str, Any]) -> dict[str, Any]:
    """Local Noul/Choice question to a documented predicate/choice question."""
    criteria = question["criteria"]
    if question["type"] == "noul":
        return {"type": "predicate", "name": name,
                "instructions": _PREDICATE_FORMAT.format(
                    instructions=question["instructions"],
                    true=criteria["true"], false=criteria["false"])}
    return {"type": "choice", "name": name, "instructions": question["instructions"],
            "choices": [{"value": value, "description": description}
                        for value, description in criteria.items()]}


def _translate(payload: bytes) -> tuple[bytes, dict[str, Any]]:
    if type(payload) is not bytes:
        raise ProviderError("invalid_request")
    try:
        data = json.loads(payload.decode("utf-8"))
    except (UnicodeError, ValueError):
        raise ProviderError("invalid_request") from None
    if (type(data) is not dict or data.keys() != {"contract", "state", "questions"}
            or data["contract"] != CONTRACT_VERSION or type(data["state"]) is not dict):
        raise ProviderError("invalid_request")
    questions: dict[str, Any] = data["questions"]
    validate_questions(questions)
    try:
        # The shared evidence is the exact state fragment of the local
        # envelope, so one request hash describes both representations.
        body = {"model": MODEL, "input": _json(data["state"]).decode("utf-8"),
                "questions": [_question(name, question)
                              for name, question in questions.items()]}
        wire = _json(body)
    except ValueError:
        raise ProviderError("invalid_request") from None
    if len(wire) > MAX_BODY_BYTES:
        raise ProviderError("request_too_large")
    return wire, questions


def translate_request(payload: bytes) -> bytes:
    """Local ``dbh-judge-v1`` envelope bytes to the documented request body."""
    return _translate(payload)[0]


def _usage(value: Any) -> dict[str, Any] | None:
    """Keep only the two locally validated counters; absent usage is unknown."""
    if value is None:
        return None
    if type(value) is not dict:
        return {"input_tokens": None, "output_tokens": None}
    return {"input_tokens": value.get("input_tokens"),
            "output_tokens": value.get("output_tokens")}


def _table(entries: Any) -> dict[str, Any]:
    if type(entries) is not list:
        raise ProviderError("response_distribution")
    table: dict[str, Any] = {}
    for entry in entries:
        if (type(entry) is not dict or type(entry.get("value")) is not str
                or "probability" not in entry or entry["value"] in table):
            raise ProviderError("response_distribution")
        table[entry["value"]] = entry["probability"]
    return table


def _answers(items: Any, questions: Mapping[str, Any]) -> dict[str, Any]:
    """Associate answers by echoed name; every expected name exactly once."""
    if type(items) is not list:
        raise ProviderError("response_schema")
    result: dict[str, Any] = {}
    refused = False
    for item in items:
        if type(item) is not dict:
            raise ProviderError("response_schema")
        name, kind = item.get("name"), item.get("type")
        if type(name) is not str or name not in questions or name in result:
            raise ProviderError("response_schema")
        if kind == "refusal":
            refused = True
            result[name] = None
        elif questions[name]["type"] == "noul":
            if kind != "predicate" or "probability" not in item:
                raise ProviderError("response_schema")
            result[name] = {"type": "noul", "noul": item["probability"]}
        else:
            if kind != "choice" or not {"choice", "probabilities", "confidence"} <= item.keys():
                raise ProviderError("response_schema")
            result[name] = {"type": "choice", "choice": item["choice"],
                            "probabilities": _table(item["probabilities"]),
                            "confidence": item["confidence"]}
    if result.keys() != questions.keys():
        raise ProviderError("response_schema")
    if refused:
        # A declined question withholds the whole atomic batch; nothing is
        # substituted for the missing judgment.
        raise ProviderError("response_refused")
    return result


def translate_response(raw: bytes, questions: Mapping[str, Any],
                       api_key: str = "") -> ProviderResponse:
    """Documented response bytes to a local ``ProviderResponse``.

    Usage learned from a well-formed envelope is retained even when the
    answers are rejected; that rejection travels as ``ProviderResponse.error``
    so the gateway journals both. Undocumented fields are ignored, never kept.
    The gateway still validates every returned answer object exactly.
    """
    if type(raw) is not bytes or len(raw) > MAX_RESPONSE_BYTES:
        raise ProviderError("response_too_large")
    if api_key and _secret_in(api_key, [raw]):
        raise ProviderError("response_sensitive")
    try:
        data = json.loads(raw.decode("utf-8"), object_pairs_hook=_pairs,
                          parse_float=_decimal, parse_constant=_constant)
    except ProviderError:
        raise
    except Exception:
        raise ProviderError("response_invalid_json") from None
    if api_key and _secret_in(api_key, [data]):
        raise ProviderError("response_sensitive")
    if type(data) is not dict or "answers" not in data:
        raise ProviderError("response_schema")
    usage = _usage(data.get("usage"))
    try:
        model = data.get("model")
        if type(model) is not str or (model != MODEL and not model.startswith(MODEL + "-")):
            raise ProviderError("response_model")
        answers = _answers(data["answers"], questions)
    except ProviderError as exc:
        return ProviderResponse({}, usage, True, exc.code)
    return ProviderResponse(answers, usage)


def _status_error(status: int) -> str:
    if status in _STATUS_CODES:
        return _STATUS_CODES[status]
    if 300 <= status < 400:
        return "http_redirect"
    if status >= 500:
        return "http_server_error"
    return "http_rejected"


def _exchange(exchange: HttpsExchange, body: bytes, headers: Mapping[str, str],
              timeout: float) -> bytes:
    """One HTTPS POST to the fixed documented origin; nothing is retried.

    The deadline is absolute from now: connect, TLS, send and every receive
    share it. Error-code mapping is unchanged from the single-shot adapter.
    """
    error: str | None = None
    try:
        outcome = exchange.post(body, headers, exchange.deadline(timeout))
    except ExchangeError as exc:
        error = "deadline_exceeded" if exc.kind == "timeout" else "transport_failed"
    if error is not None:
        # Raised outside the handler: no exception text or context is attached.
        raise ProviderError(error)
    if outcome.status != 200:
        raise ProviderError(_status_error(outcome.status))
    return outcome.body


def _token(value: Any) -> str | None:
    if type(value) is not str or not _HEADER_TOKEN.fullmatch(value):
        return None
    return value


class DecisionsProvider:
    """Hosted adapter; construction reads the environment and nothing else.

    Without a usable ``OPENAI_API_KEY`` every operation raises
    ``provider_unavailable`` before any source read, output or network use.
    Optional ``OPENAI_ORG_ID`` and ``OPENAI_PROJECT_ID`` become the routing
    headers used by the official SDKs; a malformed value raises
    ``routing_invalid`` the same way, and the value itself is never kept,
    journaled or printed. Later environment changes are not read.
    """

    identity = ProviderIdentity(PROVIDER_NAME, model=MODEL)

    def __init__(self, api_key: str | None = None, *,
                 environ: Mapping[str, str] | None = None,
                 exchange: HttpsExchange | None = None) -> None:
        env: Mapping[str, str] = os.environ if environ is None else environ
        # One exchange, hence one TLS context and connection, per provider.
        # Nothing is built or opened until the first dispatch.
        self._exchange = exchange if exchange is not None else HttpsExchange(
            HOST, PATH, port=PORT)
        key = env.get(CREDENTIAL_VARIABLE, "") if api_key is None else api_key
        self._api_key = _token(key)
        self._routing: dict[str, str] = {}
        self._routing_invalid = False
        for variable, header in ((ORGANIZATION_VARIABLE, "OpenAI-Organization"),
                                 (PROJECT_VARIABLE, "OpenAI-Project")):
            value = env.get(variable, "")
            if value:
                if _token(value) is None:
                    self._routing_invalid = True
                else:
                    self._routing[header] = value
        if self._routing_invalid:
            # No partial routing: a request never goes out with one header.
            self._routing = {}

    def require_available(self) -> None:
        if self._api_key is None:
            raise ProviderError("provider_unavailable")
        if self._routing_invalid:
            raise ProviderError("routing_invalid")

    def check_sensitive(self, *values: Any) -> None:
        """Reject the literal active credential anywhere in local data."""
        if self._api_key is not None and _secret_in(self._api_key, values):
            raise ProviderError("sensitive_input")

    def decide(self, request: ProviderRequest) -> ProviderResponse:
        self.require_available()
        assert self._api_key is not None
        if type(request) is not ProviderRequest:
            raise ProviderError("invalid_request")
        timeout = request.timeout_seconds
        if type(timeout) not in (int, float) or not math.isfinite(timeout):
            raise ProviderError("invalid_deadline")
        if timeout <= 0:
            raise ProviderError("deadline_exceeded")
        body, questions = _translate(request.payload)
        if _secret_in(self._api_key, [body]):
            raise ProviderError("sensitive_input")
        headers = {"Authorization": "Bearer " + self._api_key,
                   "Content-Type": "application/json", "Accept": "application/json",
                   "Accept-Encoding": "identity", **self._routing}
        raw = _exchange(self._exchange, body, headers, float(timeout))
        return translate_response(raw, questions, self._api_key)

    def close(self) -> None:
        """Close the kept-alive connection, if any; the provider stays usable."""
        self._exchange.close()
