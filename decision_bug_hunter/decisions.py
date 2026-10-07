"""OpenAI Decisions adapter for the documented ``POST /v1/decisions`` endpoint.

The endpoint, request and response shapes follow the public documentation of
2026-10-06 (public beta, model ``gpt-6-luna``). The adapter uses only the
standard library: one HTTPS request per local batch through
``exchange.HttpsExchange`` (one TLS context and at most one kept-alive
connection per provider, an absolute per-call deadline), no SDK, no retry,
no backoff, no redirect following, no proxy, no image input and no fallback
model. The credential is read from the environment once, at construction,
and never enters request bodies, receipts, reports or error text.

A non-200 body is read only when it is small JSON free of every configured
credential, and only structural fields are kept from it (``error.type``,
``error.code`` and, on 400/422, an ``error.param`` path into DBH-authored
request structure); the message never is (ADR-8).
"""
from __future__ import annotations

from collections.abc import Iterable, Mapping
from decimal import Decimal
import json
import os
import re
from typing import Any

from .exchange import HttpsExchange, Outcome
from .hosted import (HostedProvider, ModelSpec, RouteSpec, identifier, model_echo_ok,
                     model_returned, token)
from .protocol import (CONTRACT_VERSION, MAX_RESPONSE_BYTES, ProviderError,
                       _constant, _decimal, _json, _pairs, _secret_in,
                       validate_questions)
from .providers import ProviderResponse


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
_PREDICATE_FORMAT = "{instructions}\nAnswer true if: {true}\nAnswer false if: {false}"
#: A dated snapshot of the requested model: ``-YYYYMMDD`` or ``-YYYY-MM-DD``.
_ECHO_SUFFIXES = (re.compile(r"-[0-9]{8}"), re.compile(r"-[0-9]{4}-[0-9]{2}-[0-9]{2}"))
#: Matched exactly on ``error.code`` or ``error.type`` of a 429 (ADR-2(2)).
QUOTA_CODES = frozenset({"insufficient_quota", "billing_hard_limit_reached",
                         "billing_not_active"})
OVERLOADED_CODE = "server_is_overloaded"
_ERROR_TOKEN = re.compile(r"[a-z0-9_.-]{1,64}\Z")
_PARAM_SEGMENT = re.compile(r"([a-z_]{1,32})(?:\[[0-9]{1,3}\])?\Z")
_PARAM_FIRST = frozenset({"model", "input", "questions", "safety_identifier"})
_PARAM_LATER = frozenset({"type", "name", "instructions", "choices", "levels", "value",
                          "description", "label", "role", "content", "text"})

ROUTE = RouteSpec(
    name=PROVIDER_NAME, selector="openai", host=HOST, path=PATH,
    credential_variable=CREDENTIAL_VARIABLE,
    models=(ModelSpec(MODEL, price_in_per_mtok=Decimal("0.10"),
                      price_out_upper_per_mtok=Decimal("0")),),
    default_model=MODEL, port=PORT)


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


def _translate(payload: bytes, model: str = MODEL) -> tuple[bytes, dict[str, Any]]:
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
        body = {"model": model, "input": _json(data["state"]).decode("utf-8"),
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


def _answers(items: Any, questions: Mapping[str, Any]) -> tuple[dict[str, Any], int]:
    """Associate answers by echoed name; every expected name exactly once.

    Returns the answers in question order and 1 when they arrived in a
    different order (counted, never fatal: association is by name).
    """
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
    mismatch = int(list(result) != list(questions))
    return {name: result[name] for name in questions}, mismatch


def param_path(value: Any) -> str | None:
    """``error.param`` only as a path of known DBH request field names.

    The first segment names a top-level request field, later ones nested
    question fields; each may carry one index of up to three digits; at
    most four segments. Such a path cannot carry source text or a key.
    """
    if type(value) is not str:
        return None
    parts = value.split(".")
    if not 1 <= len(parts) <= 4:
        return None
    for index, part in enumerate(parts):
        match = _PARAM_SEGMENT.fullmatch(part)
        if match is None or match.group(1) not in (_PARAM_LATER if index else _PARAM_FIRST):
            return None
    return value


def error_fields(status: int, error: Mapping[str, Any] | None) -> dict[str, Any]:
    """Receipt-only structural fields of an OpenAI error object (ADR-8(2))."""
    fields: dict[str, Any] = {}
    if error is None:
        return fields
    for key, name in (("type", "error_type"), ("code", "error_code")):
        value = error.get(key)
        if type(value) is str and _ERROR_TOKEN.fullmatch(value):
            fields[name] = value
    if status in (400, 422) and error.get("param") is not None:
        path = param_path(error["param"])
        if path is None:
            fields["param_withheld"] = True
        else:
            fields["param"] = path
    return fields


def _names(error: Mapping[str, Any] | None, values: Iterable[str]) -> bool:
    if error is None:
        return False
    wanted = frozenset(values)
    return any(type(error.get(key)) is str and error[key] in wanted
               for key in ("code", "type"))


def status_code(status: int, error: Mapping[str, Any] | None = None) -> str:
    """The OpenAI-direct status table (ADR-2(2))."""
    if 300 <= status < 400:
        return "http_redirect"
    fixed = {401: "http_unauthorized", 403: "http_forbidden", 404: "route_unavailable",
             408: "http_request_timeout", 413: "request_too_large"}
    if status in fixed:
        return fixed[status]
    if status == 429:
        return "http_quota_exhausted" if _names(error, QUOTA_CODES) else "http_rate_limited"
    if status == 503 and _names(error, (OVERLOADED_CODE,)):
        return "http_overloaded"
    if status >= 500:
        return "http_server_error"
    return "http_rejected"


def translate_response(raw: bytes, questions: Mapping[str, Any],
                       api_key: str | Iterable[str] = "") -> ProviderResponse:
    """Documented response bytes to a local ``ProviderResponse``.

    ``api_key`` is the credential, or every configured credential, that must
    not appear in the body. Usage learned from a well-formed envelope is
    retained even when the answers are rejected; that rejection travels as
    ``ProviderResponse.error`` so the gateway journals both. A 200 carrying
    ``error`` and no ``answers`` is ``provider_error_in_body``. Undocumented
    fields are ignored, never kept. The gateway still validates every
    returned answer object exactly.
    """
    credentials = tuple(item for item in ((api_key,) if isinstance(api_key, str)
                                          else api_key) if item)
    if type(raw) is not bytes or len(raw) > MAX_RESPONSE_BYTES:
        raise ProviderError("response_too_large")
    if any(_secret_in(credential, [raw]) for credential in credentials):
        raise ProviderError("response_sensitive")
    try:
        data = json.loads(raw.decode("utf-8"), object_pairs_hook=_pairs,
                          parse_float=_decimal, parse_constant=_constant)
    except ProviderError:
        raise
    except Exception:
        raise ProviderError("response_invalid_json") from None
    if any(_secret_in(credential, [data]) for credential in credentials):
        raise ProviderError("response_sensitive")
    if type(data) is not dict:
        raise ProviderError("response_schema")
    provenance: dict[str, Any] = {}
    returned = model_returned(data.get("model"))
    if returned is not None:
        provenance["model_returned"] = returned
    if "answers" not in data:
        if "error" in data:
            error = data["error"] if type(data["error"]) is dict else None
            return ProviderResponse({}, _usage(data.get("usage")), True,
                                    "provider_error_in_body",
                                    provenance={**provenance, **error_fields(200, error)})
        raise ProviderError("response_schema")
    usage = _usage(data.get("usage"))
    try:
        if not model_echo_ok(data.get("model"), MODEL, _ECHO_SUFFIXES):
            raise ProviderError("response_model")
        answers, mismatch = _answers(data["answers"], questions)
    except ProviderError as exc:
        return ProviderResponse({}, usage, True, exc.code, provenance=provenance)
    return ProviderResponse(answers, usage, provenance=provenance, order_mismatch=mismatch)


class DecisionsProvider(HostedProvider):
    """Hosted adapter; construction reads the environment and nothing else.

    Without a usable ``OPENAI_API_KEY`` every operation raises
    ``provider_unavailable`` before any source read, output or network use.
    Optional ``OPENAI_ORG_ID`` and ``OPENAI_PROJECT_ID`` become the routing
    headers used by the official SDKs; a malformed value raises
    ``routing_invalid`` the same way, and the value itself is never kept,
    journaled or printed. Later environment changes are not read.
    """

    route = ROUTE

    def __init__(self, api_key: str | None = None, *,
                 environ: Mapping[str, str] | None = None,
                 exchange: HttpsExchange | None = None,
                 model: str | None = None) -> None:
        super().__init__(api_key, environ=environ, exchange=exchange, model=model)
        env: Mapping[str, str] = os.environ if environ is None else environ
        self._routing: dict[str, str] = {}
        self._routing_invalid = False
        for variable, header in ((ORGANIZATION_VARIABLE, "OpenAI-Organization"),
                                 (PROJECT_VARIABLE, "OpenAI-Project")):
            value = env.get(variable, "")
            if value:
                if token(value) is None:
                    self._routing_invalid = True
                else:
                    self._routing[header] = value
        if self._routing_invalid:
            # No partial routing: a request never goes out with one header.
            self._routing = {}

    def require_available(self) -> None:
        super().require_available()
        if self._routing_invalid:
            raise ProviderError("routing_invalid")

    def encode(self, payload: bytes) -> tuple[bytes, dict[str, Any]]:
        return _translate(payload, self.model_spec.id)

    def extra_headers(self) -> dict[str, str]:
        return dict(self._routing)

    def decode(self, raw: bytes, questions: Mapping[str, Any],
               outcome: Outcome) -> ProviderResponse:
        return translate_response(raw, questions, self._credentials)

    def status_error(self, status: int, error: dict[str, Any] | None,
                     outcome: Outcome) -> tuple[str, dict[str, Any]]:
        return status_code(status, error), error_fields(status, error)

    def header_ids(self, outcome: Outcome) -> dict[str, Any]:
        request_id = identifier(outcome.header("x-request-id"))
        return {} if request_id is None else {"request_id": request_id}
