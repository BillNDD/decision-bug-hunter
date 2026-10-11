"""OpenRouter route to the Decisions judges (``openai/gpt-6-luna-decisions`` and
``microsoft/microsoft-decision-1``), which share one endpoint and request shape.

OpenRouter's ``POST /api/alpha/decisions`` accepts DBH's local envelope
almost as is, so the request is a byte splice of the local envelope rather
than a re-encoding: with ``local = {"contract":...,"state":S,"questions":Q}``
the wire body is ``{"model":M,"state":S,"questions":Q<routing>}``. One
``request_sha256`` (of the local envelope) therefore describes the request on
both routes; the receipt also records the adapter's ``wire_sha256``.

Routing privacy defaults to ``"provider":{"allow_fallbacks":false,
"data_collection":"deny"}``. ``account-default`` omits the object (the CLI
discloses that once per run); ``zdr`` appends ``"zdr":true``, for which no
endpoint existed on 2026-10-06. ``session_id``, ``user``, ``trace`` and the
``HTTP-Referer`` / ``X-Title`` attribution headers are never sent and have no
option.

Responses carry an answer map keyed by question name, the echoed model,
an optional upstream ``provider`` and ``usage`` with ``cost``; the cost is
split out before the gateway's exact usage validation. Only an explicit
``{"type":"refusal"}`` counts as a refusal (an answer-scoped
``question_refused``; two or more withhold the batch as ``response_refused``)
and a choice without its vector is an answer-scoped
``response_vector_missing``; any other unknown answer type is a batch-level
``response_schema``. Error bodies keep only structural fields
(numeric ``error.code``, moderation and routing-metadata key presence, and
token-charset ``metadata.error_type``, ``provider_code``, ``provider_name``),
never ``message``, ``reasons``, ``flagged_input`` or routing metadata values.
"""
from __future__ import annotations

from collections.abc import Iterable, Mapping
from decimal import Decimal
import json
import re
from typing import Any

from .exchange import HttpsExchange, Outcome
from .hosted import (HostedProvider, ModelSpec, RouteSpec, identifier, model_echo_ok,
                     model_returned, upstream_name)
from .protocol import (CONTRACT_VERSION, DEFAULT_POLICY_PLACEMENT, MAX_QUESTIONS,
                       MAX_REFUSALS_PER_REQUEST, MAX_RESPONSE_BYTES,
                       STATE_PLACEMENT_MAX_QUESTIONS, STATE_PLACEMENT_MAX_REQUEST_BYTES,
                       ProviderError, _REQUEST_PREFIX,
                       _constant, _decimal, _json, _pairs, _secret_in, validate_questions)
from .providers import ProviderResponse


PROVIDER_NAME = "openrouter-decisions"
MODEL = "openai/gpt-6-luna-decisions"
MICROSOFT_MODEL = "microsoft/microsoft-decision-1"
HOST = "openrouter.ai"
PORT = 443
#: Pinned: the alpha path may move, and a move must be a reviewed change.
PATH = "/api/alpha/decisions"
CREDENTIAL_VARIABLE = "OPENROUTER_API_KEY"
EXPECTED_UPSTREAM = "OpenAI"
ROUTING_CHOICES = ("deny", "account-default")
DEFAULT_ROUTING = "deny"
MAX_BODY_BYTES = 64 * 1024
_ECHO_SUFFIXES = (re.compile(r"-[0-9]{8}"),)
_CHOICE_KEYS = frozenset({"type", "choice", "probabilities", "confidence"})
_NOUL_KEYS = frozenset({"type", "noul"})
_REFUSAL_KEYS = frozenset({"type", "name"})
_TOKEN = re.compile(r"[A-Za-z0-9_.:-]{1,64}\Z")
_MAX_COST = Decimal(10)

ROUTE = RouteSpec(
    name=PROVIDER_NAME, selector="openrouter", host=HOST, path=PATH,
    credential_variable=CREDENTIAL_VARIABLE,
    models=(ModelSpec(MODEL, price_in_per_mtok=Decimal("0.10"),
                      price_out_upper_per_mtok=Decimal("0"),
                      confidence_identity="chance_normalized_p1",
                      expected_upstream=EXPECTED_UPSTREAM,
                      # S12b: the route accepts 200 questions and batch
                      # geometry moved no answer; raised for policy-in-state
                      # requests only (ADR-5(5)).
                      state_placement_max_questions=STATE_PLACEMENT_MAX_QUESTIONS,
                      state_placement_max_envelope_bytes=STATE_PLACEMENT_MAX_REQUEST_BYTES),
            # The second judge on the same endpoint and request shape, verified
            # live 2026-10-11. No raised state-placement caps (owner decision
            # 5A): 64 questions and 24 KiB under either policy placement.
            # Probabilities are full-precision floats; the upstream is journaled
            # and not flagged until one has been observed.
            ModelSpec(MICROSOFT_MODEL, price_in_per_mtok=Decimal("0.042"),
                      price_out_upper_per_mtok=Decimal("0"),
                      confidence_identity="chance_normalized_p1",
                      expected_upstream=None, judge="microsoft",
                      probability_precision="full",
                      # The price was read live on this date; the shared table
                      # date (2026-10-06) predates the model.
                      price_table_date="2026-10-11")),
    default_model=MODEL, port=PORT)


def routing_fragment(routing: str = DEFAULT_ROUTING, zdr: bool = False) -> bytes:
    """The bytes appended after ``questions``; empty for the account default."""
    if routing == "deny":
        fields = b'"allow_fallbacks":false,"data_collection":"deny"'
    elif routing == "account-default":
        fields = b""
    else:
        raise ProviderError("invalid_request")
    if type(zdr) is not bool:
        raise ProviderError("invalid_request")
    if zdr:
        fields += (b"," if fields else b"") + b'"zdr":true'
    return b',"provider":{' + fields + b"}" if fields else b""


def encode_request(payload: bytes, model: str = MODEL, routing: str = DEFAULT_ROUTING,
                   zdr: bool = False, max_questions: int = MAX_QUESTIONS
                   ) -> tuple[bytes, dict[str, Any]]:
    """Splice the local envelope into the OpenRouter body; nothing is re-encoded."""
    if (type(payload) is not bytes or not payload.startswith(_REQUEST_PREFIX)
            or not payload.endswith(b"}")):
        raise ProviderError("invalid_request")
    try:
        data = json.loads(payload.decode("utf-8"))
    except (UnicodeError, ValueError):
        raise ProviderError("invalid_request") from None
    if (type(data) is not dict or list(data) != ["contract", "state", "questions"]
            or data["contract"] != CONTRACT_VERSION or type(data["state"]) is not dict):
        raise ProviderError("invalid_request")
    questions: dict[str, Any] = data["questions"]
    validate_questions(questions, max_questions)
    wire = b"".join((b'{"model":', _json(model), b',"state":',
                     payload[len(_REQUEST_PREFIX):-1], routing_fragment(routing, zdr), b"}"))
    if len(wire) > MAX_BODY_BYTES:
        raise ProviderError("request_too_large")
    return wire, questions


def _usage(value: Any) -> tuple[dict[str, Any] | None, Decimal | None, bool]:
    """Counters for the gateway, and the reported cost split out of them.

    Returns (usage, cost, cost_invalid). Absent usage is unknown; a cost that
    is not a finite number in [0, 10) is invalid and counts as unknown.
    """
    if value is None:
        return None, None, False
    if type(value) is not dict:
        return {"input_tokens": None, "output_tokens": None}, None, False
    usage = {"input_tokens": value.get("input_tokens"),
             "output_tokens": value.get("output_tokens")}
    if "cost" not in value:
        return usage, None, False
    cost = value["cost"]
    if type(cost) is int:
        cost = Decimal(cost)
    if type(cost) is not Decimal or not cost.is_finite() or not 0 <= cost < _MAX_COST:
        return usage, None, True
    return usage, cost, False


def _answers(items: Any, questions: Mapping[str, Any]
             ) -> tuple[dict[str, Any], dict[str, str], int]:
    """The answer map, exactly the requested names, in question order.

    Returns the usable answers, the answer-scoped defects (an explicit
    refusal is ``question_refused``; a choice without its probability vector
    or confidence is ``response_vector_missing``) and the order flag. More
    than one refusal in a request withholds the batch (``response_refused``).
    """
    if type(items) is not dict or items.keys() != questions.keys():
        raise ProviderError("response_schema")
    result: dict[str, Any] = {}
    scoped: dict[str, str] = {}
    for name, question in questions.items():
        item = items[name]
        if type(item) is not dict:
            raise ProviderError("response_schema")
        kind = item.get("type")
        if kind == "refusal":
            if not item.keys() <= _REFUSAL_KEYS or item.get("name", name) != name:
                raise ProviderError("response_schema")
            scoped[name] = "question_refused"
        elif question["type"] == "noul":
            if kind != "noul" or item.keys() != _NOUL_KEYS:
                raise ProviderError("response_schema")
            result[name] = {"type": "noul", "noul": item["noul"]}
        else:
            if kind != "choice" or not item.keys() <= _CHOICE_KEYS or "choice" not in item:
                raise ProviderError("response_schema")
            if not {"probabilities", "confidence"} <= item.keys():
                scoped[name] = "response_vector_missing"
                continue
            result[name] = {"type": "choice", "choice": item["choice"],
                            "probabilities": item["probabilities"],
                            "confidence": item["confidence"]}
    if sum(code == "question_refused" for code in scoped.values()) > MAX_REFUSALS_PER_REQUEST:
        raise ProviderError("response_refused")
    return result, scoped, int(list(items) != list(questions))


def _metadata(error: Mapping[str, Any] | None) -> Mapping[str, Any] | None:
    if error is None or type(error.get("metadata")) is not dict:
        return None
    metadata: Mapping[str, Any] = error["metadata"]
    return metadata


def _flags(error: Mapping[str, Any] | None) -> tuple[bool, bool]:
    """(moderation, routing metadata), by key presence only."""
    metadata = _metadata(error)
    if metadata is None:
        return False, False
    return (("reasons" in metadata or "flagged_input" in metadata),
            ("failed_routing_step" in metadata or "routing_funnel" in metadata))


def error_fields(status: int, error: Mapping[str, Any] | None) -> dict[str, Any]:
    """Receipt-only structural fields of an OpenRouter error object (ADR-8(3))."""
    if error is None:
        return {}
    fields: dict[str, Any] = {}
    code = error.get("code")
    if type(code) is int and (code == status or (status == 200 and 100 <= code <= 599)):
        fields["error_code"] = code
    fields["moderation"], fields["routing_metadata"] = _flags(error)
    metadata = _metadata(error) or {}
    for key, name in (("error_type", "provider_error_type"), ("provider_code", "provider_code")):
        value = metadata.get(key)
        if (type(value) is str and _TOKEN.fullmatch(value)) or (
                type(value) is int and 0 <= value < 2**31):
            fields[name] = value
    provider = upstream_name(metadata.get("provider_name"))
    if provider is not None:
        fields["provider_name"] = provider
    return fields


def status_code(status: int, error: Mapping[str, Any] | None = None) -> str:
    """The OpenRouter status table (ADR-2(2))."""
    moderation, routing = _flags(error)
    if 300 <= status < 400:
        return "http_redirect"
    if status == 403:
        return "provider_moderated" if moderation else "http_forbidden"
    if status == 404:
        return "routing_no_endpoint" if routing else "route_unavailable"
    if status == 503:
        return "routing_no_endpoint" if routing else "http_unavailable"
    fixed = {401: "http_unauthorized", 402: "http_payment_required",
             408: "http_request_timeout", 413: "request_too_large",
             429: "http_rate_limited", 524: "http_provider_timeout", 529: "http_overloaded"}
    if status in fixed:
        return fixed[status]
    if status >= 500:
        return "http_server_error"
    return "http_rejected"


def decode_response(raw: bytes, questions: Mapping[str, Any],
                    credentials: Iterable[str] = (), *, model: str = MODEL,
                    expected_upstream: str | None = EXPECTED_UPSTREAM) -> ProviderResponse:
    """OpenRouter 200 bytes to a local ``ProviderResponse``.

    Requires ``answers`` (an object) and ``model``; ``usage``, ``id`` and
    ``provider`` are optional and other top-level keys are ignored and never
    journaled. Usage and cost learned from a well-formed body are kept even
    when the answers are rejected.
    """
    credentials = tuple(item for item in credentials if item)
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
    # Without a backslash every decoded string is a verbatim slice of raw, and
    # an ASCII credential found there is already found in raw above, so the
    # decoded walk is needed only when an escape is present.
    if ((b"\\" in raw or not all(credential.isascii() for credential in credentials))
            and any(_secret_in(credential, [data]) for credential in credentials)):
        raise ProviderError("response_sensitive")
    if type(data) is not dict:
        raise ProviderError("response_schema")
    provenance: dict[str, Any] = {}
    returned = model_returned(data.get("model"))
    if returned is not None:
        provenance["model_returned"] = returned
    if data.get("provider") is not None:
        upstream = upstream_name(data["provider"])
        if upstream is not None:
            provenance["upstream_provider"] = upstream
        if expected_upstream is not None and upstream != expected_upstream:
            provenance["upstream_provider_unexpected"] = True
    usage, cost, cost_invalid = _usage(data.get("usage"))
    if cost_invalid:
        provenance["cost_error"] = "invalid"
    if "answers" not in data:
        if "error" in data:
            error = data["error"] if type(data["error"]) is dict else None
            return ProviderResponse({}, usage, True, "provider_error_in_body", cost_usd=cost,
                                    provenance={**provenance, **error_fields(200, error)})
        # Neither answers nor an error: a schema defect, but the usage and
        # cost of the (billed) attempt are still known.
        return ProviderResponse({}, usage, True, "response_schema", cost_usd=cost,
                                provenance=provenance)
    try:
        if not model_echo_ok(data.get("model"), model, _ECHO_SUFFIXES):
            raise ProviderError("response_model")
        answers, scoped, mismatch = _answers(data["answers"], questions)
    except ProviderError as exc:
        return ProviderResponse({}, usage, True, exc.code, cost_usd=cost, provenance=provenance)
    return ProviderResponse(answers, usage, cost_usd=cost, scoped=scoped,
                            provenance=provenance, order_mismatch=mismatch)


class OpenRouterProvider(HostedProvider):
    """The OpenRouter route; construction reads the environment and nothing else.

    Without a usable ``OPENROUTER_API_KEY`` every operation raises
    ``provider_unavailable`` before any source read, output or network use.
    """

    route = ROUTE

    def __init__(self, api_key: str | None = None, *,
                 environ: Mapping[str, str] | None = None,
                 exchange: HttpsExchange | None = None,
                 model: str | None = None, routing: str = DEFAULT_ROUTING,
                 zdr: bool = False,
                 policy_placement: str = DEFAULT_POLICY_PLACEMENT,
                 max_connections: int = 1) -> None:
        if routing not in ROUTING_CHOICES or type(zdr) is not bool:
            raise ProviderError("invalid_request")
        super().__init__(api_key, environ=environ, exchange=exchange, model=model,
                         policy_placement=policy_placement, max_connections=max_connections)
        self.routing = routing
        self.zdr = zdr

    def encode(self, payload: bytes,
               max_questions: int = MAX_QUESTIONS) -> tuple[bytes, dict[str, Any]]:
        return encode_request(payload, self.model_spec.id, self.routing, self.zdr,
                              max_questions)

    def decode(self, raw: bytes, questions: Mapping[str, Any],
               outcome: Outcome) -> ProviderResponse:
        return decode_response(raw, questions, self._credentials, model=self.model_spec.id,
                               expected_upstream=self.model_spec.expected_upstream)

    def status_error(self, status: int, error: dict[str, Any] | None,
                     outcome: Outcome) -> tuple[str, dict[str, Any]]:
        return status_code(status, error), error_fields(status, error)

    def header_ids(self, outcome: Outcome) -> dict[str, Any]:
        generation_id = identifier(outcome.header("x-generation-id"))
        return {} if generation_id is None else {"generation_id": generation_id}
