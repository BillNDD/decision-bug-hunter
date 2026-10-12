"""Microsoft Foundry route to Microsoft-Decision-1.

This route is not yet verified live. The adapter is built from Microsoft's public
documentation (Microsoft Learn, "Deploy and use Microsoft-Decision-1 in
Microsoft Foundry", updated 2026-10-09) and tested only against offline
fixtures of the documented shapes. Nothing here has been observed against a
real deployment: the response's usage field names, the dated form of the echo,
the exact error bodies and the service's real request limits are all unknown
until the owner has a deployment to run against (``VERIFIED_LIVE``).

The request is the same byte splice of the local envelope as the OpenRouter
route's, without the routing object:
``{"model":<deployment>,"state":S,"questions":Q}`` posted to
``<resource endpoint>/providers/microsoft/v1/systemone``. The deployment name
is the request's ``model``; the response's ``model`` names the underlying
model (``microsoft-decision-1``, optionally with a ``-YYYYMMDD`` suffix).
There is no ``api-version`` query and no ``score`` question.

Authentication is an ``api-key`` header (``AZURE_API_KEY``) or a
pre-acquired Microsoft Entra bearer token (``AZURE_ENTRA_TOKEN``, for example
from ``az account get-access-token --resource
https://cognitiveservices.azure.com``). DBH never acquires or refreshes a
token: one that expires mid-run is a 401 (``http_unauthorized``), which
blocks the gateway.

The endpoint is the owner's resource, so it is validated hard before any
connection: ``https`` only, no userinfo, port absent or 443, no path, query or
fragment, and a host under one of the Azure commercial-cloud suffixes. The
resource host is never written to a report, receipt or message; the report
names only its ``endpoint_family`` suffix.

Responses are decoded like OpenRouter's (an answer map by question name;
an explicit ``{"type":"refusal"}`` is answer-scoped; a choice without its
vector is ``response_vector_missing``) with three differences: the usage field
names are read tolerantly, there is no provider-reported cost (the cost is a
list-price estimate), and error bodies keep only ``error.code`` and
``error.type`` in a token charset, never the message.

The price is not an Azure price. The input price, the zero output price and
their date (2026-10-11) are the OpenRouter listing's, borrowed here because
no deployment price has been read. The cost in a report and the ``--max-cost``
bound on this route are therefore estimates until a deployment's real price is
confirmed.
"""
from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import replace
from decimal import Decimal
import json
import os
import re
from typing import Any
from urllib.parse import urlsplit

from .exchange import HttpsExchange, Outcome
from .hosted import (HostedProvider, ModelSpec, RouteSpec, identifier, model_echo_ok,
                     model_returned)
from .openrouter import _answers, encode_request
from .protocol import (DEFAULT_POLICY_PLACEMENT, MAX_QUESTIONS, MAX_RESPONSE_BYTES,
                       ProviderError, _constant, _decimal, _pairs, _secret_in)
from .providers import ProviderResponse


PROVIDER_NAME = "foundry-decisions"
PORT = 443
PATH = "/providers/microsoft/v1/systemone"
#: Foundry has not been run against a real deployment (see the module text).
VERIFIED_LIVE = False
ENDPOINT_VARIABLE = "DBH_FOUNDRY_ENDPOINT"
DEPLOYMENT_VARIABLE = "DBH_FOUNDRY_DEPLOYMENT"
API_KEY_VARIABLE = "AZURE_API_KEY"
TOKEN_VARIABLE = "AZURE_ENTRA_TOKEN"
AUTH_MODES = ("api-key", "entra-token")
_AUTH_VARIABLES = {"api-key": API_KEY_VARIABLE, "entra-token": TOKEN_VARIABLE}
#: The Azure commercial-cloud suffixes a resource endpoint may have (beta).
ENDPOINT_FAMILIES = ("services.ai.azure.com", "cognitiveservices.azure.com",
                     "openai.azure.com")
_HOST = re.compile(r"([a-z0-9][a-z0-9-]{1,62})\.(" + "|".join(
    re.escape(family) for family in ENDPOINT_FAMILIES) + r")\Z")
_PRINTABLE = re.compile(r"[!-~]{1,512}\Z")
_DEPLOYMENT = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}\Z")
#: The underlying model the response names, in the spellings seen in the
#: documentation and in the catalog, each optionally with a dated suffix.
UNDERLYING_MODELS = ("microsoft-decision-1", "Microsoft-Decision-1")
_ECHO_SUFFIXES = (re.compile(r"-[0-9]{8}"),)
_TOKEN = re.compile(r"[A-Za-z0-9_.:-]{1,64}\Z")
#: The usage counter names Foundry may use, as (input, output) pairs.
_USAGE_NAMES = (("input_tokens", "output_tokens"), ("prompt_tokens", "completion_tokens"))

#: The one allow-listed model of the route; an instance replaces ``id`` with
#: its deployment name. The price is the OpenRouter listing's list price in USD
#: per million input tokens, with its date, borrowed and not an Azure price
#: (see the module text); output is not billed. No
#: raised state-placement caps: 64 questions and 24 KiB (owner decision 5A).
TEMPLATE = ModelSpec("microsoft-foundry-deployment", price_in_per_mtok=Decimal("0.042"),
                     price_out_upper_per_mtok=Decimal("0"),
                     confidence_identity="chance_normalized_p1", expected_upstream=None,
                     judge="microsoft", probability_precision="full",
                     price_table_date="2026-10-11")
#: The class-level route is the template only: the host and the credential
#: variable belong to the instance (see ``FoundryProvider``).
ROUTE = RouteSpec(name=PROVIDER_NAME, selector="foundry", host="services.ai.azure.com",
                  path=PATH, credential_variable=API_KEY_VARIABLE, models=(TEMPLATE,),
                  default_model=TEMPLATE.id, port=PORT)


def validate_endpoint(endpoint: Any) -> tuple[str, str]:
    """(host, endpoint family) of a Foundry resource endpoint, else ``endpoint_invalid``.

    Accepts exactly ``https://<resource>.<family>`` with an optional ``:443``
    and an optional single trailing slash. A Foundry project endpoint
    (``/api/projects/...``), a query, a fragment, userinfo, a port other than
    443, another domain and an IP literal are all refused. Nothing from the
    value is ever put in an error.
    """
    if type(endpoint) is not str or _PRINTABLE.fullmatch(endpoint) is None:
        raise ProviderError("endpoint_invalid")
    if "?" in endpoint or "#" in endpoint or "\\" in endpoint or "%" in endpoint:
        raise ProviderError("endpoint_invalid")
    try:
        parts = urlsplit(endpoint)
        hostname = parts.hostname
    except ValueError:
        raise ProviderError("endpoint_invalid") from None
    if (parts.scheme != "https" or hostname is None or parts.path not in ("", "/")
            or parts.query or parts.fragment):
        raise ProviderError("endpoint_invalid")
    match = _HOST.fullmatch(hostname)
    # The netloc must be exactly the host, or the host and port 443: this
    # refuses userinfo, an empty or other port and anything urlsplit tolerates.
    if match is None or parts.netloc.lower() not in (hostname, hostname + ":443"):
        raise ProviderError("endpoint_invalid")
    return hostname, match.group(2)


def validate_deployment(deployment: Any) -> str:
    """The deployment name, else ``invalid_request``."""
    if type(deployment) is not str or _DEPLOYMENT.fullmatch(deployment) is None:
        raise ProviderError("invalid_request")
    return deployment


def _chosen_auth(auth: Any, key_given: bool, env: Mapping[str, str]) -> str:
    """The auth mode: the given one, else the one variable that is set.

    An explicit key argument without a mode is an API key. Both variables set
    and no mode is ambiguous (``invalid_request``; the command line asks
    first). Neither set selects ``api-key``, which is then unavailable.
    """
    if auth is not None:
        if type(auth) is not str or auth not in AUTH_MODES:
            raise ProviderError("invalid_request")
        return auth
    if key_given:
        return "api-key"
    has_key = bool(env.get(API_KEY_VARIABLE, ""))
    has_token = bool(env.get(TOKEN_VARIABLE, ""))
    if has_key and has_token:
        raise ProviderError("invalid_request")
    return "entra-token" if has_token else "api-key"


def _counter(value: Any) -> bool:
    return type(value) is int and 0 <= value < 2**63


def _usage(value: Any) -> tuple[dict[str, Any] | None, bool]:
    """(usage for the gateway, whether the shape was not recognized).

    Reads ``input_tokens`` and ``output_tokens``, or ``prompt_tokens`` and
    ``completion_tokens`` (``total_tokens`` and everything else is ignored).
    Absent usage is unknown. Any other shape, or counters that are not
    non-negative integers, is unknown and flagged ``unrecognized``: the field
    names are not verified live, and a billed 200 must not be lost to them.
    """
    if value is None:
        return None, False
    if type(value) is dict:
        for names in _USAGE_NAMES:
            if names[0] in value and names[1] in value:
                counters = (value[names[0]], value[names[1]])
                if all(_counter(item) for item in counters):
                    return {"input_tokens": counters[0], "output_tokens": counters[1]}, False
    return None, True


def error_fields(error: Mapping[str, Any] | None) -> dict[str, Any]:
    """Receipt-only fields of a Foundry error object: ``error.code`` and
    ``error.type`` when they are short tokens, never the message."""
    if error is None:
        return {}
    fields: dict[str, Any] = {}
    code = error.get("code")
    if (type(code) is str and _TOKEN.fullmatch(code)) or (
            type(code) is int and 100 <= code <= 599):
        fields["error_code"] = code
    kind = error.get("type")
    if type(kind) is str and _TOKEN.fullmatch(kind):
        fields["error_type"] = kind
    return fields


def status_code(status: int, error: Mapping[str, Any] | None = None) -> str:
    """The Foundry status table (400, 401, 403, 404, 422 and 429 are the
    documented statuses)."""
    if 300 <= status < 400:
        return "http_redirect"
    fixed = {401: "http_unauthorized", 403: "http_forbidden", 404: "route_unavailable",
             408: "http_request_timeout", 413: "request_too_large",
             429: "http_rate_limited"}
    if status in fixed:
        return fixed[status]
    if status >= 500:
        return "http_server_error"
    # 400, 422 (a wrong deployment name or question shape) and any other 4xx.
    return "http_rejected"


def decode_response(raw: bytes, questions: Mapping[str, Any],
                    credentials: Iterable[str] = ()) -> ProviderResponse:
    """Foundry 200 bytes to a local ``ProviderResponse``.

    Requires ``answers`` (an object) and an echoed underlying ``model``;
    ``usage`` is optional and every other key is ignored and never journaled.
    A ``cost`` in the usage is not read: Foundry reports none, so the cost is
    a list-price estimate. Usage learned from a well-formed body is kept even
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
    usage, unrecognized = _usage(data.get("usage"))
    if unrecognized:
        provenance["usage_shape"] = "unrecognized"
    if "answers" not in data:
        if "error" in data:
            error = data["error"] if type(data["error"]) is dict else None
            return ProviderResponse({}, usage, True, "provider_error_in_body",
                                    provenance={**provenance, **error_fields(error)})
        # Neither answers nor an error: a schema defect, but the usage of the
        # (billed) attempt is still known.
        return ProviderResponse({}, usage, True, "response_schema", provenance=provenance)
    try:
        if not any(model_echo_ok(data.get("model"), name, _ECHO_SUFFIXES)
                   for name in UNDERLYING_MODELS):
            raise ProviderError("response_model")
        answers, scoped, mismatch = _answers(data["answers"], questions)
    except ProviderError as exc:
        return ProviderResponse({}, usage, True, exc.code, provenance=provenance)
    return ProviderResponse(answers, usage, scoped=scoped, provenance=provenance,
                            order_mismatch=mismatch)


class FoundryProvider(HostedProvider):
    """The Foundry route; construction reads the environment and nothing else.

    ``endpoint`` and ``deployment`` default to ``DBH_FOUNDRY_ENDPOINT`` and
    ``DBH_FOUNDRY_DEPLOYMENT``; ``auth`` (``api-key`` or ``entra-token``)
    defaults to the one of ``AZURE_API_KEY`` and ``AZURE_ENTRA_TOKEN`` that is
    set. A bad endpoint is ``endpoint_invalid`` and a bad deployment name is
    ``invalid_request``, both before any connection. The credential of the
    chosen mode is read once; without it every operation raises
    ``provider_unavailable`` before any source read, output or network use.
    Every other configured provider key is still refused in outgoing data.

    The route is per instance: the validated resource host, and the credential
    variable of the chosen mode. ``endpoint_family`` (the suffix only, never
    the host) is what a report may name, and ``verified_live`` is False.
    """

    route = ROUTE
    verified_live = VERIFIED_LIVE

    def __init__(self, api_key: str | None = None, *,
                 environ: Mapping[str, str] | None = None,
                 exchange: HttpsExchange | None = None,
                 endpoint: str | None = None, deployment: str | None = None,
                 auth: str | None = None,
                 policy_placement: str = DEFAULT_POLICY_PLACEMENT,
                 max_connections: int = 1) -> None:
        env: Mapping[str, str] = os.environ if environ is None else environ
        host, family = validate_endpoint(
            env.get(ENDPOINT_VARIABLE, "") if endpoint is None else endpoint)
        name = validate_deployment(
            env.get(DEPLOYMENT_VARIABLE, "") if deployment is None else deployment)
        mode = _chosen_auth(auth, api_key is not None, env)
        spec = replace(TEMPLATE, id=name)
        self.route = RouteSpec(name=PROVIDER_NAME, selector="foundry", host=host, path=PATH,
                               credential_variable=_AUTH_VARIABLES[mode], models=(spec,),
                               default_model=name, port=PORT)
        super().__init__(api_key, environ=env, exchange=exchange,
                         policy_placement=policy_placement, max_connections=max_connections)
        self.auth = mode
        self.endpoint_family = family

    def encode(self, payload: bytes,
               max_questions: int = MAX_QUESTIONS) -> tuple[bytes, dict[str, Any]]:
        # The OpenRouter splice without its routing object. The size bound is
        # the same sanity bound; the binding caps are the local envelope's.
        return encode_request(payload, self.model_spec.id, "account-default", False,
                              max_questions)

    def auth_headers(self) -> dict[str, str]:
        assert self._api_key is not None
        if self.auth == "api-key":
            return {"api-key": self._api_key}
        return {"Authorization": "Bearer " + self._api_key}

    def decode(self, raw: bytes, questions: Mapping[str, Any],
               outcome: Outcome) -> ProviderResponse:
        return decode_response(raw, questions, self._credentials)

    def status_error(self, status: int, error: dict[str, Any] | None,
                     outcome: Outcome) -> tuple[str, dict[str, Any]]:
        return status_code(status, error), error_fields(error)

    def header_ids(self, outcome: Outcome) -> dict[str, Any]:
        request_id = identifier(outcome.header("x-request-id"))
        return {} if request_id is None else {"request_id": request_id}
