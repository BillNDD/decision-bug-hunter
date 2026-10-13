# Provider contract

This document describes DBH's internal judge interface, the four hosted
routes to the two decision models (OpenAI Decisions and Microsoft-Decision-1),
how statuses and answers are classified, and how retries, receipts and spend
work. The code is the reference; the offline tests pin every statement here.

| Route | `--judge` | `--provider` | Status |
|---|---|---|---|
| 1. OpenAI direct | `openai` | `openai` | verified live |
| 2. OpenRouter, OpenAI model | `openai` | `openrouter` | verified live |
| 3. OpenRouter, Microsoft model | `microsoft` (experimental) | `openrouter` | verified live |
| 4. Microsoft Foundry | `microsoft` (experimental) | `foundry` | **not yet verified live** |

## Internal interface

`ValidatedGateway(provider, receipt_dir, *, deadline_seconds=30.0,
rounding_places=None, retry_policy=None, clock=None, sleep=None, rng=None,
progress=None, reserve_floor_seconds=3.0, max_cost=None)` is the engine's
only path to a judge. It is a context manager; one gateway may serve
several scans. A `DecisionProvider` supplies a public `ProviderIdentity`
(`name`, `model`, `synthetic`), `require_available()`,
`decide(ProviderRequest)`, `check_sensitive(*values)` and `close()`. The
gateway also reports `judge` (`openai` or `microsoft`, from the provider's
model spec; None for a provider that declares none) and `full_precision`
(whether the model writes full-precision probabilities).

`ProviderRequest` holds owned JSON bytes (the local envelope
`{"contract":"dbh-judge-v1","state":...,"questions":...}`) and
`timeout_seconds`, the time left in the call's absolute deadline. The local
envelope exists for deterministic byte limits and request hashes; each route
turns it into its own wire body.

`ProviderResponse` carries normalized `answers`, optional `usage` (unknown
usage is `None`, never zero), `complete`, an optional whole-batch `error`
code learned after usage, `cost_usd` (a provider-reported cost), `scoped`
(answer-scoped defects the adapter found), receipt-only `provenance`
identifiers and `order_mismatch`.

| Local primitive | Engine purpose | Required local result |
|---|---|---|
| Noul (`noul`) | Screen, five bug lenses, context need, relevance, verification, refutation, relationship support, judge controls | A finite probability in [0, 1] that the statement is true |
| Choice (`choice`) | Rank and localize intervals, retrieve context, choose the next investigation step | The chosen option, a confidence, and a probability for every option |
| State | Numbered source and specification passages, explicit scope, selected evidence, operation history | Bounded context; its content is evidence, never instructions |
| Batch | Independent questions over one unchanged state | Answers matched by question name |

Local limits per request: 64 questions, a 24 KiB envelope, 16 KiB of state,
2 to 255 choice options, question names matching `[A-Za-z0-9_.-]{1,96}`.
Under `--policy-placement state`, a request whose state starts with the
policy entry may use the model's raised caps (OpenRouter with the OpenAI
model: 200 questions, 48 KiB; OpenAI direct, Microsoft-Decision-1 and Foundry
keep 64 and 24 KiB); the state cap grows only by the policy entry, so evidence
selection does not change.

### State layout and policy placement

The state layout is chosen per scan (`--state-layout`, `Config.state_layout`;
default `v1`) and recorded in the report configuration. `v1` is the
pre-release layout and policy text. `v2` starts the state with the four
DBH-written fields (`source_sha256`, `total_lines`, `context_scope`,
`specification_mode`) and its policy warns that every other field may
imitate the envelope. Requirement questions use the same corrected wording
in both layouts.

With `--policy-placement instructions` (default) the policy preamble is
prefixed to every question that carries it. With `state` it is sent once as
the first state key `policy` and removed from those questions; requests
without such a question are unchanged. Answers shift between placements, so
results are comparable only within one placement. The report records the
placement in `configuration` and, under `state`, a `request_geometry` record.

### Judge controls

With `--canaries on` (default) every request carries two extra noul
questions named `ctl_` plus 8 hex characters, at positions derived from a
hash of the request: "Does the supplied state declare a context_scope
value?" (must be true) and "Does any source line contain the word 'zebra'?"
(must be false; another listed word, or a wrong `total_lines`, when the
state contains it). A request whose must-true answer is below 0.90, whose
must-false answer is above 0.10, or whose control is missing or refused has
every answer withheld; the engine records `judge_control_failed`, never asks
that request again, and the scan is incomplete. Controls count toward
`--max-questions` and the cost bound. `--canaries off` sends the previous
request bytes exactly.

### Localization gate

Under legacy-v1, a localization choice answer passes through the gate set
by `--choice-gate` (`Config.choice_gate`, default `mass`). `mass` reads the
whole probability vector: it selects up to `--localization-beam-width`
maximal line runs whose lower-bound per-line overlap mass reaches
`--choice-mass` (default 0.5), and only while `none` plus `unlocalized`
(plus any undisplayed mass) stays below one half; one menu is asked per
target. `legacy` accepts an option when min(confidence, p[choice]) reaches
`--choice-confidence` and re-asks with a shrunken menu after each pick.
Rank, context and action choices always use the legacy rule, and
scoped-v2-beta does not gate localization. The report configuration records
`choice_gate` unless it is `legacy`; with `--choice-gate legacy` and
`--canaries off` a run reproduces the pre-beta request bytes and reports.

## Route 1: OpenAI direct (`--provider openai`)

`POST https://api.openai.com/v1/decisions`, bearer authentication with
`OPENAI_API_KEY`, optional `OpenAI-Organization` / `OpenAI-Project` headers
from `OPENAI_ORG_ID` / `OPENAI_PROJECT_ID`. Model `gpt-6-luna` only. This
route is implemented from the public documentation of 2026-10-06, pinned by
offline fixtures, and was exercised live on 2026-10-07 (a 5-request smoke
suite and two 34-case catalog runs; see [VALIDATION.md](VALIDATION.md)):
the model echo and usage without a cost field on every 200, and
`x-request-id` on every response, matched this description; every choice
vector had exact mass at two decimals with the choice equal to the argmax,
the confidence followed the same identity as on OpenRouter, and an unknown
request field returned 400 (`http_rejected`). Its 401, 429, 5xx and refusal
handling are pinned by fixtures only.

| Local | Request | Answer | Local result |
|---|---|---|---|
| `state` | `input`: the exact compact JSON of the state, byte-identical to the envelope fragment | | |
| `noul` question | `{"type":"predicate","name":id,"instructions": instructions + "\nAnswer true if: ..." + "\nAnswer false if: ..."}` | `{"type":"predicate","name","probability"}` | `{"type":"noul","noul":p}` |
| `choice` question | `{"type":"choice","name":id,"instructions","choices":[{"value","description"}...]}` in menu order | `{"type":"choice","name","choice","probabilities":[{"value","probability"}...],"confidence"}` | `{"type":"choice","choice","probabilities":{value:p},"confidence"}` |
| batch | one `questions` array | `answers` array matched by echoed `name` | every name exactly once, no extras; order differences are counted, not fatal |
| | | `{"type":"refusal","name"}` | one per request: answer-scoped `question_refused`; two or more: batch `response_refused` |
| | | `usage.input_tokens`, `usage.output_tokens` | local usage; absent usage is unknown |
| | | `model` | must be `gpt-6-luna` or `gpt-6-luna-YYYYMMDD` / `-YYYY-MM-DD`, else `response_model` |

A choice answer without `probabilities` or `confidence` is a batch-level
`response_schema` on this route. The translated body is capped at 64 KiB.
The `score` type and image input are not used.

## Route 2: OpenRouter (`--judge openai --provider openrouter`)

`POST https://openrouter.ai/api/alpha/decisions`, bearer authentication
with `OPENROUTER_API_KEY`. Model `openai/gpt-6-luna-decisions` for the OpenAI
judge (Route 3 is the same adapter with the Microsoft model).

The request is a byte splice of the local envelope:
`{"model":M,"state":S,"questions":Q,"provider":{...}}`, where `S` and `Q`
are the envelope's bytes unchanged, so one `request_sha256` describes the
request on both routes. The routing object is:

| `--openrouter-routing` | `--openrouter-zdr` | Appended |
|---|---|---|
| `deny` (default) | off | `"provider":{"allow_fallbacks":false,"data_collection":"deny"}` |
| `deny` | on | `"provider":{"allow_fallbacks":false,"data_collection":"deny","zdr":true}` |
| `account-default` | off | nothing (the CLI prints a notice once per run) |
| `account-default` | on | `"provider":{"zdr":true}` |

Live on 2026-10-06, `data_collection: deny` returned 200 and `zdr: true`
returned 404 with routing metadata (`routing_no_endpoint`). `session_id`,
`user`, `trace` and the `HTTP-Referer` / `X-Title` headers are never sent.
The wire body is capped at 64 KiB; the route accepted 200 questions and
rejected 201 with HTTP 400.

Responses are an object with `answers` (a map keyed by question name),
`model`, optional `provider` (the upstream, expected `OpenAI`), optional `id`
and `usage` `{input_tokens, output_tokens, cost}`:

- `answers` must have exactly the requested names. Noul answers are
  `{"type":"noul","noul":p}`; choice answers carry `choice`,
  `probabilities` (a map over every option) and `confidence`.
- An explicit `{"type":"refusal"}` is an answer-scoped `question_refused`
  (two or more withhold the batch as `response_refused`). A choice without
  `probabilities` or `confidence` is an answer-scoped
  `response_vector_missing`. Any other unknown answer type is a batch-level
  `response_schema`.
- `model` must be `openai/gpt-6-luna-decisions` exactly or followed by `-`
  and 8 digits (observed: a dated suffix), else `response_model`.
- `cost` is split out of `usage` before validation and becomes the attempt's
  `cost_usd`; a cost that is not a finite number in [0, 10) USD is recorded
  as invalid and counts as unknown.
- An upstream other than `OpenAI` is journaled as
  `upstream_provider_unexpected`.
- A 200 with `error` and no `answers` is `provider_error_in_body`; a 200
  with neither is `response_schema`, with its usage and cost kept.

## Route 3: Microsoft-Decision-1 through OpenRouter (`--judge microsoft --provider openrouter`)

**Experimental.** The same adapter, endpoint, bearer authentication
(`OPENROUTER_API_KEY`), request shape and response decoder as Route 2, with
the model `microsoft/microsoft-decision-1`. Verified live on 2026-10-11 (the
response shape) and 2026-10-12 (the 34-case catalog through the shipped CLI,
182 requests; see [VALIDATION.md](VALIDATION.md)). What differs from Route 2:

- **Request.** The same byte splice, with the routing object. The default
  `deny` object (`"provider":{"allow_fallbacks":false,"data_collection":"deny"}`)
  is accepted. The model declares no raised caps, so a request holds at most
  64 questions, a 24 KiB envelope and 16 KiB of state under either policy
  placement.
- **Response.** `model` must be `microsoft/microsoft-decision-1` exactly or
  followed by `-` and 8 digits (observed: `-20261009`), else `response_model`.
  The upstream is expected to be `Azure` (journaled as
  `upstream_provider_unexpected` otherwise, never fatal). `usage` is
  `{input_tokens, output_tokens, cost}` as on Route 2, and the catalog run's
  reported cost equaled its input tokens x $0.042 per million.
- **Answers.** Probabilities are full-precision floats (see
  [Probability precision](#probability-precision)); a choice answer's
  confidence follows the chance-normalized identity, as on Route 2. The answers
  can arrive in a different order than the questions, which is counted
  (`answer_order_mismatch`) and harmless because they are matched by name; it
  happened on 171 of the 182 requests of the catalog run.
- **Price.** $0.042 per million input tokens and $0 per output token, dated
  2026-10-11.

## Route 4: Microsoft Foundry (`--judge microsoft --provider foundry`)

**Experimental and not yet verified live.** Built from Microsoft's
documentation of Microsoft-Decision-1 in Microsoft Foundry (updated
2026-10-09) and pinned by offline fixtures of the documented shapes under
`tests/fixtures/foundry/`. Nothing here has been observed against a
deployment: the response's usage field names, the dated form of the model
echo, the error bodies, the real request limits and the price are unknown
until one has been run.

- **Request.** `POST <resource endpoint>/providers/microsoft/v1/systemone`,
  with no `api-version` query. The body is Route 2's byte splice without the
  routing object, `{"model":D,"state":S,"questions":Q}`, where `D` is the
  deployment name (`--foundry-deployment` or `DBH_FOUNDRY_DEPLOYMENT`,
  `[A-Za-z0-9][A-Za-z0-9._-]{0,63}`, else `invalid_request`). `S` and `Q` are the
  envelope's bytes unchanged, so one `request_sha256` still describes the
  request, and the `score` type is never sent. The wire body is capped at
  64 KiB. The local caps are 64 questions, a 24 KiB envelope and 16 KiB of
  state, also under `--policy-placement state`, until Foundry's limits are
  confirmed on a deployment.
- **Authentication.** Either `api-key: <AZURE_API_KEY>` or `Authorization:
  Bearer <AZURE_ENTRA_TOKEN>`. `--foundry-auth api-key|entra-token` chooses;
  without it, exactly one of the two variables being set chooses, both set is
  `NEED_USER_INPUT foundry_auth` (exit 3) and neither is
  `provider_unavailable`. The Entra token is acquired by the caller (for
  example `az account get-access-token --resource
  https://cognitiveservices.azure.com`); DBH never acquires or refreshes one,
  so a token that expires during a run is a 401 (`http_unauthorized`), which
  blocks the gateway.
- **Endpoint rules** (`endpoint_invalid`, exit 2, before any connection; the
  value is never echoed or journaled). The scheme is `https`, with no user
  information, no query, no fragment, a path of nothing or `/`, and a port
  that is absent or 443. The host, lower-cased, is
  `<resource>.services.ai.azure.com`, `<resource>.cognitiveservices.azure.com`
  or `<resource>.openai.azure.com`, where `<resource>` is 2 to 63 characters
  of `a-z`, `0-9` and `-` that start with a letter or digit. That is the Azure
  commercial cloud only. A Foundry project endpoint (`/api/projects/...`), an
  IP literal and any other domain are refused. A missing endpoint is
  `NEED_USER_INPUT foundry_endpoint` and a missing deployment `NEED_USER_INPUT
  foundry_deployment` (exit 3). `--model`, the OpenRouter options and the
  Foundry options on another route are `invalid_request`.
- **Response.** `answers` is decoded as on Route 2 (noul `{type, noul}`; choice
  `{type, choice, probabilities, confidence}`; an explicit
  `{"type":"refusal"}` is answer-scoped and two or more withhold the batch; a
  choice without its vector is `response_vector_missing`). `model` names the
  underlying model, not the deployment: `microsoft-decision-1` or
  `Microsoft-Decision-1`, each optionally followed by `-` and 8 digits, else
  `response_model`. Any other key is ignored. A 200 with `error` and no
  `answers` is `provider_error_in_body`; with neither, `response_schema`, with
  its usage kept. `x-request-id` becomes the receipt's `request_id`.
- **Usage tolerance.** The field names are unverified, so usage is read as
  `{input_tokens, output_tokens}` or `{prompt_tokens, completion_tokens}`
  (non-negative integers; `total_tokens` and everything else is ignored).
  Absent usage is unknown. Any other shape is also unknown, the receipt
  records `provider_error.usage_shape: "unrecognized"`, and the attempt is
  bounded as unknown usage. A `cost` field is never read.
- **Cost.** No cost is reported, so the cost is the list-price estimate:
  input tokens x $0.042 per million, output $0. That price is the OpenRouter
  listing's (dated 2026-10-11), borrowed because no Azure price has been read.
  `--max-cost` works on the estimate; an attempt with unknown usage is bounded
  by its wire bytes plus 64 tokens per question (about $0.0012 for a full
  request).
- **Status table.** See the table below: the statuses Microsoft documents are
  400, 401, 403, 404, 422 and 429. A 422 (a wrong deployment name or question
  shape) is `http_rejected`, with the error's `code` and `type` kept.

## Probability precision

A model declares how it writes probabilities. OpenAI Decisions writes two
decimals (`probability_precision = "display"`, `display_places` 2).
Microsoft-Decision-1 writes full-precision floats (`"full"`) on both of its
routes, and the gateway then reports `full_precision` and no display places.
What that changes:

- Answers are decoded exactly as written, including exponent forms such as
  `3.2e-05`. Choice mass is still strict (the sum within 10^-12 of 1) and
  values are never renormalized; the 94 choice answers of the catalog run all
  passed.
- The localization mass gate uses a half-quantum of exactly 0, because the
  shown value is the value, unless `--choice-rounding-places` is given.
- The confidence identity (`chance_normalized_p1`) is checked as if the
  values were rounded to 6 places: a half-unit h of 5 x 10^-7 is carried
  through the identity as h x (1 + 1/(1 - 1/k)) for k options, so a deviation
  of about 1.5 x 10^-6 (two options) or about 1.1 x 10^-6 (many options) or
  more is a violation. Float error in the model's own arithmetic is never a
  violation, and a real change in its semantics is. None occurred in the
  catalog run (94 of 94 checked).
- Thresholds (0.60, 0.80, controls 0.90 and 0.10) are compared as before.
  They were set for OpenAI Decisions and not re-fitted.
- Identical requests give probabilities that differ by about 10^-10 (observed
  2026-10-11), so repeated runs are not byte-identical in their answers.
  Within a scan, identical requests are still reused by hash.

## Judge fields

The judge is named only when it is not OpenAI; absent means OpenAI, so every
report, receipt and bench fingerprint of the OpenAI judge is byte-identical to
what it was before the second judge existed.

- The report has a top-level `"judge": "microsoft"` after `"model"`. The
  `tile_sieve` block, which only Tile Sieve reports have, always records
  `thresholds_set`.
- Each receipt has `"judge": "microsoft"` after `model_requested`. On Foundry
  `model_requested` is the deployment name and `model_returned` the underlying
  model.
- The stderr summary line gains ` (judge microsoft)`. The handoff and
  `findings.txt` do not name the judge.
- A caller-supplied gateway with no model spec has no `judge`, and its
  provenance stays `custom-unverified`.

## Transport

Each provider holds its own exchange, whatever the route: an explicit TLS context
(system trust store, TLS 1.2 minimum, never `SSLKEYLOGFILE`), at most one
kept-alive connection, no proxy (proxy variables are ignored), no redirect
following and no content decoding (`Accept-Encoding: identity`). Requests are
written as bytes; `http.client.HTTPConnection` is never used.

Every phase runs under one absolute per-call deadline (`--deadline-seconds`,
default 30, at most 300): connect, where every resolved address gets a share
of the time left, the TLS handshake, the send and every single read. Name
resolution is bounded only by the operating system's resolver.

A connection is kept only after a complete, framing-valid 200 that did not
announce `Connection: close` and left no unread byte. It is reused only if it
has been idle at most 10 s, is not readable and has no TLS bytes pending.
Any error, non-200 or framing failure drops it. Responses must be JSON,
identity-encoded, unambiguously framed and at most 256 KiB.

Response headers are dropped except `content-type`, `content-length`,
`transfer-encoding`, `content-encoding`, `connection`, `retry-after`,
`x-ratelimit-*`, `x-request-id` and `x-generation-id`.

### Error bodies

A non-200 body is read only when it is JSON, at most 16 KiB and contains no
configured key; its state is journaled as `error_body` (`ok`, `absent`,
`oversized`, `not_json`, `withheld_sensitive`). Only structural fields are
kept, never `message`:

- OpenAI: `error.type`, `error.code` (token charset), and on 400/422 an
  `error.param` path made only of known request field names
  (`param_withheld` otherwise).
- OpenRouter: the numeric `error.code` (when it matches the status),
  whether `metadata` has moderation keys (`reasons`, `flagged_input`) or
  routing keys (`failed_routing_step`, `routing_funnel`), and token-charset
  `metadata.error_type`, `provider_code` and `provider_name`. Routing
  metadata values are never kept.
- Foundry: `error.code` and `error.type`, each only as a short token (a
  numeric code in 100 to 599 is also accepted). The `message` is never kept.

## Status classification

Each failure has a submission class: `not_sent` (no complete request left
this process), `rejected_unprocessed` (the service said it did not process
it), `possible` (it may have been processed and billed) or `terminal` (a
deliberate rejection of this request). Blocking codes stop the gateway for
the rest of the run.

| Status | OpenAI direct | OpenRouter | Foundry | Class | Blocks | Retried |
|---|---|---|---|---|---|---|
| connect failure (DNS, TCP or TLS, or a failed send on a fresh connection) | `connect_failed` | `connect_failed` | `connect_failed` | not_sent | no | up to 3 |
| timeout or reset after sending | `deadline_exceeded` / `transport_failed` | same | same | possible | no | no |
| 3xx | `http_redirect` | `http_redirect` | `http_redirect` | terminal | yes | no |
| 401 | `http_unauthorized` | `http_unauthorized` | `http_unauthorized` | terminal | yes | no |
| 402 | `http_rejected` | `http_payment_required` | `http_rejected` | terminal | OpenRouter only | no |
| 403 | `http_forbidden` | `provider_moderated` with moderation metadata, else `http_forbidden` | `http_forbidden` | terminal | `http_forbidden` only | no |
| 404 | `route_unavailable` | `routing_no_endpoint` with routing metadata, else `route_unavailable` | `route_unavailable` | terminal | yes | no |
| 408 | `http_request_timeout` | `http_request_timeout` | `http_request_timeout` | not_sent | no | up to 3 |
| 413 | `request_too_large` | `request_too_large` | `request_too_large` | terminal | no | no |
| 429 | `http_quota_exhausted` for `insufficient_quota`, `billing_hard_limit_reached`, `billing_not_active`; else `http_rate_limited` | `http_rate_limited` | `http_rate_limited` | terminal / rejected_unprocessed | quota only | rate limit: up to 3 |
| 503 | `http_overloaded` for `server_is_overloaded`, else `http_server_error` | `routing_no_endpoint` with routing metadata, else `http_unavailable` | `http_server_error` | rejected_unprocessed (overloaded, unavailable); possible (server error); terminal (routing) | routing only | overloaded, unavailable: up to 3 |
| 524 | `http_server_error` | `http_provider_timeout` | `http_server_error` | possible | no | no |
| 529 | `http_server_error` | `http_overloaded` | `http_server_error` | rejected_unprocessed on OpenRouter; possible elsewhere | no | OpenRouter: up to 3 |
| other 5xx | `http_server_error` | `http_server_error` | `http_server_error` | possible | no | no |
| other 4xx (Foundry: 400 and 422) | `http_rejected` | `http_rejected` | `http_rejected` | terminal | no | no |
| 200 with an error object | `provider_error_in_body` | `provider_error_in_body` | `provider_error_in_body` | possible | no | no |

`interrupted`, `internal_error` and `receipt_failed` also block.
`provider_moderated`, `http_rejected`, `request_too_large`, `sensitive_input`
and every batch-level response defect are permanent for that request: the
engine never asks it again.

## Retries, breaker and reserve

`RetryPolicy()` is the CLI default; `--no-retry` uses `RetryPolicy.none()`.

| Kind | Codes | Attempts after the first | Wait |
|---|---|---|---|
| not_sent | `connect_failed`, `http_request_timeout` | 3 | full jitter, base 0.5 s, cap 8 s |
| rejected | `http_rate_limited`, `http_overloaded`, `http_unavailable` | 3 | a valid `Retry-After` (seconds or HTTP date, capped at 60 s), else full jitter, base 1 s, cap 30 s |
| possible | `transport_failed`, `deadline_exceeded`, `http_server_error`, `http_provider_timeout`, `provider_error_in_body` | 0 | not retried: a repeat may be billed twice |
| stale connection | `transport_failed` from a reset or EOF with zero response bytes on a reused connection, during the send or within 1 s after it | 1 | immediate, on a new connection; `duplicate_billing_possible: true` |

Each retry gets a fresh call deadline. A retry is abandoned
(`retry_abandoned: "run_deadline"`) when its wait would cut into the run
reserve, max(3 s, 1.5 x p95 of the last 50 transmitted attempts), or
(`"cost_budget"`) when it could exceed `--max-cost`. A new request is
refused with `run_deadline_reserved`, before any receipt or byte, when less
than the reserve is left of the run deadline (`--run-deadline-seconds`,
default 1800 s).

The breaker sees one record per logical request, after its retries.
Answer-scoped defects never reach it. It stops the run after 3 consecutive
requests ending `http_rate_limited` or `http_overloaded`
(`rate_limit_sustained`); 3 ending with a degraded-provider code after
sending (`provider_degraded`); 3 that could not be sent because of
`connect_failed` or `http_request_timeout` (`network_unreachable`); 2 ending
with a contract code (`response_schema`, `response_model`,
`response_framing`, `response_type`, `response_invalid_json`,
`response_truncated`, `http_rejected`, `request_too_large`;
`contract_mismatch`); or 8 moderated among the last 10
(`provider_moderation_sustained`). A blocking code stops it as
`blocked:<code>`. After a stop every call raises `provider_stopped` without
a connection; the engine records one `provider_stopped` issue and the scan is
incomplete. The engine re-asks a transiently failed request once
(`failed_request_reasked`); it never re-asks a permanent failure.

## Receipts

Each attempt has one receipt file in `receipts/` (schema 2). It is written
as `dispatching` before the request is sent and replaced by the settled
record after the attempt ends; a write failure blocks the gateway
(`receipt_failed`), and an interruption blocks it before propagating.

Fields: `provider`, `model`, `synthetic`, `metadata`, `request_sha256` (of the
local envelope; the same on every route and attempt), `route`,
`model_requested`, `judge` (only for a judge other than OpenAI),
`model_returned`, `upstream_provider`, `generation_id` (OpenRouter
`x-generation-id`) or `request_id` (OpenAI or Foundry `x-request-id`),
`wire_sha256`, `answer_order_mismatch`, `question_count`, `rounding_places`,
`logical_id`, `attempt`, `retry_reason`, `waited_seconds`,
`duplicate_billing_possible`, `late`, `deadline_seconds`, `timeout_seconds`,
`status`, `submission`, `submission_possible`, `usage`, `answers`, `error`,
`scoped`, `provider_error`, `cost_usd`, `cost_source`, `cost_bound_usd`, and
`upstream_provider_unexpected` when the upstream was not the expected one.
`provider_error` holds only validated structural fields: the failing `phase`
and whether the connection was `reused`, the `error_body` state, the error
fields above, `retry_after_seconds` (0 to 60), on a validated receipt whose
reported cost was unusable, `cost_error: "invalid"` and, on a Foundry receipt
whose usage had an unrecognized shape, `usage_shape: "unrecognized"`. The
final attempt of a logical request adds `logical_status`, `logical_attempts`,
`logical_usage` and, when a retry was refused, `retry_abandoned`.

A 200 that fails framing, type, size or decoding keeps its `wire_sha256`
and generation or request id. Source text, specifications, request and
response bodies, error messages and keys are never journaled. A
caller-supplied gateway without these fields reports `custom-unverified`
provenance.

## Answers and partial batches

Answers are matched by name. The gateway validates every answer exactly:
finite numbers in range, exact keys, every option present. Answer-scoped
defects cost one answer and make the attempt `validated_partial` with
`scoped: {name: code}`:

- `question_refused` (at most one per request);
- `response_vector_missing` (OpenRouter or Foundry choice without its vector);
- `response_distribution` (choice mass or option keys wrong);
- `choice_argmax_mismatch` (the displayed argmax differs from the choice;
  displayed ties are allowed).

Wrong types, missing or extra names, extra keys and non-finite or out-of-range
numbers reject the batch. Choice mass is strict by default (sum within 10^-12
of 1); `--choice-rounding-places N` (2 to 8) accepts mass consistent with
nearest rounding at N places. Values are never renormalized. Live, all 61
observed choice vectors of OpenAI Decisions summed to exactly 1 at two
decimals, and the 94 full-precision vectors of Microsoft-Decision-1 passed the
strict test.

The report summarizes answer quality: `answer_defects` (by code), `refusals`
(count, rate and a 95% Clopper-Pearson interval), `possible_suppression`,
`judge_diagnostics` (argmax mismatches and, for a model that declares one, a
check of the observed confidence identity at the model's display precision of
two places, or to six places for a full-precision model) and `banners`
(`judge_inconsistent` when more than 2% of at least 50 choice answers have a
mismatched argmax; `judge_semantics_changed` after 3 confidence-identity
violations). The CLI prints a `Judge warning` line for either banner.

## Spend

Prices come from the route's model table: $0.10 per million input tokens
and $0 per output token for OpenAI Decisions on both of its routes, dated
2026-10-06, and $0.042 per million input tokens and $0 per output token for
Microsoft-Decision-1 (dated 2026-10-11; on Foundry this is the OpenRouter
listing's price, borrowed because no Azure price has been read).

Each attempt receipt records `cost_usd`, `cost_source` and
`cost_bound_usd`:

- `provider_reported`: OpenRouter's `usage.cost` (observed equal to input
  tokens times the model's listed price in every response);
- `list_price_estimate`: known usage at list price (the OpenAI and Foundry
  routes, or an OpenRouter response without a valid cost);
- `none`: no usage. A possibly billed attempt then adds a bound of its wire
  bytes plus 64 tokens per question as input and 64 tokens per question as
  output (about $0.0029 for a full 24 KiB, 64-question request of OpenAI
  Decisions, about $0.0012 for Microsoft-Decision-1).

The report's `spend` sums them exactly in Decimal: `provider_reported_usd`,
`estimated_usd`, `unknown_usage_upper_bound_usd`, `upper_bound_usd`,
`price_table_date`, `max_cost_usd` and per-source attempt counts. A scan on
a shared gateway reports its own share; the gateway's lifetime totals then
appear under `gateway_totals`. With `--max-cost USD` (0 < USD <= 1000) the
gateway refuses any attempt, first or retry, whose bound could take
`upper_bound_usd` above the limit; the engine records
`cost_budget_exhausted` and the scan is incomplete. A gateway whose provider
has no price table refuses `max_cost` with `invalid_request`.

## Error codes

Every code in `protocol.ERROR_CODES`:

| Code | Meaning |
|---|---|
| `call_budget_exhausted` | `--max-calls` reached |
| `choice_argmax_mismatch` | Displayed argmax differs from the chosen option (answer-scoped) |
| `connect_failed` | No connection could be opened |
| `cost_budget_exhausted` | `--max-cost` refused the next attempt |
| `deadline_exceeded` | The call deadline expired |
| `endpoint_invalid` | The Foundry endpoint is not an accepted resource endpoint (the value is never echoed) |
| `http_forbidden` | HTTP 403 without moderation metadata |
| `http_overloaded` | Overloaded (OpenAI 503 `server_is_overloaded`, OpenRouter 529) |
| `http_payment_required` | OpenRouter 402 |
| `http_provider_timeout` | OpenRouter 524 |
| `http_quota_exhausted` | OpenAI 429 for an exhausted quota or billing limit |
| `http_rate_limited` | HTTP 429 |
| `http_redirect` | HTTP 3xx (never followed) |
| `http_rejected` | Another 4xx (or OpenAI 402; on Foundry also 400, 422 and 402) |
| `http_request_timeout` | HTTP 408 |
| `http_server_error` | Another 5xx (on Foundry every 5xx) |
| `http_unauthorized` | HTTP 401 |
| `http_unavailable` | OpenRouter 503 without routing metadata |
| `internal_error` | Unexpected adapter or gateway defect |
| `interrupted` | Interrupted during a call or journal write |
| `invalid_deadline` | Deadline out of range |
| `invalid_judge` | Unknown judge name (`DBH_JUDGE`; the value is never echoed) |
| `invalid_metadata` | Invalid provider identity or request metadata |
| `invalid_probability_profile` | Invalid `--choice-rounding-places` |
| `invalid_provider` | Unknown route name (also `DBH_PROVIDER`) |
| `invalid_request` | Invalid request, option combination or model id |
| `provider_capability_missing` | Reserved; not raised by the hosted routes |
| `provider_error_in_body` | A 200 carrying an error object |
| `provider_moderated` | OpenRouter 403 with moderation metadata |
| `provider_stopped` | The breaker or a blocking failure stopped dispatch |
| `provider_unavailable` | No usable key for the selected route |
| `question_budget_exhausted` | `--max-questions` reached |
| `question_refused` | One question refused (answer-scoped) |
| `receipt_failed` | A receipt could not be written |
| `request_too_large` | Request over a local cap, or HTTP 413 |
| `response_distribution` | Choice mass or option keys wrong (answer-scoped) |
| `response_framing` | Ambiguous or inconsistent HTTP framing |
| `response_invalid_json` | Response body is not valid JSON |
| `response_model` | Returned model is not the requested one |
| `response_probability` | Probability not a finite number in [0, 1] |
| `response_refused` | Two or more refusals in one request |
| `response_schema` | Response shape wrong |
| `response_sensitive` | Response contains a configured key |
| `response_too_large` | Response over 256 KiB |
| `response_truncated` | Response marked incomplete |
| `response_type` | Wrong content type or encoding |
| `response_usage` | Usage malformed |
| `response_vector_missing` | OpenRouter or Foundry choice without its vector (answer-scoped) |
| `route_unavailable` | HTTP 404 without routing metadata |
| `routing_invalid` | Malformed `OPENAI_ORG_ID` or `OPENAI_PROJECT_ID` |
| `routing_no_endpoint` | OpenRouter 404/503 with routing metadata |
| `run_deadline_exceeded` | The run deadline expired |
| `run_deadline_reserved` | Too little run time left for another call |
| `secret_detected` | Credential-shaped text in the file or specification |
| `sensitive_input` | A configured key in data that would be sent |
| `transport_failed` | Connection reset or other transport error after connecting |

Engine issue codes such as `judge_control_failed`, `context_unresolved`,
`localization_unresolved` and `evidence_search_limited` describe scan
limitations, not provider failures; they appear in the report's `issues`.

## Deadlines and limits

Deadlines stop work at cooperative boundaries and reject late judgments
while keeping known usage. A 200 that was read in full but finished at or
after the call deadline is kept and journaled with `late: true`, because it
was paid for. Deadlines
cannot interrupt arbitrary custom gateway code or filesystem operations.
Hash reuse within a scan is not a service idempotency guarantee. Library
`scan()` does not run the secret scan on the target file.
