# Provider contract

This document describes DBH's internal judge interface, the two hosted
routes to the OpenAI Decisions model, how statuses and answers are
classified, and how retries, receipts and spend work. The code is the
reference; the offline tests pin every statement here.

## Internal interface

`ValidatedGateway(provider, receipt_dir, *, deadline_seconds=30.0,
rounding_places=None, retry_policy=None, clock=None, sleep=None, rng=None,
progress=None, reserve_floor_seconds=3.0, max_cost=None)` is the engine's
only path to a judge. It is a context manager; one gateway may serve
several scans. A `DecisionProvider` supplies a public `ProviderIdentity`
(`name`, `model`, `synthetic`), `require_available()`,
`decide(ProviderRequest)`, `check_sensitive(*values)` and `close()`.

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
policy entry may use the model's raised caps (OpenRouter: 200 questions,
48 KiB; OpenAI direct keeps 64 and 24 KiB); the state cap grows only by the
policy entry, so evidence selection does not change.

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

## Route 2: OpenRouter (`--provider openrouter`)

`POST https://openrouter.ai/api/alpha/decisions`, bearer authentication
with `OPENROUTER_API_KEY`. Model `openai/gpt-6-luna-decisions` only.

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

## Transport

Both routes share one exchange per provider: an explicit TLS context
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

## Status classification

Each failure has a submission class: `not_sent` (no complete request left
this process), `rejected_unprocessed` (the service said it did not process
it), `possible` (it may have been processed and billed) or `terminal` (a
deliberate rejection of this request). Blocking codes stop the gateway for
the rest of the run.

| Status | OpenAI direct | OpenRouter | Class | Blocks | Retried |
|---|---|---|---|---|---|
| connect failure (DNS, TCP or TLS, or a failed send on a fresh connection) | `connect_failed` | `connect_failed` | not_sent | no | up to 3 |
| timeout or reset after sending | `deadline_exceeded` / `transport_failed` | same | possible | no | no |
| 3xx | `http_redirect` | `http_redirect` | terminal | yes | no |
| 401 | `http_unauthorized` | `http_unauthorized` | terminal | yes | no |
| 402 | `http_rejected` | `http_payment_required` | terminal | OpenRouter only | no |
| 403 | `http_forbidden` | `provider_moderated` with moderation metadata, else `http_forbidden` | terminal | `http_forbidden` only | no |
| 404 | `route_unavailable` | `routing_no_endpoint` with routing metadata, else `route_unavailable` | terminal | yes | no |
| 408 | `http_request_timeout` | `http_request_timeout` | not_sent | no | up to 3 |
| 413 | `request_too_large` | `request_too_large` | terminal | no | no |
| 429 | `http_quota_exhausted` for `insufficient_quota`, `billing_hard_limit_reached`, `billing_not_active`; else `http_rate_limited` | `http_rate_limited` | terminal / rejected_unprocessed | quota only | rate limit: up to 3 |
| 503 | `http_overloaded` for `server_is_overloaded`, else `http_server_error` | `routing_no_endpoint` with routing metadata, else `http_unavailable` | rejected_unprocessed (overloaded, unavailable); possible (server error); terminal (routing) | routing only | overloaded, unavailable: up to 3 |
| 524 | `http_server_error` | `http_provider_timeout` | possible | no | no |
| 529 | `http_server_error` | `http_overloaded` | rejected_unprocessed on OpenRouter | no | OpenRouter: up to 3 |
| other 5xx | `http_server_error` | `http_server_error` | possible | no | no |
| other 4xx | `http_rejected` | `http_rejected` | terminal | no | no |
| 200 with an error object | `provider_error_in_body` | `provider_error_in_body` | possible | no | no |

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

Fields: `provider`, `model`, `synthetic`, `metadata`, `request_sha256` (of
the local envelope; the same on every route and attempt), `route`,
`model_requested`, `model_returned`, `upstream_provider`, `generation_id`
(OpenRouter `x-generation-id`) or `request_id` (OpenAI `x-request-id`),
`wire_sha256`, `answer_order_mismatch`, `question_count`, `rounding_places`,
`logical_id`, `attempt`, `retry_reason`, `waited_seconds`,
`duplicate_billing_possible`, `late`, `deadline_seconds`, `timeout_seconds`,
`status`, `submission`, `submission_possible`, `usage`, `answers`, `error`,
`scoped`, `provider_error`, `cost_usd`, `cost_source`, `cost_bound_usd`, and
`upstream_provider_unexpected` when the upstream was not the expected one.
`provider_error` holds only validated structural fields: the failing
`phase` and whether the connection was `reused`, the `error_body` state, the
error fields above, `retry_after_seconds` (0 to 60) and, on a validated
receipt whose reported cost was unusable, `cost_error: "invalid"`. The final attempt of a logical
request adds `logical_status`, `logical_attempts`, `logical_usage` and, when
a retry was refused, `retry_abandoned`.

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
- `response_vector_missing` (OpenRouter choice without its vector);
- `response_distribution` (choice mass or option keys wrong);
- `choice_argmax_mismatch` (the displayed argmax differs from the choice;
  displayed ties are allowed).

Wrong types, missing or extra names, extra keys and non-finite or
out-of-range numbers reject the batch. Choice mass is strict by default
(sum within 10^-12 of 1); `--choice-rounding-places N` (2 to 8) accepts mass
consistent with nearest rounding at N places. Values are never
renormalized. Live, all 61 observed choice vectors summed to exactly 1 at two
decimals.

The report summarizes answer quality: `answer_defects` (by code),
`refusals` (count, rate and a 95% Clopper-Pearson interval),
`possible_suppression`, `judge_diagnostics` (argmax mismatches and, on the
OpenRouter route, a check of the observed confidence identity at the model's
display precision of two places) and `banners` (`judge_inconsistent` when
more than 2% of at least 50 choice answers have a mismatched argmax; `judge_semantics_changed` after 3
confidence-identity violations). The CLI prints a `Judge warning` line for
either banner.

## Spend

Prices come from the route's model table: $0.10 per million input tokens
and $0 per output token on both routes, dated 2026-10-06.

Each attempt receipt records `cost_usd`, `cost_source` and
`cost_bound_usd`:

- `provider_reported`: OpenRouter's `usage.cost` (observed equal to input
  tokens x 1e-7 in every response);
- `list_price_estimate`: known usage at list price (the OpenAI route, or an
  OpenRouter response without a valid cost);
- `none`: no usage. A possibly billed attempt then adds a bound of its wire
  bytes plus 64 tokens per question as input and 64 tokens per question as
  output (about $0.0029 for a full 24 KiB, 64-question request).

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
| `http_forbidden` | HTTP 403 without moderation metadata |
| `http_overloaded` | Overloaded (OpenAI 503 `server_is_overloaded`, OpenRouter 529) |
| `http_payment_required` | OpenRouter 402 |
| `http_provider_timeout` | OpenRouter 524 |
| `http_quota_exhausted` | OpenAI 429 for an exhausted quota or billing limit |
| `http_rate_limited` | HTTP 429 |
| `http_redirect` | HTTP 3xx (never followed) |
| `http_rejected` | Another 4xx (or OpenAI 402) |
| `http_request_timeout` | HTTP 408 |
| `http_server_error` | Another 5xx |
| `http_unauthorized` | HTTP 401 |
| `http_unavailable` | OpenRouter 503 without routing metadata |
| `internal_error` | Unexpected adapter or gateway defect |
| `interrupted` | Interrupted during a call or journal write |
| `invalid_deadline` | Deadline out of range |
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
| `response_vector_missing` | OpenRouter choice without its vector (answer-scoped) |
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
