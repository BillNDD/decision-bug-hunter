# Provider contract and the Decisions mapping

This document has two parts: DBH's internal provider interface, which any
judge must satisfy, and the documented translation that the hosted adapter
performs for the OpenAI Decisions API. The internal interface is **not** an
OpenAI schema; the translation is pinned to the public documentation of
2026-10-06 and is reproduced by offline fixtures in `tests/test_decisions.py`.

## Internal interface

`ValidatedGateway(provider, receipt_dir, deadline_seconds=30,
rounding_places=None)` is the engine boundary. A `DecisionProvider` supplies a
public `ProviderIdentity`, `require_available()`, `decide(ProviderRequest)`,
`check_sensitive(*values)` and `close()`.

`ProviderRequest.payload` contains owned immutable JSON bytes with local
`contract: "dbh-judge-v1"`, `state` and `questions`. This envelope exists for
deterministic byte limits, snapshots and request hashes. It is never sent as
a service envelope; the adapter translates it. `timeout_seconds` is the
remaining cooperative call budget.

`ProviderResponse` contains normalized `answers`, optional token `usage`, an
explicit Boolean `complete` and an optional `error` code. Unknown usage is
`None`; it is never zero usage. Usage learned before a semantic failure
remains available for bookkeeping, and `error` lets an adapter report a
documented whole-batch rejection together with that usage. Malformed usage
makes the attempt a limitation. `complete=False` supplies no judgments.

| Local primitive | Engine purpose | Required local result |
|---|---|---|
| Noul (`noul`) | Screen, five bug lenses, context need, relevance, independent verification, refutation, relationship support, continue/coverage controls | Finite exact numeric P(true) in [0,1], not a Boolean or string |
| Choice (`choice`) | Rank/localize intervals, retrieve context, choose a legal investigation action | Chosen option ID, confidence, and a probability for every menu option |
| State | Numbered source/specification passages, explicit scope, selected evidence and factual operation history | Bounded text context; content remains evidence, not instructions |
| Batch | Independent questions over one unchanged context | Exact question-ID coverage, accepted atomically |

`noul` is a retained legacy key for the tested engine mechanics. Action Choice
routes work; it does not itself support a bug. Probabilities are never
compared across menus or summed into bug confidence. Same-request answers
never become dependencies for other same-request questions.

Noul results have exactly `type` and `noul`. Choice results have exactly
`type`, `choice`, `confidence` and `probabilities`. Question objects have
`type`, `instructions` and named `criteria`. Probability values are finite
int/float/Decimal numbers (Booleans are rejected), snapshot to owned Decimal
values and meet resource bounds. All expected question IDs and menu IDs must
be present with no extras. An invalid final answer rejects the entire batch.

The exact displayed argmax must match the chosen option; displayed ties are
allowed. Strict mass is the default with 10^-12 serialization slack. An
explicit rounding profile of 2–8 decimal places permits only feasible mass
rounding; values are never renormalized. This is a local policy. The
documentation does not state the precision of returned probabilities, so a
live run that reports `response_distribution` on choice batches should be
rerun with `--choice-rounding-places`.

The local limits are 16 KiB state, 24 KiB request, 64 questions per batch and
2–255 Choice options. They are conservative engine bounds.

## Documented Decisions mapping

Endpoint `POST https://api.openai.com/v1/decisions`, bearer authentication,
JSON body with `model`, `input` and `questions`; response with `model`,
`answers` and `usage`. Only `gpt-6-luna` is documented and only it is sent.

| Local | Decisions request | Decisions answer | Local result |
|---|---|---|---|
| `state` object | `input` string: the exact compact JSON of the state, byte-identical to the local envelope fragment | — | — |
| `noul` question | `{"type": "predicate", "name": id, "instructions": instructions + "Answer true if: …" + "Answer false if: …"}` | `{"type": "predicate", "name", "probability"}` | `{"type": "noul", "noul": probability}` |
| `choice` question | `{"type": "choice", "name": id, "instructions", "choices": [{"value": option, "description"}…]}` in menu order | `{"type": "choice", "name", "choice", "probabilities": [{"value", "probability"}…], "confidence"}` | `{"type": "choice", "choice", "probabilities": {value: probability}, "confidence"}` |
| batch | one `questions` array per local batch | `answers` array, matched by echoed `name` | atomic; every name exactly once, no extras |
| — | — | `{"type": "refusal", "name"}` | whole batch fails `response_refused` |
| — | — | `usage.input_tokens`, `usage.output_tokens` | local usage; other counters dropped; absent usage is unknown |
| — | — | `model` equal to `gpt-6-luna` or a dated `gpt-6-luna-*` snapshot | otherwise `response_model` |

The `score` question type and image input are not used. Undocumented request
options are not sent. Undocumented response fields, including answer fields
beyond the documented ones, are ignored and never journaled. Choice values
may be Booleans in the documented schema; a Boolean choice or option never
matches a local string option and fails `response_distribution`. The
question-name pattern `[A-Za-z0-9_.-]{1,96}` and option IDs are local
constraints; the documentation states no name, option-count or question-count
limits, and `input_text` allows up to 10 MiB.

## Transport, bookkeeping and failure behavior

The adapter uses `http.client` over TLS from `ssl.create_default_context()`
to the fixed host and path with `Accept-Encoding: identity` and
`Connection: close`. It follows no redirects, uses no proxy, sends no SDK
headers, and makes one request per batch with no retry or backoff. Responses
must be `application/json`, identity-encoded, unambiguously framed and at most
256 KiB. Status mapping: `401`/`403` `http_unauthorized` (blocks further
dispatch for the gateway), `429` `http_rate_limited`, `3xx` `http_redirect`,
`5xx` `http_server_error`, other non-200 `http_rejected`. Error bodies are
never read. Socket timeouts are `deadline_exceeded`; other transport errors
are `transport_failed`; neither carries exception text or chained context.

The gateway validates requests, scope metadata, active-adapter sensitive data
and deadlines before dispatch. A durable `dispatching` receipt precedes one
`decide` invocation. The remaining run budget is recomputed after intent
persistence, immediately before dispatch; an expired budget permits no call.
A terminal receipt records validated answers or a fixed safe failure code. No
raw source/specification, request body, response body or provider exception
text is journaled. Receipt persistence failure prevents further gateway use.
An interruption during either journal transition or provider execution
blocks reuse before propagation. Best-effort settlement retains possible
submission and validated usage while withholding judgments. Uncertain
transport failure also blocks reuse.

`last_call_stats` and `last_receipt` belong to the thread owning the attempt.
A rejected concurrent caller sees no other caller's record. A new blocked
attempt clears its statistics so earlier known usage cannot be booked twice.
Preflight failures create no journal because dispatch was never possible.

The engine revalidates gateway outputs, preserves limits and incomplete
coverage, and counts attempts with known/unknown usage separately. Custom
gateways are a library extension with public `custom-unverified` provenance
by default. Contract fixtures carry `synthetic: true` and no model identifier;
the hosted adapter reports `openai-decisions` and `gpt-6-luna`.

Deadlines stop work at cooperative boundaries and reject late judgments while
retaining known usage. They cannot interrupt arbitrary custom code or
filesystem operations. Monetary accounting, pricing and service idempotency
are not implemented; hash reuse within a local scan is not a service
idempotency guarantee.
