# Local provider contract

This is DBH's internal interface, **not an OpenAI endpoint, SDK method, or wire
schema**. The adapter translates it only after the actual API is documented.

`ValidatedGateway(provider, receipt_dir, deadline_seconds=30,
rounding_places=None)` is the engine boundary. `DecisionProvider` supplies a
public `ProviderIdentity`, `require_available()`, `decide(ProviderRequest)`,
`check_sensitive(*values)`, and `close()`. The current `DecisionsProvider` always
raises the fixed safe code `provider_unavailable`; it reads no credentials,
imports no service SDK, and has no transport or fallback.

`ProviderRequest.payload` contains owned immutable JSON bytes with local
`contract: "dbh-judge-v1"`, `state`, and `questions`. This envelope exists for
deterministic byte limits, snapshots, and request hashes. It must not be sent to
a service as an assumed service envelope. `timeout_seconds` is the remaining
cooperative call budget; an actual adapter must enforce documented transport
timeouts and cancellation. Local metadata is separately validated and journaled.

`ProviderResponse` contains normalized `answers`, optional token `usage`, and an
explicit Boolean `complete`. Unknown usage is `None`; it is never zero usage.
Usage validated before a semantic failure remains available for bookkeeping.
Malformed usage makes the attempt a limitation. A reply with `complete=False`
is incomplete and supplies no usable judgments.

## Primitive mappings and unresolved capabilities

| Inherited primitive | Engine purpose | Required local result | Decisions status |
|---|---|---|---|
| Noul (`noul`) | Screen, five bug lenses, context need, relevance, independent verification, refutation, relationship support, continue/coverage controls | Finite exact numeric P(true) in [0,1], not a Boolean or string | Finite answer menus announced; probability semantics unverified |
| Choice (`choice`) | Rank/localize intervals, retrieve context, choose a legal investigation action | Chosen option ID, confidence, and a probability for every menu option | Finite answer menus announced; full vectors/confidence/precision unverified |
| State | Numbered source/specification passages, explicit scope, selected evidence and factual operation history | Bounded text context; content remains evidence, not instructions | Text/image context announced; structured-context encoding/limits unverified |
| Batch | Independent questions over one unchanged context | Exact question-ID coverage, accepted atomically | Native batching, independence and result association unverified |

`noul` is retained as a local legacy key to preserve tested engine mechanics. It
does not imply that Decisions has a Noul type. Action Choice routes work; it
does not itself support a bug. Probabilities are never compared across menus or
summed into bug confidence. Same-request answers do not become dependencies for
other same-request questions.

Noul results have exactly `type` and `noul`. Choice results have exactly `type`,
`choice`, `confidence`, and `probabilities`. Question objects have `type`,
`instructions`, and named `criteria`. Probability values are finite int/float/
Decimal numbers (Boolean values are rejected), snapshot to owned Decimal values,
and meet resource bounds. All expected question IDs and menu IDs must be present,
with no extras. An invalid final answer rejects the entire batch.

The exact displayed argmax must match the chosen option; displayed ties are
allowed. Strict mass is the default with inherited 10^-12 serialization slack.
An explicit rounding profile of 2–8 decimal places permits only feasible mass
rounding; values remain unchanged. This is a local policy, not a claim about
OpenAI precision. A future adapter must select a policy supported by actual docs.

The inherited local limits are 16 KiB state, 24 KiB request, 64 questions per
batch, and 2–255 Choice options. They are conservative engine bounds, not API
limits. Official byte/token/option/batch limits must be reconciled before launch.
Image support is outside the present source-triage scope and is not implemented.

Missing probabilities, choice confidence, trustworthy completeness, or exact
answer association must fail closed. Do not turn a selected answer into P=1,
derive binary false probability by an undocumented rule, fabricate a full vector,
or route through another API. If the public service lacks required outputs, an
explicitly reviewed algorithm change is a release prerequisite. Native batching
must be verified; a future serial expansion would also need physical-call,
deadline, usage, partial-failure, and durable-submission accounting changes.

## Bookkeeping and failure behavior

The gateway validates requests, scope metadata, active-adapter sensitive data,
and deadlines before dispatch. A durable `dispatching` receipt precedes one
`decide` invocation. A terminal receipt records validated answers or a fixed
safe failure code. No raw source/specification or provider exception text is
journaled. Receipt persistence failure prevents further gateway use. An
interruption or uncertain transport failure retains possible submission and
blocks reuse; no automatic retry is performed.

The engine also revalidates gateway outputs, preserves limits and incomplete
coverage, and counts attempts with known/unknown usage separately. Direct custom
gateways are a library extension, with public `custom-unverified` provenance by
default. Contract fixtures carry `synthetic: true` and no model identifier.

Deadlines stop work at cooperative boundaries and reject late judgments while
retaining known usage. They cannot interrupt arbitrary custom code or filesystem
operations. Durable crash recovery, monetary accounting, pricing, service
idempotency, and actual transport cancellation remain release gates; hash reuse
within a local scan is not a service idempotency guarantee.
