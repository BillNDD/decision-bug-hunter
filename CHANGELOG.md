# Changelog

## 0.1.0b1 (unreleased)

First public beta. Nothing has been published before this version; this
entry describes everything in it. For where the starting files came from,
see [docs/PROVENANCE.md](docs/PROVENANCE.md).

### Judge and routes

- One judge, the OpenAI Decisions model, through two routes:
  `--provider openai` (`POST https://api.openai.com/v1/decisions`, model
  `gpt-6-luna`, `OPENAI_API_KEY`) and `--provider openrouter`
  (`POST https://openrouter.ai/api/alpha/decisions`, model
  `openai/gpt-6-luna-decisions`, `OPENROUTER_API_KEY`). No other model is
  supported. Both routes were verified live on 2026-10-06 and 2026-10-07
  (smoke suites and the 34-case development catalog); the OpenAI-direct
  adapter needed no change after its first live contact.
- Explicit route selection with `--provider` or `DBH_PROVIDER`; never
  inferred from which key is set. Without a route the CLI exits 3 with
  `NEED_USER_INPUT provider`; without the route's key it exits 2 with
  `provider_unavailable`, both before reading the source.
- `--model` accepts only the route's allowed model; the returned model must
  match exactly or with a dated suffix.
- OpenRouter requests carry `"provider":{"allow_fallbacks":false,
  "data_collection":"deny"}` by default; `--openrouter-routing
  account-default` omits it (with a notice) and `--openrouter-zdr` adds
  `"zdr":true`. `session_id`, `user`, `trace` and attribution headers are
  never sent.
- OpenAI direct: optional `OPENAI_ORG_ID` / `OPENAI_PROJECT_ID` routing
  headers; malformed values stop with `routing_invalid`.
- Every configured provider key is checked against everything that would
  be sent and against responses.

### Transport, retries and deadlines

- A standard-library HTTPS exchange: explicit TLS context that never reads
  `SSLKEYLOGFILE`, one kept-alive connection reused only when safe, no
  proxy, no redirects, no content decoding, strict framing, 256 KiB response
  cap, and one absolute deadline per call covering connect (shared across
  resolved addresses), TLS, send and every read. `--deadline-seconds`
  defaults to 30 (at most 300).
- Per-route status tables with submission classes; status codes include
  `connect_failed`, `http_request_timeout`, `http_quota_exhausted`,
  `http_payment_required`, `http_forbidden`, `provider_moderated`,
  `route_unavailable`, `routing_no_endpoint`, `http_overloaded`,
  `http_unavailable`, `http_provider_timeout` and `provider_error_in_body`.
- Error bodies up to 16 KiB are read when they are JSON and free of keys;
  only structural fields are kept, never messages.
- Journaled retries on by default: up to 3 for failures before sending and
  up to 3 for rate limits and overload (honoring `Retry-After` up to 60 s),
  none for possibly processed requests, and one immediate retry of a stale
  keep-alive connection (marked `duplicate_billing_possible`). `--no-retry`
  turns them off.
- A breaker stops the run after sustained rate limiting, provider errors,
  network failures, contract mismatches or moderation
  (`provider_stopped`); blocking failures such as `http_unauthorized` stop it
  at once.
- `--run-deadline-seconds` defaults to 1800, and a reserve of
  max(3 s, 1.5 x p95 of recent attempts) refuses calls that could not finish
  (`run_deadline_reserved`). A progress line goes to stderr every 100 calls
  or 30 s.

### Answers

- Answers are matched by name. One refused question costs that answer
  (`question_refused`); two or more refusals withhold the batch
  (`response_refused`). Wrong choice mass or keys (`response_distribution`),
  an argmax mismatch (`choice_argmax_mismatch`) and an OpenRouter choice
  without its vector (`response_vector_missing`) also cost one answer; the
  attempt is `validated_partial`.
- Strict choice mass (within 10^-12) is the default; every live vector
  observed summed to exactly 1. `--choice-rounding-places N` is opt-in and
  `--strict-choice-mass` is a no-op kept for compatibility.
- Reports include `answer_defects`, `refusals`, `possible_suppression`,
  `judge_diagnostics`, `banners` and an always-`uncalibrated`
  `calibration` record. The CLI prints a `Judge warning` line for a banner.

### Cost

- Every attempt receipt records `cost_usd`, `cost_source`
  (`provider_reported`, `list_price_estimate` or `none`) and
  `cost_bound_usd`. Reports include `spend`; a scan on a shared gateway reports
  its own share and, when different, `gateway_totals`.
- `--max-cost USD` refuses any attempt, retries included, whose bound could
  take spend above the limit (`cost_budget_exhausted`). A stderr line
  summarizes spend.

### Safety checks

- A credential-shape scan of the file and specification runs before any
  output or request (`secret_detected`, exit 2, line numbers and pattern ids
  only). It recognizes tokens after escape sequences and percent-encoded
  bytes, and PEM private-key headers anywhere. `--allow-secrets` overrides it
  for the file and specification; project files with a hit are always
  skipped (`project.skipped_secret_content`).
- Judge controls (`--canaries on`, the default): two questions with known
  answers in every request; a failed control withholds that request's
  answers (`judge_control_failed`). They add about 19% input tokens on the
  development suite; `--canaries off` removes them.
- Injection markers: a local pattern scan that annotates findings on lines
  that look like instructions to the judge (`injection-marker`).

### Request shape and opt-in options

- Question pack 5.0.0 with two state layouts: `v1` (default) and `v2`
  (`--state-layout v2`), which starts the state with the DBH-written fields
  and warns about envelope imitation. Layout v1 is the default because v2
  added false findings on clean controls in the development suite and,
  combined with the mass gate, reversed its gain (31/34 against 32/34).
  Requirement questions use corrected wording in both layouts.
- `--policy-placement state`: the policy text is sent once in the state; on
  OpenRouter such requests may hold 200 questions and 48 KiB. Default
  `instructions`.
- Localization gate `--choice-gate` (default `mass`) with `--choice-mass`
  (default 0.5): legacy-v1 localization selects line runs whose per-line
  overlap mass reaches the threshold. It became the default after a live
  comparison on the development suite (32/34 against 31/34 for the earlier
  gate, controls 16/16 in both); `--choice-gate legacy` restores the earlier
  min(confidence, p[choice]) gate. scoped-v2-beta does not gate
  localization. Also `--localization-menu singletons` (default `intervals`)
  and `--choice-rounding-caps` (default off).
- `--require-verification` (default off): only suspicions with a second
  look are findings; the rest are listed as `unverified_suspicions`.
- `--polarity-twin` (default off): a diagnostic that never changes findings.
- Report configuration lists the tier-2 options only when they differ from
  their pre-beta values, so default reports record `choice_gate: "mass"`.
  Runs with `--choice-gate legacy` and `--canaries off` reproduce the
  pre-beta request bytes and reports; tests pin both those and the shipped
  defaults.

### Reports, receipts and output

- Report schema 7 (legacy-v1) and 8 (scoped-v2-beta); handoff schema 4 and
  5, with `stop_reason`. Reports include `provenance`, `attempts_transmitted`,
  `retries`, `stop_reason`, `secret_scan`, `controls`, and, when relevant,
  `injection_markers`, `request_geometry` and `unverified_suspicions`.
- Receipt schema 2: route, requested and returned model, upstream provider,
  generation or request id, wire hash, attempt and retry fields, cost
  fields and structural error fields. A 200 that fails framing or decoding
  keeps its identifiers, and a parsed body without answers keeps its usage
  and cost.
- Run directories get `.gitignore` and `CACHEDIR.TAG`; the project indexer
  skips cache-tagged directories.

### Tooling and packaging

- `tools/smoke` (repository only): first-contact smoke suites for both
  routes through the shipped exchange, with a sanitizer for promoting
  observed fixtures.
- `tools/eval`: the 34-case labeled development catalog and its runner.
- The offline test suite refuses real sockets. `tools/check_distribution.py`
  checks both archives, a keyless wheel install with the route-selection and
  `provider_unavailable` gates, and the unpacked sdist's own test suite. The
  sdist ships the observed fixtures and `SECURITY.md` and leaves out
  `tools/smoke`.
- Python 3.11 to 3.13; no runtime dependencies.
