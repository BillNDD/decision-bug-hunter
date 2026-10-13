# Changelog

## 0.1.0b1 (unreleased)

First public beta. Nothing has been published before this version; this
entry describes everything in it. For where the starting files came from,
see [docs/PROVENANCE.md](docs/PROVENANCE.md).

### Judges and routes

- Two decision models, chosen explicitly with `--judge openai|microsoft` (or
  `DBH_JUDGE`; the flag wins). There is no default judge and `--provider`
  alone does not imply one: without a judge the CLI exits 3 with
  `NEED_USER_INPUT judge`, an unknown `DBH_JUDGE` is `invalid_judge` (exit 2),
  and a judge with a route that is not one of its own prints
  `NEED_USER_INPUT judge_route` (exit 3).
- OpenAI Decisions through two routes: `--provider openai`
  (`POST https://api.openai.com/v1/decisions`, model `gpt-6-luna`,
  `OPENAI_API_KEY`) and `--provider openrouter`
  (`POST https://openrouter.ai/api/alpha/decisions`, model
  `openai/gpt-6-luna-decisions`, `OPENROUTER_API_KEY`). Both routes were
  verified live with smoke suites and the 34-case development catalog:
  OpenRouter on 2026-10-06 and 2026-10-07, OpenAI direct on 2026-10-07. The
  OpenAI-direct adapter needed no change after its first live contact.
- Microsoft-Decision-1, **experimental**, through `--provider openrouter`
  (model `microsoft/microsoft-decision-1` on the same endpoint and request
  shape, `OPENROUTER_API_KEY`, $0.042 per million input tokens) or
  `--provider foundry` (a new route to your own Microsoft Foundry resource,
  built from Microsoft's documentation and **not yet verified live**; see
  below). It is offered for the default `legacy-v1` search only, and it finds
  fewer bugs than OpenAI Decisions on the development catalog (28 of 34 cases
  against 32 of 34 through OpenRouter). Every run with it prints one stderr
  note saying so. A live tuning study did not bring it to the bar DBH sets
  for a judge.
- Explicit route selection with `--provider` or `DBH_PROVIDER`; never
  inferred from which key is set. Without a route the CLI exits 3 with
  `NEED_USER_INPUT provider` (naming only the routes and key variables of
  the chosen judge); without the route's key it exits 2 with
  `provider_unavailable`, both before reading the source.
- `--model` accepts only the chosen judge's model on the route; a model of
  the other judge is `invalid_request`. The returned model must match
  exactly or with a dated suffix (the Microsoft model echoes
  `microsoft/microsoft-decision-1-20261009` on OpenRouter).
- OpenRouter requests carry `"provider":{"allow_fallbacks":false,
  "data_collection":"deny"}` by default for both judges; `--openrouter-routing
  account-default` omits it (with a notice) and `--openrouter-zdr` adds
  `"zdr":true`. `session_id`, `user`, `trace` and attribution headers are
  never sent. Microsoft-Decision-1 requests keep the local limits of 64
  questions and 24 KiB also under `--policy-placement state`.
- OpenAI direct: optional `OPENAI_ORG_ID` / `OPENAI_PROJECT_ID` routing
  headers; malformed values stop with `routing_invalid`.
- Microsoft Foundry (`--provider foundry`, `--judge microsoft`): endpoint
  `--foundry-endpoint` / `DBH_FOUNDRY_ENDPOINT` (an `https` resource endpoint
  under `services.ai.azure.com`, `cognitiveservices.azure.com` or
  `openai.azure.com`; anything else, including a project URL, is
  `endpoint_invalid`), deployment `--foundry-deployment` /
  `DBH_FOUNDRY_DEPLOYMENT` (sent as the model), and either `AZURE_API_KEY` (an
  `api-key` header) or a pre-acquired `AZURE_ENTRA_TOKEN` (a bearer token)
  chosen with `--foundry-auth` or by whichever variable is set. A missing
  endpoint or deployment, or an ambiguous credential, is `NEED_USER_INPUT
  foundry_endpoint`, `foundry_deployment` or `foundry_auth`. DBH never
  acquires or refreshes an Entra token. Usage field names are read tolerantly,
  the cost is a list-price estimate, and the endpoint host is never written to
  a report, receipt or message.
- Every configured provider key (`OPENAI_API_KEY`, `OPENROUTER_API_KEY`,
  `AZURE_API_KEY`, `AZURE_ENTRA_TOKEN`) is checked against everything that
  would be sent and against responses, whichever judge and route are chosen.

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
- `--concurrency N` (1 to 8, default 1) is opt-in: it lets up to N requests
  be in flight at once. Results are identical on success; after a failure or
  a stop, requests already in flight still complete and are billed. The
  engine fan-out that makes runs faster with it arrives separately.

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
- Full-precision probabilities: Microsoft-Decision-1 writes full-precision
  floats, so a model can declare `probability_precision = "full"`. The mass
  gate then uses exact values and the confidence identity is checked to six
  decimal places. Answers may arrive in a different order than the questions
  and are matched by name.
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
- A configured key is matched by its text without surrounding whitespace or
  quotes, so a key set with a trailing newline or space is still never sent.

### Tile Sieve (beta)

- `--search-policy tile-sieve-beta`: an opt-in whole-file search for the
  OpenAI judge. A file that fits in one request is read in one or two
  whole-file looks, each flagged region gets one focus request, and rule 8C
  reports a strong region at a lower bar than any other, with no second
  stage. A file that does not fit one request is scanned with `legacy-v1`,
  and stderr and the report say so.
- The thresholds are data, one set per judge, in
  `decision_bug_hunter/tile_sieve_thresholds.json`; its sha256 and the set
  used are recorded in every Tile Sieve report. Only the OpenAI judge has a
  set. `--judge microsoft` with this policy exits 2 with
  `invalid_search_configuration: tile-sieve-beta has no calibrated thresholds
  for judge microsoft`, before the source is read.
- It needs `--canaries on`, `--state-layout v1` and `--policy-placement
  instructions`, and refuses `--polarity-twin` and `--require-verification`.
- On the 34-case development catalog it located 34 of 34 cases with 53 calls
  through OpenAI direct and 33 of 34 with 52 calls through OpenRouter, against
  211 and 214 calls for `legacy-v1`. The thresholds were chosen in a pilot
  that also ran that catalog, so those scores are optimistic.

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

- Report schema 7 (legacy-v1), 8 (scoped-v2-beta) and 9 (tile-sieve-beta);
  handoff schema 4, 5 and 6, with `stop_reason`. Reports include
  `provenance`, `attempts_transmitted`, `retries`, `stop_reason`,
  `secret_scan`, `controls`, and, when relevant, `injection_markers`,
  `request_geometry`, `unverified_suspicions`, `tile_sieve` and `judge`.
  `judge` appears in a report and a receipt only for a judge other than
  OpenAI (absent means OpenAI), so every OpenAI report and receipt keeps its
  bytes.
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
- `tools/eval`: the 34-case labeled development catalog and its runner,
  which forwards `--judge`, takes `--search-policy` and `--max-total-cost`
  (counted at each case's spend upper bound), and plans a Tile Sieve dry run.
- `tools/bench`: an offline benchmark with golden fingerprints and a
  regression gate (see `docs/performance.md`), including Tile Sieve and
  Microsoft-judge scenarios.
- The offline test suite refuses real sockets. `tools/check_distribution.py`
  checks both archives, a keyless wheel install with the route-selection and
  `provider_unavailable` gates, and the unpacked sdist's own test suite. The
  sdist ships the observed fixtures and `SECURITY.md` and leaves out
  `tools/smoke`.
- Python 3.11 to 3.13; no runtime dependencies.
