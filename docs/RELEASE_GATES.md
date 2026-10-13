# Release gates

Status for `0.1.0b1` (unreleased). "Satisfied" means the evidence is in this
repository or in [VALIDATION.md](VALIDATION.md); "open" means it does not
exist yet. Offline fixtures cannot satisfy a live-service gate. Gates 1 to 11
concern the OpenAI Decisions judge and its two routes ("both routes" below);
gates 12 to 15 cover Microsoft-Decision-1 and Tile Sieve.

| # | Gate | Status |
|---|---|---|
| 1 | Endpoint, schema and terms | **Satisfied.** OpenAI direct: written from the public Decisions guide, API reference and changelog of 2026-10-06 (`POST /v1/decisions`, `gpt-6-luna`), and confirmed live on 2026-10-07 (model echo, usage without a cost field, `x-request-id`, a 400 for an unknown request field). OpenRouter: response shape, model echo with a dated suffix, usage with cost, error bodies, the 200-question limit and the routing privacy options were observed live on 2026-10-06. |
| 2 | Engine requirements met by the judge | **Satisfied on both routes.** OpenRouter: noul answers are probabilities, every choice answer carried a full vector and a confidence, all 61 vectors summed to exactly 1 at two decimals, argmax matched the choice 61/61, and repeated requests were byte-identical. OpenAI direct: 4 of 4 answer batches validated (76 answers); all 32 choice vectors summed to exactly 1 at two decimals, the choice equaled the argmax 32/32, and the confidence followed the same identity as on OpenRouter. Strict mass stays the default. |
| 3 | Adapter and gateway | **Satisfied.** Both routes share a deadline-bounded exchange (explicit TLS context, keep-alive reuse, no proxy, no redirects), per-route status tables, bounded error-body reading that keeps structural fields only, journaled retries with a breaker and a run reserve, answer-scoped refusals and defects, spend accounting with `--max-cost`, and a credential-shape scan. See the [provider contract](PROVIDER_CONTRACT.md). |
| 4 | Offline fixtures and distribution checks | **Satisfied.** The offline suite forbids sockets and runs with dummy keys. `tools/check_distribution.py` inspects both archives, installs the wheel without keys, checks the exit-3 route selection and exit-2 `provider_unavailable` gates for both routes, and runs the unpacked sdist's test suite. Sanitized live response fixtures are under `tests/fixtures/openrouter/observed/2026-10-06/`. |
| 5 | Credentials and spend | **Satisfied on both routes.** Live runs used operator keys with a credit cap, read from the environment only; about $1.27 was spent in total (about $1.16 on OpenRouter, about $0.11 on OpenAI direct). Every attempt records its cost, and `--max-cost` refuses attempts that could exceed a limit. OpenRouter reports the cost of each request; OpenAI direct reports usage but no cost, so its spend is the list-price estimate. |
| 6 | Live compatibility | **Satisfied on both routes.** OpenRouter: smoke suites of 32 and 48 requests, and 23 full catalog runs totaling about 5,700 calls. OpenAI direct: the direct smoke suite (`tools/smoke/run_openai.py`, 5 requests; 4 answer batches validated, `x-request-id` on every response, a 400 for an unknown request field classified `http_rejected`) and 2 full catalog runs (507 calls). The direct route's 401, 429, 5xx and refusal handling remain fixture-only. |
| 7 | Effectiveness | **Development evidence only.** On the 34-case public development suite the shipped defaults (`--choice-gate mass`, state layout v1, canaries on) pass 32/34 (legacy-v1) and 32/34 (scoped-v2-beta) on OpenRouter, and 32/34 (legacy-v1) and 31/34 (scoped-v2-beta) on OpenAI direct, with 16/16 controls clear in all four runs; under OpenRouter legacy-v1 the earlier legacy gate passed 31/34. The suite is synthetic, small and not held out. No held-out evaluation exists; no recall, precision or calibration claim is made. |
| 8 | Final release evaluation | **Satisfied (development suite only).** At the release code with the shipped defaults: OpenRouter legacy-v1 with `--choice-gate mass` 32/34 (214 calls, $0.0450) and scoped-v2-beta 32/34 (312 calls, $0.0683, which the gate does not affect); OpenAI direct legacy-v1 32/34 (211 calls, about $0.045 estimated) and scoped-v2-beta 31/34 (296 calls, about $0.065 estimated); 16/16 controls clear in all four. The only later code change makes the mass gate the default. Under the earlier legacy gate OpenRouter legacy-v1 gave 31/34 (211 calls, $0.0451), identical to the earlier canary-on runs. A 10-request OpenRouter release smoke subset ($0.0025) returned 200 throughout with every judge control passing and routing `deny` accepted. See [VALIDATION.md](VALIDATION.md). |
| 9 | Judge controls and injection | **Partly satisfied.** Controls passed in all 523 live requests of the canary runs and did not move other answers. Two crude injection attempts failed live. No held-out injection set has been run; controls and markers catch crude attempts only. |
| 10 | Offline regressions, lint, types, build | **Satisfied locally** on Windows 11 with Python 3.11, 3.12 and 3.13 (see [VALIDATION.md](VALIDATION.md)). The GitHub Actions matrix (Ubuntu and Windows, Python 3.11 to 3.13) runs on push and has not run for this tree yet. |
| 11 | Repository and release | **Operator decision.** The packaging metadata names `https://github.com/BillNDD/decision-bug-hunter`. Creating the repository, pushing, tagging `v0.1.0b1` and publishing are the operator's actions. |
| 12 | Microsoft-Decision-1 through OpenRouter | **Verified live and published as experimental, below the full-judge bar. This is not a pass.** The response shape, the dated model echo, usage with a cost, the routing object and the Azure upstream were observed on 2026-10-11, and the 34-case catalog ran through the shipped CLI on 2026-10-12: 28/34 under `legacy-v1` (13/16 defective programs, 14/17 individual defects, 14/16 controls clear, 1/2 missing evidence; 182 calls, $0.0107) against 32/34 for OpenAI Decisions on the same route, with no answer defect and every judge control passed. A live tuning study ($0.2143) tried six screening formats, three verification formats and a window-size sweep and did not reach the bar (its held-out screening gate failed). The judge ships labelled experimental, offered for `legacy-v1` only, with a stderr note on every run. See [VALIDATION.md](VALIDATION.md). |
| 13 | Microsoft-Decision-1 through Foundry | **Open.** The route is built from Microsoft's documentation and pinned by offline fixtures only; nothing has been sent to a deployment. It closes only with a live run against one: a 5-request smoke, then the legacy-v1 catalog, which also confirms the usage field names, error bodies, limits and price. Until then the route is labelled "not yet verified live" in the README, the CLI help and this table. |
| 14 | Tile Sieve, OpenAI judge | **Satisfied (development suite only, optimistic).** Through the shipped CLI on 2026-10-12 the 34-case catalog gave 34/34 by location (strict 32/34) in 53 calls and about $0.0154 (estimated) on OpenAI direct, and 33/34 (strict 31/34) in 52 calls and $0.0149 through OpenRouter, against 211 and 214 calls for `legacy-v1`; every case fit one request. The thresholds were fitted on the pilot study's own planted and clean files, but the pilot also ran this 34-case catalog while the report rule was chosen, so the catalog is not held out and these scores are optimistic. |
| 15 | Tile Sieve, Microsoft judge | **Not offered.** Microsoft-Decision-1 has no calibrated threshold set, the tuning study's held-out screening gate failed, and `--search-policy tile-sieve-beta` refuses `--judge microsoft` (exit 2). No Microsoft set will be added in this beta. |

## Changes that require new evidence

- Any change to `tile_sieve_thresholds.json` (a value, a screening rule or a
  new judge's set) needs a fresh catalog run through the shipped CLI for each
  judge and route it affects, and held-out labeled evidence before it is
  called calibrated: the current set was chosen in a pilot that also ran the
  development catalog.
- A default that moves findings (thresholds, the choice gate, the
  localization menu, policy placement, verification gating, the state
  layout, the question pack) needs held-out labeled evidence, not only the
  development suite. The one exception so far: the maintainer made
  `--choice-gate mass` the default on development-suite evidence alone
  (32/34 against 31/34 on OpenRouter legacy-v1, controls 16/16 in both); a
  held-out evaluation should confirm or revert it.
- A change to request bytes, routing, retries, status tables or the answer
  decoders needs updated offline fixtures and a live smoke run on the route
  it affects.
- A new judge or model needs its own allow-list entry, price table, fixtures,
  live smoke evidence and a `legacy-v1` catalog run reported next to OpenAI
  Decisions' on the same catalog. A new route needs the same, except the
  catalog run when the judge is unchanged. A judge offered with Tile Sieve
  also needs its own threshold set.

## Known issues

- Request concurrency is not exposed in 0.1.0b1. The gateway can hold several
  requests in flight (`max_in_flight`) and the exchange can pool connections
  (`max_connections`), but both search policies send one request at a time,
  so there is no `--concurrency` flag. Before one is added, three latent
  gateway issues found by the 2026-10-12 audit must be fixed:
  - Gateway worker threads do not inherit context variables, so a worker
    does not see the active request envelope or state layout, and a request
    the calling thread would have completed can be sent (and billed) and then
    fail as `invalid_request`.
  - `max_in_flight` is not checked against the provider's `max_connections`,
    so with a gateway wider than its provider one unlocked exchange can be
    shared by several workers.
  - A budget refusal caused only by other calls' in-flight cost reservations
    latches `cost_budget_exhausted` and cancels calls that were admitted but
    not yet sent, so a tight `--max-cost` completes fewer calls at a higher
    `max_in_flight`.
