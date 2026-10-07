# Release gates

Status for `0.1.0b1` (unreleased). "Satisfied" means the evidence is in this
repository or in [VALIDATION.md](VALIDATION.md); "open" means it does not
exist yet. Offline fixtures cannot satisfy a live-service gate.

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
| 10 | Offline regressions, lint, types, build | **Satisfied locally** on Windows 11 with Python 3.12 and 3.13 (see [VALIDATION.md](VALIDATION.md)). The GitHub Actions matrix (Ubuntu and Windows, Python 3.11 to 3.13) runs on push and has not run for this tree yet. |
| 11 | Repository and release | **Operator decision.** The packaging metadata names `https://github.com/BillNDD/decision-bug-hunter`. Creating the repository, pushing, tagging `v0.1.0b1` and publishing are the operator's actions. |

## Changes that require new evidence

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
- A new model or route needs its own allow-list entry, price table, fixtures
  and live smoke evidence.
