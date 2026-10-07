# Release gates

Status for `0.1.0b1` (unreleased). "Satisfied" means the evidence is in this
repository or in [VALIDATION.md](VALIDATION.md); "open" means it does not
exist yet. Offline fixtures cannot satisfy a live-service gate.

| # | Gate | Status |
|---|---|---|
| 1 | Endpoint, schema and terms | **Satisfied.** OpenAI direct: written from the public Decisions guide, API reference and changelog of 2026-10-06 (`POST /v1/decisions`, `gpt-6-luna`). OpenRouter: response shape, model echo with a dated suffix, usage with cost, error bodies, the 200-question limit and the routing privacy options were observed live on 2026-10-06. |
| 2 | Engine requirements met by the judge | **Satisfied on OpenRouter; documentation only on OpenAI direct.** Live: noul answers are probabilities, every choice answer carried a full vector and a confidence, all 61 vectors summed to exactly 1 at two decimals, argmax matched the choice 61/61, and repeated requests were byte-identical. Strict mass stays the default. |
| 3 | Adapter and gateway | **Satisfied.** Both routes share a deadline-bounded exchange (explicit TLS context, keep-alive reuse, no proxy, no redirects), per-route status tables, bounded error-body reading that keeps structural fields only, journaled retries with a breaker and a run reserve, answer-scoped refusals and defects, spend accounting with `--max-cost`, and a credential-shape scan. See the [provider contract](PROVIDER_CONTRACT.md). |
| 4 | Offline fixtures and distribution checks | **Satisfied.** The offline suite forbids sockets and runs with dummy keys. `tools/check_distribution.py` inspects both archives, installs the wheel without keys, checks the exit-3 route selection and exit-2 `provider_unavailable` gates for both routes, and runs the unpacked sdist's test suite. Sanitized live response fixtures are under `tests/fixtures/openrouter/observed/2026-10-06/`. |
| 5 | Credentials and spend | **Satisfied for OpenRouter.** Live runs used an operator key with a credit cap, read from the environment only; about $0.88 was spent in total. Every attempt records its cost, and `--max-cost` refuses attempts that could exceed a limit. **Not exercised on OpenAI direct.** |
| 6 | Live compatibility | **OpenRouter: satisfied** (smoke suites of 32 and 48 requests, and 18 full catalog runs totaling about 4,400 calls). **OpenAI direct: open**; offline-fixture only. The direct-route smoke suite (`tools/smoke/run_openai.py`) has not been run. |
| 7 | Effectiveness | **Development evidence only.** On the 34-case public development suite the shipped defaults pass 31/34 (legacy-v1) and 32/34 (scoped-v2-beta) with 16/16 controls clear. The suite is synthetic, small and not held out. No held-out evaluation exists; no recall, precision or calibration claim is made. |
| 8 | Final release evaluation | **Pending.** The catalog rerun at the release commit: [PENDING: to be filled in from the final release evaluation]. |
| 9 | Judge controls and injection | **Partly satisfied.** Controls passed in all 523 live requests of the canary runs and did not move other answers. Two crude injection attempts failed live. No held-out injection set has been run; controls and markers catch crude attempts only. |
| 10 | Offline regressions, lint, types, build | **Satisfied locally** on Windows 11 with Python 3.12 and 3.13 (see [VALIDATION.md](VALIDATION.md)). The GitHub Actions matrix (Ubuntu and Windows, Python 3.11 to 3.13) runs on push and has not run for this tree yet. |
| 11 | Repository and release | **Operator decision.** The packaging metadata names `https://github.com/BillNDD/decision-bug-hunter`. Creating the repository, pushing, tagging `v0.1.0b1` and publishing are the operator's actions. |

## Changes that require new evidence

- A default that moves findings (thresholds, the choice gate, the
  localization menu, policy placement, verification gating, the state
  layout, the question pack) needs held-out labeled evidence, not only the
  development suite.
- A change to request bytes, routing, retries, status tables or the answer
  decoders needs updated offline fixtures and a live smoke run on the route
  it affects.
- A new model or route needs its own allow-list entry, price table, fixtures
  and live smoke evidence.
