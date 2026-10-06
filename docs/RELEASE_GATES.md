# Release gates

Status for `0.1.0b1` as of 2026-10-06. "Satisfied" means evidence exists in
this repository; "open" means the gate depends on a live account, budget or
dataset that this preparation did not use. Offline fixtures and upstream Jev
campaigns cannot satisfy a live-service gate.

| # | Gate | Status |
|---|---|---|
| 1 | Official endpoint, schema and terms | **Satisfied for documentation.** The [guide](https://developers.openai.com/api/docs/guides/decisions), [reference](https://developers.openai.com/api/reference/resources/decisions) and [changelog](https://developers.openai.com/api/docs/changelog) of 2026-10-06 document `POST /v1/decisions`, bearer authentication, `gpt-6-luna`, predicate/choice/score answers with probabilities and confidence, refusal answers, the usage object, input-only pricing, ZDR/HIPAA/data-residency support and public-beta status. No question-count, option-count or precision limits are documented. Account access was **not** verified. |
| 2 | Engine requirements met by the API | **Satisfied by documentation, unverified live.** Predicates return P(true); choices return a full vector plus confidence; native batching with name-matched answers in question order is documented. Independence of same-request questions, probability precision and ordering guarantees rest on the documentation alone. The strict-mass default is a local policy; `--choice-rounding-places` exists if live replies are rounded. |
| 3 | Adapter implementation | **Satisfied.** `decision_bug_hunter/decisions.py` implements only the documented translation and a fixed-origin stdlib transport: bounded bodies, socket timeouts, no redirects, no proxy, no retry, suppressed error bodies, fixed codes for auth/rate/redirect/server failures, refusal handling, usage retention on semantic failure, credential isolation and receipts. |
| 4 | Fixtures and installed-wheel checks | **Satisfied.** `tests/test_decisions.py` fixes the documented request and response examples, framing, status, timeout, refusal, usage and leak behavior, plus an end-to-end CLI run through a synthetic service. `tools/check_distribution.py` installs the wheel into a fresh environment without a key and checks the `provider_unavailable` gate. |
| 5 | Credentials and budget | **Open.** No credential, grant, paid call or access request was used. The operator supplies `OPENAI_API_KEY` and accepts provider pricing; DBH bounds work by calls, questions, windows and deadlines but does not reserve or settle money. |
| 6 | Live compatibility and effectiveness | **Open.** No live request has been made. Recommended first live check: a small file with `--scope standalone`, inspecting `report.json` issues for `response_distribution`, `response_refused`, `http_*` codes and unknown usage. No labeled holdout has been run; no recall, precision or calibration claim is made for DBH. |
| 7 | Offline regressions, lint, types, build, packaging, scans | **Satisfied locally** on Windows / Python 3.12 (see [VALIDATION.md](VALIDATION.md)); the GitHub Actions matrix (Ubuntu and Windows, Python 3.11–3.13) runs on push. The tracked tree and reachable history were scanned for credentials, private paths, personal identifiers and unnecessary assets; commits use an anonymous contributor identity. |
| 8 | Repository and release authorization | **Operator decision.** The packaging metadata assumes `https://github.com/BillNDD/decision-bug-hunter`. Creating the repository, pushing, tagging `v0.1.0b1` and publishing a release are the operator's actions. |

## Changes that require new evidence

Engine thresholds, budgets, probability-mass policy and the question pack are
unchanged from the offline foundation. Changing any of them, or adding the
`score` type, image input, retries, backoff or proxy support, requires a
reviewed change with new fixtures and, where behavior depends on the service,
live evidence.
