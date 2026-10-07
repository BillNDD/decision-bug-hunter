# Decisions smoke suites

Live first-contact tests for the two routes to the one Decisions judge:

- OpenRouter: `POST https://openrouter.ai/api/alpha/decisions`, model
  `openai/gpt-6-luna-decisions` (`run_openrouter.py`, S-IDs);
- OpenAI direct: `POST https://api.openai.com/v1/decisions`, model
  `gpt-6-luna` (`run_openai.py`, O-IDs).

Both runners send through DBH's shipped code path:
`decision_bug_hunter.exchange.HttpsExchange` (explicit TLS context that never
reads `SSLKEYLOGFILE`, no proxy, no redirects, an absolute deadline per
request) and the route's provider (`OpenRouterProvider` splice and routing
default, or `DecisionsProvider` translation). Nothing here uses urllib. The
suites continue after a network failure and record it.

This directory is repository-only: the sdist leaves it out, and the tests
that need it skip there. The request bodies are built for the shipped state
layout (`v1`); the pre-registered layout checks ran on `v2` bodies before
the default was reverted (see `docs/VALIDATION.md`).

The full OpenRouter suite is 48 requests. Its run on 2026-10-07 used about
230,600 input tokens and cost $0.0231 at the listed $0.10 per 1M input
tokens. The direct OpenAI suite has not been run against the live service.
Results of the OpenRouter runs are summarized in `docs/VALIDATION.md`.

## Operator rules

1. The key comes only from the environment (`OPENROUTER_API_KEY` or
   `OPENAI_API_KEY`) or from `--env-file`, which reads only that one
   variable. Never put a key on a command line, in a file in this
   repository, or in a chat with an agent.
2. Hermes, or any other agent, reads only a v2 `summary.md`. It never reads
   `results.jsonl`, anything under `raw/`, request bodies of S13 (prompt
   injection) or any summary written by the pre-hardening runner.
3. Generation ids and request ids stay local. The runners record them only
   as `<gen-id>` / `<request-id>`; `--keep-raw` bodies under `raw/` may still
   contain them, so `raw/` never leaves this machine.
4. Results go to `smoke-results/<route>-<UTC time>/`, which git ignores; the
   runner also writes `.gitignore` and `CACHEDIR.TAG` into it.
5. Fixtures enter `tests/fixtures/openrouter/observed/<date>/` only through
   `sanitize.py --promote` and a reviewed commit.

## Run it

From the repository root, with Python 3.11 or newer:

```sh
python tools/smoke/run_openrouter.py --dry-run
python tools/smoke/run_openrouter.py --only S01h,S02s,S19b,S20
python tools/smoke/run_openrouter.py
python tools/smoke/run_openai.py --dry-run
```

`--only` takes ids or families (`S02s` selects every S02s batch).
`--include-optional` adds S21 (fixed invalid token) and S22 (provider pin),
or O05 on the direct route. `--keep-raw` keeps raw response bodies under
`raw/` (off by default). `--summarize <dir>` rebuilds `summary.md`.

### Through the Hermes agent

Hermes can run the runner from its terminal tool, from this repository's
directory, and then read only the new `summary.md`:

```sh
python3 tools/smoke/run_openrouter.py --env-file ~/.hermes/.env
```

Under WSL the repository is under `/mnt/<drive>/...`.

## What the files contain

- `results.jsonl`: one record per attempt: S-ID, status (or `null` with the
  failing phase and exception kind), DBH code, submission class, elapsed
  time, connection reuse, allow-listed headers (`content-type`,
  `content-length`, `transfer-encoding`, `content-encoding`, `connection`,
  `retry-after`, `x-ratelimit-*`, ids as placeholders), the names of dropped
  headers (never `cf-ray`, whose value reveals the caller's region), the
  ADR-8 error fields, and the body reduced to answer numbers, DBH-authored
  names, model, upstream provider and usage. Messages and metadata values are
  never kept.
- `summary.md`: S-IDs, statuses, codes, counts and numeric summaries only.

## Sanitizing and promoting

```sh
python tools/smoke/sanitize.py smoke-results/<run>              # sanitized copy
python tools/smoke/sanitize.py smoke-results/<run> --in-place   # originals to raw/
python tools/smoke/sanitize.py smoke-results/<run> --promote 2026-10-06 \
    --ids S01,S02 --builder-layout v1
```

The sanitizer accepts both runner generations and is idempotent. S15 (a
model DBH no longer targets) is dropped and can never be promoted.

## What each request answers

| ID | Send | Question it answers |
|---|---|---|
| S01 | body | Response shape, returned model string, usage and cost, id, provider |
| S01h | splice | S01 through the shipped path: framing, echo, cost, generation id header |
| S02 | body | A real DBH screening batch: names, values, the planted bug on line 5 |
| S02s | splice | The same questions in production batches: caps, receipts, partial handling |
| S03, S04 | body | Evidence as a JSON string or as numbered text: do answers change? |
| S05 | body | Policy text sent once in the state: equivalence and token saving |
| S06 | body | 64 per-line questions and an inverted polarity twin |
| S07, S08 | body | 200 questions (accepted) and 201 (the error status and body) |
| S09 | body | A 13 KB instruction |
| S10, S10b | body | The 212-option nested localization menu versus 20 single lines |
| S11 | body | What `confidence` means relative to the probabilities |
| S12 | body | S02 five times: run-to-run noise |
| S12b | splice | Batch geometry: max \|delta\| against S02s above 0.02 enters the calibration key |
| S12c | splice | S02s plus the two canaries: max \|delta\| above 0.02 would have kept canaries off (observed: 0) |
| S13a, S13b | body | Prompt injection with must-true and must-false canaries |
| S13c | splice | Injection under the shipped pack and layout, plus a policy-in-state cell |
| S14-1..8 | body | Four planted bugs and four clean twins: separation preview, not calibration |
| S16 | body | Invalid model id |
| S17 | body | Score question shape |
| S18, S19 | body | Zero-data-retention and data-collection-deny routing |
| S19b | splice | DBH's exact default routing object |
| S19c | body | Unsatisfiable routing: status and routing-metadata keys |
| S20 | splice | Keep-alive: is the second of two back-to-back requests reused? |
| S21 | body | Optional: 401 with a fixed invalid token |
| S22 | body | Optional: `provider.only` openai |
| O01-O05 | mixed | The direct-route analogs; O06 is the `x-request-id` count in the summary |

Rebuild the request files after changing question text with
`python tools/smoke/build_openrouter.py`; a test fails when the committed files
drift from the builder.
