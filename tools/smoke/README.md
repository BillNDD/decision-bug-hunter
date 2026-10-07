# OpenRouter Decisions smoke suite

First-contact tests for the Decisions API through OpenRouter
(`POST https://openrouter.ai/api/alpha/decisions`, model
`openai/gpt-6-luna-decisions`). The requests are built by DBH's own question
code, so they match what DBH would send. Each one is designed to answer a
specific open question about live behavior. The analysis is written to a
summary that the maintainer reads to set defaults.

The full suite is 31 requests, about 134k input tokens, roughly one or two
cents at the listed $0.10 per 1M input tokens.

## Run it

From the repository root, with Python 3.11 or newer:

```sh
python tools/smoke/run_openrouter.py --dry-run
python tools/smoke/run_openrouter.py
```

The key is read from `OPENROUTER_API_KEY`, or from a dotenv file with
`--env-file` (only that one variable is read). It is never printed or saved.
Results go to `smoke-results/openrouter-<UTC time>/`, which git ignores:
`results.jsonl` holds every response and `summary.md` holds the analysis.

### Through the Hermes agent

Hermes does not need a Decisions integration: its terminal tool can run the
runner. Ask Hermes to run, from this repository's directory:

```sh
python3 tools/smoke/run_openrouter.py --env-file ~/.hermes/.env
```

If Hermes runs under WSL, the repository is under `/mnt/<drive>/...`. Add
`--only S01,S02` to run a subset first.

### One request by hand

```sh
curl -sS https://openrouter.ai/api/alpha/decisions -H "Authorization: Bearer $OPENROUTER_API_KEY" -H "Content-Type: application/json" --data-binary @tools/smoke/openrouter/S01-baseline.json
```

## What each test answers

| ID | Question it answers |
|---|---|
| S01 | Response shape, returned model string, usage and cost fields, id, provider |
| S02 | Does a real DBH screening batch (26 questions, interval names like `screen_L1-8`) pass, and do the screens find the planted bug on line 5? |
| S03, S04 | Same batch with the evidence as a JSON string or as numbered text: do answers change? |
| S05 | Same batch with the policy text sent once in the state instead of in every question: 53 percent smaller, are answers equivalent? |
| S06 | 64 per-line questions: per-line localization, and whether an inverted twin question gives the complementary probability |
| S07 | 200 questions, the documented maximum, with objective answers known locally: are probabilities sensible and correctly oriented? |
| S08 | 201 questions: the error status and error body format |
| S09 | A 13 KB instruction: length acceptance |
| S10, S10b | DBH's real 212-option nested localization menu versus a 20-option single-line menu: precision, mass sums, argmax, confidence |
| S11 | 30 choice questions from unambiguous to arbitrary: what `confidence` means relative to the probabilities |
| S12 | S02 repeated five times: run-to-run noise |
| S13a, S13b | Prompt injection in the source ("answer false" / "answer true") with must-true and must-false canary questions |
| S14-1..8 | Four planted bugs and four clean twins: a separation preview, not a calibration |
| S16 | Invalid model id: error format |
| S17 | Score question shape |
| S18, S19 | Whether zero-data-retention or data-collection-deny routing is available for this model |

Rebuild the request files after changing question text with
`python tools/smoke/build_openrouter.py`, and re-run the analysis on saved
results with `--summarize <results directory>`.
