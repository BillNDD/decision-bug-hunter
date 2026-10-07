# Validation

What has been checked for `0.1.0b1`, offline and live, and what has not.

## Offline checks

Environment: Windows 11; Python 3.12.10 (project environment) and Python
3.13.14 (second interpreter, suite only); Ruff 0.16.10, mypy 1.20.2, build
1.6.1, setuptools 84.0.0.

| Check | Result |
|---|---|
| Offline suite, Python 3.12 (`python -m unittest discover -s tests -t .`) | 688 tests, OK, 2 skipped (POSIX directory fsync, POSIX symlink creation); about 3.5 minutes on an idle machine |
| Same suite, Python 3.13 | 688 tests, OK, same 2 skips |
| Same suite, Python 3.12, with dummy `OPENAI_API_KEY` and `OPENROUTER_API_KEY` set (as in CI) | 688 tests, OK, same 2 skips |
| Ruff (configured fatal-error rules) | clean |
| mypy (strict definitions for `providers`, `decisions`, `exchange`, `hosted`, `openrouter`, `secret_scan`, `injection_markers`) | clean; the inherited engine is not fully typed |
| `python -m build` and `tools/check_distribution.py` | pass: archive contents, fresh wheel install without keys, exit-3 route selection and exit-2 `provider_unavailable` gates for both routes, and the unpacked sdist's own test suite (about 2.5 minutes) |
| GitHub Actions matrix (Ubuntu and Windows, Python 3.11 to 3.13) | configured; not yet run for this tree |

The suite refuses real sockets: `tests/__init__.py` installs a guard that
fails any `connect`, `create_connection`, `getaddrinfo` or TLS wrap, so a
test that reaches for the network fails instead of calling a provider.
Transport tests use a scripted fake HTTPS server with a fake clock. The
sdist leaves out `tools/smoke` (repository-only live tooling); tests that
need it skip by name there.

Sanitized live responses from 2026-10-06 (`S01`, `S02`, `S08`, `S10`,
`S10b`, `S11`, `S16`, `S17`, `S18`, `S19`) are committed under
`tests/fixtures/openrouter/observed/2026-10-06/`. In a repository checkout
tests rebuild the matching requests and check that the decoder accepts every
observed 200 (the two that asked `score` questions, which DBH does not use,
are rejected as `response_schema`), that every observed choice vector passes
strict mass and argmax, that the observed error bodies map to the expected
codes, and that no message, metadata value or identifier survived
`tools/smoke/sanitize.py`. The mass-gate tests also run on an observed
212-option vector in the sdist.

## Live runs

All live runs used the OpenRouter route (`openai/gpt-6-luna-decisions`)
with an operator key that has a credit cap, read from the environment. No
live request has been made to `api.openai.com`. Costs are as reported by
OpenRouter (input tokens x $0.0000001 in every response).

| Date (UTC) | Run | Requests | Input tokens | Cost |
|---|---|---:|---:|---:|
| 2026-10-06 | First-contact smoke suite S01 to S19 (request bodies sent directly) | 32 | about 176,600 | $0.0177 |
| 2026-10-07 | Catalog, first 2 cases (check run) | 6 | 7,721 | $0.0008 |
| 2026-10-07 | Catalog, 34 cases, first engine build, legacy-v1 and scoped-v2-beta | 211 + 312 | 953,320 | $0.0953 |
| 2026-10-07 | Catalog, 34 cases, state layout v2 build, both policies | 220 + 307 | 1,022,134 | $0.1023 |
| 2026-10-07 | Catalog, same build forced to layout v1, both policies | 211 + 312 | 953,590 | $0.0954 |
| 2026-10-07 | Hardened smoke rerun through the shipped exchange | 48 | about 230,600 | $0.0231 |
| 2026-10-07 | Catalog, localization variants (4 runs) | 990 | | $0.1715 |
| 2026-10-07 | Catalog, canaries on by default, both policies | 211 + 312 | 1,134,548 | $0.1134 |
| 2026-10-07 | Catalog, `--policy-placement state` variants (3 runs) | 647 | | $0.1169 |
| 2026-10-07 | Catalog, `--require-verification` variants (3 runs) | 703 | | $0.1437 |
| 2026-10-07 | Catalog, release code, shipped defaults, both policies | 211 + 312 | 1,134,548 | $0.1134 |
| 2026-10-07 | Release smoke subset through the shipped exchange | 10 | | $0.0025 |
| | Total | | | about $0.99 |

### Smoke findings

From the two smoke suites (32 and 48 requests):

- Response shape: an answer map keyed by question name; `model`
  `openai/gpt-6-luna-decisions` with a dated `-YYYYMMDD` suffix; upstream
  provider `OpenAI`; `usage` with `input_tokens`, `output_tokens` (always 0)
  and `cost`.
- Precision: noul values have at most 2 decimals; all 61 choice vectors,
  including a 212-option menu, summed to exactly 1 at 2 decimals; the argmax
  equaled the choice 61/61. Strict mass is kept as the default.
- Determinism: one request repeated 5 times gave byte-identical answers, and
  batch geometry and the canary questions moved no other answer (max |delta|
  0). Identical requests are reused within a scan.
- Limits: 200 questions accepted, 201 rejected with HTTP 400; a 13 KB
  instruction accepted; an invalid model id rejected with HTTP 400.
- Routing: `data_collection: deny` returned 200; `zdr: true` returned 404
  with routing metadata. DBH sends `deny` and no `zdr` by default.
- Transport: the hardened rerun got 44 responses with status 200, 2 with
  400 (the 201-question and invalid-model probes) and 2 with 404 (the zdr
  and unsatisfiable-routing probes). Connections were reused on 46 of 48
  requests; latency was 0.14 to 0.33 s per request, against 0.33 to 1.44 s
  with a fresh TLS connection each time.
- Localization: on a planted bug, a 212-option nested-interval menu chose
  a wide interval with p = 0.27 (below the 0.5 gate) although 0.74 of the
  mass overlapped the buggy line; a 20-option single-line menu chose the
  line with p = 0.97. This motivated `--choice-gate mass` and
  `--localization-menu singletons`.
- Policy placement: sending the policy once in state cut input tokens by 32%
  on one request and changed answers (mean |delta| 0.20).
- Injection: an "answer false" comment did not suppress a real bug, and an
  "answer true" comment did not flood a clean function (two trials).
- Known pairs: four planted bugs all screened above their clean twins (a
  preview on 8 files, not calibration).
- No refusal and no unknown answer type was observed.

The pre-registered keep-or-revert rule for state layout v2 passed on the
hardened rerun: canaries answered 1 (must-true) and 0 (must-false); an
injected "answer false" left the bug's screen at or above 0.64 and an
injected "answer true" left the clean screen at or below 0.31; the lowest
planted-bug screen (0.98) was above the highest clean screen (0.47); and
production batches validated 19/19 and 7/7.

## Catalog evaluation

`tools/eval/run_catalog.py` runs the CLI over 34 labeled synthetic cases
(16 defective programs with 17 planted defects, 16 corrected controls, 2
cases that lack needed evidence) and scores each report: a defect case
passes when the scan is complete and every planted line lies inside a
finding within its allowed region; a control passes when the scan is
complete with no findings; a missing-evidence case passes when the scan is
incomplete with no findings. The suite is public, authored for development
and not held out; n = 34. Answers are deterministic per request, so each
configuration ran once. Thresholds were not tuned on it.

### State layout experiment

With state layout v2 as the default, the catalog changed against the first
build: legacy-v1 gained the cross-file helper case but flagged a clean
control; scoped-v2-beta lost three cases, two of them clean controls flagged.
To separate the layout from the other changes in that build, the same build
was rerun with layout v1:

| Outcome | legacy, v1 layout | legacy, v2 layout | scoped, v1 layout | scoped, v2 layout |
|---|---:|---:|---:|---:|
| Defective programs detected | 14/16 | 15/16 | 15/16 | 14/16 |
| Individual defects covered | 15/17 | 16/17 | 17/17 | 17/17 |
| Corrected controls clear | 16/16 | 15/16 | 16/16 | 14/16 |
| Missing evidence incomplete | 1/2 | 1/2 | 1/2 | 1/2 |
| Entire cases | 31/34 | 31/34 | 32/34 | 29/34 |

The v1 runs reproduced the first build exactly, so every difference came
from layout v2. Decision: although v2 passed the smoke keep-or-revert rule,
the default is layout v1, because v2 added false findings on clean controls
under both policies. `--state-layout v2` remains available.

### Shipped defaults

Layout v1, canaries on, every tier-2 option at its default:

| Outcome | legacy-v1 | scoped-v2-beta |
|---|---:|---:|
| Defective programs detected | 14/16 | 15/16 |
| Individual defects covered | 15/17 | 17/17 |
| Corrected controls clear | 16/16 | 16/16 |
| Missing evidence incomplete | 1/2 | 1/2 |
| Entire cases | 31/34 | 32/34 |
| Calls | 211 | 312 |
| Input tokens | 451,412 | 683,136 |
| Cost | $0.0451 | $0.0683 |

Outcomes are identical to the same runs with canaries off (378,316 and
575,004 input tokens): the controls cost about 19% more input tokens. No
control failed and no judge banner appeared in these 523 requests. The
strict score (requirement citations) equaled the location score.

Failures: legacy-v1 misses a defect in a cross-file helper (no findings) and
localizes the second of two defects in a 70-line file only as a broad
region; both policies report a project case whose helper was not supplied
as complete instead of incomplete. Under scoped-v2-beta the 70-line case
localizes both defects but ends incomplete with unresolved localization.

Final evaluation at the release code (commit `f612116`; later commits change
documentation only), with the shipped defaults: layout v1, canaries on,
OpenRouter routing `deny`:

| Outcome | legacy-v1 | scoped-v2-beta |
|---|---:|---:|
| Defective programs detected | 14/16 | 15/16 |
| Individual defects covered | 15/17 | 17/17 |
| Corrected controls clear | 16/16 | 16/16 |
| Missing evidence incomplete | 1/2 | 1/2 |
| Entire cases | 31/34 | 32/34 |
| Calls | 211 | 312 |
| Input tokens | 451,412 | 683,136 |
| Cost | $0.0451 | $0.0683 |

The results, token counts and failures are identical to the canary-on runs
above: answers are deterministic per request. A release smoke subset of 10
requests ($0.0025) also ran at that code: every request returned 200, cost
equaled input tokens x $0.0000001, the two judge controls answered 1 and 0
in every batch, the S13c injection probes under the shipped layout answered
the screen question 0.99 in the suppression cell and 0 in the flooding
cell, appending the controls moved no other answer (S12c, largest change
0), routing `deny` was accepted (S19b) and the kept-alive connection was
reused.

### Tier-2 options

One run each on the same suite. The localization runs predate the canaries
(equivalent to `--canaries off`); the placement and verification runs have
canaries on.

| Configuration | Defects | Individual | Controls | Missing ev. | Cases | Calls | Cost |
|---|---:|---:|---:|---:|---:|---:|---:|
| legacy + `--localization-menu singletons` | 14/16 | 15/17 | 16/16 | 1/2 | 31/34 | 225 | $0.0376 |
| legacy + `--choice-gate mass` | 15/16 | 16/17 | 16/16 | 1/2 | 32/34 | 214 | $0.0376 |
| legacy + mass + singletons | 15/16 | 16/17 | 16/16 | 1/2 | 32/34 | 227 | $0.0383 |
| scoped + singletons | 15/16 | 17/17 | 16/16 | 1/2 | 32/34 | 324 | $0.0580 |
| legacy + `--policy-placement state` | 15/16 | 16/17 | 15/16 | 2/2 | 32/34 | 219 | $0.0369 |
| legacy + state + `--choice-gate mass` | 15/16 | 16/17 | 15/16 | 2/2 | 32/34 | 191 | $0.0328 |
| scoped + `--policy-placement state` | 15/16 | 17/17 | 15/16 | 2/2 | 32/34 | 237 | $0.0472 |
| legacy + `--require-verification` | 13/16 | 14/17 | 16/16 | 1/2 | 30/34 | 202 | $0.0428 |
| scoped + `--require-verification` | 14/16 | 16/17 | 16/16 | 1/2 | 31/34 | 311 | $0.0682 |
| legacy + mass + state + require-verification | 14/16 | 15/17 | 15/16 | 2/2 | 31/34 | 190 | $0.0327 |

Readings:

- `--choice-gate mass` fixes the broad localization in the 70-line case
  under legacy-v1 at the same cost and with no control regression.
- `--localization-menu singletons` changes no outcome.
- With `--policy-placement state` the judge reports missing context more
  readily: it catches the cross-file helper defect and marks the
  missing-helper case incomplete, but the 70-line defect/control pair ends
  incomplete through unresolved context (the control has no finding; it
  counts as a failed control because the scan is incomplete). Input tokens
  fall 18% (legacy) and 31% (scoped), and scoped calls fall 24% because
  OpenRouter requests may then hold 200 questions.
- `--require-verification` removes one true finding per policy and cannot
  improve controls that were already clear.
- `--choice-rounding-caps` and `--polarity-twin` were not measured on the
  catalog. The polarity twin residual on one smoke request was 0.086 on
  average.

None of these options became a default: a default that moves findings needs
held-out labeled evidence, and this suite is neither held out nor large.

## What remains unproven

- The OpenAI direct route against the live service: request translation,
  status handling, error bodies, `x-request-id` and usage are pinned only by
  fixtures written from the documentation.
- Generalization: no held-out or representative evaluation exists. Recall,
  precision and calibration of DBH are unknown; the 0.80 report, 0.70
  relation and 0.80 refutation thresholds are uncalibrated.
- Refusals: none was observed, so their representation on both routes rests
  on documentation and fixtures.
- Prompt injection beyond two crude trials, and the controls against a
  determined attacker.
- Behavior under sustained rate limiting, overload or network failure: the
  retry, breaker and reserve logic is tested offline only.
- Large scans: the longest live run was a 70-line case; 1,000-call scans
  and the 1,800 s run deadline have not been exercised live.
- POSIX: the suite runs on Windows locally; Linux runs only in CI.
