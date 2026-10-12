# Validation

What has been checked for `0.1.0b1`, offline and live, and what has not.

## Offline checks

Environment: Windows 11; Python 3.12.10 (project environment) and Python
3.13.14 (second interpreter, suite only); Ruff 0.16.10, mypy 1.20.2, build
1.6.1, setuptools 84.0.0.

| Check | Result |
|---|---|
| Offline suite, Python 3.12 (`python -m unittest discover -s tests -t .`) | 693 tests, OK, 2 skipped (POSIX directory fsync, POSIX symlink creation); about 3.5 minutes on an idle machine |
| Same suite, Python 3.13 | 688 tests, OK, same 2 skips (last run before the choice-gate default change, which added 5 tests) |
| Same suite, Python 3.12, with dummy `OPENAI_API_KEY` and `OPENROUTER_API_KEY` set (as in CI) | 688 tests, OK, same 2 skips (same note) |
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

The Foundry fixtures under `tests/fixtures/foundry/` are not observed
responses: they are written from Microsoft's documentation of
Microsoft-Decision-1 in Microsoft Foundry (updated 2026-10-09), with
full-precision probabilities, the two documented usage spellings and one
unrecognized usage shape. The Tile Sieve fixtures under
`tests/fixtures/tile_sieve/` are recorded decisions of the OpenAI judge from
the pilot study and the planned requests of the catalog; the engine tests
replay them offline, without a socket.

## Live runs

Live runs used both routes with operator keys that have a credit cap, read
from the environment: OpenRouter (`openai/gpt-6-luna-decisions`) and OpenAI
direct (`gpt-6-luna` at `api.openai.com`). OpenRouter costs are as reported
by OpenRouter (input tokens x $0.0000001 in every response). OpenAI direct
reports usage but no cost, so its costs are list-price estimates (input
tokens x $0.0000001).

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
| 2026-10-07 | Catalog, release code with `--choice-gate mass --state-layout v2`, both policies | 219 + 307 | 1,199,357 | $0.1200 |
| 2026-10-07 | Catalog, release code with `--choice-gate mass` (layout v1), legacy-v1 | 214 | 449,566 | $0.0450 |
| | OpenRouter subtotal | | | about $1.16 |
| 2026-10-07 | OpenAI direct: smoke suite O01 to O04 through the shipped exchange | 5 | 19,717 | about $0.0020 (estimated) |
| 2026-10-07 | OpenAI direct: catalog, shipped defaults, both policies | 211 + 296 | 1,100,027 | about $0.110 (estimated) |
| | OpenAI direct subtotal | | | about $0.11 |
| | Total | | | about $1.27 |

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

### OpenAI-direct smoke findings

The direct suite (`tools/smoke/run_openai.py`, 5 requests: O01, the two
O02 batches, O03 and O04) ran through the shipped exchange and the
`DecisionsProvider` translation; the adapter needed no change.

- Status: the 4 answer batches returned 200 and all validated: 76 answers
  (44 yes/no, 32 choice). O04, a request with an unknown field, returned
  400 and was classified `http_rejected`; its `error.param` was not a known
  request field, so it was withheld from the records.
- Model and usage: the returned model was accepted 4 of 4 times; usage was
  present in every 200 (output tokens 0). No cost field is returned, so
  spend on this route is the list-price estimate.
- Precision: yes/no values had 1 or 2 decimals; all 32 choice vectors
  summed to exactly 1 at 2 decimals, the choice equaled the argmax 32 of 32
  times, and the confidence matched the same chance-normalized identity as
  on OpenRouter (within 0.015) 32 of 32 times.
- Headers: `x-request-id` on all 5 responses, `x-ratelimit-*` on 2, no
  generation id.
- Transport: 1.53 s for the first request, then 0.14 to 0.19 s over the
  reused connection.

### Keep-or-revert rule for layout v2

The pre-registered keep-or-revert rule for state layout v2 passed on the
OpenRouter hardened rerun: canaries answered 1 (must-true) and 0
(must-false); an injected "answer false" left the bug's screen at or above
0.64 and an injected "answer true" left the clean screen at or below 0.31;
the lowest planted-bug screen (0.98) was above the highest clean screen
(0.47); and production batches validated 19/19 and 7/7.

## Catalog evaluation

`tools/eval/run_catalog.py` runs the CLI over 34 labeled synthetic cases
(16 defective programs with 17 planted defects, 16 corrected controls, 2
cases that lack needed evidence) and scores each report: a defect case
passes when the scan is complete and every planted line lies inside a
finding within its allowed region; a control passes when the scan is
complete with no findings; a missing-evidence case passes when the scan is
incomplete with no findings. The suite is public, authored for development
and not held out; n = 34. Answers are deterministic per request, so each
configuration ran once per route. Thresholds were not tuned on it. All
runs below are on OpenRouter unless they say OpenAI direct.

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

### Default decisions

The maintainer settled two defaults after live comparisons on this suite,
both on OpenRouter under legacy-v1 with canaries on:

- Choice gate: `--choice-gate mass` became the default. Against the earlier
  legacy gate it passed 32/34 instead of 31/34, with corrected controls
  16/16 in both and 214 against 211 calls at about the same cost ($0.0450
  against $0.0451). The mass gate localizes the second defect of the
  70-line case that the legacy gate left as a broad region.
  `--choice-gate legacy` remains selectable. The gate applies to legacy-v1
  localization only; scoped-v2-beta sends the same requests under either
  gate.
- State layout: `--state-layout v2` stays opt-in. Combined with the mass
  gate, layout v2 gave 31/34 with one clean program flagged (controls
  15/16), against 32/34 with controls 16/16 for the mass gate with layout
  v1: it reverses the mass-gate gain on the 70-line case and adds a false
  finding on its corrected control.

The other defaults were kept: `--policy-placement instructions`,
`--search-policy legacy-v1` and `--canaries on`. All of these decisions rest
on this development suite alone (not held out, n = 34).

### Shipped defaults

`--choice-gate mass`, layout v1, canaries on, every other tier-2 option at
its default:

| Outcome | OpenRouter legacy-v1 | OpenRouter scoped-v2-beta | OpenAI direct legacy-v1 | OpenAI direct scoped-v2-beta |
|---|---:|---:|---:|---:|
| Defective programs detected | 15/16 | 15/16 | 16/16 | 14/16 |
| Individual defects covered | 16/17 | 17/17 | 17/17 | 17/17 |
| Corrected controls clear | 16/16 | 16/16 | 16/16 | 16/16 |
| Missing evidence incomplete | 1/2 | 1/2 | 0/2 | 1/2 |
| Entire cases | 32/34 | 32/34 | 32/34 | 31/34 |
| Calls | 214 | 312 | 211 | 296 |
| Input tokens | 449,566 | 683,136 | 445,685 | 654,342 |
| Cost | $0.0450 | $0.0683 | about $0.0446 (estimated) | about $0.0654 (estimated) |

The OpenRouter legacy-v1 column was measured at the release code with
`--choice-gate mass` passed explicitly; the only later code change makes it
the default. The OpenRouter scoped-v2-beta column is the release run below:
the gate does not apply to scoped-v2-beta. The OpenAI-direct columns ran
with the same shipped defaults. The strict score (requirement citations)
equaled the location score in all four runs.

OpenRouter failures: legacy-v1 misses a defect in a cross-file helper (no
findings); both policies report a project case whose helper was not
supplied as complete instead of incomplete. Under scoped-v2-beta the
70-line case localizes both defects but ends incomplete with unresolved
localization.

OpenAI-direct failures: under legacy-v1 both missing-evidence cases were
reported complete. Under scoped-v2-beta the cross-file helper case and the
70-line case ended incomplete (four conflicting claims, two unresolved
localizations and one disagreement about continuing), and the
missing-helper case was reported complete.

The two routes ask the same questions but encode them differently: OpenAI
direct folds the yes/no criteria into each question's instructions and
sends the state as a JSON string inside `input`, while OpenRouter sends the
local envelope natively. The same model gives somewhat different answers to
the two encodings, so the routes' results differ; neither route is better
on every outcome.

The combined run with the mass gate and layout v2 (OpenRouter, canaries on,
release code) gave:

| Outcome | legacy-v1 | scoped-v2-beta |
|---|---:|---:|
| Defective programs detected | 15/16 | 14/16 |
| Individual defects covered | 16/17 | 17/17 |
| Corrected controls clear | 15/16 | 14/16 |
| Missing evidence incomplete | 1/2 | 1/2 |
| Entire cases | 31/34 | 29/34 |
| Calls | 219 | 307 |
| Input tokens | 516,510 | 682,847 |
| Cost | $0.0517 | $0.0683 |

Under legacy-v1 the second 70-line defect was again localized only as a
broad region, the corrected 70-line control was flagged, and a case with a
missing external implementation was reported complete. Under scoped-v2-beta
two clean controls were flagged.

### Earlier default: `--choice-gate legacy`

OpenRouter, layout v1, canaries on, the legacy gate (the default until the
decision above):

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
control failed and no judge banner appeared in these 523 requests.

Failures: legacy-v1 misses a defect in a cross-file helper (no findings) and
localizes the second of two defects in a 70-line file only as a broad
region; both policies report a project case whose helper was not supplied
as complete instead of incomplete.

Final evaluation at the release code (later commits change documentation
and the choice-gate default only), with layout v1, canaries on, OpenRouter
routing `deny` and the then-default legacy gate: the results, calls (211
and 312), input tokens (451,412 and 683,136), costs ($0.0451 and $0.0683)
and failures were identical to the table above, because answers are
deterministic per request. A release smoke subset of 10 requests ($0.0025)
also ran at that code: every request returned 200, cost equaled input
tokens x $0.0000001, the two judge controls answered 1 and 0 in every
batch, the S13c injection probes under the shipped layout answered the
screen question 0.99 in the suppression cell and 0 in the flooding cell,
appending the controls moved no other answer (S12c, largest change 0),
routing `deny` was accepted (S19b) and the kept-alive connection was
reused. The smoke subset sends fixed request bodies, so the gate default
does not affect it.

### Tier-2 options

One run each on the same suite (OpenRouter), measured while the legacy
gate was the default: "legacy" rows without "mass" ran with the legacy
gate. The localization runs predate the canaries (equivalent to
`--canaries off`); the placement and verification runs have canaries on.

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
  under legacy-v1 at the same cost and with no control regression; it is
  now the default (see Default decisions).
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

Only the mass gate became a default, by the maintainer's decision on this
suite's evidence; the other options stay opt-in. A default that moves
findings would ideally rest on held-out labeled evidence, and this suite is
neither held out nor large.

## Microsoft-Decision-1 and Tile Sieve

Live runs of the second judge and of the whole-file search, all through the
shipped CLI (`tools/eval/run_catalog.py`) on 2026-10-12 with the shipped
defaults, `data_collection: deny` on OpenRouter and operator keys with a credit
cap read from the environment. OpenRouter reports each request's cost
(input tokens x the model's listed price). OpenAI direct reports none, so its
cost is the list-price estimate (input tokens x $0.0000001); the catalog
runner's first summary of that run read $0 for this reason, and the figures
here are the reports' own spend.

| Date (UTC) | Run | Requests | Input tokens | Cost |
|---|---|---:|---:|---:|
| 2026-10-12 | Microsoft-Decision-1, `legacy-v1`, 34-case catalog, OpenRouter | 182 | 254,661 | $0.0107 |
| 2026-10-12 | OpenAI Decisions, `tile-sieve-beta`, 34-case catalog, OpenAI direct | 53 | 153,561 | about $0.0154 (estimated) |
| 2026-10-12 | OpenAI Decisions, `tile-sieve-beta`, 34-case catalog, OpenRouter | 52 | 148,640 | $0.0149 |

The three catalog runs cost about $0.041 in all. The Microsoft tuning study
below cost another $0.2143 of a $0.40 cap.

### Microsoft-Decision-1 on OpenRouter

What a live probe on 2026-10-11 and the catalog run showed:

- The endpoint (`/api/alpha/decisions`), the request shape and the response
  shape are those of `openai/gpt-6-luna-decisions`. The model id is
  `microsoft/microsoft-decision-1` and the response names
  `microsoft/microsoft-decision-1-20261009`, which the dated-suffix rule
  accepts. `usage` has `input_tokens`, `output_tokens` and `cost`. The
  routing object `{"allow_fallbacks":false,"data_collection":"deny"}` is
  accepted, and the upstream was Azure on every one of the 1,225 Microsoft
  receipts recorded on 2026-10-11.
- Probabilities are full-precision floats, and identical requests differ by
  about 10^-10. A choice answer's confidence follows the chance-normalized
  identity: in the catalog run all 94 choice answers were checked and none
  violated it, none had an answer defect or a displayed argmax that differed
  from its choice, and all 182 requests passed their judge controls.
- Answers arrived in a different order than the questions on 171 of the 182
  requests of the catalog run (reports count it as
  `provenance.answer_order_mismatch`); they are matched by name.
- Latency depends on concurrency: a 24 KB request had a median of 1.70 s with 8
  requests in flight and 0.59 s with 2 (2026-10-11), hence the advice to use
  `--concurrency 2`.

The 34-case catalog under `legacy-v1`, Microsoft-Decision-1 against OpenAI
Decisions on the same route and on OpenAI direct (the OpenAI columns are the
shipped-defaults runs above):

| Outcome | Microsoft-Decision-1 | OpenAI Decisions, OpenRouter | OpenAI Decisions, direct |
|---|---:|---:|---:|
| Defective programs detected | 13/16 | 15/16 | 16/16 |
| Individual defects covered | 14/17 | 16/17 | 17/17 |
| Corrected controls clear | 14/16 | 16/16 | 16/16 |
| Missing evidence incomplete | 1/2 | 1/2 | 0/2 |
| Entire cases | 28/34 | 32/34 | 32/34 |
| Calls | 182 | 214 | 211 |
| Input tokens | 254,661 | 449,566 | 445,685 |
| Cost | $0.0107 | $0.0450 | about $0.0446 (estimated) |

The strict score (requirement citations) equaled the location score, 28/34.
Microsoft-Decision-1 missed the defects in three programs (cases C009, C027
and the 70-line C029, which took 36 calls), flagged two corrected programs
(C008 and C026) and reported the missing-helper project case (C034) as
complete. A research-harness run the day before gave 27 of 34 (12 of 16
defective programs, 14 of 16 clean files).
This is one run on a development catalog that is not held out (n = 34), and
the thresholds are OpenAI's, not re-fitted.

### Microsoft tuning study

Between 2026-10-11 and 2026-10-12 a research harness, which is not part of
this repository, tried to bring Microsoft-Decision-1 to the bar DBH sets for a
judge, so that it could be offered with Tile Sieve as well. The results:

- Judge controls: they passed on 85 of 86 checks, which was accepted, and a
  drift check passed.
- Screening request formats: six were compared (a control and five variants).
  The best combination cut request bytes by 40% with a change in the
  screening AUC within noise. Window size was not a limiter: leaf AUC was
  0.55, 0.59 and 0.63 for windows of 16, 48 and 144 lines.
- Verification (focus) formats: three were compared. None won; the best
  pooled AUC was 0.60 against a bar of 0.65.
- Held-out screening gate: it failed. A clean file produced 0.80 to 0.93 false
  clusters on average (the bar was at most 0.65), and 25 to 35% of the looks
  at a planted bug flagged it (the bar was at least 30%).
- A 40-case development set: Tile Sieve scored 21 to 23 of 40 and
  `legacy-v1` 16 to 21 of 40, against a bar of 36 of 40. The final stage was
  not run.

Neither six screening formats nor three verification formats helped, and
window size was not a limiter, so the limit looks like the model, not the
request design. Microsoft-Decision-1 therefore
ships as experimental, on `legacy-v1` only, and Tile Sieve refuses it with no
Microsoft threshold set.

### Tile Sieve on the catalog

`tile-sieve-beta` through the shipped CLI with the OpenAI judge (all 34 cases
fit one request, so none fell back to `legacy-v1`), against the `legacy-v1`
runs above. Location score; the strict score also requires each finding to
cite the requirement and, in project cases, the helper file:

| Outcome | Tile Sieve, OpenAI direct | Tile Sieve, OpenRouter | `legacy-v1`, OpenAI direct | `legacy-v1`, OpenRouter |
|---|---:|---:|---:|---:|
| Defective programs detected | 16/16 | 15/16 | 16/16 | 15/16 |
| Individual defects covered | 17/17 | 16/17 | 17/17 | 16/17 |
| Corrected controls clear | 16/16 | 16/16 | 16/16 | 16/16 |
| Missing evidence incomplete | 2/2 | 2/2 | 0/2 | 1/2 |
| Entire cases | 34/34 | 33/34 | 32/34 | 32/34 |
| Entire cases, strict | 32/34 | 31/34 | 32/34 | 32/34 |
| Calls | 53 | 52 | 211 | 214 |
| Input tokens | 153,561 | 148,640 | 445,685 | 449,566 |
| Cost | about $0.0154 (estimated) | $0.0149 | about $0.0446 (estimated) | $0.0450 |

- The OpenAI-direct run took 53 requests: 36 whole-file looks (34 first looks
  and 2 second looks; a file of 8 lines or fewer gets one look) and 17 focus
  requests, one for each flagged region. Through OpenRouter there were 36
  looks and 16 focus requests. The offline `catalog-tile-sieve` benchmark
  scenario makes the same 53 requests.
- All judge controls passed (53 of 53 and 52 of 52 requests), no answer had a
  defect and the report schema was 9. The two missing-evidence cases ended
  incomplete through `context_unresolved`, as intended.
- Through OpenRouter the screening did not flag the defect of the
  unit-conversion case C017, which OpenAI direct caught. The strict misses are
  the two project cases C025 and C027 (the finding did not cite the helper
  file), and C017 on OpenRouter.
- The thresholds were fitted on the pilot study's own planted and clean files,
  but the pilot also ran this 34-case catalog while the report rule was
  chosen, so the catalog is not held out and these scores are optimistic. The
  34 cases are synthetic and public, and no held-out evaluation exists. Treat
  Tile Sieve as a beta.

## What remains unproven

- The Foundry route: nothing has been sent to it. Its response fields (usage
  names, the dated model echo), error bodies, real request limits and price are
  taken from Microsoft's documentation and offline fixtures. It is verified
  only by a live run against a deployment: a 5-request smoke first, then the
  catalog.
- Microsoft-Decision-1 beyond one catalog run on OpenRouter and the tuning
  study: the legacy-v1 thresholds were not re-fitted for it, no held-out
  evaluation exists, and the tuning study did not bring it to the bar for a
  judge.
- Tile Sieve beyond the catalog: its thresholds were chosen in a pilot that
  also ran this catalog, files longer than one request fall back to
  `legacy-v1`, and no held-out evaluation exists.
- The OpenAI direct route beyond the smoke suite and two catalog runs: its
  401, 429, 5xx and refusal handling, and its rate-limit headers under load,
  are pinned only by fixtures written from the documentation.
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
