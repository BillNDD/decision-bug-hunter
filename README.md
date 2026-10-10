# Decision Bug Hunter

Decision Bug Hunter (DBH) is a bounded, first-pass bug hunter for single
source files. It asks the OpenAI Decisions model closed-form questions about
overlapping regions of a file and reports suspected bug locations with line
citations. One more tool in the toolshed, not the whole workshop.

**`0.1.0b1` is an experimental beta.** DBH is Decisions-only: its one judge
is the OpenAI Decisions model, reached either directly or through OpenRouter.
It supports no other model. Both routes have been exercised live with
smoke requests and the 34-case development suite (see
[Evidence and limits](#evidence-and-limits)).

## How it works

DBH never executes your program. Python splits the target file into
overlapping windows and asks the judge two kinds of questions about each
region: yes/no questions that return the probability of a bug, and choice
questions over supplied line intervals or next steps that return a full
probability vector plus a confidence. Choice answers localize a suspicion
and pick the next bounded investigation step. Every answer is validated
before it can affect anything: answers are matched by name, probability
vectors must sum to 1, the displayed argmax must equal the chosen option,
and anything malformed, refused or missing becomes a recorded limitation,
never an invented score.

Findings are suspicions with line citations. A scan reports "complete" only
when every line was assessed and nothing blocked the assessment; a failed
call, a hit limit or a failed judge control marks it incomplete instead. A scan that reports no
suspicions is a fast signal, never a correctness certificate. DBH
complements tests, static analyzers, fuzzing and human review.

## Install

Python 3.11, 3.12 or 3.13; no third-party runtime dependencies.

```sh
python -m venv .venv
# Activate .venv using your shell's activation command.
python -m pip install "git+https://github.com/BillNDD/decision-bug-hunter.git@v0.1.0b1"
decision-bug-hunter --help
```

Pin a full commit SHA in place of the tag if you want an immutable install.
From a source checkout, run `python -m pip install .` in the repository root.

## Choose a route and set a key

Every scan names its route with `--provider` (or the `DBH_PROVIDER`
variable). DBH never picks a route because a key happens to be set:

| `--provider` | Endpoint | Model sent | Key variable |
|---|---|---|---|
| `openai` | `POST https://api.openai.com/v1/decisions` | `gpt-6-luna` | `OPENAI_API_KEY` |
| `openrouter` | `POST https://openrouter.ai/api/alpha/decisions` | `openai/gpt-6-luna-decisions` | `OPENROUTER_API_KEY` |

With neither `--provider` nor `DBH_PROVIDER`, the CLI prints
`NEED_USER_INPUT provider: openai | openrouter (set: <names of key variables
that are set>)` and exits `3` before reading the source. With a route but no
usable key it exits `2` with `provider_unavailable`, also before any source
read, output or network use.

Credential handling:

- The key is read from the environment once, when the route is built. It is
  never accepted as a flag and the CLI never loads it from a file; DBH does
  not read `.env` files. [.env.example](.env.example) lists the variable
  names.
- Every configured provider key (both variables, selected or not) is checked
  against the file, the specification, project files and the output path
  before anything is sent; a match stops the scan with `sensitive_input`. A
  response that echoes a key is rejected as `response_sensitive`.
- Keys never appear in requests other than the `Authorization` header, nor in
  receipts, reports, error text or progress lines.
- On the `openai` route, optional `OPENAI_ORG_ID` and `OPENAI_PROJECT_ID`
  become the `OpenAI-Organization` and `OpenAI-Project` headers; a malformed
  value stops the scan with `routing_invalid` (the value is never printed).
- On the `openrouter` route, every request carries
  `"provider":{"allow_fallbacks":false,"data_collection":"deny"}`, so
  OpenRouter may only use endpoints that do not collect data and may not fall
  back to other providers. `--openrouter-routing account-default` omits that
  object and prints a one-line notice that your account settings decide.
  `--openrouter-zdr` also asks for zero-data-retention endpoints; none existed
  on 2026-10-06, when such a request failed with `routing_no_endpoint`
  (HTTP 404). DBH never
  sends `session_id`, `user`, `trace` or attribution headers.
- Direct HTTPS egress is required. Proxy variables are ignored, redirects
  are not followed, and the TLS context ignores `SSLKEYLOGFILE`.

PowerShell:

```powershell
$secret = Read-Host "OpenRouter API key" -AsSecureString
$env:OPENROUTER_API_KEY = [System.Net.NetworkCredential]::new("", $secret).Password
Remove-Variable secret
decision-bug-hunter target.py --provider openrouter --scope standalone --spec-file requirements.txt
Remove-Item Env:OPENROUTER_API_KEY
```

POSIX shell:

```sh
read -rs OPENAI_API_KEY && export OPENAI_API_KEY
trap 'unset OPENAI_API_KEY' EXIT
decision-bug-hunter target.py --provider openai --scope standalone --spec-file requirements.txt
```

A key with a small credit limit reduces the cost of a leak or a runaway run.

## Scope

The caller declares the scope; the tool never infers a project boundary.
Scope is mandatory in both the CLI and library.

```sh
# related files may be searched; a project root is required
decision-bug-hunter target.py --provider openrouter --scope project --project-root ./repo

# the owner declares there is no related project
decision-bug-hunter target.py --provider openrouter --scope standalone

# related files may exist; judge this file only
decision-bug-hunter target.py --provider openrouter --scope isolate
```

Missing or conflicting scope information fails clearly and machine-readably,
before the route is checked:

```text
NEED_USER_INPUT project_scope: provide project directory | standalone | isolate
NEED_USER_INPUT project_root: provide related directory
NEED_USER_INPUT conflicting_options: --project-root conflicts with --scope standalone | isolate
```

In project scope DBH reads at most 128 related files (1 MiB each, 16 MiB in
total). It skips dotfiles, key-like file names (`.pem`, `.key`, `.env`,
`id_rsa`, `credentials.json` and similar), version-control, virtual-env,
build and cache directories, directories tagged with `CACHEDIR.TAG`, its own
run directories, and any file whose text matches the secret scan below.

Exit codes: `0` complete, no suspicions; `1` complete, suspicions reported;
`2` scan failed or incomplete (also invalid arguments); `3` caller input
needed (see `NEED_USER_INPUT`).

## Flags and defaults

Defaults are the shipped configuration. The localization gate defaults to
`--choice-gate mass`, chosen after a live comparison on the development
suite; `--choice-gate legacy` restores the earlier gate. The other tier-2
options (`--localization-menu`, `--choice-rounding-caps`,
`--policy-placement`, `--require-verification`, `--polarity-twin`,
`--state-layout v2`) are opt-in, and most were measured live only on a
small development suite; see [Evidence and limits](#evidence-and-limits)
before turning one on.

| Flag | Default | Meaning |
|---|---|---|
| `--provider` | required | `openai` or `openrouter`; or set `DBH_PROVIDER`. |
| `--scope` | required | `project`, `standalone` or `isolate`. |
| `--project-root` | unset | Related directory; required with `--scope project`, forbidden otherwise. |
| `--spec-file` | unset | Requirements text (at most 8 KiB and 2,000 lines). Without it, intent is inferred from the file. |
| `--encoding` | `utf-8-sig` | Encoding of the file, specification and project files. |
| `--model` | unset | Model id; when unset, the route's model is used (`gpt-6-luna` for `openai`, `openai/gpt-6-luna-decisions` for `openrouter`). If given, it must be that model. |
| `--openrouter-routing` | `deny` | `deny` sends `allow_fallbacks: false` and `data_collection: deny`; `account-default` omits them. OpenRouter only. |
| `--openrouter-zdr` | off | Also request zero-data-retention endpoints. OpenRouter only. |
| `--search-policy` | `legacy-v1` | `scoped-v2-beta` adds scoped verification, explicit refutation and exploratory beams. |
| `--state-layout` | `v1` | `v2` puts the DBH-written state fields first and adds an imitation warning to the policy text. |
| `--policy-placement` | `instructions` | `state` sends the policy text once as the first state key instead of in every question. |
| `--canaries` | `on` | Two judge-control questions with known answers in every request; `off` removes them. |
| `--choice-gate` | `mass` | Localization gate (legacy-v1 only; scoped-v2-beta does not gate localization). `mass`: up to `--localization-beam-width` line runs whose per-line overlap mass reaches `--choice-mass` while none + unlocalized stays below 0.5. `legacy`: min(confidence, p[choice]) >= `--choice-confidence`. |
| `--choice-mass` | `0.5` | Per-line overlap mass needed under `--choice-gate mass`, in (0, 1]. |
| `--localization-menu` | `intervals` | `singletons` offers one option per line instead of every interval. |
| `--choice-rounding-places` | unset (strict mass) | Accept choice vectors whose mass is consistent with rounding at N places (2 to 8). |
| `--strict-choice-mass` | off | No-op kept for compatibility; strict mass is already the default. |
| `--choice-rounding-caps` | off | With `--choice-rounding-places`, keep options x half-quantum <= 0.125 per choice menu. |
| `--require-verification` | off | Report only suspicions supported by a second look; screen-only ones are listed as unverified. |
| `--polarity-twin` | off | Diagnostic: also ask the inverted question and report the residual; never changes findings. |
| `--no-bug-lenses` | off | Skip the five extra bug-lens questions per screened window. |
| `--no-whole-file` | off | Skip the whole-file screening window. |
| `--width` | `48` | Screening window width in lines. |
| `--min-width` | `12` | Smallest window when subdividing a suspicious region. |
| `--max-depth` | `4` | Subdivision depth. |
| `--context-lines` | `12` | Neighboring lines included with each window. |
| `--inspect-threshold` (`--drill-threshold`) | `0.60` | Score that triggers detailed search of a window. |
| `--report-threshold` | `0.80` | Score needed to report a finding. |
| `--refute-threshold` | `0.80` | Explicit-refutation threshold (scoped-v2-beta only). |
| `--relation-threshold` | `0.70` | Support needed from a relationship recheck. |
| `--context-threshold` | `0.60` | Score that marks a context request or evidence packet as needed. |
| `--choice-confidence` | `0.50` | Confidence gate for rank, context and action choices, and for localization under `--choice-gate legacy`. |
| `--localization-beam-width` | `3` | Candidate intervals (line runs under `--choice-gate mass`) kept per localization round. |
| `--max-localizations` | `4` | Localization candidates examined per target. |
| `--max-context-packets` | `8` | Context packets considered per region. |
| `--max-action-steps` | `4` | Bounded investigation steps per target. |
| `--max-action-targets` | `32` | Targets that may take investigation steps. |
| `--evidence-min-width` | `8` | Smallest evidence span. |
| `--evidence-beam-width` | `3` | Evidence candidates kept per round. |
| `--evidence-max-depth` | `4` | Evidence search depth. |
| `--max-evidence-candidates` | `96` | Evidence candidates examined per evidence search. |
| `--max-relationships` | `4` | Evidence passages given a relationship recheck per target. |
| `--max-handoff-candidates` | `64` | Reference candidates per kind per finding in the handoff; omissions are flagged. |
| `--max-project-files` | `128` | Related files read in project scope. |
| `--max-project-file-bytes` | `1048576` | Largest related file read. |
| `--max-project-total-bytes` | `16777216` | Total related bytes read. |
| `--max-project-candidates` | `128` | Related references considered per search. |
| `--max-calls` | `1000` | Logical judge requests per scan (retries are not counted separately). |
| `--max-questions` | `20000` | Questions per scan, controls included. |
| `--max-windows` | `50000` | Windows planned per scan. |
| `--deadline-seconds` | `30.0` | Absolute deadline per call (connect, TLS, send and every read); at most 300. |
| `--run-deadline-seconds` | `1800.0` | Cooperative deadline for the whole run, indexing included. |
| `--no-retry` | off | One attempt per request. |
| `--max-cost` | unset | Stop before any attempt whose cost bound could take spend above this many USD (at most 1000). |
| `--concurrency` | `1` | Opt-in: up to N requests in flight at once (1 to 8). Results are identical on success; after a failure or a stop, requests already in flight still complete and are billed. |
| `--allow-secrets` | off | Send the file and specification even when they contain credential-shaped text. |
| `--output-dir` | `dbh_runs` | Parent of the private run directories. |
| `--output-format` | `compact` | What is printed on stdout: `compact`, `ranges` or `json`. All formats are saved. |

OpenRouter-only options combined with `--provider openai` stop the scan with
`invalid_request`.

## Cost and limits

Both routes list the model at $0.10 per million input tokens and bill no
output tokens (price table dated 2026-10-06; check the provider's current
price yourself). OpenRouter reports the cost of every request, and in every
observed response it equaled input tokens x $0.0000001. OpenAI direct
reports usage but no cost, so on that route DBH records the list-price
estimate (input tokens x $0.0000001).

Observed costs (2026-10-06 and 2026-10-07):

- One screening request of a short file, about 8,500 input tokens: $0.00085.
- Across the 34-case development suite with the shipped defaults, one call
  averaged about 2,100 input tokens ($0.0002), and one case about $0.0013
  (legacy-v1: 214 calls and $0.0450 for all 34 cases on OpenRouter, 211
  calls and about $0.045 estimated on OpenAI direct) or about $0.002
  (scoped-v2-beta: 312 calls and $0.0683 on OpenRouter, 296 calls and about
  $0.065 estimated on OpenAI direct).
- Judge controls (`--canaries on`, the default) add about 19 percent input
  tokens: two extra questions per request, each carrying the policy text.
  `--canaries off` removes them.

Each request carries at most 64 questions and a 24 KiB local envelope
(16 KiB of state). The wire body is capped at 64 KiB on both routes. Under
`--policy-placement state`, OpenRouter requests that carry the policy in
state may hold 200 questions and 48 KiB. Responses are capped at 256 KiB.

DBH bounds an attempt whose usage is unknown at its wire bytes plus 64
tokens per question: about $0.0029 for a full 24 KiB, 64-question request
and about $0.007 to $0.008 at the 64 KiB wire cap (65,536 bytes plus
200 x 64 tokens, at $0.0000001 each), which only translated OpenAI bodies
or 200-question state-placement requests approach. Under the default
1000-call limit a scan of full-size requests would therefore cost about $3,
and at most about $8, plus one possible duplicate charge for each
stale-connection retry. Real requests
are much smaller. For a hard limit pass `--max-cost USD`: before every
attempt, retries included, DBH adds the reported cost, the list-price
estimate of known usage and the bound of every possibly billed attempt with
unknown usage, and refuses an attempt that could exceed the limit. The scan
then ends incomplete with `cost_budget_exhausted`.

Other limits: source files up to 16 MiB and 200,000 lines; specifications
up to 8 KiB and 2,000 lines. Image input is not used. Nothing is silently
truncated.

On the hardened OpenRouter smoke run requests took 0.14 to 0.33 s each over
a reused connection; on OpenAI direct the first request took 1.53 s and the
next ones 0.14 to 0.19 s. A run stops dispatching when `--run-deadline-seconds` (default
1800 s) leaves less than a reserve of max(3 s, 1.5 x p95 of recent request
times); those requests are recorded as `run_deadline_reserved` and the scan
is incomplete.

## Failure and retry behavior

Every attempt is journaled in a receipt before it is sent and settled
after it ends. Retries are on by default; `--no-retry` makes
every request a single attempt.

| Failure | Code | Retried by default |
|---|---|---|
| Connection could not be opened (DNS, TCP, TLS) | `connect_failed` | up to 3 times, random wait up to 8 s |
| HTTP 408 | `http_request_timeout` | up to 3 times, random wait up to 8 s |
| HTTP 429 (rate limit) | `http_rate_limited` | up to 3 times, after `Retry-After` (capped at 60 s) or a random wait up to 30 s |
| Overload (OpenRouter 529, OpenAI 503 `server_is_overloaded`), OpenRouter 503 | `http_overloaded`, `http_unavailable` | as for 429 |
| Reset or EOF on a reused keep-alive connection, before any response byte and within 1 s of sending | `transport_failed` | once, immediately, on a new connection; may be billed twice and the receipt says `duplicate_billing_possible` |
| Timeout or reset after the request was sent, 5xx, OpenRouter 524, an error inside a 200 body | `deadline_exceeded`, `transport_failed`, `http_server_error`, `http_provider_timeout`, `provider_error_in_body` | no: the request may have been processed and billed |
| 401, 402, 403, 404, redirects, quota exhausted, a 404/503 routing failure | `http_unauthorized`, `http_payment_required`, `http_forbidden` or `provider_moderated`, `route_unavailable`, `http_redirect`, `http_quota_exhausted`, `routing_no_endpoint` | no; most stop the run (see the [provider contract](docs/PROVIDER_CONTRACT.md)) |
| 400, 413 and other statuses | `http_rejected`, `request_too_large` | no |

A wait that would cut into the run reserve, or a retry that could exceed
`--max-cost`, is abandoned and recorded. The engine asks a request that
failed transiently once more; it never repeats a permanent failure.

A breaker stops the run after 3 consecutive requests end rate-limited or
overloaded, 3 end with provider or transport errors after sending, 3 cannot
connect (or get 408), 2 get contract-breaking responses (a malformed 200 or
a rejected request), or 8 of the last 10 are moderated. After a stop, or after a
blocking failure such as `http_unauthorized`, nothing more is sent; the scan
is incomplete with `provider_stopped`, and stderr says
`Provider stopped (<reason>); remaining work was not sent.`

Error bodies are read only when they are JSON, at most 16 KiB and free of
every configured key. Only structural fields are kept (error type and code,
a parameter path on the `openai` route, routing and moderation key presence
on `openrouter`); the provider's message is never kept or printed.

Refusals and malformed answers cost one answer, not the batch. One refused
question in a request becomes `question_refused` for that answer; two or
more refusals withhold the batch as `response_refused`. A choice answer with
the wrong mass or option keys (`response_distribution`), a displayed argmax
that differs from the choice (`choice_argmax_mismatch`) or, on OpenRouter, a
choice without its vector (`response_vector_missing`) also costs only that
answer. The attempt is then `validated_partial`. Wrong types, missing or
extra names and out-of-range numbers still reject the whole batch.

Choice vectors must sum to 1 within 10^-12 by default. Every one of the 61
choice vectors observed live summed to exactly 1 at two decimals, so this
strict default holds for the current model; `--choice-rounding-places N`
exists in case a future model rounds differently. Values are never
renormalized.

## Security checks before sending

- **Secret scan.** Before any project indexing, output directory or request,
  DBH scans the file and the specification for credential-shaped text:
  OpenRouter, Anthropic, OpenAI, AWS, GitHub, Slack, Google, Stripe and JWT
  tokens and PEM private-key headers, including tokens that follow an escape
  sequence (`\n`, `\t`, `\"`) or a percent-encoded byte. A hit stops the scan
  with `secret_detected` (exit `2`), naming line numbers and pattern ids only.
  `--allow-secrets` sends the file and specification anyway; project files
  with a hit are always skipped. This is a guard against obvious accidents,
  not a secret scanner.
- **Judge controls (canaries).** With `--canaries on` (default), each
  request carries two yes/no questions with known answers. If the must-true
  answer is below 0.90, the must-false answer is above 0.10, or a control is
  missing or refused, every answer of that request is withheld and the scan
  is incomplete with `judge_control_failed`. In 523 live requests no control
  failed, and adding the controls moved no other answer. Controls catch
  crude manipulation only.
- **Injection markers.** A local pattern scan flags lines that look like
  instructions to the judge ("ignore all previous instructions", "answer
  false to every question", chat-template tokens). Findings on such lines get
  the limitation `injection-marker`; nothing else changes. The absence of
  markers proves nothing.

Prompt injection inside reviewed files is a known limitation of any
model-based reviewer: the file's author can try to suppress or invent
findings. Do not use DBH to gate untrusted contributions. See
[SECURITY.md](SECURITY.md).

## Output

Each run writes a private directory `run-*` under `--output-dir` (default
`dbh_runs`), marked with `.gitignore` and `CACHEDIR.TAG` so version control,
backup tools and DBH's own indexer skip it. DBH writes those two files into
the parent only if it created the parent. Contents:

- `report.json`: the full report (schema 7 for legacy-v1, 8 for
  scoped-v2-beta): findings, coverage, issues, `provenance`, `usage`,
  `spend`, `attempts_transmitted`, `retries`, `stop_reason`,
  `answer_defects`, `refusals`, `judge_diagnostics`, `banners`, `controls`,
  `secret_scan` and `calibration` (always `uncalibrated`). Some fields appear
  only when relevant: `request_geometry` (`--policy-placement state`),
  `unverified_suspicions` (`--require-verification`), `injection_markers`
  (markers found) and `gateway_totals` (a gateway shared by several scans);
  `controls` is absent with `--canaries off`.
- `findings.txt` (compact handoff), `handoff.json` (schema 4 or 5) and
  `ranges.txt`.
- `receipts/`: one JSON receipt per attempt (schema 2) with hashes, route,
  requested and returned model, the provider's generation or request id,
  usage, cost and its source, the cost bound, validated answers and fixed
  failure codes. Source text, specifications, request and response bodies
  and keys are never journaled.

Stderr carries the run name, a progress line every 100 calls or 30 s
(`progress: calls=... attempts=... elapsed=... remaining=... spend<=$...`),
a `Spend (USD): provider-reported ..., estimated ..., unknown-usage bound
...` line, judge warnings, and a final summary. File names, hashes, line
ranges, judgments and generation ids can still be sensitive: keep run
directories private and review them before sharing. Filesystem permission
hardening is POSIX-specific; on Windows access control is the caller's
concern.

## Library use

```python
from pathlib import Path
from decision_bug_hunter.core import Config, Source, scan
from decision_bug_hunter.providers import ValidatedGateway, make_provider

provider = make_provider("openrouter")  # reads OPENROUTER_API_KEY now, calls nothing
with ValidatedGateway(provider, Path("dbh_runs/receipts")) as gateway:
    report = scan(Source.read(Path("target.py")), gateway, Config(),
                  context_scope="declared_standalone")
```

`make_provider("openai")` builds the direct route. `context_scope` is
required: `project` (with `project=ProjectIndex`), `declared_standalone` or
`owner_isolated`. `ValidatedGateway` takes `retry_policy=`
(`RetryPolicy.none()` for `--no-retry`), `max_cost=` (a `Decimal`) and
`deadline_seconds=`; `Config` takes the engine options above
(`canaries`, `state_layout`, `policy_placement`, `choice_gate`, and so on).
When you set `policy_placement="state"` in `Config`, pass the same
`policy_placement=` to `make_provider(...)` too: the provider sets the
raised OpenRouter caps (200 questions, 48 KiB) that the CLI uses.
A library `scan()` does not run the secret scan on the target; call
`decision_bug_hunter.secret_scan.scan_lines` yourself first. A caller-owned
gateway with the same interface can replace the hosted one for offline
embedding; such gateways report `custom-unverified` provenance. The
engine's requirements on any judge are in the
[provider contract](docs/PROVIDER_CONTRACT.md).

## Checks

Tests are deterministic and offline; no key, paid run or authentication
grant is required, and the suite refuses real sockets.

```sh
python -m pip install -e ".[dev]"
python -m unittest discover -s tests -t .
python -m ruff check .
python -m mypy
python -m build
python tools/check_distribution.py dist
```

The distribution checker inspects both archives, installs the wheel into a
fresh environment without keys, confirms the CLI exits `3` without a route
and `2` with `provider_unavailable` for each route, and runs the unpacked
sdist's own test suite. [docs/VALIDATION.md](docs/VALIDATION.md) records the
latest results. The repository also holds live tooling: `tools/eval` (the
labeled development catalog, shipped in the sdist; see
[tools/eval/README.md](tools/eval/README.md)) and `tools/smoke`
(first-contact smoke suites, repository only).

## Evidence and limits

All live evidence comes from 2026-10-06 and 2026-10-07: smoke suites and
catalog runs on OpenRouter, and a 5-request smoke suite plus two catalog
runs on OpenAI direct.

The catalog below is a small public development suite of 34 synthetic
cases (16 defective programs with 17 planted defects, 16 corrected
controls, 2 cases that lack needed evidence). It was used while developing
DBH, it is not held out, and n = 34 cannot support precision, recall or
calibration claims. Answers are deterministic per request, so each
configuration was run once per route.

Shipped defaults (`--choice-gate mass`, state layout v1, canaries on):

| Outcome | OpenRouter legacy-v1 | OpenRouter scoped-v2-beta | OpenAI direct legacy-v1 | OpenAI direct scoped-v2-beta |
|---|---:|---:|---:|---:|
| Defective programs detected | 15/16 | 15/16 | 16/16 | 14/16 |
| Individual defects covered | 16/17 | 17/17 | 17/17 | 17/17 |
| Corrected controls clear | 16/16 | 16/16 | 16/16 | 16/16 |
| Missing evidence marked incomplete | 1/2 | 1/2 | 0/2 | 1/2 |
| Entire cases | 32/34 | 32/34 | 32/34 | 31/34 |
| Calls / cost | 214 / $0.0450 | 312 / $0.0683 | 211 / about $0.045 (estimated) | 296 / about $0.065 (estimated) |

The two routes ask the same questions but encode them differently: OpenAI
direct folds the yes/no criteria into each question's instructions and
sends the state as a JSON string in `input`, while OpenRouter sends the
local envelope natively. The same model therefore gives somewhat different
answers, and results differ between the routes.

Final evaluation at the release code: OpenRouter legacy-v1 ran with
`--choice-gate mass` passed explicitly (the only later code change makes it
the default), at 214 calls, 449,566 input tokens and $0.0450. The mass gate
does not apply to scoped-v2-beta, which sends the same requests under
either gate, so its OpenRouter column is the release run under the earlier
default: 312 calls, 683,136 input tokens and $0.0683. The OpenAI-direct
columns ran with the same shipped defaults (445,685 and 654,342 input
tokens). A 10-request OpenRouter release smoke subset ($0.0025) returned
200 for every request with every judge control passing.

Misses under the defaults: on OpenRouter, a defect in a cross-file helper
(legacy-v1), a 70-line file with two defects that ended incomplete with
unresolved localization (scoped-v2-beta) and a project case with a missing
helper reported complete instead of incomplete (both policies). On OpenAI direct, both cases that
lack needed evidence reported complete (legacy-v1); under scoped-v2-beta
the cross-file helper case and the 70-line case ended incomplete through
conflicting or unresolved answers, and the missing-helper case reported
complete.

Measured variants (OpenRouter, one run each, same suite):

| Configuration | Cases | Notes |
|---|---:|---|
| legacy-v1 + `--choice-gate legacy` | 31/34 | The earlier default: localizes the second 70-line defect only as a broad region; controls 16/16; 211 calls, $0.0451 |
| legacy-v1 + `--policy-placement state` | 32/34 | Catches the cross-file defect and marks the missing helper incomplete; the 70-line pair ends unresolved (controls 15/16, no false finding); 191 calls, $0.0328, the cheapest measured |
| legacy-v1 + `--choice-gate legacy --policy-placement state` | 32/34 | Same outcomes as the row above; 219 calls, 18% fewer input tokens than `--choice-gate legacy` alone |
| scoped-v2-beta + `--policy-placement state` | 32/34 | Marks the missing helper incomplete; the 70-line control ends unresolved; 31% fewer input tokens, 237 calls |
| `--localization-menu singletons` | 32/34 legacy, 32/34 scoped | No change in outcomes (31/34 legacy with `--choice-gate legacy`) |
| `--require-verification` | 30/34 legacy (with `--choice-gate legacy`), 31/34 scoped | Drops one true finding per policy; controls were already clear |
| `--state-layout v2` | 31/34 legacy, 29/34 scoped | Reverses the mass-gate gain: under legacy-v1 the second 70-line defect is again broad and one clean program is flagged (controls 15/16); under scoped-v2-beta two clean controls are flagged; the reason v1 is the default |

The localization-menu variants were measured before canaries existed
(equivalent to `--canaries off`); the others with canaries on.
`--choice-rounding-caps` and `--polarity-twin` have no catalog measurement.
The mass gate became the default after the live comparison (32/34 against
31/34 under OpenRouter legacy-v1, controls 16/16 in both, about the same
cost). That choice rests on this development suite alone: a default that
moves findings would ideally have held-out labeled evidence, which does not
exist yet. The other variants stay opt-in.

Other live observations (OpenRouter smoke runs, 32 and 48 requests): answers
were byte-identical across repeated requests; four planted bugs all
screened above their clean twins (a preview on 8 files, not calibration);
two crude prompt-injection attempts neither suppressed a real bug nor
flooded a clean function. On the OpenAI-direct smoke run all 4 answer
batches validated (76 answers); every choice vector summed to exactly 1 at
two decimals with the choice equal to the argmax, and the confidence
followed the same identity as on OpenRouter. No refusal was observed on
either route, so the refusal handling is pinned only by fixtures.

Limits: returned probabilities are operating heuristics, and the report,
relation and refutation thresholds (0.80, 0.70, 0.80) are uncalibrated.
Name resolution is bounded only by the operating system's resolver. DBH
judges text; it cannot see runtime behavior, and a clean report is not
evidence of correctness. Release status is tracked in
[docs/RELEASE_GATES.md](docs/RELEASE_GATES.md).

## License and provenance

MIT. DBH is a standalone repository that started from MIT-licensed files of
an earlier bug-hunting tool; its notice is kept in [LICENSE](LICENSE) and the
details are in [docs/PROVENANCE.md](docs/PROVENANCE.md).
