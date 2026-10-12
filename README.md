# Decision Bug Hunter

A super-fast sanity check for LLM-written code, not a full bug checker. The OpenAI Decisions model answers closed questions about a file and DBH flags suspect line ranges in seconds, for about a tenth of a cent per small file. Tested live through both OpenAI and OpenRouter.

**`0.1.0b1` is an experimental beta.** DBH asks decision models only: the
OpenAI Decisions model (`gpt-6-luna`), reached directly or through
OpenRouter, and Microsoft-Decision-1 as an **experimental** second judge,
reached through OpenRouter or your own Microsoft Foundry resource. You choose
the judge explicitly with `--judge`; DBH never picks one for you. OpenAI
Decisions is the judge DBH was built and validated on. Microsoft-Decision-1
finds fewer bugs on the same test catalog (see
[Choosing a judge](#choosing-a-judge)). Both OpenAI routes and the Microsoft
route through OpenRouter have been exercised live with smoke requests and the
34-case development suite; the Foundry route is not yet verified live (see
[Evidence and limits](#evidence-and-limits)).

## How it works

Decision Bug Hunter (DBH) is a bounded, first-pass bug hunter for single
source files. One more tool in the toolshed, not the whole workshop. DBH
never executes your program. Python splits the target file into
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

## Choose a judge, a route and set a key

Every scan names its judge, the decision model, with `--judge` (or the
`DBH_JUDGE` variable), and the route to it with `--provider` (or the
`DBH_PROVIDER` variable). Neither has a default, and DBH never picks either
because a key happens to be set; the flag wins over the variable.

| `--judge` | `--provider` | Endpoint | Model sent | Key variable |
|---|---|---|---|---|
| `openai` | `openai` | `POST https://api.openai.com/v1/decisions` | `gpt-6-luna` | `OPENAI_API_KEY` |
| `openai` | `openrouter` | `POST https://openrouter.ai/api/alpha/decisions` | `openai/gpt-6-luna-decisions` | `OPENROUTER_API_KEY` |
| `microsoft` (experimental) | `openrouter` | `POST https://openrouter.ai/api/alpha/decisions` | `microsoft/microsoft-decision-1` | `OPENROUTER_API_KEY` |
| `microsoft` (experimental) | `foundry` (not yet verified live) | `POST <your resource endpoint>/providers/microsoft/v1/systemone` | your deployment name | `AZURE_API_KEY` or `AZURE_ENTRA_TOKEN` |

The checks run in this order, each before the source is read, any output
exists or the network is used: scope, the `--search-policy tile-sieve-beta`
option conflicts, judge, that the judge has Tile Sieve thresholds (when that
policy is chosen), route, that the route is one of that judge's, `--model`
against the pair's allow-list, the route's own options, then availability.

- With no judge, the CLI prints `NEED_USER_INPUT judge: openai (OpenAI
  Decisions gpt-6-luna; routes openai | openrouter) | microsoft
  (Microsoft-Decision-1; routes openrouter | foundry)` and exits `3`. An
  unknown `DBH_JUDGE` exits `2` with `invalid_judge`.
- With a judge but neither `--provider` nor `DBH_PROVIDER`, it prints
  `NEED_USER_INPUT provider: openai | openrouter (set: <names of key variables
  that are set>)` for the OpenAI judge, or `openrouter | foundry` for the
  Microsoft judge, and exits `3`. Only the key variables of that judge's
  routes are listed; a key of the other judge never selects anything.
- A judge and a route that do not go together, such as `--judge microsoft
  --provider openai`, print `NEED_USER_INPUT judge_route: microsoft routes:
  openrouter | foundry` and exit `3`.
- A model of the other judge is `invalid_request` (exit `2`).
- With a route but no usable key it exits `2` with `provider_unavailable`.

Credential handling:

- The key is read from the environment once, when the route is built. It is
  never accepted as a flag and the CLI never loads it from a file; DBH does
  not read `.env` files. [.env.example](.env.example) lists the variable
  names.
- Every configured provider key (`OPENAI_API_KEY`, `OPENROUTER_API_KEY`,
  `AZURE_API_KEY` and `AZURE_ENTRA_TOKEN`, selected or not, whichever judge) is
  checked against the file, the specification, project files and the output
  path before anything is sent; a match stops the scan with
  `sensitive_input`. A response that echoes a key is rejected as
  `response_sensitive`. The credential-shaped text scanner recognizes an Entra
  token but has no pattern for an Azure resource key, which is covered only by
  this exact-value check.
- Keys never appear in requests other than the `Authorization` header (or
  the `api-key` header of a Foundry resource key), nor in receipts, reports,
  error text or progress lines.
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
decision-bug-hunter target.py --judge openai --provider openrouter --scope standalone --spec-file requirements.txt
Remove-Item Env:OPENROUTER_API_KEY
```

POSIX shell:

```sh
read -rs OPENAI_API_KEY && export OPENAI_API_KEY
trap 'unset OPENAI_API_KEY' EXIT
decision-bug-hunter target.py --judge openai --provider openai --scope standalone --spec-file requirements.txt
```

A key with a small credit limit reduces the cost of a leak or a runaway run.

### Microsoft Foundry

The `foundry` route reaches Microsoft-Decision-1 directly through your own
Microsoft Foundry resource. It is built from Microsoft's documentation and is
**not yet verified live**: the response fields, the error bodies and the
service's real limits have not been observed against a deployment.

| Setting | Flag | Variable |
|---|---|---|
| Resource endpoint, `https://<resource>.services.ai.azure.com` (or `.cognitiveservices.azure.com`, `.openai.azure.com`) | `--foundry-endpoint` | `DBH_FOUNDRY_ENDPOINT` |
| Deployment name, sent as the model | `--foundry-deployment` | `DBH_FOUNDRY_DEPLOYMENT` |
| Resource key, sent as the `api-key` header | `--foundry-auth api-key` | `AZURE_API_KEY` |
| Pre-acquired Microsoft Entra token, sent as a bearer token | `--foundry-auth entra-token` | `AZURE_ENTRA_TOKEN` |

- A missing endpoint or deployment prints `NEED_USER_INPUT foundry_endpoint`
  or `NEED_USER_INPUT foundry_deployment` and exits `3`. With both credential
  variables set and no `--foundry-auth`, it prints `NEED_USER_INPUT
  foundry_auth: ...` and exits `3`; with one set, that one is used.
- The endpoint must be `https` on port 443 with no path, query or user
  information; anything else, including a Foundry project URL, is
  `endpoint_invalid` (exit `2`). The endpoint names your resource: it is never
  printed or written to a report, receipt or message.
- DBH never acquires or refreshes an Entra token. One that expires during a run
  is a `401` (`http_unauthorized`), the run stops, and stderr says to refresh
  `AZURE_ENTRA_TOKEN`.
- `--model` and the OpenRouter options do not apply to Foundry (`invalid_request`),
  and the Foundry flags do not apply to any other route.

Setup with the Azure CLI, once. The deployment and token commands follow
Microsoft's documentation of 2026-10-09; the account line is the standard
step for a subscription that has no Foundry resource yet. Replace the
`<...>` names with your own, and let the shell read the key so that it never
appears in your history or in a chat:

```sh
az login
az cognitiveservices account create --name <ACCOUNT_NAME> --resource-group <RESOURCE_GROUP> --kind AIServices --sku S0 --location <REGION> --custom-domain <ACCOUNT_NAME>
az cognitiveservices account deployment create --name <ACCOUNT_NAME> --resource-group <RESOURCE_GROUP> --deployment-name <DEPLOYMENT_NAME> --model-name "Microsoft-Decision-1" --model-format Microsoft --model-version "1" --sku-name GlobalStandard --sku-capacity 1
export DBH_FOUNDRY_ENDPOINT=$(az cognitiveservices account show --name <ACCOUNT_NAME> --resource-group <RESOURCE_GROUP> --query properties.endpoint --output tsv)
export DBH_FOUNDRY_DEPLOYMENT=<DEPLOYMENT_NAME>
export AZURE_API_KEY=$(az cognitiveservices account keys list --name <ACCOUNT_NAME> --resource-group <RESOURCE_GROUP> --query key1 --output tsv)
# or, for Microsoft Entra instead of the key:
# export AZURE_ENTRA_TOKEN=$(az account get-access-token --resource https://cognitiveservices.azure.com --query accessToken --output tsv)
decision-bug-hunter target.py --judge microsoft --provider foundry --scope standalone
```

An Entra access token is short-lived (typically about an hour; `az account
get-access-token` prints its expiry). Get a fresh one before a long scan.
The response fields, error bodies and limits of this route are the ones
Microsoft documents, not ones DBH has observed, and no Azure price has been
read: the cost DBH shows for it is an estimate at the OpenRouter list price of
Microsoft-Decision-1 ($0.042 per million input tokens).

## Choosing a judge

OpenAI Decisions is the judge DBH was built, tuned and validated on; choose it
unless you have a reason not to. Microsoft-Decision-1 is **experimental** in
this beta, and the CLI prints a one-line note to stderr, once, before each run
with it:

```text
Note: Microsoft-Decision-1 support is experimental: in DBH's validation it finds fewer bugs than OpenAI Decisions (README: Choosing a judge).
```

It finds fewer bugs. On the 34-case development catalog with the default
`legacy-v1` search and the shipped defaults (the Microsoft run is from
2026-10-12, through OpenRouter and the shipped CLI):

| Outcome | Microsoft-Decision-1 | OpenAI Decisions, OpenRouter | OpenAI Decisions, direct |
|---|---:|---:|---:|
| Defective programs detected | 13/16 | 15/16 | 16/16 |
| Individual defects covered | 14/17 | 16/17 | 17/17 |
| Corrected controls clear | 14/16 | 16/16 | 16/16 |
| Missing evidence marked incomplete | 1/2 | 1/2 | 0/2 |
| Entire cases | 28/34 | 32/34 | 32/34 |
| Calls / cost | 182 / $0.0107 | 214 / $0.0450 | 211 / about $0.045 (estimated) |

Microsoft-Decision-1 missed the defect in three programs, flagged two
corrected programs and reported one case with missing evidence as complete;
an earlier run of the same catalog the day before, through a research
harness, gave 27 of 34 (12 of 16 defective programs, 14 of 16 clean files).
It costs less per scan because it is listed at $0.042 per million input
tokens and made fewer calls. A live tuning study tried to bring it to the bar
DBH sets for a judge: it tried six request formats for the screening
questions and three for the verification questions, and varied the window
size, which was not a limiter. A held-out screening check still failed, so the
limit looks like the model, not the request design. The figures are in
[docs/VALIDATION.md](docs/VALIDATION.md). Microsoft-Decision-1 is therefore
offered for the default `legacy-v1` search only: `--search-policy
tile-sieve-beta` refuses it (see [Tile Sieve (beta)](#tile-sieve-beta)).

Using it:

```sh
decision-bug-hunter target.py --judge microsoft --provider openrouter --concurrency 2 --scope standalone
```

- Use `--concurrency 2` through OpenRouter. On 2026-10-11 a 24 KB request had
  a median latency of 1.70 s with 8 requests in flight and 0.59 s with 2.
- Probabilities arrive as full-precision floats, not two-decimal values, and
  identical requests differ by about 10^-10, so answers are not byte-identical
  across repeated requests the way OpenAI Decisions' are. With no display
  precision to allow for, the localization mass gate uses the exact values and
  the confidence identity (the chance-normalized one OpenAI Decisions also
  follows) is checked to six decimal places. Choice vectors still must sum to
  1 within 10^-12; none failed in the catalog run.
- Answers may arrive in a different order than the questions. DBH matches
  them by name, so this is harmless; it was seen on 171 of the 182 requests
  of the catalog run (the report's `provenance.answer_order_mismatch` counts
  them).
- Through OpenRouter, the default routing object is accepted:
  `"data_collection":"deny"` returned 200 and the upstream was Azure. A
  different upstream is journaled as `upstream_provider_unexpected`, never
  fatal. The request limits are the same as OpenAI direct's: 64 questions and
  24 KiB, also under `--policy-placement state`.
- A report or receipt names the judge only when it is not OpenAI (a `judge`
  field; absent means OpenAI). The stderr summary line gains
  `(judge microsoft)` before its final period. The handoff does not name it.

## Scope

The caller declares the scope; the tool never infers a project boundary.
Scope is mandatory in both the CLI and library.

```sh
# related files may be searched; a project root is required
decision-bug-hunter target.py --judge openai --provider openrouter --scope project --project-root ./repo

# the owner declares there is no related project
decision-bug-hunter target.py --judge openai --provider openrouter --scope standalone

# related files may exist; judge this file only
decision-bug-hunter target.py --judge openai --provider openrouter --scope isolate
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
| `--judge` | required | `openai` (OpenAI Decisions) or `microsoft` (Microsoft-Decision-1, experimental); or set `DBH_JUDGE`. |
| `--provider` | required | A route of the judge: `openai` or `openrouter` for `--judge openai`; `openrouter` or `foundry` (not yet verified live) for `--judge microsoft`; or set `DBH_PROVIDER`. |
| `--scope` | required | `project`, `standalone` or `isolate`. |
| `--project-root` | unset | Related directory; required with `--scope project`, forbidden otherwise. |
| `--spec-file` | unset | Requirements text (at most 8 KiB and 2,000 lines). Without it, intent is inferred from the file. |
| `--encoding` | `utf-8-sig` | Encoding of the file, specification and project files. |
| `--model` | unset | Model id; when unset, the judge's model on the route is used (`gpt-6-luna` for `openai`; `openai/gpt-6-luna-decisions` or `microsoft/microsoft-decision-1` for `openrouter`, by judge). If given, it must be that model. Not used with `foundry`. |
| `--foundry-endpoint` | unset | Foundry resource endpoint, `https://<resource>.services.ai.azure.com`; or set `DBH_FOUNDRY_ENDPOINT`. `foundry` only. |
| `--foundry-deployment` | unset | Foundry deployment name, sent as the model; or set `DBH_FOUNDRY_DEPLOYMENT`. `foundry` only. |
| `--foundry-auth` | unset | `api-key` (`AZURE_API_KEY`) or `entra-token` (`AZURE_ENTRA_TOKEN`); needed only when both variables are set. `foundry` only. |
| `--openrouter-routing` | `deny` | `deny` sends `allow_fallbacks: false` and `data_collection: deny`; `account-default` omits them. OpenRouter only. |
| `--openrouter-zdr` | off | Also request zero-data-retention endpoints. OpenRouter only. |
| `--search-policy` | `legacy-v1` | `scoped-v2-beta` adds scoped verification, explicit refutation and exploratory beams. `tile-sieve-beta` is an opt-in whole-file beta calibrated for the OpenAI judge only: a file that fits in one request is read in one or two whole-file looks, then each flagged region gets one focus request (no stage 2), and strong regions report at a lower bar. A larger file falls back to `legacy-v1` with a stderr notice. It needs `--canaries on`, `--state-layout v1` and `--policy-placement instructions`, and refuses `--polarity-twin`, `--require-verification` and `--judge microsoft`. See [Tile Sieve (beta)](#tile-sieve-beta). |
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
| `--concurrency` | `1` | Opt-in: up to N requests in flight at once (1 to 8). Results are identical on success; after a failure or a stop, requests already in flight still complete and are billed. Use 2 with Microsoft-Decision-1 through OpenRouter. |
| `--allow-secrets` | off | Send the file and specification even when they contain credential-shaped text. |
| `--output-dir` | `dbh_runs` | Parent of the private run directories. |
| `--output-format` | `compact` | What is printed on stdout: `compact`, `ranges` or `json`. All formats are saved. |

OpenRouter-only options combined with `--provider openai` or `--provider
foundry`, and Foundry-only options with any other route, stop the scan with
`invalid_request`.

## Tile Sieve (beta)

`--search-policy tile-sieve-beta` is an opt-in whole-file search for the
OpenAI judge. Where `legacy-v1` screens overlapping windows and drills into
the suspicious ones, Tile Sieve reads the whole file at once:
- A file that fits in one request (at most 64 questions and 24,064 bytes with
  15,872 bytes of state, about 200 lines of typical code) is read in one or
  two whole-file looks. Each look asks about 16-line and 48-line cells and
  ranks 8-line cells, over the whole file, with the two judge controls. A file
  of 8 lines or fewer gets one look.
- Flagged cells merge into regions, and each region gets one focus request
  that asks where the bug is and puts the suspicion to the judge again, also
  as its inverted twin.
- Rule 8C decides each region. A strong region, one in which a 16-line cell
  scored 0.96 or more in a look or an overlapping 8-line cell did, is reported
  at a focus score of 0.39 or more. Any other region is reported at 0.54 (the
  bar for a file of up to 200 lines; it rises with file length). A region that
  a related passage of code supports at 0.75 or more is reported from 0.39.
  There is no second stage. If only the twin question is refused, the region
  is decided on the other answer and carries a note that does not block the
  scan; any other missing answer leaves the region unmeasured and the scan
  incomplete.
- A larger file falls back to `legacy-v1`: stderr prints a notice and the
  report's `tile_sieve.mode` is `legacy-fallback` with the reason. A design
  that tiles larger files was modeled, and its modeled recall on large files
  was about 0.30, so it is not offered.

It needs `--canaries on`, `--state-layout v1` and `--policy-placement
instructions`, refuses `--polarity-twin` and `--require-verification`, and
uses the other search options only for the fallback. The report is schema 9
with a `tile_sieve` block (the looks, each region's strength, bar, score and
decision, and the thresholds used) and the handoff is schema 6, with a
`SEARCH:` line in `findings.txt`. `tools/eval/run_catalog.py --search-policy
tile-sieve-beta --dry-run` prints the plan for the catalog (36 tile requests
and a projection of 34 focus requests) without sending anything.

The thresholds are data, one set per judge, in
`decision_bug_hunter/tile_sieve_thresholds.json`. The file holds a set for the
OpenAI judge only, and every Tile Sieve report records the set used
(`thresholds_set`), the file's sha256 (`thresholds_sha256`) and the screening
rule. Microsoft-Decision-1 has no set and will get none in this beta:
choosing it with Tile Sieve stops before the source is read, on every route,
with exit `2` and

```text
Scan failed (invalid_search_configuration: tile-sieve-beta has no calibrated thresholds for judge microsoft).
```

A library caller whose gateway declares no judge is given the OpenAI set, and
the report says `"judge_declared": false`.

The same 34-case development catalog through the shipped CLI (OpenAI
Decisions, 2026-10-12), against `legacy-v1`. Scores are by location, except
the strict row, which also requires each finding to cite the requirement and,
in project cases, the helper file:

| Outcome | Tile Sieve, OpenAI direct | Tile Sieve, OpenRouter | `legacy-v1`, OpenAI direct | `legacy-v1`, OpenRouter |
|---|---:|---:|---:|---:|
| Defective programs detected | 16/16 | 15/16 | 16/16 | 15/16 |
| Individual defects covered | 17/17 | 16/17 | 17/17 | 16/17 |
| Corrected controls clear | 16/16 | 16/16 | 16/16 | 16/16 |
| Missing evidence marked incomplete | 2/2 | 2/2 | 0/2 | 1/2 |
| Entire cases | 34/34 | 33/34 | 32/34 | 32/34 |
| Entire cases, strict | 32/34 | 31/34 | 32/34 | 32/34 |
| Calls | 53 | 52 | 211 | 214 |
| Input tokens | 153,561 | 148,640 | 445,685 | 449,566 |
| Cost | about $0.015 (estimated) | $0.0149 | about $0.045 (estimated) | $0.0450 |

Every case fit one request, so none fell back. The 53 requests of the
OpenAI-direct run were 36 whole-file looks and 17 focus requests. Through
OpenRouter the screening did not flag the defect in one case that OpenAI
direct caught (the unit-conversion case), so the two routes differ here as
they do under `legacy-v1`.

Treat Tile Sieve as a beta. The thresholds were fitted on the pilot study's
own planted and clean files, but the pilot also ran this 34-case catalog while
the report rule was chosen, so the catalog is not held out and these scores
are optimistic: this is development evidence, not held-out evidence, with
n = 34 and one run per route (answers are deterministic per request). Expect
lower scores on files that are unlike the catalog, and use it as a fast first
look, not as a verdict.

## Cost and limits

OpenAI Decisions is listed at $0.10 per million input tokens on both of its
routes, and Microsoft-Decision-1 at $0.042 through OpenRouter; neither bills
output tokens (price tables dated 2026-10-06 and 2026-10-11; check the
provider's current price yourself). OpenRouter reports the cost of every
request, and in every observed response it equaled input tokens times the
listed price. OpenAI direct and Foundry report usage but no cost, so on those
routes DBH records the list-price estimate (input tokens x $0.0000001, or
x $0.000000042 on Foundry, which borrows the OpenRouter price because no Azure
price has been read).

Observed costs (2026-10-06 to 2026-10-12):

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
- Microsoft-Decision-1 through OpenRouter (legacy-v1, all 34 cases): 182 calls,
  254,661 input tokens, $0.0107.
- Tile Sieve (all 34 cases): 53 calls and about $0.015 on OpenAI direct (153,561
  input tokens, estimated), 52 calls and $0.0149 through OpenRouter.

Each request carries at most 64 questions and a 24 KiB local envelope
(16 KiB of state). The wire body is capped at 64 KiB on every route. Under
`--policy-placement state`, OpenRouter requests for OpenAI Decisions that
carry the policy in state may hold 200 questions and 48 KiB; Microsoft-Decision-1
keeps 64 questions and 24 KiB on every route, and so does Foundry until its
limits are confirmed on a deployment. Responses are capped at 256 KiB.

DBH bounds an attempt whose usage is unknown at its wire bytes plus 64
tokens per question: about $0.0029 for a full 24 KiB, 64-question request
and about $0.007 to $0.008 at the 64 KiB wire cap (65,536 bytes plus
200 x 64 tokens, at $0.0000001 each), which only translated OpenAI bodies
or 200-question state-placement requests approach. Under the default
1000-call limit a scan of full-size requests would therefore cost about $3,
and at most about $8, plus one possible duplicate charge for each
stale-connection retry; for Microsoft-Decision-1, whose
price is lower, a full 24 KiB request is bounded at about $0.0012. Real requests
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
on `openrouter`, only the error type and code on `foundry`); the provider's
message is never kept or printed.

Refusals and malformed answers cost one answer, not the batch. One refused
question in a request becomes `question_refused` for that answer; two or
more refusals withhold the batch as `response_refused`. A choice answer with
the wrong mass or option keys (`response_distribution`), a displayed argmax
that differs from the choice (`choice_argmax_mismatch`) or, on OpenRouter and
Foundry, a choice without its vector (`response_vector_missing`) also costs only
that answer. The attempt is then `validated_partial`. Wrong types, missing or
extra names and out-of-range numbers still reject the whole batch.

Choice vectors must sum to 1 within 10^-12 by default. Every one of the 61
choice vectors observed live summed to exactly 1 at two decimals, so this
strict default holds for the current model; `--choice-rounding-places N`
exists in case a future model rounds differently. Microsoft-Decision-1 writes
full-precision floats, and its 94 choice answers in the catalog run passed the
same strict test. Values are never renormalized.

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
  scoped-v2-beta, 9 for tile-sieve-beta): findings, coverage, issues,
  `provenance`, `usage`, `spend`, `attempts_transmitted`, `retries`, `stop_reason`,
  `answer_defects`, `refusals`, `judge_diagnostics`, `banners`, `controls`,
  `secret_scan` and `calibration` (always `uncalibrated`). Some fields appear
  only when relevant: `judge` (a judge other than OpenAI), `tile_sieve`
  (`tile-sieve-beta`), `request_geometry` (`--policy-placement state`),
  `unverified_suspicions` (`--require-verification`), `injection_markers`
  (markers found) and `gateway_totals` (a gateway shared by several scans);
  `controls` is absent with `--canaries off`.
- `findings.txt` (compact handoff), `handoff.json` (schema 4, 5 or 6) and
  `ranges.txt`.
- `receipts/`: one JSON receipt per attempt (schema 2) with hashes, route,
  requested and returned model, `judge` (a judge other than OpenAI), the
  provider's generation or request id,
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

`make_provider("openai")` builds the direct route, and
`make_provider("openrouter", judge="microsoft")` the Microsoft judge through
OpenRouter (`judge=` may also be given with the other judge; `"foundry"` takes
`foundry_endpoint=`, `foundry_deployment=` and `foundry_auth=`). `context_scope`
is required: `project` (with `project=ProjectIndex`), `declared_standalone` or
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
fresh environment without keys, confirms the CLI exits `3` without a judge and
without a route and `2` with `provider_unavailable` for each OpenAI route, and
runs the unpacked sdist's own test suite.
[docs/VALIDATION.md](docs/VALIDATION.md) records the latest results. The
repository also holds live tooling: `tools/eval` (the labeled development
catalog, shipped in the sdist; see
[tools/eval/README.md](tools/eval/README.md)) and `tools/smoke` (first-contact
smoke suites, repository only).

## Evidence and limits

The evidence for OpenAI Decisions comes from 2026-10-06 and 2026-10-07:
smoke suites and catalog runs on OpenRouter, and a 5-request smoke suite plus
two catalog runs on OpenAI direct. The evidence for Microsoft-Decision-1 and
Tile Sieve comes from 2026-10-11 and 2026-10-12: probes and a tuning study of
the Microsoft model on OpenRouter, and three catalog runs through the shipped
CLI (see [Choosing a judge](#choosing-a-judge) and
[Tile Sieve (beta)](#tile-sieve-beta); the figures are in
[docs/VALIDATION.md](docs/VALIDATION.md)). No request has ever been sent to
the Foundry route.

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

Other live observations (OpenRouter smoke runs of OpenAI Decisions, 32 and 48
requests): answers were byte-identical across repeated requests; four planted
bugs all screened above their clean twins (a preview on 8 files, not
calibration); two crude prompt-injection attempts neither suppressed a real
bug nor flooded a clean function. On the OpenAI-direct smoke run all 4 answer
batches validated (76 answers); every choice vector summed to exactly 1 at two
decimals with the choice equal to the argmax, and the confidence followed the
same identity as on OpenRouter. No refusal was observed on either route, so
the refusal handling is pinned only by fixtures.

Limits: returned probabilities are operating heuristics, and the report,
relation and refutation thresholds (0.80, 0.70, 0.80) are uncalibrated. They
were set for OpenAI Decisions and are applied unchanged to
Microsoft-Decision-1; they were not re-fitted for it. The Microsoft figures
rest on one catalog run, and the Tile Sieve thresholds were chosen in a pilot
that also ran this catalog.
Name resolution is bounded only by the operating system's resolver. DBH
judges text; it cannot see runtime behavior, and a clean report is not
evidence of correctness. Release status is tracked in
[docs/RELEASE_GATES.md](docs/RELEASE_GATES.md).

## License and provenance

MIT. DBH is a standalone repository that started from MIT-licensed files of
an earlier bug-hunting tool; its notice is kept in [LICENSE](LICENSE) and the
details are in [docs/PROVENANCE.md](docs/PROVENANCE.md).
