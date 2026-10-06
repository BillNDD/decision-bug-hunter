# Decision Bug Hunter

A bounded, first-pass bug hunter for source files, built on the OpenAI
Decisions API. One more tool in the toolshed, not the whole workshop.

**`0.1.0b1` is an experimental beta.** The hosted adapter targets the
`POST /v1/decisions` endpoint and the `gpt-6-luna` model exactly as documented
in the [Decisions guide](https://developers.openai.com/api/docs/guides/decisions)
and [API reference](https://developers.openai.com/api/reference/resources/decisions)
published on 2026-10-06, the day the API entered public beta. All adapter
behavior is pinned by offline fixtures built from the documented request and
response shapes. **No live request to the service was made while preparing
this release**, so live compatibility, probability precision, calibration,
recall, precision, cost and speed are unverified. See
[validation](docs/VALIDATION.md) and the [remaining gates](docs/RELEASE_GATES.md).

Decision Bug Hunter (DBH) derives from the MIT-licensed
[Jev Bug Hunter beta](https://github.com/BillNDD/jev-bug-hunter/tree/339f245f2169b9baf0ebbf406497c6a8422408db),
which uses the TypeSafe Jev judge. DBH keeps its multiscale windows, bounded
evidence search, independent rechecks, explicit scope, deterministic request
reuse, uncertainty handling and compact handoffs, and replaces the judge with
Decisions. The original tool continues separately. See [provenance](docs/PROVENANCE.md).

## How it works

The tool never executes your program. Python splits the target file into
overlapping windows and asks Decisions closed-form questions about each
region: `predicate` questions that return the probability of a bug, and
`choice` questions over supplied intervals that return a full probability
vector plus confidence, used for localization and for picking the next bounded
investigation step. Every answer is validated before it can affect anything:
exact answer association by name, atomic batches, exact displayed argmax,
probability mass checks, a fixed error taxonomy and fail-closed handling. A
malformed, refused or missing answer becomes a recorded limitation, never an
invented score. Receipts hold hashes, usage and validated judgments, never
your source, your specification or your credential.

Findings are suspicions with line citations. Statuses are honest: "unknown"
and "not-identified" are real outputs, and any failed call, hit limit or
incomplete pass marks the run incomplete rather than clean. A run that reports
no suspicions is a fast signal, never a correctness certificate. DBH
complements tests, static analyzers, fuzzing and human review.

## Install

Python 3.11 or newer; no third-party runtime dependencies.

```sh
python -m venv .venv
# Activate .venv using your shell's activation command.
python -m pip install "git+https://github.com/BillNDD/decision-bug-hunter.git@v0.1.0b1"
decision-bug-hunter --help
```

From a source checkout, run `python -m pip install .` in the repository root.

## Credentials

Real scans call `https://api.openai.com/v1/decisions` and need your own
`OPENAI_API_KEY`. The key is read from the environment only, once, when the
adapter is constructed. It is never accepted as a flag, never loaded from a
file, and never written to receipts, reports, errors or request bodies; any
input that contains the literal key is rejected before dispatch. Without a
usable key every scan exits `2` with `provider_unavailable` before any source
read, output or network use. Optional `OPENAI_ORG_ID` and `OPENAI_PROJECT_ID`
become the routing headers used by the official SDKs. Direct HTTPS egress is
required; redirects and proxies are not followed.

PowerShell:

```powershell
$secret = Read-Host "OpenAI API key" -AsSecureString
$env:OPENAI_API_KEY = [System.Net.NetworkCredential]::new("", $secret).Password
Remove-Variable secret
decision-bug-hunter target.py --scope standalone --spec-file requirements.txt
Remove-Item Env:OPENAI_API_KEY
```

POSIX shell:

```sh
read -rs OPENAI_API_KEY && export OPENAI_API_KEY
trap 'unset OPENAI_API_KEY' EXIT
decision-bug-hunter target.py --scope standalone --spec-file requirements.txt
```

The sample [.env.example](.env.example) documents the variable names. DBH does
not load `.env` files.

## Project scope

The caller declares the scope; the tool never infers a project boundary.
Scope is mandatory in both the CLI and library.

```sh
# related files may be searched; a project root is required
decision-bug-hunter target.py --scope project --project-root ./repo

# the owner declares there is no related project
decision-bug-hunter target.py --scope standalone

# related files may exist; judge this file only
decision-bug-hunter target.py --scope isolate
```

Missing or conflicting scope information fails clearly and machine-readably:

```text
NEED_USER_INPUT project_scope: provide project directory | standalone | isolate
NEED_USER_INPUT project_root: provide related directory
```

Exit codes: `0` complete, no suspicions · `1` complete, suspicions reported ·
`2` scan failed or incomplete · `3` caller input needed (see `NEED_USER_INPUT`).

## Cost, limits and failure behavior

Decisions bills input tokens only, listed at $0.10 per 1M tokens for
`gpt-6-luna` when this beta was prepared; check the current
[pricing](https://developers.openai.com/api/docs/guides/decisions) yourself.
Each request carries at most 16 KiB of encoded evidence and at most 64
questions, and the translated body is capped at 64 KiB. Work is bounded by
`--max-calls` (default 1000), `--max-questions`, `--max-windows`,
`--deadline-seconds` per call (default 30) and `--run-deadline-seconds`
(default 300). Under those defaults the 64 KiB body cap and the 1000-call
limit bound a scan at about 16 million input tokens, roughly $1.60 at the
listed rate, in the worst case; a typical request is well under 32 KiB and
small files finish in far fewer calls. Tokenization, regional premiums and
long-context multipliers are the provider's; DBH does not estimate or
reserve money.

There is no automatic retry or backoff. An HTTP `429` is recorded as
`http_rate_limited` and the scan continues to the next request; rerun later
if many calls were rate limited. `401`/`403` is recorded as
`http_unauthorized` and stops further dispatch for the run. `3xx` responses
are never followed, `5xx` responses are `http_server_error`, other statuses
are `http_rejected`, and error bodies are never read. A question the service
declines (`refusal`) withholds that whole batch as `response_refused`.

Choice answers must be a full probability vector over the supplied options.
The default policy requires the vector to sum to 1 within 10^-12. If live
answers are displayed with rounding, choice batches fail with
`response_distribution`; pass `--choice-rounding-places N` (2–8) to accept
mass consistent with nearest rounding at N places. Values are never
renormalized and the displayed argmax must still match the chosen option.

Source limit: 16 MiB / 200 000 physical lines; CLI specifications: 8 KiB /
2 000 lines. Image input is not used. Nothing is silently truncated.

## Output

Each run writes a private directory under `--output-dir` (default
`dbh_runs/run-*`): `report.json` (full engine report), `findings.txt`
(compact handoff), `handoff.json`, `ranges.txt` and `receipts/` (one journal
entry per request: hashes, provider identity, usage, validated judgments and
failure codes). `--output-format compact|ranges|json` selects what is printed.
Names, hashes, line ranges and judgments can still be sensitive: keep run
directories private and review artifacts before sharing. Filesystem permission
hardening is POSIX-specific; Windows access controls remain the caller's concern.

## Library use

```python
from pathlib import Path
from decision_bug_hunter.core import Config, Source, scan
from decision_bug_hunter.decisions import DecisionsProvider
from decision_bug_hunter.providers import ValidatedGateway

provider = DecisionsProvider()  # reads OPENAI_API_KEY now, calls nothing
with ValidatedGateway(provider, Path("dbh_runs/receipts")) as gateway:
    report = scan(Source.read(Path("target.py")), gateway, Config(),
                  context_scope="declared_standalone")
```

`context_scope` is required: `project` (with `project=ProjectIndex`),
`declared_standalone` or `owner_isolated`. A caller-owned gateway with the
same interface can replace the hosted one for offline embedding; such
gateways report `custom-unverified` provenance. The engine's requirements on
any judge are in the [provider contract](docs/PROVIDER_CONTRACT.md).

## Checks

Tests are deterministic and offline; no key, paid run or authentication
grant is required, and the suite forbids real sockets.

```sh
python -m pip install -e ".[dev]"
python -m unittest discover -s tests
python -m ruff check .
python -m mypy
python -m build
python tools/check_distribution.py dist
```

The distribution checker installs the built wheel into a fresh environment,
imports it, and confirms the installed CLI stops with `provider_unavailable`
when no key is present. [docs/VALIDATION.md](docs/VALIDATION.md) records the
latest results and coverage reconciliation against upstream.

## Evidence and limits

Passing fixtures establishes local mechanics, not live Decisions
compatibility, model calibration, recall, precision, comparative cost or
speed. Returned probabilities are operating heuristics; the report, relation
and refutation thresholds (0.80, 0.70, 0.80) are inherited and uncalibrated.
The upstream Jev `0.5.0b2` development campaign detected 10/16 defective
programs (11/17 individual defects), cleared 16/16 controls, marked 2/2
missing-evidence cases incomplete and failed its full outcome gate with six
known misses. Those are Jev results on a synthetic development suite; they do
not transfer to Decisions or DBH. See the
[upstream validation](https://github.com/BillNDD/jev-bug-hunter/blob/339f245f2169b9baf0ebbf406497c6a8422408db/docs/BETA2_VALIDATION.md).

## License

MIT, including the retained upstream notice. See [LICENSE](LICENSE) and
[provenance](docs/PROVENANCE.md).
