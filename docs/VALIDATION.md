# Local validation

Date: 2026-10-06. DBH `0.1.0b1`, Windows 11, Python `3.12.10` (project
environment) and `3.13.14` (second interpreter, suite only).
Tools: Ruff `0.16.10`, mypy `1.20.2`, build `1.6.1`, setuptools `84.0.0`,
driver pip `25.0.1`. The packaging checker installs the wheel into a fresh
pip-less virtual environment with `--no-index --no-deps`; imports run under
`-I` with `OPENAI_API_KEY`, `OPENAI_ORG_ID` and `OPENAI_PROJECT_ID` removed
from the subprocess environment.

| Check | Passed | Failed | Skipped / not run |
|---|---:|---:|---|
| Full offline suite, fresh process 1, Python 3.12 (368.378 s) | 364 | 0 | 1 POSIX directory-fsync check |
| Same suite, fresh process 2, Python 3.12 (402.022 s) | 364 | 0 | Same 1 platform skip |
| Same suite, fresh process, Python 3.13 (343.893 s) | 364 | 0 | Same 1 platform skip |
| Configured fatal-error lint (Ruff) | Pass | 0 | Full style lint not configured |
| Provider/Decisions boundary types (mypy, strict defs) | 2 modules | 0 | Inherited engine not fully typed |
| Wheel and source archive build (`--no-isolation`) | 2 artifacts | 0 | None |
| Fresh wheel installation and CLI/resource gates | 6 checks | 0 | None |
| Live Decisions service requests | 0 | 0 | **No live request was made** |
| GitHub CI matrix | 0 | 0 | Runs on first push |

Reproduce with the README commands. Each suite runs 365 methods: 313
inherited or adapted upstream methods, 31 DBH boundary methods and 21 new
adapter methods in `tests/test_decisions.py`. The adapter methods pin, from
the documented examples: envelope translation (state as exact JSON `input`,
predicate/choice question shapes, menu order, no local contract or credential
in the body); exact Decimal normalization of documented answers in any
order; usage mapping to the two local counters with absent usage unknown;
the fixed origin, path, headers, TLS context and timeout; chunked and
content-length framing; rejection of ambiguous or non-JSON framing; status
mapping for `3xx`/`400`/`401`/`403`/`404`/`429`/`5xx` without reading error
bodies; blocking after `401`; continuation after `429` without retry; socket
timeout and transport failures with fixed codes and no chained context;
oversized, malformed and credential-bearing bodies; refusal, missing,
duplicate, extra, mistyped and malformed answers with usage retained;
model provenance including dated snapshots; undocumented fields ignored and
never journaled; expired budgets opening no connection; credential
validation and construction-time-only environment reads; the CLI stopping
before any source read without a key; and one end-to-end CLI run through a
synthetic service that answers documented requests with the deterministic
fixture judge, checking findings, usage accounting, receipt count and the
absence of the key, host paths and source text from every artifact.

## Coverage reconciliation

The pinned upstream executed unchanged: 372 methods, 370 passed, 2 platform
skips. The `0.1.0a0` tree ran 344 methods (`372 - 59 + 31`). This beta adds
21 adapter methods: `365 = 372 - 59 + 52`. The Windows pass count is
`364 = 370 - 58 + 52`, with one inherited POSIX-only method still skipped.

| Remaining upstream exclusions | Methods | Scope and lost coverage |
|---|---:|---|
| Jev service/transport implementation | 38 | Jev HTTPS origin/auth/framing, supervised OS worker lifecycle and transport-specific receipt details. The Decisions adapter has its own 21 fixtures, but no live Decisions transport has been exercised |
| Hosted acceptance/campaign tooling | 20 | Campaign catalog, trusted-witness and charged-ledger harness are outside this repository; no campaign or effectiveness gate is claimed |
| Old generated README example | 1 | DBH has no generated findings example; formatter and fixture CLI output regressions remain |

Ported assertions target DBH's declared local behavior: strict mass defaults
to `None`, rounded mass requires an explicit profile, preflight creates no
journal, and one request hash binds the owned state and questions. The
adapter fixtures target the documented Decisions shapes; they are not
evidence about undocumented precision, limits or ordering.

## Failure evidence and limits

Earlier preparation exposed deadline expiry during durable intent and reuse
after interrupted journal transitions; the corrected gateway recomputes the
budget after intent, blocks reuse before propagating interruption, retains
possible submission and known usage, and attempts safe settlement. Those
regressions still pass.

During this beta's adapter work one new fixture expectation was corrected:
a `Content-Length` one byte longer than the body was expected to surface as
`transport_failed` from the socket layer but is caught first by the adapter's
own length reconciliation as `response_framing`; the stricter observed
behavior was kept. All other adapter fixtures passed on their first run.

No credentials, authentication grants, paid calls or live model requests
were used. Passing fixtures does not establish live compatibility,
probability precision, calibration, accuracy, novelty or speed. The
documentation states no precision for returned probabilities; the strict
mass default may reject rounded live choice vectors until
`--choice-rounding-places` is supplied. Live, holdout and monetary gates
remain open in [RELEASE_GATES.md](RELEASE_GATES.md).

The final tracked tree, reachable history and both distribution archives
received credential-pattern, private identity/path, artifact-name and
archive-content scans plus manual diff review. Synthetic privacy-test paths
and sentinel credentials are public fixtures. Commits carry an anonymous
contributor identity. This bounded scan is not a guarantee that every
possible sensitive datum can be recognized.
