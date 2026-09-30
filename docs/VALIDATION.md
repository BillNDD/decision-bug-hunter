# Local preparation validation

Date: 2026-09-30. DBH `0.1.0a0`, Windows, Python `3.12.14`.
Tools: Ruff `0.16.9`, mypy `1.20.2`, build `1.6.1`, setuptools `84.0.0`.
The packaging checker used driver pip `25.0.1` to install into a fresh pip-less
virtual environment with `--no-index --no-deps`; imports ran under `-I`.

| Check | Passed | Failed | Skipped / not run |
|---|---:|---:|---|
| Full offline suite, fresh process 1 (497.320 s) | 343 | 0 | 1 POSIX directory-fsync check |
| Same suite, fresh process 2 (460.028 s) | 343 | 0 | Same 1 platform skip |
| Configured fatal-error lint | Pass | 0 | Full style lint not configured |
| Provider/Decisions boundary types | 2 modules | 0 | Inherited engine not fully typed |
| Python syntax compilation | Pass | 0 | None |
| Wheel and source archive build | 2 artifacts | 0 | None |
| Fresh wheel installation and CLI/resource gates | 6 checks | 0 | None |
| Actual Decisions service tests | 0 | 0 | Entire service integration untested |
| GitHub CI matrix | 0 | 0 | All 6 remote jobs unrun |

Reproduce with the README commands. Each suite runs 344 methods: 313 inherited
or adapted upstream methods and 31 DBH boundary methods. These include exact
JSON/Decimal validation, malformed and missing answers, full-vector/argmax/mass
rules, unmodified probability values, unknown and retained known usage, explicit
scope, source non-execution, raw BOM/CRLF hashes, compact/JSON/range output,
contrary and missing evidence, and deterministic routing under both policies.
Fresh synthetic runs compare identical request bytes and full engine reports.
Judgments are preassigned fixtures, not learned-model outputs.

## Coverage reconciliation

The pinned upstream was executed unchanged: 372 methods, 370 passed, 0 failed,
2 platform skips. Its older public 369-test count is not substituted here.
The earlier 294-pass DBH tree contained 268 inherited methods plus 26 new methods
and omitted 104 upstream methods. The audit found portable tests mixed into
those exclusions. Forty-five were restored: JSON validation (7), Choice profiles
and parity (7), localization profiles (4), compact CLI (6), immutable/sensitive
batch input (2), receipt repairs (3), focused discovery (1), mandatory library
scope (1), real-filesystem durability/crash checks (9), and ownership/CLI cleanup/
concurrent isolation (5). Five further DBH regressions brought new methods to 31.

| Remaining upstream exclusions | Methods | Scope and lost coverage |
|---|---:|---|
| Jev service/transport implementation | 38 | Jev HTTPS origin/auth/framing, supervised/reused OS worker lifecycle, legacy isolated child and transport-specific receipt details are absent; a real Decisions transport remains untested |
| Hosted acceptance/campaign tooling | 20 | Campaign catalog, trusted-witness and charged-ledger harness are outside this lean source-triage repository; no inherited campaign or effectiveness gate is claimed |
| Old generated README example | 1 | DBH has no generated findings example while unavailable; formatter and actual fixture CLI output regressions remain |

Thus `344 = 372 - 59 + 31`; the final Windows pass count is
`343 = 370 - 58 + 31`, with one inherited POSIX-only method still skipped.
The exclusions are not all provider-specific. Portable generic invariants were
restored. Ported assertions target DBH's declared local behavior: strict mass
defaults to `None`, rounded mass requires an explicit profile, preflight creates
no journal, and one request hash binds the owned state and questions. These are
local choices, not assumptions about undocumented Decisions outputs or precision.

## Failure evidence and limits

Independent fault injection exposed deadline expiry during durable intent and
reuse after interrupted journal transitions in the initial local snapshot.
The corrected boundary recomputes positive/expired budgets after intent,
blocks reuse before propagating interruption, retains possible submission and
known usage, and attempts safe settlement. Tests cover interrupts before/after
both writes, fsync/serialization/replace
failures, abrupt child-process exit, and isolation of another caller's receipt.
Blocked attempts cannot book earlier usage again.

The independent review reported seven passing boundary methods on the corrected
provider source, including repeated interruption during settlement. The
integrated independent reproductions were first
observed failing (six failure records across three methods), then passing.
A restored timeout fixture initially supplied a question without its required
span; restoring the original span-aware screen question retained the exact
0.25-second assertion. Earlier extraction/rounding/scoped-role fixture failures
and a wrong-directory invocation are retained in private preparation evidence.
They are not final passing evidence. The corrected focused run passed 47 of 48
methods with the same one POSIX skip before the full runs above.
Packaging preparation also retained an archive-permission-context failure and
a 120-second pip-bootstrap timeout. The checker now uses documented pip
`--python` installation into a fresh environment without pip bootstrapping;
the wheel installation and all six checks remain required.

No credentials, new authentication grants, paid calls or live model requests
were used. Passing fixtures does not establish real-service compatibility,
probability calibration, accuracy, scientific novelty or speedup. Actual-API,
independent holdout and monetary/transport gates remain in
[RELEASE_GATES.md](RELEASE_GATES.md).

The final tracked tree, reachable local history, and both distribution archives
receive credential-pattern, active-credential exact-match, private identity/path,
artifact-name and archive-content scans plus manual diff review. Synthetic
privacy-test paths are public fixtures. This bounded scan is not a guarantee
that every possible sensitive datum can be recognized. Private review logs,
reference checkout, environments and recovery copies remain outside the repo.
