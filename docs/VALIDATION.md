# Local preparation validation

Date: 2026-09-30. DBH `0.1.0a0`, Windows, Python `3.12.14`.

| Check | Passed | Failed | Skipped / not run |
|---|---:|---:|---|
| Final full offline suite, fresh process 1 | 294 | 0 | 0 skipped |
| Same suite, independent fresh process 2 | 294 | 0 | 0 skipped |
| Configured fatal-error lint | Pass | 0 | Style/full lint not configured |
| Provider/Decisions boundary type checks | 2 modules | 0 | Inherited engine not fully typed |
| Python syntax compilation | Pass | 0 | None |
| Wheel and source archive build | 2 artifacts | 0 | None |
| Fresh wheel installation and CLI/resource gates | 6 checks | 0 | None |
| Actual Decisions service tests | 0 | 0 | Entire service integration untested |
| GitHub CI matrix | 0 | 0 | All 6 remote jobs unrun |

Run the README commands to reproduce the local suite. The suite contains 26
provider-boundary regressions covering unavailable/empty-input behavior,
malformed/missing/extra answers, exact probabilities and mass profiles, unknown
usage, late/truncated replies, durable submission intent, persistence failures,
safe exception text, reentrancy, cleanup failure and source non-execution.
Fresh synthetic runs under both search policies must have identical request
bytes and full reports. These checks use preassigned fixture judgments, not a
learned model or actual API outputs.

The pinned upstream beta suite was separately executed unchanged: 372 tests,
370 passed, 0 failed and 2 platform skips. Its public older 369-test validation
count is not substituted for this observed local count.

Initial DBH fixture failures from removed Jev seams, inherited default-rounding
expectations and incorrectly assigned scoped role answers were corrected before
the final passing runs. There was also a test invocation from the wrong working
directory; it produced import errors and supplied no validation evidence.

Only the two final full passing executions describe the final prepared code.
No credentials, authentication grants, paid provider calls or live model requests
were used. No accuracy, calibration, scientific novelty, E2E speedup or Decisions
compatibility follows from these checks. Actual-service and held-out gates remain
in [RELEASE_GATES.md](RELEASE_GATES.md).

The staged public tree and prospective root history receive credential-pattern,
active-credential exact-match, private-identity/path, artifact-name and archive
content scans plus manual diff review. Synthetic privacy-test paths are public
fixtures. This bounded inspection is not proof that every possible sensitive
datum can be recognized.
