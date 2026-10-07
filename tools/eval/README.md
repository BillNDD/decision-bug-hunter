# Catalog evaluation

`run_catalog.py` runs DBH's CLI over the 34 labeled synthetic cases in
`catalog.py` and scores the saved reports. The cases were ported under the
MIT notice (see `docs/PROVENANCE.md`); they form a small public development
suite, not a held-out benchmark.

Each case is written to a fresh temporary directory: the scanned directory
holds only the subject file (plus helper files for project-scope cases), the
requirement is written outside it, and labels are never written anywhere.
Scoring:

- defect: the scan is complete, and every planted bug line lies inside a
  finding whose range sits within that bug's allowed region;
- clear: the scan is complete with no findings;
- unresolved: the scan is incomplete with no findings.

The strict score also requires a requirement citation on each covering
finding and, for project cases that name one, a citation of the helper
file.

```sh
python tools/eval/run_catalog.py --dry-run
python tools/eval/run_catalog.py --only C001,C002 -- --provider openrouter
python tools/eval/run_catalog.py -- --provider openrouter --search-policy scoped-v2-beta
python tools/eval/run_catalog.py --summarize smoke-results/eval-YYYYmmdd-HHMMSS
```

`--dry-run` prints the CLI command for each case and sends nothing.
Arguments after `--` go to every CLI invocation; `--provider` is required
there for a live run. The runner reads no key itself: the CLI reads the
selected route's key from the environment. A live run bills that route; each
case runs with `--max-calls 32` (96 for the two 70-line cases). A full run
of the shipped defaults cost $0.0450 (legacy-v1) and $0.0683
(scoped-v2-beta) on OpenRouter, and about $0.045 and $0.065 at list price on
OpenAI direct, on 2026-10-07.

Output goes to `smoke-results/eval-<UTC time>/` (git-ignored, or `--out`):
`results.json`, one saved report per case under `reports/`, and
`summary.md` with the outcome table, calls, tokens and the summed
provider-reported cost. OpenAI direct reports no cost, so on that route the
summary shows $0; estimate the spend as input tokens x $0.0000001. Results
so far are in `docs/VALIDATION.md`.
