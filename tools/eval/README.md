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
python tools/eval/run_catalog.py --dry-run -- --judge openai
python tools/eval/run_catalog.py --only C001,C002 -- --judge openai --provider openrouter
python tools/eval/run_catalog.py -- --judge openai --provider openrouter --search-policy scoped-v2-beta
python tools/eval/run_catalog.py --search-policy tile-sieve-beta --dry-run -- --judge openai
python tools/eval/run_catalog.py --search-policy tile-sieve-beta --max-total-cost 0.05 -- --judge openai --provider openrouter --max-cost 0.02
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

## Judge and search policy

The runner reads (and still forwards) the arguments that come after `--` with
the CLI's own parser, so an unambiguous abbreviation (`--judg openai`) means
what it means to the CLI, and a rejected argument is refused as the CLI
refuses it, with exit 2 and without echoing the value. A missing judge
(`--judge` or `DBH_JUDGE`) is reported up front with the CLI's own
`NEED_USER_INPUT judge` text and exit 3, before any case runs; so is a route
outside the judge's.
The judge, the route, the model requested and the models the provider
returned (from each report's route provenance) are recorded in
`results.json` and in the `summary.md` header. A summary of a run from before
this was recorded has no such line.

`--search-policy {legacy-v1,scoped-v2-beta,tile-sieve-beta}` is the runner's
own flag and is forwarded to every CLI call (giving it after `--` too is fine
if the values agree). Microsoft-Decision-1 is experimental and is validated on the
`legacy-v1` policy only. With `--judge microsoft` and `tile-sieve-beta`, both
a dry run and a real run stop up front with the CLI's refusal
(`invalid_search_configuration: tile-sieve-beta has no calibrated thresholds
for judge microsoft`, exit 2) and run no case.

With `tile-sieve-beta`, `--dry-run` builds no provider and opens no socket.
It plans every case with the Tile Sieve planner, from the files a live run
would read, and prints one line per case: the mode (`whole-file`, or
`legacy-fallback` with the reason), the tile requests, the questions and the
largest request in bytes. A `Worst case:` line comes next: the engine sends one
focus request per flagged cluster and has no limit of its own on them, so the
hard bound is its call budget, `--max-calls` per case (the catalog's, or the
one forwarded), and the line gives the most requests that allows over the
planned cases and their cost bound with every request at the full request size.
The last line gives the
totals: the tile requests (36) and the focus requests *projected* (34, the
pilot's one per whole-file case; not a bound), the projected request bytes and a
projected cost bound. The bound prices one attempt per request at the judge's
list price ($0.10 per million input tokens for OpenAI Decisions, $0.042 for
Microsoft-Decision-1), taken from the route specs through `attempt_cost_bound`;
a request's output is not billed. The totals are projections, not a worst case:
the CLI's `--max-calls` and `--max-cost` (and the runner's `--max-total-cost`)
are the hard bounds.

`--max-total-cost USD` stops before the next case once the summed case costs
reach the limit. A case's cost is its report's spend upper bound
(`upper_bound_usd`: provider-reported + list-price estimate + unknown-usage
bound), so the limit binds on a route that reports no cost, such as OpenAI
direct. With no saved report the cost is read from the CLI's stderr line
`Spend (USD): provider-reported X, estimated Y, unknown-usage bound Z.`; with
neither, the case counts at its forwarded `--max-cost`, else at `--max-calls`
requests of the full request size at the judge's list price. It is never
counted as zero. The case that did not run is recorded as `stopped_at_case` in
`results.json` and named in `summary.md`. The limit is checked between cases,
so a run can pass it by one case; the CLI's `--max-cost` bounds each case. A
forwarded `--max-cost` outside (0, 1000] USD or `--max-calls` outside 1 to
100000 is refused up front with the CLI's own text (exit 2), before any case
runs, and the rejected value is never echoed.

Output goes to `smoke-results/eval-<UTC time>/` (git-ignored, or `--out`):
`results.json`, one saved report per case under `reports/`, and
`summary.md` with the outcome table, a mode column and the count of
legacy-v1 fallbacks (Tile Sieve runs), calls, tokens and the cost. The summary
shows the provider-reported cost, the list-price estimate and the unknown-usage
bound separately (OpenAI direct reports no cost, so its provider-reported line
is $0 and the estimate carries the spend), the reported-or-estimated cost
(reported + estimate), and the spend counted toward `--max-total-cost`, which
is the sum of each case's upper bound. In `results.json`, `spent_usd` is that
counted spend, each case has `provider_reported_usd`, `estimated_usd`,
`unknown_usage_upper_bound_usd`, `upper_bound_usd`, `cost_usd` and `cost_basis`
(`report`, `stderr`, `max-cost` or `call-cap`), and a `spend` block holds the
totals.

`--summarize <dir>` rebuilds `summary.md` and recomputes those totals the same
way from the stored cases, so a directory recorded before the upper bound was
kept (whose `spent_usd` reads $0 on OpenAI direct) is corrected in its summary;
older rows take their spend upper bound from the saved
`reports/<id>-report.json` (a row with no saved report shows its unknown-usage
bound as not recorded); its `results.json` is left as recorded. Results so far are in
`docs/VALIDATION.md`.
