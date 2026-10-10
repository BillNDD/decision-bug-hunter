# Performance and the benchmark gate

`tools/bench/bench.py` measures Decision Bug Hunter offline. It runs the real
engine and CLI over the real OpenRouter adapter, with an in-process fake
exchange and a deterministic synthetic judge. No socket opens, and no
credential is read. The scenarios and their inputs are in
`tools/bench/scenarios.py`; the recorded values are in `tools/bench/golden.json`.

## How to run

```
python tools/bench/bench.py --check            # fingerprints against golden.json
python tools/bench/bench.py --gate             # fingerprints, exact values and ceilings (see the version rule)
python tools/bench/bench.py --scenario synth-200 --gate
python tools/bench/bench.py --update-golden    # re-record; refuses unless hash seeds 0 and 1 agree
python tools/bench/bench.py --markdown tools/bench/golden.json
python tools/bench/bench.py --compare OLD.json NEW.json
python tools/bench/bench.py                    # timed measurement; writes a result file
```

Add `--parallel N` to run scenarios in N concurrent subprocesses. Counts are
unaffected; timings are noisier. Results are written under the system temporary
directory (`dbh-bench`) unless `--out` names another path. Nothing else is
written into the repository, except by `--update-golden`.

The gate runs every scenario in its own subprocess with `PYTHONHASHSEED=0` and
in-memory receipts. The in-memory receipts keep the exact receipt bytes and skip
only the temp-file, fsync and rename steps. Those steps dominated wall time on
the machine where this was measured, and they are the only difference from the
shipped write.

## What each metric means

- **Fingerprints** (`fingerprint`, `request_envelopes_sha256`, per-case
  `report_sha256` and `receipts_sha256`): hashes of the shipped output. Timing
  and uuid fields are removed first. Equal fingerprints mean byte-identical
  reports, receipts and provider requests.
- **Exact values**: provider calls, unique requests, questions, envelope and
  wire bytes, receipt writes and files, and ask() rounds (as executed, the
  critical-path upper bound, and per phase). Any change is a behavior change.
- **Gated counters**:
  - `dbh_ncalls` and `dbh_primitive_calls`: cProfile calls of functions defined
    in the `decision_bug_hunter` package. Stdlib internals are excluded, but
    the interpreter still moves this count: see the version rule below.
  - `copy_deepcopy_calls`, `json_dumps_calls`, `json_loads_calls`,
    `sha256_calls`, `protocol_snapshot_calls`, `protocol_secret_in_calls`,
    `path_mkdir_calls`: call counts.
  - `json_dumps_chars`, `json_loads_bytes`, `sha256_bytes`: sizes. These carry
    wall-clock digits from receipts, so they move by a few characters between
    runs.
- **Informational only** (never gated, not in golden): total cProfile calls,
  `process_time`, and the tracemalloc peak.

## The gate and the ratchet

- Any change to a fingerprint, a per-case hash, or an exact value fails.
- A gated call counter may grow by at most 2%. A gated byte or character counter
  may grow by at most 1%.
- If a gated counter falls by more than 2%, the gate prints a notice. Re-record
  with `--update-golden` and commit the new values, so the improvement becomes
  the new ceiling.
- `--update-golden` runs each scenario with two hash seeds. Every count must
  agree between them. The byte and character counters may differ by their 1%
  tolerance, because of the wall-clock digits; the difference is printed.

## The version rule

The cost counters depend on the interpreter, so `golden.json` records the
Python minor version it was recorded with (`meta.python_minor`, now 3.12) and
`--update-golden` writes it.

- On that minor version, `--gate` enforces everything above.
- On any other minor version, `--gate` still enforces the fingerprints, the
  per-case hashes and every exact value. It reports the cost counters as one
  informational notice per scenario, naming the counters that are above their
  ceiling, and never fails on them. A fingerprint or exact-value change fails on
  every version, and so does a counter that is missing altogether.
- `--update-golden` on a different minor version refuses to re-record only some
  scenarios, because that would mix versions in one file. Re-record every
  scenario on one version, or use the recorded one.

Why the counters move on 3.11 (measured on `synth-200` and `catalog-4`):

- `dbh_ncalls` is about 17% higher on `synth-200`. Before 3.12 (PEP 709), every
  list, dict and set comprehension in the package is a separate function call
  that cProfile counts; 3.12 inlines them. On `synth-200` that is about 16,500
  of the 110,600 package calls.
- `copy_deepcopy_calls` is higher, for example 36 on 3.12 and 160 on 3.11 on
  `catalog-4`. `dataclasses.asdict` calls `copy.deepcopy` on every leaf, and
  3.12 skips the call for `str`, `int`, `None` and the other immutable leaf
  types. The package reaches it through `SourceRef.id` and `as_dict`,
  `ClaimKey.id` and `as_dict`, `EvidenceRevision.id` and the revision data in
  `claim_search`: 152 of the 160 calls on 3.11. None of this is work that only
  3.11 does; the interpreter's own accounting and fast paths differ. Replacing
  `asdict` with explicit field dicts in those few methods would remove the
  calls on every version, and is not done here.

## Current numbers

Recorded on Python 3.12.10. On 3.13 the counters were within the gate
tolerances when measured; the gate enforces them only on 3.12 (see the version
rule). On 3.11 the fingerprints and exact values are identical, and the
counters differ as described above.

| Scenario | Jobs | Provider calls | Questions | Envelope bytes | Rounds (executed) | Critical path (upper) | DBH-own ncalls | JSON dumps chars | sha256 bytes | Receipt writes |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| synth-200 | 1 | 120 | 980 | 1,351,813 | 96 | 88 | 116,605 | 4,521,899 | 6,887,295 | 240 |
| synth-1000 | 1 | 235 | 3,426 | 4,013,114 | 112 | 72 | 263,296 | 12,597,639 | 19,899,969 | 470 |
| synth-1000-legacy-gate | 1 | 246 | 3,470 | 4,139,876 | 123 | 83 | 281,715 | 13,017,522 | 20,532,173 | 492 |
| synth-1000-state | 1 | 112 | 3,180 | 1,738,384 | 112 | 72 | 213,495 | 6,427,050 | 9,024,087 | 224 |
| synth-1000-nocanary | 1 | 235 | 2,956 | 3,923,814 | 112 | 72 | 243,441 | 12,305,746 | 15,541,307 | 470 |
| synth-5000 | 1 | 903 | 16,116 | 18,228,326 | 279 | 72 | 1,074,877 | 56,224,835 | 89,645,013 | 1,806 |
| catalog-legacy | 34 | 199 | 1,178 | 1,117,659 | 187 | 183 | 134,261 | 4,149,510 | 5,874,398 | 398 |
| catalog-scoped | 34 | 191 | 1,246 | 1,261,404 | 179 | 175 | 145,633 | 5,076,104 | 7,107,116 | 382 |
| cli-1000 | 1 | 235 | 3,426 | 4,013,114 | 112 | 72 | 263,578 | 13,592,461 | 19,903,318 | 470 |
| catalog-4 | 4 | 20 | 94 | 74,685 | 20 | 20 | 11,398 | 299,126 | 401,915 | 40 |

"Critical path (upper)" is an upper bound on dependent provider round trips,
not a measured latency. Timings are indicative only. This machine is loaded and
its disk is slow, so process times and wall clocks are not reported here.
