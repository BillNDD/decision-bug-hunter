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
| synth-200 | 1 | 120 | 980 | 1,351,813 | 96 | 88 | 95,140 | 2,785,635 | 5,535,482 | 240 |
| synth-1000 | 1 | 235 | 3,426 | 4,013,114 | 112 | 72 | 209,973 | 8,151,014 | 15,886,855 | 470 |
| synth-1000-legacy-gate | 1 | 246 | 3,470 | 4,139,876 | 123 | 83 | 225,323 | 8,401,355 | 16,392,297 | 492 |
| synth-1000-state | 1 | 112 | 3,180 | 1,738,384 | 112 | 72 | 175,835 | 4,179,889 | 7,285,703 | 224 |
| synth-1000-nocanary | 1 | 235 | 2,956 | 3,923,814 | 112 | 72 | 194,348 | 7,948,814 | 11,617,493 | 470 |
| synth-5000 | 1 | 903 | 16,116 | 18,228,326 | 279 | 72 | 847,574 | 36,916,902 | 71,416,687 | 1,806 |
| catalog-legacy | 34 | 199 | 1,178 | 1,117,659 | 187 | 183 | 117,119 | 2,853,621 | 4,756,739 | 398 |
| catalog-scoped | 34 | 191 | 1,246 | 1,261,404 | 179 | 175 | 127,550 | 3,533,459 | 5,845,712 | 382 |
| cli-1000 | 1 | 235 | 3,426 | 4,013,114 | 112 | 72 | 210,256 | 9,146,255 | 15,890,204 | 470 |
| catalog-4 | 4 | 20 | 94 | 74,685 | 20 | 20 | 10,216 | 215,798 | 327,230 | 40 |
| catalog-4-tile-sieve | 4 | 6 | 76 | 36,134 | 6 | 6 | 8,482 | 172,952 | 276,517 | 12 |
| catalog-tile-sieve | 34 | 53 | 690 | 350,041 | 53 | 53 | 79,658 | 1,680,442 | 2,615,493 | 106 |
| synth-200-tile-sieve | 1 | 3 | 70 | 57,397 | 3 | 3 | 11,885 | 274,611 | 364,120 | 6 |
| synth-1000-tile-sieve | 1 | 235 | 3,426 | 4,013,114 | 112 | 72 | 210,410 | 8,160,082 | 15,894,008 | 470 |
| catalog-4-microsoft | 4 | 20 | 94 | 74,685 | 20 | 20 | 10,170 | 219,193 | 327,290 | 40 |

"Critical path (upper)" is an upper bound on dependent provider round trips,
not a measured latency. Timings are indicative only. This machine is loaded and
its disk is slow, so process times and wall clocks are not reported here.

## The Tile Sieve and Microsoft scenarios

Five scenarios cover the second judge and the whole-file search. The ten that
existed before them keep the fingerprints and exact values they had before the
second judge: the OpenAI judge's reports, receipts and requests are
byte-identical. Their `dbh_ncalls` and `dbh_primitive_calls` counters rose by
at most about 1.4% (gate 2%) and `json_dumps_chars` moved by less than 0.01%
(gate 1%); no other counter moved.

- `catalog-tile-sieve`: all 34 catalog cases under `--search-policy
  tile-sieve-beta`. It makes 53 provider calls, 690 questions and 350,041
  envelope bytes, against 199 calls and 1,117,659 bytes for `catalog-legacy`.
  The rounds by phase are 34 first looks (`ts-screen-l0`), 2 second looks
  (`ts-screen-l1`) and 17 focus requests (`ts-focus`): 36 look requests and 17
  focus requests. The 53 matches the live catalog run of the OpenAI judge on
  OpenAI direct.
- `catalog-4-tile-sieve`: the first four catalog cases, 6 provider calls (4
  looks and 2 focus requests).
- `synth-200-tile-sieve`: the 200-line synthetic file, 3 provider calls (two
  looks and one focus request).
- `synth-1000-tile-sieve`: the 1,000-line file does not fit one request, so the
  scan falls back to `legacy-v1`. Its provider calls, questions, envelope bytes
  and rounds equal `synth-1000`'s; the fingerprint differs because the report
  carries the `tile_sieve` block that names the fallback.
- `catalog-4-microsoft`: the first four catalog cases on the Microsoft model
  with full-precision probabilities from the synthetic judge. The requests are
  those of `catalog-4` (the same request envelope hash and the same calls,
  questions and envelope bytes; the wire bytes are 60 larger because the model
  id is longer); the fingerprint differs because the report and receipts name
  the judge.

`python tools/bench/bench.py --markdown tools/bench/golden.json` prints the
table above from the recorded values; the exact-value columns (jobs, calls,
questions, envelope bytes, rounds, critical path, receipt writes) are also
checked against `golden.json` by the documentation tests.
