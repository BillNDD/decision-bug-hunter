# Provenance

Decision Bug Hunter is a standalone repository with its own history. It is
not a branch or fork of another project, and it does not import another
project's Git history.

## Starting point

DBH started on 2026-09-30 from selected public files of the MIT-licensed
[Jev Bug Hunter](https://github.com/BillNDD/jev-bug-hunter) at commit
`339f245f2169b9baf0ebbf406497c6a8422408db` (package `0.5.0b2`). The
[LICENSE](../LICENSE) keeps that project's notice, **Copyright (c) 2026 Jev
Bug Hunter contributors**, next to DBH's own; DBH's additions are also MIT.

Kept from the starting files, and changed since where noted elsewhere:
source snapshots and line geometry, byte-bounded question packing, window
and localization logic, evidence search and repository safety, independent
rechecks, scoped claims and refutation, the compact handoff, offline
evaluation helpers, the question pack, and the deterministic regression
tests that cover them. The `legacy-v1` and `scoped-v2-beta` search policies
and the 0.80 / 0.70 / 0.80 report, relation and refutation thresholds come
from there and remain uncalibrated.

Replaced or new in DBH: the judge (the OpenAI Decisions model only, directly
or through OpenRouter), the hosted adapters and HTTPS exchange, explicit
route selection, retries, the breaker and spend accounting, answer-scoped
defects, the receipt schema, the secret scan, judge controls, injection
markers, the tier-2 options, packaging and the CLI identity.

Excluded: the Jev endpoint, the Jev model and its credential loading, its
hosted worker and transport and their tests, the upstream live acceptance,
campaign and witness machinery, benchmark data, generated reports, audit
bundles and transcripts. DBH sends nothing to that endpoint and supports no
model other than the Decisions model.

## Ported evaluation cases

`tools/eval/catalog.py` ports the 34 labeled synthetic cases of the upstream
file `acceptance/catalog.py` (catalog revision `bounded-builtins-v2`) at the
commit above, under the MIT notice, with an attribution header in the file.
Only the case definitions were copied; the upstream executable witness
checks were dropped because DBH never runs target code.
`tools/eval/run_catalog.py` scores DBH's reports with the same outcome rules
the upstream suite used. The cases are used for development evaluation only;
they are public and not a held-out benchmark.

## Decisions documentation

The direct OpenAI adapter was written from the public Decisions guide, API
reference and changelog of 2026-10-06. The OpenRouter adapter was written
from the observed behavior of `POST /api/alpha/decisions` on 2026-10-06 (see
[VALIDATION.md](VALIDATION.md)). No OpenAI or OpenRouter SDK code is used or
vendored.

DBH does not claim a novel detection algorithm or a new effectiveness
result; see [RELEASE_GATES.md](RELEASE_GATES.md).
