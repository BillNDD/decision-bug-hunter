# Provenance and retained scope

Prepared against public [BillNDD/jev-bug-hunter](https://github.com/BillNDD/jev-bug-hunter)
on 2026-09-30:

- Selected branch: `beta/v0.5.0b1`.
- Selected commit: `339f245f2169b9baf0ebbf406497c6a8422408db`.
- Package/release: `0.5.0b2`; original `v0.5.0b1` tag is distinct.
- Default `main` observed at `fcaacdeedf07561b18721ca3a5f16d528de7e709`.
- Upstream license: MIT, retaining **Copyright (c) 2026 Jev Bug Hunter contributors**
  in this repository's LICENSE. DBH additions are also MIT.

This is a new root-history repository prepared from selected public files,
with no imported upstream Git history or private working checkout. JBH continues
using Jev independently.

Retained: source snapshot/line geometry, deterministic byte-bounded question
packing, window/localization logic, evidence/repository safety, independent
verification, scoped claims and refutation, compact handoff, offline evaluation,
the question pack, and relevant deterministic regression tests. The default
search policy stays `legacy-v1`; `scoped-v2-beta` remains experimental. Report,
relation and refutation thresholds remain 0.80, 0.70 and 0.80. They are uncalibrated.

Changed: distribution/package/CLI identity, pure local protocol extraction,
provider provenance, strict-by-default probability mass, generic single-attempt
receipt gateway, packaging scope, and fixtures that formerly patched Jev
transport. Legacy internal Noul/Choice mechanics are documented as engine
requirements rather than a Decisions service schema.

Excluded: Jev HTTP endpoint/model/credential loading, hosted worker/transport,
provider-specific transport tests, live acceptance/campaign/witness machinery,
benchmark tools/data, generated run reports, audit bundles, transcripts, private
datasets, prior engineering histories and unrelated assets. Replaced distribution
checks inspect only DBH runtime, necessary docs, tools and offline tests.

Upstream [beta validation](https://github.com/BillNDD/jev-bug-hunter/blob/339f245f2169b9baf0ebbf406497c6a8422408db/docs/BETA2_VALIDATION.md)
records 10/16 defective programs detected, 11/17 individual defects covered,
16/16 corrected controls clear, 2/2 missing-evidence cases incomplete and a failed
full outcome gate. Six misses include empty-input division, a half-open bound,
loop early return, unit conversion, a cross-file limit and SQL NULL semantics.
These Jev development results do not transfer to Decisions or DBH.

## Decisions documentation

The hosted adapter added in `0.1.0b1` was written from the public
[Decisions guide](https://developers.openai.com/api/docs/guides/decisions),
[API reference](https://developers.openai.com/api/reference/resources/decisions)
and the [changelog](https://developers.openai.com/api/docs/changelog) entry of
2026-10-06 announcing the public beta with `gpt-6-luna`. The transport design
mirrors the upstream Jev adapter's fixed-origin, strict-framing, no-retry
pattern, reimplemented for the documented Decisions shapes. No OpenAI SDK
code is used or vendored. No provider account access was tested.

This preparation does not claim a novel detection algorithm or new scientific
effectiveness result. Fresh deterministic regressions establish reproducible
local behavior only; live-service and held-out evidence remain separate gates.
See [release gates](RELEASE_GATES.md).
