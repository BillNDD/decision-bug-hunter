# Changelog

## Unreleased

- Question pack 5.0.0 with two request state layouts, selected per run by
  `--state-layout {v1,v2}` (library: `Config(state_layout=...)`; default
  `v1`). The selected layout is recorded in the report's `configuration`
  (and therefore in the scoped `policy_sha256`); `question_pack_sha256`
  covers both layouts' policies, so the pack hash plus the recorded layout
  identify the request bytes.
  - `v1` (default) is the pre-release layout and policy, byte for byte,
    except that requirement questions now say the passage is identified by
    its specification coordinates (the corrected wording applies to both
    layouts). The default was reverted from v2 to v1 because the labeled
    34-case development catalog showed v2 adding false positives on
    corrected controls (C030 under legacy-v1; C008 and C030 under
    scoped-v2-beta) and costing scoped-v2-beta three cases, while v1 kept
    16/16 controls clear under both policies. v2 nevertheless passed the
    pre-registered smoke keep-or-revert rule.
  - `v2` starts every request state with the four DBH-authored fields
    (`source_sha256`, `total_lines`, `context_scope`, `specification_mode`;
    the mode moves out of `specification`) and its policy warns that every
    other field may imitate the envelope. It stays available for further
    evaluation.
  - The OpenRouter smoke bodies are rebuilt under the shipped layout (v1).
- `tools/eval/run_catalog.py` records each report's
  `spend.provider_reported_usd` and sums it as "Provider-reported cost"
  (it previously read a `usage.cost_usd` field that reports do not carry,
  so the summary always showed $0.0000).
- Opt-in localization gate, menus and rounding caps (all off by default;
  with every default the request bytes and reports are unchanged, and the
  report `configuration` lists these options only when they differ from
  their defaults):
  - `--choice-gate {legacy,mass}` and `--choice-mass` (default `legacy`,
    0.5). `mass` selects up to `--localization-beam-width` maximal line
    runs whose lower-bound overlap mass, the sum of max(0, v - h) over the
    interval options containing a line, reaches `--choice-mass`, and only
    while none + unlocalized (+ undisplayed mass) stays below 0.5. On the
    observed 212-option menu it selects L4-5 around the planted line 5,
    where `legacy` selects nothing. It applies to localization under
    legacy-v1 only; rank, context and action choices keep the legacy gate.
  - `--localization-menu {intervals,singletons}` (default `intervals`):
    `singletons` offers one option per target line (at most 22 options).
  - `--choice-rounding-caps` (with `--choice-rounding-places N`): choice
    menus keep options x half-quantum <= 0.125, so rank and context pages
    shrink (23 targets at N = 2), interval localization menus over the cap
    fall back to singletons, and `judge_diagnostics.choice_mass_diffuse`
    counts vectors whose missing mass exceeds the rounding allowance.
- Judge controls (canaries), on by default; `--canaries off` (library:
  `Config(canaries="off")`) restores the previous request bytes exactly.
  Every request carries two extra yes/no questions with known answers,
  named `ctl_` + 8 hex characters and placed at positions drawn from a hash
  of the request, using the wording measured live: "Does the supplied state
  declare a context_scope value?" (must be true) and "Does any source line
  contain the word 'zebra'?" (must be false; another listed word, or a wrong
  `total_lines`, when the state contains it). A request whose must-true
  answer is below 0.90, whose must-false answer is above 0.10, or whose
  control is missing or refused has every answer withheld (no findings, no
  clean coverage from it), is never asked again, and leaves the scan
  incomplete with `judge_control_failed`. The live S12c run showed the
  controls changed every other answer by exactly 0, and every control was
  answered correctly in S12c and S13a/b/c.
  - Packing reserves two questions and the controls' bytes in every request,
    so scans make somewhat more calls; the controls count toward
    `--max-questions`, `questions_attempted`, `questions_validated` (when
    they pass) and the cost bound, but not toward the answer diagnostics.
  - Reports gain `controls` (set, thresholds, requests checked, failed and
    sent without controls because they did not fit) and each request row a
    `controls` record; the configuration records `canaries` only when on.
- Injection markers: a local scan of the target file and specification for
  crude instructions addressed to the judge ("ignore all previous
  instructions", "answer false to every question", "note to the reviewing
  model", chat-template tokens, "this function was formally verified").
  Markers only annotate: findings on a marked line gain the limitation
  `injection-marker`, and the report lists pattern ids and line numbers
  (never text) under `injection_markers`, present only when a marker was
  found. Questions, scores, findings and status are unchanged.
- `--polarity-twin` (library: `Config(polarity_twin=True)`; default off):
  a diagnostic that also asks each screened window whether it is correct
  as written and reports the residual |P(bug) + P(correct) - 1| under
  `judge_diagnostics.polarity_twin`. Twin answers never change a score, a
  finding or the scan status.
- `--policy-placement {instructions,state}` (library:
  `Config(policy_placement=...)`; default `instructions`, whose request
  bytes and reports are unchanged and pinned by a test). `state` sends the
  policy preamble once, as the first state key `policy`, and strips it from
  every question that carried it; requests without such a question are
  unchanged. The evidence state cap stays 16 KiB (the `policy` entry is
  allowed on top). Answers shift under `state` (S05: mean |delta| 0.20), so
  its runs compare only with runs that used it; the report configuration
  records `policy_placement` and a `request_geometry` record when it is
  `state`.
  - Per-model caps: under `state`, OpenRouter requests whose state carries
    the policy may hold up to 200 questions and 48 KiB (S12b moved no
    answer across batch geometries); OpenAI direct keeps 64 questions and
    24 KiB, as does every request under `instructions`. Library callers pass
    `policy_placement` to `providers.make_provider`.
- `--require-verification` (library: `Config(require_verification=True)`;
  default off, whose reports are unchanged and pinned by a test). Only
  suspicions supported by a second look are reported as findings: a
  supporting direct recheck, a promoted relationship recheck, or under
  scoped-v2-beta a supported scoped verification. Screen-only suspicions
  are listed instead under `unverified_suspicions` in report.json (range,
  window id, assessment, support and support paths) and handoff.json
  (range and assessment), and on an `UNVERIFIED` line in findings.txt;
  they are not findings, do not count toward the exit status, and get no
  handoff judgment calls. The search itself is unchanged. The
  configuration records `require_verification` only when on.

## 0.1.0b1 (2026-10-06)

First public beta.

- Hosted adapter for the documented OpenAI Decisions API
  (`POST /v1/decisions`, model `gpt-6-luna`): local Noul/Choice questions
  become `predicate`/`choice` questions, the state becomes the `input` text,
  answers are matched by name, refusals fail the batch, documented usage
  counters are retained, and the returned model is checked for provenance.
- Standard-library HTTPS transport with a fixed origin, strict framing,
  bounded bodies, socket timeouts, no redirects, no proxy and no retry.
  New fixed failure codes: `http_unauthorized`, `http_rate_limited`,
  `http_redirect`, `http_rejected`, `http_server_error`, `response_refused`.
- `OPENAI_API_KEY` is read from the environment once at construction;
  optional `OPENAI_ORG_ID` / `OPENAI_PROJECT_ID` routing headers. The CLI
  prints a hint when the key is missing.
- `ProviderResponse.error` lets an adapter report a documented whole-batch
  rejection while keeping learned usage; a rejected credential blocks
  further dispatch for the run.
- Offline fixtures built from the documented examples, including an
  end-to-end CLI run through a synthetic service; the distribution checker
  strips credentials from its environment and rejects private files.
- Packaging metadata, `.env.example` and documentation updated for the beta.

## 0.1.0a0 (2026-09-30)

Offline preparation snapshot derived from Jev Bug Hunter `0.5.0b2`: local
protocol, validated receipt gateway, explicit scope, engine regressions and
an intentionally unavailable adapter. Not published.
