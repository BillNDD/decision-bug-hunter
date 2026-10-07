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
