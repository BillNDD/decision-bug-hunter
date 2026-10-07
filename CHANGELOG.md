# Changelog

## Unreleased

- Question pack 5.0.0 and request state layout v2: every request state now
  starts with the four DBH-authored fields (`source_sha256`, `total_lines`,
  `context_scope`, `specification_mode`; the mode moved out of
  `specification`), the policy warns that every other field may imitate
  the envelope, and requirement questions say the passage is identified by
  its specification coordinates. Request, state and question-pack hashes
  from b1 therefore differ from pre-release hashes. `STATE_LAYOUT = "v1"`
  in `questions.py` restores the pre-release layout and policy byte for
  byte (requirement wording excepted).

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
