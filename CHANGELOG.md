# Changelog

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
