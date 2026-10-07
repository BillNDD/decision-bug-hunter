# Security policy

## Reporting a vulnerability

Please report security problems privately through GitHub's
**Report a vulnerability** button on this repository's Security tab. Do not
open a public issue for anything that could expose credentials, source code or
users' systems. Include the version, the command or library call, and what you
observed. Reports are acknowledged as soon as practical; this is a volunteer
beta project without a response-time guarantee.

## Supported versions

Only the latest beta release receives fixes.

## Where your source goes

DBH never executes the file it reviews, but it sends the file's text, the
optional specification and, in project scope, related files to the route you
select:

- `--provider openai`: directly to OpenAI at `api.openai.com`.
- `--provider openrouter`: to OpenRouter at `openrouter.ai`, which forwards
  the request to OpenAI. By default each request tells OpenRouter not to use
  endpoints that collect data and not to fall back to other providers
  (`"provider":{"allow_fallbacks":false,"data_collection":"deny"}`).
  `--openrouter-routing account-default` drops that object, and then your
  OpenRouter account settings decide.

Both providers' own retention and logging terms apply. In project scope,
passages of related files are sent to the judge so it can say whether they
are relevant, so any file under `--project-root` that survives the indexer's
filters may be sent; point it at a directory that holds only what you are
willing to share.

## Credentials

The CLI reads `OPENAI_API_KEY` or `OPENROUTER_API_KEY` according to
`--provider` (or `DBH_PROVIDER`); it never picks a route because a key
happens to be set, never takes a key as a flag and never loads `.env` files.
Every configured key, selected or not, is checked against the files it would
send and against responses. No key is written to receipts, reports, errors
or request bodies.

Before sending, DBH also scans the file and specification for
credential-shaped text of common providers and stops with
`secret_detected`; project files with such text are always skipped. This
catches obvious accidents only.

`tools/eval` runs the CLI and reads no key itself. The repository-only smoke
tools read `OPENROUTER_API_KEY` (`tools/smoke/run_openrouter.py`) or
`OPENAI_API_KEY` plus the optional `OPENAI_ORG_ID` and `OPENAI_PROJECT_ID`
(`tools/smoke/run_openai.py`), from the environment or from one named
variable in `--env-file`.

Use a key with a small credit limit. If you believe a key was exposed,
revoke and rotate it at the provider first (both keys if both were set),
then check your shell history and any run directories you shared.

## Prompt injection

Text inside a reviewed file can address the judge. The file's author can
try to suppress findings on real bugs or to flood clean code with findings.
With `--canaries on` (the default) DBH adds two judge-control questions
with known answers to every request and withholds a request's answers when
a control fails, and it marks lines that look like instructions to the
judge. Both catch crude attempts only.
Do not use DBH to gate untrusted contributions, and do not treat a clean
report on untrusted code as evidence of anything. A request that OpenRouter
moderates fails with `provider_moderated`.

## Run directories and smoke results

Keep run directories private: they contain file names, hashes, line ranges,
judgments and provider generation or request ids that can describe
weaknesses in proprietary code. Smoke results under `smoke-results/` are
git-ignored; the runners keep only allow-listed headers and never record
`cf-ray`, whose value reveals the caller's region. Raw bodies kept with
`--keep-raw` may contain generation ids and must not leave the machine.
