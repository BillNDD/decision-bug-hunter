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

- `--judge openai --provider openai`: directly to OpenAI at `api.openai.com`.
- `--provider openrouter`: to OpenRouter at `openrouter.ai`, which forwards
  the request to the judge's host: OpenAI for `--judge openai`, Azure for
  `--judge microsoft` (Microsoft-Decision-1, experimental). By default each
  request tells OpenRouter not to use endpoints that collect data and not to
  fall back to other providers
  (`"provider":{"allow_fallbacks":false,"data_collection":"deny"}`).
  `--openrouter-routing account-default` drops that object, and then your
  OpenRouter account settings decide.
- `--judge microsoft --provider foundry`: directly to your own Microsoft
  Foundry resource, at the endpoint you give (`https://<resource>.services.ai.azure.com`
  or another accepted Azure resource domain). This route has not been
  verified live. The endpoint names your resource, so DBH never writes it to a
  report, receipt, message or progress line.

Each provider's own retention and logging terms apply. In project scope,
passages of related files are sent to the judge so it can say whether they
are relevant, so any file under `--project-root` that survives the indexer's
filters may be sent; point it at a directory that holds only what you are
willing to share.

## Credentials

The CLI reads `OPENAI_API_KEY` or `OPENROUTER_API_KEY` according to
`--judge` and `--provider` (or `DBH_JUDGE` and `DBH_PROVIDER`), and on the
Foundry route `AZURE_API_KEY` (sent as an `api-key` header) or
`AZURE_ENTRA_TOKEN` (sent as a bearer token). It never picks a judge or a
route because a key happens to be set, never takes a key as a flag and never
loads `.env` files. `DBH_FOUNDRY_ENDPOINT` and `DBH_FOUNDRY_DEPLOYMENT` are
not secrets, but the endpoint names your resource and is never journaled.

Every configured key of the four (`OPENAI_API_KEY`, `OPENROUTER_API_KEY`,
`AZURE_API_KEY`, `AZURE_ENTRA_TOKEN`), selected or not, is checked by its
exact value against the files, the specification, project files and the
output path before anything is sent, on every route, and against responses
and the final report. A set Azure key or token, even one that belongs to
another tool, is therefore refused wherever its unaltered text appears in
those inputs, whichever route is selected, and an OpenAI or OpenRouter key is
refused the same way on the Foundry route. Surrounding whitespace and one pair
of surrounding quotes are ignored when matching configured keys, so a key
pasted with a trailing newline is still caught; a key with a line break inside
is also matched line by line. No key is written to receipts, reports, errors or
request bodies.

The check matches the key's text as configured, nothing more. It does not
recognize a key written in your files in an escaped or encoded form (JSON
`\u` escapes, base64 or hex), a key split across strings or lines, or a
configured value wrapped in anything else (a byte-order mark, a zero-width
character, an unbalanced quote, a `Bearer ` prefix or backticks). Keep keys
out of the files you scan.

The credential-shaped text scan below recognizes an Entra token (it is a JWT)
but has no pattern for an Azure resource key, which has no reliable public
shape; the exact-value check above is its only cover. An Entra access token
is short-lived (typically about an hour). DBH never acquires or refreshes
one: a token that expires during a run is a 401 (`http_unauthorized`), the
run stops, and you must get a fresh token. Prefer a token over a long-lived
resource key when you can, and revoke a leaked key at once in the Azure
portal.

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
revoke and rotate it at the provider first (every key that was set),
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
