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

## Credentials

The CLI reads `OPENAI_API_KEY` (`tools/eval` only runs the CLI); the operator
smoke tools in `tools/smoke` read `OPENROUTER_API_KEY`. Neither key is ever
written to receipts, reports, errors or request bodies. If you believe a key
was exposed anyway, revoke it at the provider first, then check your shell
history and any run directories you shared. A key with a small credit limit
reduces the cost of an accidental leak.

## Scope notes

Decision Bug Hunter never executes the file it reviews, but it does send the
file's text, the optional specification and, in project scope, related files
to the selected provider. Keep run directories private: they contain file
names, hashes, line ranges and judgments that can describe weaknesses in
proprietary code. Prompt injection inside reviewed files is a known limitation
of any model-based reviewer; see the README.
