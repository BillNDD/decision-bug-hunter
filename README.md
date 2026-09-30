# Decision Bug Hunter

Decision Bug Hunter (DBH) prepares a bounded, first-pass source triage engine for
OpenAI's announced Decisions API. **The live adapter is unavailable.** Version
`0.1.0a0` is an offline preparation snapshot, not a working service integration.

The [September 29 announcement](https://openai.com/index/devday-2026-recap/)
describes Luna answering user-defined questions with finite predefined answers
and text or image context, initially in limited preview. As of September 30,
2026, no public endpoint, request/response schema, SDK method, probability
semantics, or account access has been verified for this project. No endpoint,
model identifier, credential configuration, or fallback has been guessed.

DBH derives from the MIT-licensed
[Jev Bug Hunter beta](https://github.com/BillNDD/jev-bug-hunter/tree/339f245f2169b9baf0ebbf406497c6a8422408db).
It keeps multiscale windows, bounded evidence search, independent rechecks,
explicit scope, deterministic request reuse, uncertainty, and compact handoffs.
It never executes target files. The original JBH remains a separate Jev tool.

## Install and check

Python 3.11 or later; no runtime dependencies. From this repository:

```sh
python -m venv .venv
# Activate .venv using your shell's normal command.
python -m pip install -e ".[dev]"
python -m unittest discover -s tests
python -m ruff check .
python -m mypy
python -m build
python tools/check_distribution.py dist
```

Tests are deterministic and offline. No key, paid run, or authentication grant is
required. The sample [.env.example](.env.example) contains no credentials and is
not loaded by DBH. Test fixtures are available only through the test suite.

```sh
decision-bug-hunter --help
decision-bug-hunter target.py --scope standalone
```

The second command exits `2` with `provider_unavailable`, before source reads,
project indexing, output creation, or networking. Scope is mandatory in both the
CLI and library: `project` requires an explicit related directory; `standalone`
declares a complete standalone input; `isolate` explicitly excludes external
context. Missing/conflicting scope exits `3`.

For offline embedding, `decision_bug_hunter.core.scan(source, gateway, config,
spec=None, project=None, context_scope="declared_standalone")` uses a caller-owned
gateway. See the [local provider contract](docs/PROVIDER_CONTRACT.md) and
[release gates](docs/RELEASE_GATES.md) before implementing a hosted adapter.

## Evidence and limits

Passing fixtures establishes local mechanics, not real Decisions compatibility,
model calibration, recall, precision, comparative cost, or speed. Returned
probabilities are operating heuristics; missing probability data is rejected,
not replaced by certainty. No suspected ranges is not a correctness certificate.

The upstream `0.5.0b2` development campaign detected **10/16 defective programs**
(11/17 individual defects), cleared 16/16 controls, and marked 2/2 missing-evidence
cases incomplete. Its full live outcome gate failed, with six known misses.
These are upstream Jev results from a synthetic development suite, not DBH or
held-out accuracy. See [upstream validation](https://github.com/BillNDD/jev-bug-hunter/blob/339f245f2169b9baf0ebbf406497c6a8422408db/docs/BETA2_VALIDATION.md).

Reports preserve incomplete coverage, contrary evidence, failed answers, and
known versus unknown usage. Receipts contain hashes, public provider identity,
validated judgments, and bookkeeping rather than request/response bodies.
Names, hashes, line ranges, and judgments can still be sensitive; keep run
directories private and review artifacts before sharing. Filesystem permission
hardening is POSIX-specific; Windows access controls remain the caller's concern.

MIT, including the retained upstream notice. See [LICENSE](LICENSE) and
[provenance](docs/PROVENANCE.md).
