# Actual-API release gates

The prepared `0.1.0a0` snapshot is local and unpublished. The hosted provider
remains unavailable until all relevant gates below have evidence. Offline
fixtures, upstream Jev campaigns, and announcement language cannot satisfy
real-service gates.

1. Obtain public official endpoint/schema/SDK documentation and verify authorized
   account access. Record exact versions, authentication, model selection,
   response semantics, pricing, retention and data-use terms, regional access,
   byte/token/option/batch limits, completeness/truncation and error behavior.
2. Verify binary probabilities and Choice full vectors/confidence against the
   [local engine requirements](PROVIDER_CONTRACT.md). Resolve independence,
   ordering, precision, native batching and atomic validation. If unsupported,
   keep the adapter unavailable pending a reviewed change; never invent scores.
3. Implement only the adapter and documented normalization. Bound responses,
   enforce timeout/cancellation, reject redirects/unexpected endpoints, suppress
   sensitive exception bodies, and handle auth/rate/transport failures explicitly.
   Preserve possible submission, known/unknown usage and no automatic retry.
   Review receipts/crash recovery, model provenance and service idempotency.
4. Add captured, sanitized schema fixtures from actual documented responses.
   Verify installed-wheel behavior separately from these local fixtures.
5. Obtain explicit authorization for credential use and a bounded live budget.
   Verify monetary reservation/settlement, pricing and unknown-use handling
   before paid dispatch. No credentials, grants, paid calls or access request
   are included in this preparation.
6. Run authorized installed CLI compatibility checks, including auth/rate/timeouts,
   bad/partial/truncated answers, actual usage and source non-execution. Freeze
   an independent labeled holdout before effectiveness measurement; keep labels
   out of requests. Disclose misses, incomplete cases and valid-file false flags.
   Evaluate both search policies without claiming calibration or inherited recall.
7. Re-run offline regressions, configured lint/types, build and fresh-install
   checks on supported Python/Windows/Linux environments. Scan the final tree,
   reachable initial history and both distributions for secrets, private paths,
   personal data, transcripts, reports, datasets and unnecessary assets.
8. Confirm the intended GitHub repository name and actual creation/push permission.
   Review the final concrete tree and release claims, then obtain publication/
   release authorization. No remote, repository, package release or GitHub release
   has been created by this preparation.

Expected small integration delta if the API meets the contract: implement
`decision_bug_hunter/decisions.py`, add its justified runtime dependency and
credential configuration, and add official-schema fixtures. Changes to engine
thresholds, budgets or probability assumptions require independent review and
new evidence. Smallness is conditional on the actual contract.
