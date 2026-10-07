"""Local receipt-overhead benchmark (ADR-9, F23). No network, provider or key.

Runs the real ``ValidatedGateway`` over an instant in-process provider and
times the journal work of every attempt: the dispatching write (file fsync,
rename, and the directory fsync on POSIX) and the settlement write (file
fsync and rename only). Prints one JSON line with p50/p95 per attempt in
milliseconds. A p50 above 94 ms is the signal to move to a JSONL journal in
b2; below it the per-attempt JSON receipts stay.

Usage: python tools/bench_receipts.py [--count N] [--dir PATH]
"""
from __future__ import annotations

import argparse
from decimal import Decimal
import json
from pathlib import Path
import statistics
import sys
import tempfile
import time
from typing import Any

try:
    from decision_bug_hunter import providers
except ImportError:  # run from a source checkout without installing
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
    from decision_bug_hunter import providers
from decision_bug_hunter.protocol import QUESTION

#: p50 receipt overhead per attempt above which the JSONL journal goes to b2.
THRESHOLD_MS = 94.0
STATE = {"file": "bench.txt", "total_lines": 1,
         "excerpts": [{"start_line": 1, "end_line": 1,
                       "lines": [{"line": 1, "text": "bench line"}]}],
         "context_scope": "declared_standalone"}


class InstantProvider:
    """Answers every question at once; never opens a socket."""

    identity = providers.ProviderIdentity("bench-local", synthetic=True)

    def require_available(self) -> None:
        return None

    def check_sensitive(self, *values: Any) -> None:
        return None

    def decide(self, request: providers.ProviderRequest) -> providers.ProviderResponse:
        questions = json.loads(request.payload)["questions"]
        return providers.ProviderResponse(
            {name: {"type": "noul", "noul": Decimal("0.5")} for name in questions},
            {"input_tokens": 100, "output_tokens": 0}, cost_usd=Decimal("0.00001"))

    def close(self) -> None:
        return None


def bench(count: int, directory: Path) -> dict[str, Any]:
    """Journal milliseconds per attempt over ``count`` attempts."""
    spent: list[float] = []
    current = [0.0]
    write, sync = providers._write_receipt, providers._sync_directory

    def timed_write(path: Path, receipt: dict[str, Any]) -> None:
        started = time.perf_counter()
        try:
            write(path, receipt)
        finally:
            current[0] += time.perf_counter() - started

    def timed_sync(path: Path) -> None:
        started = time.perf_counter()
        try:
            sync(path)
        finally:
            current[0] += time.perf_counter() - started

    providers._write_receipt = timed_write  # type: ignore[assignment]
    providers._sync_directory = timed_sync  # type: ignore[assignment]
    try:
        gateway = providers.ValidatedGateway(InstantProvider(), directory / "receipts",
                                             retry_policy=providers.RetryPolicy.none())
        with gateway:
            for sequence in range(1, count + 1):
                current[0] = 0.0
                gateway.evaluate({**STATE, "total_lines": sequence}, {"q": QUESTION},
                                 metadata={"sequence": sequence, "phase": "bench"})
                spent.append(current[0] * 1000.0)
    finally:
        providers._write_receipt = write  # type: ignore[assignment]
        providers._sync_directory = sync  # type: ignore[assignment]
    ordered = sorted(spent)
    p50 = statistics.median(ordered)
    p95 = ordered[max(0, -(-95 * len(ordered) // 100) - 1)]
    return {"attempts": count, "p50_ms": round(p50, 3), "p95_ms": round(p95, 3),
            "max_ms": round(ordered[-1], 3), "threshold_ms": THRESHOLD_MS,
            "verdict": ("jsonl_journal_b2" if p50 > THRESHOLD_MS
                        else "keep_json_receipts")}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--count", type=int, default=200)
    parser.add_argument("--dir", type=Path, default=None,
                        help="Parent for the temporary receipt directory "
                             "(default: the system temporary directory).")
    args = parser.parse_args(argv)
    if not 1 <= args.count <= 100000:
        parser.error("--count must be between 1 and 100000")
    with tempfile.TemporaryDirectory(prefix="dbh-bench-", dir=args.dir) as temp:
        result = bench(args.count, Path(temp))
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
