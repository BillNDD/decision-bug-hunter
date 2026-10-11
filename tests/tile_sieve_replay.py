"""A replay judge for the Tile Sieve engine tests.

``ReplayProvider`` is a ``DecisionProvider`` for the real ``ValidatedGateway``. It
answers each request by the sha256 of the bytes it was sent, from the answers the
pilot recorded on the 34-case catalog (``tests/fixtures/tile_sieve/e4_catalog.json``),
records every hash it was sent in order, and fails on a hash it does not know. A
request the engine builds differently from the pilot's therefore cannot be answered,
and a request it builds identically gets the pilot's answers, judge controls
included. Nothing here opens a socket.

``run_case`` materializes a catalog case as ``tools/eval/run_catalog.py`` does and
scans it through ``core.scan`` with the real engine and gateway.
"""
from __future__ import annotations

from decimal import Decimal
import hashlib
import importlib
import json
from pathlib import Path
import sys
import tempfile
from typing import Any, Callable

from decision_bug_hunter.core import Config, Source, scan
from decision_bug_hunter.providers import (ProviderIdentity, ProviderResponse, RetryPolicy,
                                           ValidatedGateway)
from decision_bug_hunter.repository import ProjectIndex

ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "tests" / "fixtures" / "tile_sieve" / "e4_catalog.json"
EVAL = ROOT / "tools" / "eval"
SCOPES = {"standalone": "declared_standalone", "project": "project", "isolate": "owner_isolated"}


def tool(name: str) -> Any:
    """Import a module of ``tools/eval`` (the catalog and its runner)."""
    if str(EVAL) not in sys.path:
        sys.path.insert(0, str(EVAL))
    return importlib.import_module(name)


def load_fixture() -> dict:
    return json.loads(FIXTURE.read_text(encoding="utf-8"))


def requests_by_sha(fixture: dict) -> dict:
    """{sha256: (case id, 'tile' | 'focus', recorded request)} for every recorded request."""
    table = {}
    for case in fixture["cases"]:
        for kind, rows in (("tile", case["tiles"]), ("focus", case["focus"])):
            for row in rows:
                table[row["sha256"]] = (case["id"], kind, row)
    return table


def local_answer(plain: dict) -> dict:
    """A recorded plain answer (strings) in the provider's local form (Decimals)."""
    if plain["type"] == "noul":
        return {"type": "noul", "noul": Decimal(plain["noul"])}
    return {"type": "choice", "choice": plain["choice"], "confidence": Decimal(plain["confidence"]),
            "probabilities": {k: Decimal(v) for k, v in plain["probabilities"].items()}}


class ReplayProvider:
    """Answers by request sha256 from the pilot's recorded answers; fails on an unknown sha.

    *model_spec*, when given, is exposed as ``model_spec`` (the judge a gateway reports).
    *edit(sha256, answers, scoped)* may change the local answers of a request before they
    are handed over, or mark a question as refused (``scoped[qid] = "question_refused"``
    after removing it from *answers*)."""

    identity = ProviderIdentity("offline-tile-sieve-replay", synthetic=True)

    def __init__(self, table: dict | None = None, *, model_spec: Any = None,
                 edit: Callable[[str, dict, dict], None] | None = None) -> None:
        self.table = requests_by_sha(load_fixture()) if table is None else table
        self.edit = edit
        self.sent: list[str] = []
        self.unknown: list[str] = []
        if model_spec is not None:
            self.model_spec = model_spec

    def require_available(self) -> None:
        return None

    def check_sensitive(self, *values: Any) -> None:
        return None

    def decide(self, request: Any) -> ProviderResponse:
        sha = hashlib.sha256(request.payload).hexdigest()
        self.sent.append(sha)
        recorded = self.table.get(sha)
        if recorded is None:
            self.unknown.append(sha)
            raise AssertionError("replay: unknown request sha256 " + sha)
        answers = {qid: local_answer(plain) for qid, plain in recorded[2]["answers"].items()}
        scoped: dict = {}
        if self.edit is not None:
            self.edit(sha, answers, scoped)
        return ProviderResponse(answers, {"input_tokens": 10, "output_tokens": 0}, scoped=scoped)

    def close(self) -> None:
        return None


class CaseInputs:
    """A catalog case written out as the CLI would see it, and read back."""

    def __init__(self, case: dict, base: Path) -> None:
        run_catalog = tool("run_catalog")
        argv, out = run_catalog.materialize(case, base)
        subject = Path(argv[0])
        spec_path = Path(argv[argv.index("--spec-file") + 1])
        self.case = case
        self.source = Source.read(subject)
        self.spec = Source.read(spec_path, max_bytes=8192, max_lines=2000)
        self.scope = SCOPES[case["scope"]]
        self.project = (ProjectIndex.read(base / "scanned", primary_path=subject,
                                          exclude_paths=(out, spec_path))
                        if case["scope"] == "project" else None)


def catalog_inputs(root: Path) -> list[CaseInputs]:
    """Every catalog case, materialized under *root*."""
    inputs = []
    for case in tool("catalog").cases():
        base = root / case["id"]
        base.mkdir()
        inputs.append(CaseInputs(case, base))
    return inputs


def run_scan(inputs: CaseInputs, provider: Any, receipts: Path, *, config: Config | None = None,
             **gateway_options: Any) -> dict:
    """One scan with the real engine and a real gateway; the gateway is closed afterwards."""
    gateway_options.setdefault("retry_policy", RetryPolicy.none())
    gateway = ValidatedGateway(provider, receipts, **gateway_options)
    try:
        return scan(inputs.source, gateway,
                    config or Config(search_policy="tile-sieve-beta",
                                     max_calls=inputs.case["max_calls"]),
                    spec=inputs.spec, project=inputs.project, context_scope=inputs.scope)
    finally:
        gateway.close()


def run_case(inputs: CaseInputs, provider: Any, *, config: Config | None = None,
             **gateway_options: Any) -> dict:
    """``run_scan`` with receipts in a temporary directory."""
    with tempfile.TemporaryDirectory() as temp:
        return run_scan(inputs, provider, Path(temp) / "receipts", config=config,
                        **gateway_options)
