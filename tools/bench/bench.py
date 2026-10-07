"""Offline benchmark and byte-identity gate for Decision Bug Hunter.

The benchmark runs the real engine (``core.scan`` over a real
``ValidatedGateway``) and the real CLI (``__main__.main`` with its
``make_provider`` seam replaced) over the real ``OpenRouterProvider`` adapter.
Its exchange is an in-process fake whose answers come from a deterministic
synthetic judge, so nothing opens a socket: importing ``tests`` installs the
network guard, which this script requires. Providers are built with
``environ={}`` and a fixed synthetic key; credential variables are removed
from every child process and never read.

Per scenario (see ``scenarios.py``) it records:

* exact: provider calls, unique requests, questions, envelope and wire bytes,
  receipt writes and files, ask() rounds (as executed, the critical-path upper
  bound and per phase). Any change here is a behavior change.
* fingerprints: the report and receipts (timing and uuid fields removed) per
  case, and the ordered request envelopes. These prove byte identity.
* gated counters: cProfile calls of functions defined in the
  ``decision_bug_hunter`` package, copy.deepcopy, json.dumps and json.loads
  calls and sizes, sha256 calls and bytes, protocol._snapshot and _secret_in
  calls, and Path.mkdir calls made by the package.
* informational only: total cProfile calls, process_time and the tracemalloc
  peak. Timings are indicative and never gated.

    python tools/bench/bench.py                  # measure; writes --out
    python tools/bench/bench.py --check          # fingerprints against golden.json
    python tools/bench/bench.py --gate           # exact values and ceilings
    python tools/bench/bench.py --update-golden  # re-record; two hash seeds must agree
    python tools/bench/bench.py --markdown FILE  # table from golden.json or a result
    python tools/bench/bench.py --compare OLD NEW

Outputs go under ``tempfile.gettempdir()/dbh-bench`` unless ``--out`` names
another path; nothing is written into the repository except ``--update-golden``.
Every scenario runs in its own subprocess with ``PYTHONHASHSEED`` set.
"""
from __future__ import annotations

import argparse
import concurrent.futures
import contextlib
import copy
import cProfile
import datetime
import hashlib
import importlib
import io
import json
import os
from pathlib import Path
import pathlib
import platform
import pstats
import statistics
import subprocess
import sys
import tempfile
import time
import tracemalloc
from collections import Counter, defaultdict
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
ROOT = Path(__file__).resolve().parents[2]
GOLDEN = HERE / "golden.json"
SCRATCH = Path(tempfile.gettempdir()) / "dbh-bench"
PACKAGE_DIR = os.path.normcase(os.path.abspath(str(ROOT / "decision_bug_hunter"))) + os.sep
#: Captured before any counting patch, so the harness's own hashing is never counted.
_REAL_SHA256 = hashlib.sha256

# The code under test is the checkout this file lives in. Put it first on
# sys.path so an installed or editable copy elsewhere can never win.
sys.path[:0] = [str(ROOT), str(HERE)]

from scenarios import SCENARIOS, SCOPES, prepare  # noqa: E402

#: Modules imported by ``_import_code`` (filled once per process).
core = engine = protocol = providers = openrouter = exchange = cli = None
repository = claims = support = FixtureProvider = Source = Config = None


def _import_code() -> None:
    """Import the code under test and its offline support from this checkout."""
    import tests  # noqa: F401  (installs the process-wide network guard)
    from tests import network_guard
    if not network_guard.active():
        raise SystemExit("network guard not active; refusing to run")
    package = importlib.import_module("decision_bug_hunter")
    if Path(package.__file__).resolve().parent != ROOT / "decision_bug_hunter":
        raise SystemExit("decision_bug_hunter is not imported from this checkout")
    global core, engine, protocol, providers, openrouter, exchange, cli
    global repository, claims, support, FixtureProvider, Source, Config
    core = importlib.import_module("decision_bug_hunter.core")
    engine = importlib.import_module("decision_bug_hunter.engine")
    protocol = importlib.import_module("decision_bug_hunter.protocol")
    providers = importlib.import_module("decision_bug_hunter.providers")
    openrouter = importlib.import_module("decision_bug_hunter.openrouter")
    exchange = importlib.import_module("decision_bug_hunter.exchange")
    cli = importlib.import_module("decision_bug_hunter.__main__")
    repository = importlib.import_module("decision_bug_hunter.repository")
    claims = importlib.import_module("decision_bug_hunter.claims")
    support = importlib.import_module("tests.support")
    FixtureProvider = support.FixtureProvider
    Source, Config = core.Source, core.Config


# ---------------------------------------------------------------------------
# Synthetic judge and offline transport
# ---------------------------------------------------------------------------

def make_judge(bugs):
    """FixtureProvider rules plus answers that keep both policies' action loops clean.

    FixtureProvider always chooses ``finish`` but says 0.95 to ``continue``,
    which scoped-v2-beta flags as a disagreement. This judge answers
    ``continue`` 0.05, consistent with ``finish``.
    """
    roles = claims.ROLES

    class Judge(FixtureProvider):
        def answer(self, qid, q, state):
            if qid == "continue":
                return {"type": "noul", "noul": 0.05}
            if qid in roles:
                spans = support.spans_in(q["instructions"])
                hot = bool(spans) and self.contains_bug(spans[0])
                value = {roles[0]: 0.95 if hot else 0.05,
                         roles[1]: 0.05, roles[2]: 0.05}[qid]
                return {"type": "noul", "noul": value}
            return super().answer(qid, q, state)

    return Judge(bugs=bugs)


#: True while the fake transport and judge run (their JSON and hashing are not DBH work).
IN_FAKE = [False]


class JudgeClock:
    """CPU seconds spent inside the fake judge and transport (not DBH work)."""

    def __init__(self):
        self.cpu = 0.0


class FakeExchange:
    """In-process stand-in for ``exchange.HttpsExchange``: no sockets.

    Decodes the OpenRouter wire body, answers with the synthetic judge and
    returns an OpenRouter-shaped 200 ``Outcome``.
    """

    def __init__(self, judge, clock: JudgeClock, recorder):
        self.judge, self.clock, self.recorder = judge, clock, recorder
        self.posts = 0

    def deadline(self, seconds):
        return seconds

    def post(self, body, headers, deadline, *, read_errors=False, credentials=()):
        started = time.process_time()
        IN_FAKE[0] = True
        try:
            return self._post(body, started)
        finally:
            IN_FAKE[0] = False

    def _post(self, body, started):
        data = json.loads(body)
        state, questions = data["state"], data["questions"]
        answers = {qid: self.judge.answer(qid, q, state) for qid, q in questions.items()}
        raw = support.openrouter_body(answers, input_tokens=max(1, len(body) // 4))
        self.posts += 1
        outcome = exchange.Outcome(
            status=200, headers=(("content-type", "application/json"),
                                 ("x-generation-id", f"gen-offline{self.posts:08d}")),
            body=raw, error_raw=None, error_body_state="unread", reused=self.posts > 1,
            elapsed=0.0, bytes_sent=len(body), response_bytes=len(raw))
        if self.recorder is not None:
            self.recorder.wire(len(body), len(raw), len(questions))
        self.clock.cpu += time.process_time() - started
        return outcome

    def close(self):
        pass


KEY = "offline-synthetic-key-not-a-real-credential"


def offline_provider(judge, clock, recorder, policy_placement="instructions"):
    """The real OpenRouter adapter over the fake exchange (never env, never net)."""
    ex = FakeExchange(judge, clock, recorder)
    provider = openrouter.OpenRouterProvider(KEY, environ={}, exchange=ex,
                                             policy_placement=policy_placement)
    if recorder is not None:
        recorder.attach(provider)
    return provider


class Recorder:
    """Counts provider calls (local envelopes) and engine ask() rounds."""

    def __init__(self):
        self.calls = []          # one row per provider decide()
        self.asks = []           # one row per Search.ask() that was entered
        self.envelope_hash = _REAL_SHA256()
        self.current = None
        self.case = None

    def attach(self, provider):
        original = provider.decide
        recorder = self

        def decide(request):
            recorder.request(request.payload)
            return original(request)

        provider.decide = decide

    def request(self, payload):
        self.envelope_hash.update(len(payload).to_bytes(8, "big"))
        self.envelope_hash.update(payload)
        key = _REAL_SHA256(payload).hexdigest()
        ask = self.current
        self.calls.append({"case": self.case, "seq": len(self.calls) + 1,
                           "phase": ask["phase"] if ask else None,
                           "ask": ask["index"] if ask else None,
                           "envelope_bytes": len(payload), "request_sha256": key,
                           "wire_bytes": None, "response_bytes": None, "questions": None})

    def wire(self, body_len, response_len, questions):
        if self.calls:
            self.calls[-1].update(wire_bytes=body_len, response_bytes=response_len,
                                  questions=questions)


@contextlib.contextmanager
def ask_tracking(recorder):
    """Wrap Search.ask for the counting run only."""
    original = engine.Search.ask

    def ask(self, state, questions, region, phase, *, origins=None):
        row = {"case": recorder.case, "index": len(recorder.asks), "phase": phase,
               "questions_offered": len(questions) if questions else 0,
               "calls": 0, "questions_sent": 0}
        before_calls, before_q = self.calls, self.questions
        recorder.asks.append(row)
        outer, recorder.current = recorder.current, row
        try:
            return original(self, state, questions, region, phase, origins=origins)
        finally:
            row["calls"] = self.calls - before_calls
            row["questions_sent"] = self.questions - before_q
            recorder.current = outer

    engine.Search.ask = ask
    try:
        yield
    finally:
        engine.Search.ask = original


# ---------------------------------------------------------------------------
# Counting instrumentation (counting run only; never the timed or profiled runs)
# ---------------------------------------------------------------------------

def _in_package(filename: str) -> bool:
    return os.path.normcase(os.path.abspath(filename)).startswith(PACKAGE_DIR)


def _rebind_everywhere(stack, owner, name, wrapper):
    """Patch ``name`` on ``owner`` and on every package module that bound the same object.

    ``from copy import deepcopy`` and ``from .protocol import _secret_in`` copy
    the name, so patching the owner alone would miss those call sites.
    """
    original = getattr(owner, name)
    stack.enter_context(patch.object(owner, name, wrapper))
    for module in list(sys.modules.values()):
        modname = getattr(module, "__name__", "") or ""
        if (module is not owner and modname.startswith("decision_bug_hunter")
                and getattr(module, name, None) is original):
            stack.enter_context(patch.object(module, name, wrapper))


@contextlib.contextmanager
def counting(c: Counter):
    real_dumps, real_loads, real_sha = json.dumps, json.loads, hashlib.sha256
    real_deepcopy = copy.deepcopy
    real_snapshot, real_secret_in = protocol._snapshot, protocol._secret_in
    real_mkdir = pathlib.Path.mkdir
    real_write_receipt = providers._write_receipt

    def dumps(obj, *args, **kwargs):
        out = real_dumps(obj, *args, **kwargs)
        if not IN_FAKE[0]:
            c["json_dumps_calls"] += 1
            c["json_dumps_chars"] += len(out)
        return out

    def loads(s, *args, **kwargs):
        if not IN_FAKE[0]:
            c["json_loads_calls"] += 1
            c["json_loads_bytes"] += len(s)
        return real_loads(s, *args, **kwargs)

    def sha256(data=b"", **kwargs):
        if not IN_FAKE[0]:
            c["sha256_calls"] += 1
            c["sha256_bytes"] += len(data)
        return real_sha(data, **kwargs)

    def deep(*args, **kwargs):
        c["copy_deepcopy_calls"] += 1
        return real_deepcopy(*args, **kwargs)

    def snapshot(*args, **kwargs):
        c["protocol_snapshot_calls"] += 1
        return real_snapshot(*args, **kwargs)

    def secret_in(*args, **kwargs):
        c["protocol_secret_in_calls"] += 1
        return real_secret_in(*args, **kwargs)

    def mkdir(self, *args, **kwargs):
        # Only calls made by the package; pathlib's own recursion is excluded.
        if _in_package(sys._getframe(1).f_code.co_filename):
            c["path_mkdir_calls"] += 1
        return real_mkdir(self, *args, **kwargs)

    def write_receipt(path, receipt):
        c["receipt_writes"] += 1
        return real_write_receipt(path, receipt)

    with contextlib.ExitStack() as stack:
        stack.enter_context(patch.object(json, "dumps", dumps))
        stack.enter_context(patch.object(json, "loads", loads))
        stack.enter_context(patch.object(hashlib, "sha256", sha256))
        stack.enter_context(patch.object(pathlib.Path, "mkdir", mkdir))
        stack.enter_context(patch.object(providers, "_write_receipt", write_receipt))
        _rebind_everywhere(stack, copy, "deepcopy", deep)
        _rebind_everywhere(stack, protocol, "_snapshot", snapshot)
        _rebind_everywhere(stack, protocol, "_secret_in", secret_in)
        yield


def package_calls(stats: pstats.Stats):
    """(ncalls, primitive calls) of every function whose file is in the package."""
    calls = primitive = 0
    for (filename, _line, _name), row in stats.stats.items():
        if _in_package(filename):
            primitive += row[0]
            calls += row[1]
    return calls, primitive


class MemoryReceipts:
    """In-memory stand-in for the durable receipt write.

    It keeps the exact receipt bytes and skips only the temp-file, fsync and
    rename syscalls, which took 0.5-1.9 s each on the slow disk this was
    measured on. A seam with ``providers._durable_write`` is patched there, so
    receipt serialization stays measured; otherwise ``_write_receipt`` is.
    """

    def __init__(self):
        self.files = {}

    @contextlib.contextmanager
    def active(self):
        files = self.files
        if hasattr(providers, "_durable_write"):
            def durable_write(path, data):
                files[str(Path(path))] = bytes(data)

            with patch.object(providers, "_durable_write", durable_write):
                yield
            return

        json_bytes, plain = protocol._json, protocol.plain

        def write_receipt(path, receipt):
            files[str(Path(path))] = json_bytes(plain(receipt))

        with patch.object(providers, "_write_receipt", write_receipt):
            yield

    def under(self, directory: Path):
        prefix = str(Path(directory))
        return {Path(k).name: v for k, v in self.files.items()
                if str(Path(k).parent) == prefix}


# ---------------------------------------------------------------------------
# Fingerprints (byte-identity guard)
# ---------------------------------------------------------------------------

#: Receipt fields that legitimately vary run to run (clock, uuid).
RECEIPT_VOLATILE = ("elapsed_seconds", "timeout_seconds", "deadline_seconds", "late",
                    "logical_id")
#: Codes that only appear when wall-clock deadlines bite. A run that shows one
#: measured different work, so it cannot be compared.
TIMING_CODES = frozenset({"deadline_exceeded", "run_deadline_exceeded",
                          "run_deadline_reserved"})
#: Report fields that vary run to run.
REPORT_VOLATILE = ("run_id", "started_at_utc", "finished_at_utc")


def receipts_fingerprint(directory: Path, memory: "MemoryReceipts | None" = None):
    rows = []
    total_bytes = 0
    if memory is not None:
        blobs = [v for _k, v in sorted(memory.under(directory).items())]
        leftovers = []
    else:
        files = sorted(directory.glob("*.json")) if directory.is_dir() else []
        blobs = [p.read_bytes() for p in files]
        leftovers = ([p.name for p in directory.iterdir() if p.suffix != ".json"]
                     if directory.is_dir() else [])
    timing = 0
    for raw in blobs:
        total_bytes += len(raw)
        data = json.loads(raw)
        if data.get("late") or data.get("error") in TIMING_CODES:
            timing += 1
        for key in RECEIPT_VOLATILE:
            data.pop(key, None)
        rows.append(json.dumps(data, sort_keys=True, ensure_ascii=True))
    rows.sort()
    digest = hashlib.sha256("\n".join(rows).encode()).hexdigest()
    return {"receipt_files": len(blobs), "receipt_bytes": total_bytes,
            "receipts_sha256": digest, "stray_files": len(leftovers),
            "timing_receipts": timing}


def report_fingerprint(report: dict):
    data = {k: v for k, v in report.items() if k not in REPORT_VOLATILE}
    text = json.dumps(data, ensure_ascii=True, indent=2, allow_nan=False)
    return hashlib.sha256(text.encode()).hexdigest(), len(text)


def combine(hashes):
    return hashlib.sha256("\n".join(hashes).encode()).hexdigest()


# ---------------------------------------------------------------------------
# One scenario run
# ---------------------------------------------------------------------------

def run_engine_job(job, scenario_config, out: Path, recorder, clock):
    """Timed pipeline for one engine job: read inputs, index, scan, close."""
    config = Config(**{**job["config"], **scenario_config})
    source = Source.read(job["file"])
    spec = Source.read(job["spec"], max_bytes=8192, max_lines=2000)
    project = None
    if job["project_root"] is not None:
        project = repository.ProjectIndex.read(job["project_root"], primary_path=job["file"])
    judge = make_judge(job["bugs"])
    provider = offline_provider(judge, clock, recorder, config.policy_placement)
    receipts = out / "receipts"
    gateway = providers.ValidatedGateway(provider, receipts, rounding_places=None,
                                         retry_policy=providers.RetryPolicy())
    try:
        result = core.scan(source, gateway, config=config, spec=spec, project=project,
                           context_scope=SCOPES[job["scope"]],
                           secret_scan={"target": "clean", "project_files_skipped": 0})
    finally:
        gateway.close()
    return result, receipts


def run_cli_job(job, scenario_config, out: Path, recorder, clock):
    argv = [str(job["file"]), "--scope", job["scope"], "--spec-file", str(job["spec"]),
            "--output-dir", str(out / "results"), "--output-format", "json",
            "--provider", "openrouter"]
    for key, value in scenario_config.items():
        argv += ["--" + key.replace("_", "-"), str(value)]
    judge = make_judge(job["bugs"])

    def make(args):
        return offline_provider(judge, clock, recorder,
                                getattr(args, "policy_placement", "instructions"))

    stdout, stderr = io.StringIO(), io.StringIO()
    with patch.object(cli, "make_provider", side_effect=make), \
            contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
        code = cli.main(argv)
    runs = sorted((out / "results").glob("run-*"))
    if len(runs) != 1:
        raise RuntimeError(f"cli produced {len(runs)} run dirs; exit {code}; "
                           f"stderr tail: {stderr.getvalue()[-400:]}")
    run_dir = runs[0]
    report = json.loads((run_dir / "report.json").read_text(encoding="utf-8"))
    extra = {name: hashlib.sha256((run_dir / name).read_bytes()).hexdigest()
             for name in ("findings.txt", "handoff.json", "ranges.txt")}
    extra["stdout"] = hashlib.sha256(stdout.getvalue().encode()).hexdigest()
    extra["exit_code"] = code
    report["_cli_outputs"] = extra
    return report, run_dir / "receipts"


def execute(name, jobs, base: Path, *, receipts, recorder=None, counters=None, profiler=None):
    """One run of a scenario. ``receipts`` is "disk" (the shipped write) or "memory"."""
    spec = SCENARIOS[name]
    runner = run_engine_job if spec["kind"] == "engine" else run_cli_job
    clock = JudgeClock()
    run_dir = Path(tempfile.mkdtemp(prefix="run-", dir=base))
    cpu = 0.0
    fingerprints, per_case = [], []
    for job in jobs:
        out = run_dir / job["id"]
        out.mkdir()
        if recorder is not None:
            recorder.case = job["id"]
        store = MemoryReceipts() if receipts == "memory" else None
        with contextlib.ExitStack() as stack:
            if store is not None:   # before counting, so counting wraps the shim
                stack.enter_context(store.active())
            if counters is not None:
                stack.enter_context(counting(counters))
            if profiler is not None:
                profiler.enable()
            started = time.process_time()
            result, receipt_dir = runner(job, spec["config"], out, recorder, clock)
            cpu += time.process_time() - started
            if profiler is not None:
                profiler.disable()
        report_hash, report_chars = report_fingerprint(result)
        receipt_info = receipts_fingerprint(receipt_dir, store)
        issues = result.get("issues", [])
        per_case.append({"id": job["id"], "status": result.get("status"),
                         "findings": [[f["start_line"], f["end_line"]]
                                      for f in result.get("findings", [])],
                         "calls_attempted": result.get("calls_attempted"),
                         "questions_attempted": result.get("questions_attempted"),
                         "report_sha256": report_hash, "report_chars": report_chars,
                         "timing_issues": sum(1 for i in issues if i.get("code") in TIMING_CODES),
                         **receipt_info})
        fingerprints.append(report_hash + ":" + receipt_info["receipts_sha256"])
    timing = sum(c["timing_issues"] + c["timing_receipts"] for c in per_case)
    return {"cpu": cpu, "judge_cpu": clock.cpu, "fingerprint": combine(fingerprints),
            "cases": per_case, "timing_affected": timing}


SCREEN_PHASES = frozenset({"whole", "screen"})


def critical_path(recorder):
    """Dependency rounds of provider calls.

    Facts used: (1) all batches of one Search.ask() are packed from one state
    and question set before any is sent, so they never depend on each other's
    answers; (2) the screening phases ("whole", "screen") build every request
    from file geometry only, so all screening calls of a scan are mutually
    independent. Later phases read answers, but which answer each later ask()
    reads is not tracked, so every later ask() with a dispatch counts as its
    own dependent round. The result is an UPPER bound on the critical path.
    """
    by_case = defaultdict(list)
    for row in recorder.asks:
        by_case[row["case"]].append(row)
    out = {"critical_path_upper": 0, "phase_rounds": Counter(), "phase_calls": Counter()}
    for rows in by_case.values():
        screen_calls = sum(r["calls"] for r in rows if r["phase"] in SCREEN_PHASES)
        later = [r for r in rows if r["phase"] not in SCREEN_PHASES and r["calls"]]
        out["critical_path_upper"] += (1 if screen_calls else 0) + len(later)
        for r in rows:
            if r["calls"]:
                out["phase_rounds"][r["phase"]] += 1
                out["phase_calls"][r["phase"]] += r["calls"]
    out["phase_rounds"] = dict(sorted(out["phase_rounds"].items()))
    out["phase_calls"] = dict(sorted(out["phase_calls"].items()))
    return out


def call_stats(recorder):
    calls = recorder.calls
    qs = [c["questions"] for c in calls if c["questions"] is not None]
    return {"provider_calls": len(calls),
            "unique_requests": len(set(c["request_sha256"] for c in calls)),
            "questions_total": sum(qs),
            "envelope_bytes_total": sum(c["envelope_bytes"] for c in calls),
            "wire_bytes_total": sum(c["wire_bytes"] for c in calls if c["wire_bytes"] is not None),
            "response_bytes_total": sum(c["response_bytes"] for c in calls
                                        if c["response_bytes"] is not None)}


def _stats(values):
    if not values:
        return None
    return {"median": statistics.median(values), "min": min(values), "max": max(values),
            "runs": values}


def measure(name, *, count_receipts, reps, profile, tracemalloc_run):
    """Every run of one scenario, reduced to one record (see the module docstring)."""
    _import_code()
    SCRATCH.mkdir(parents=True, exist_ok=True)
    spec = SCENARIOS[name]
    with tempfile.TemporaryDirectory(prefix=f"{name}-", dir=SCRATCH,
                                     ignore_cleanup_errors=True) as temp:
        base = Path(temp)
        (base / "inputs").mkdir()
        jobs = prepare(name, base / "inputs")

        # 1. Counting run: exact values, fingerprints, counters.
        recorder, counters = Recorder(), Counter()
        with ask_tracking(recorder):
            counted = execute(name, jobs, base, receipts=count_receipts,
                              recorder=recorder, counters=counters)
        runs = {"count": counted["fingerprint"]}
        timing = counted["timing_affected"]
        calls = call_stats(recorder)
        path = critical_path(recorder)

        # 2. Timed runs (process_time only; memory receipts).
        cpu, dbh_cpu = [], []
        for i in range(reps):
            timed = execute(name, jobs, base, receipts="memory")
            cpu.append(timed["cpu"])
            dbh_cpu.append(timed["cpu"] - timed["judge_cpu"])
            runs[f"timed{i + 1}"] = timed["fingerprint"]
            timing += timed["timing_affected"]

        # 3. cProfile run (memory receipts).
        dbh_ncalls = dbh_primitive = total_ncalls = total_primitive = None
        if profile:
            profiler = cProfile.Profile()
            prof = execute(name, jobs, base, receipts="memory", profiler=profiler)
            runs["profile"] = prof["fingerprint"]
            timing += prof["timing_affected"]
            stats = pstats.Stats(profiler)
            dbh_ncalls, dbh_primitive = package_calls(stats)
            total_ncalls, total_primitive = stats.total_calls, stats.prim_calls

        # 4. tracemalloc run (memory receipts).
        peak = None
        if tracemalloc_run:
            tracemalloc.start()
            try:
                mem = execute(name, jobs, base, receipts="memory")
                peak = tracemalloc.get_traced_memory()[1]
            finally:
                tracemalloc.stop()
            runs["tracemalloc"] = mem["fingerprint"]
            timing += mem["timing_affected"]

    rounds = sum(path["phase_rounds"].values())
    return {
        "scenario": name, "doc": spec["doc"], "config": spec["config"], "jobs": len(jobs),
        "fingerprint": counted["fingerprint"],
        "request_envelopes_sha256": recorder.envelope_hash.hexdigest(),
        "cases": [{k: c[k] for k in ("id", "report_sha256", "receipts_sha256", "receipt_files")}
                  for c in counted["cases"]],
        "exact": {**calls,
                  "receipt_writes": counters.get("receipt_writes", 0),
                  "receipt_files": sum(c["receipt_files"] for c in counted["cases"]),
                  "rounds_as_executed": rounds,
                  "critical_path_upper": path["critical_path_upper"],
                  "rounds_by_phase": path["phase_rounds"]},
        "counters": {"dbh_ncalls": dbh_ncalls, "dbh_primitive_calls": dbh_primitive,
                     "copy_deepcopy_calls": counters.get("copy_deepcopy_calls", 0),
                     "json_dumps_calls": counters.get("json_dumps_calls", 0),
                     "json_dumps_chars": counters.get("json_dumps_chars", 0),
                     "json_loads_calls": counters.get("json_loads_calls", 0),
                     "json_loads_bytes": counters.get("json_loads_bytes", 0),
                     "sha256_calls": counters.get("sha256_calls", 0),
                     "sha256_bytes": counters.get("sha256_bytes", 0),
                     "protocol_snapshot_calls": counters.get("protocol_snapshot_calls", 0),
                     "protocol_secret_in_calls": counters.get("protocol_secret_in_calls", 0),
                     "path_mkdir_calls": counters.get("path_mkdir_calls", 0)},
        "deterministic": len(set(runs.values())) == 1,
        "timing_affected": timing,
        "info": {"process_time_s": _stats(cpu), "dbh_process_time_s": _stats(dbh_cpu),
                 "total_ncalls": total_ncalls, "total_primitive_calls": total_primitive,
                 "tracemalloc_peak_bytes": peak,
                 "receipt_bytes": sum(c["receipt_bytes"] for c in counted["cases"]),
                 "hash_seed": os.environ.get("PYTHONHASHSEED")},
    }


# ---------------------------------------------------------------------------
# Gate: comparison rules
# ---------------------------------------------------------------------------

#: Gated counters and the growth each may show before the gate fails.
GATED = {"dbh_ncalls": 0.02, "dbh_primitive_calls": 0.02, "copy_deepcopy_calls": 0.02,
         "json_dumps_calls": 0.02, "json_dumps_chars": 0.01, "json_loads_calls": 0.02,
         "json_loads_bytes": 0.01, "sha256_calls": 0.02, "sha256_bytes": 0.01,
         "protocol_snapshot_calls": 0.02, "protocol_secret_in_calls": 0.02,
         "path_mkdir_calls": 0.02}
#: A gated counter that falls by more than this prints a re-record notice.
RATCHET = 0.02
#: Fields a golden entry keeps (documentation and timings are not recorded).
GOLDEN_FIELDS = ("config", "jobs", "fingerprint", "request_envelopes_sha256", "cases",
                 "exact", "counters")


def _pct(want, got):
    if not want:
        return "from zero"
    return f"{(got - want) / want:+.1%}"


def identity_failures(golden, observed):
    """Byte-identity failures: fingerprints, envelopes, per-case hashes, timing guard."""
    if golden is None:
        return ["no golden entry; run --update-golden"]
    failures = []
    if observed["timing_affected"]:
        failures.append("timing-affected: wall-clock deadlines changed the work")
    if not observed["deterministic"]:
        failures.append("runs disagree: fingerprints differ between runs of one process")
    for key in ("fingerprint", "request_envelopes_sha256"):
        if observed[key] != golden[key]:
            failures.append(f"{key} differs")
    if observed["cases"] != golden["cases"]:
        failures.append("per-case fingerprints differ")
    return failures


def gate_compare(golden, observed):
    """(failures, notices) for one scenario: identity, exact values, gated counters."""
    failures = identity_failures(golden, observed)
    if golden is None:
        return failures, []
    notices = []
    for key in sorted(set(golden["exact"]) | set(observed["exact"])):
        want, got = golden["exact"].get(key), observed["exact"].get(key)
        if want != got:
            failures.append(f"exact {key}: {want} -> {got}")
    for key, allowed in GATED.items():
        want, got = golden["counters"].get(key), observed["counters"].get(key)
        if want is None or got is None:
            failures.append(f"counter {key} missing")
        elif got > want * (1 + allowed):
            failures.append(f"{key}: {want} -> {got} ({_pct(want, got)}; "
                            f"ceiling +{allowed:.0%})")
        elif got < want * (1 - RATCHET):
            notices.append(f"{key}: {want} -> {got} ({_pct(want, got)}); "
                           "re-record with --update-golden")
    return failures, notices


def record_differences(first, second):
    """(hard, noted): fields in which two runs of one scenario disagree.

    Everything must agree exactly, except the byte and character counters
    (the 1% group in GATED). Receipts and reports carry wall-clock floats
    (``elapsed_seconds``), so those counters move by a few characters from run
    to run, even with one hash seed. Only that group may move, and only within
    its gate tolerance; each such move is returned as ``noted``.
    """
    hard = [key for key in ("fingerprint", "request_envelopes_sha256", "cases", "deterministic")
            if first[key] != second[key]]
    hard += [f"exact.{k}" for k in sorted(set(first["exact"]) | set(second["exact"]))
             if first["exact"].get(k) != second["exact"].get(k)]
    noted = []
    for key in sorted(set(first["counters"]) | set(second["counters"])):
        a, b = first["counters"].get(key), second["counters"].get(key)
        if a == b:
            continue
        if GATED.get(key) == 0.01 and a is not None and b is not None and abs(a - b) <= 0.01 * a:
            noted.append(f"counters.{key}: {a} vs {b} (wall-clock digits; within +1%)")
        else:
            hard.append(f"counters.{key}")
    return hard, noted


# ---------------------------------------------------------------------------
# Child processes and the golden file
# ---------------------------------------------------------------------------

class ChildFailed(RuntimeError):
    pass


def child_env(seed: int):
    """The parent environment minus provider credentials and DBH/Python path toggles.

    Only variable names are inspected here; no credential value is read.
    """
    env = {}
    for key, value in os.environ.items():
        upper = key.upper()
        if (upper.endswith("_API_KEY") or upper.startswith(("OPENAI_", "OPENROUTER_", "DBH_"))
                or upper in ("PYTHONPATH", "PYTHONSAFEPATH", "PYTHONSTARTUP")):
            continue
        env[key] = value
    env["PYTHONHASHSEED"] = str(seed)
    return env


def run_child(name, *, seed, count_receipts, reps, profile, tracemalloc_run):
    """Measure one scenario in a fresh interpreter with the given hash seed."""
    SCRATCH.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="record-", dir=SCRATCH,
                                     ignore_cleanup_errors=True) as temp:
        record_path = Path(temp) / "record.json"
        cmd = [sys.executable, str(HERE / "bench.py"), "--worker", str(record_path),
               "--scenario", name, "--count-receipts", count_receipts, "--reps", str(reps)]
        if not profile:
            cmd.append("--no-profile")
        if not tracemalloc_run:
            cmd.append("--no-tracemalloc")
        proc = subprocess.run(cmd, cwd=str(SCRATCH), env=child_env(seed), capture_output=True,
                              encoding="utf-8", errors="replace", timeout=7200)
        if proc.returncode != 0:
            raise ChildFailed(f"{name} (hash seed {seed}) exited {proc.returncode}: "
                              f"{proc.stderr[-1500:]}")
        return json.loads(record_path.read_text(encoding="utf-8"))


def run_children(names, *, parallel, seed, **options):
    with concurrent.futures.ThreadPoolExecutor(max_workers=max(1, parallel)) as pool:
        futures = {name: pool.submit(run_child, name, seed=seed, **options) for name in names}
        return {name: futures[name].result() for name in names}


def load_golden():
    if not GOLDEN.exists():
        return {}
    return json.loads(GOLDEN.read_text(encoding="utf-8"))["scenarios"]


def write_golden(entries):
    ordered = {name: entries[name] for name in SCENARIOS if name in entries}
    data = {"meta": {"recorded_with_python": platform.python_version(),
                     "hash_seeds": [0, 1], "receipts": "memory"},
            "scenarios": ordered}
    GOLDEN.write_bytes((json.dumps(data, indent=2, sort_keys=True) + "\n").encode("utf-8"))


def _scenarios_of(path):
    return json.loads(Path(path).read_text(encoding="utf-8"))["scenarios"]


# ---------------------------------------------------------------------------
# Markdown and comparison output
# ---------------------------------------------------------------------------

def markdown(scenarios):
    lines = ["| Scenario | Jobs | Provider calls | Questions | Envelope bytes | Rounds "
             "(executed) | Critical path (upper) | DBH-own ncalls | JSON dumps chars | "
             "sha256 bytes | Receipt writes |",
             "|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|"]
    for name in SCENARIOS:
        rec = scenarios.get(name)
        if rec is None:
            continue
        e, c = rec["exact"], rec["counters"]
        lines.append(
            f"| {name} | {rec['jobs']} | {e['provider_calls']:,} | {e['questions_total']:,} | "
            f"{e['envelope_bytes_total']:,} | {e['rounds_as_executed']} | "
            f"{e['critical_path_upper']} | {c['dbh_ncalls']:,} | {c['json_dumps_chars']:,} | "
            f"{c['sha256_bytes']:,} | {e['receipt_writes']} |")
    return "\n".join(lines) + "\n"


def compare(old_path, new_path):
    old, new = _scenarios_of(old_path), _scenarios_of(new_path)
    for name in SCENARIOS:
        if name not in old or name not in new:
            continue
        o, n = old[name], new[name]
        same = (o["fingerprint"] == n["fingerprint"]
                and o["request_envelopes_sha256"] == n["request_envelopes_sha256"])
        print(f"{name}: fingerprints {'identical' if same else 'DIFFER'}")
        for group in ("exact", "counters"):
            for key, after in n[group].items():
                before = o[group].get(key)
                if isinstance(before, (int, float)) and isinstance(after, (int, float)):
                    change = _pct(before, after) if before != after else "same"
                    print(f"  {key:<28}{before!s:>16} -> {after!s:<16} {change}")


def _git_head():
    try:
        out = subprocess.run(["git", "-C", str(ROOT), "rev-parse", "--short", "HEAD"],
                             capture_output=True, text=True, timeout=30)
        return out.stdout.strip() or None
    except (OSError, subprocess.SubprocessError):
        return None


# ---------------------------------------------------------------------------
# Modes
# ---------------------------------------------------------------------------

def do_check(names, args):
    golden = load_golden()
    records = run_children(names, parallel=args.parallel, seed=0,
                           count_receipts=args.count_receipts, reps=0, profile=False,
                           tracemalloc_run=False)
    problems = 0
    for name in names:
        failures = identity_failures(golden.get(name), records[name])
        problems += len(failures)
        for failure in failures:
            print(f"DIFF {name}: {failure}")
        if not failures:
            print(f"{name}: byte-identical")
    print("byte-identical" if not problems else f"{problems} difference(s)")
    return 1 if problems else 0


def do_gate(names, args):
    golden = load_golden()
    records = run_children(names, parallel=args.parallel, seed=0,
                           count_receipts=args.count_receipts, reps=0, profile=True,
                           tracemalloc_run=False)
    problems = 0
    for name in names:
        failures, notices = gate_compare(golden.get(name), records[name])
        problems += len(failures)
        print(f"{name}: {'ok' if not failures else 'FAIL'}")
        for line in failures:
            print(f"  FAIL {line}")
        for line in notices:
            print(f"  NOTICE {line}")
    print("gate passed" if not problems else f"gate failed: {problems} problem(s)")
    return 1 if problems else 0


def do_update(names, args):
    first = run_children(names, parallel=args.parallel, seed=0,
                         count_receipts=args.count_receipts, reps=0, profile=True,
                         tracemalloc_run=False)
    second = run_children(names, parallel=args.parallel, seed=1,
                          count_receipts=args.count_receipts, reps=0, profile=True,
                          tracemalloc_run=False)
    refused = []
    for name in names:
        diffs, noted = record_differences(first[name], second[name])
        for line in noted:
            print(f"{name}: {line}")
        if first[name]["timing_affected"] or second[name]["timing_affected"]:
            diffs.append("timing_affected")
        if diffs:
            refused.append(f"{name}: differs between hash seeds 0 and 1: {', '.join(diffs)}")
    if refused:
        for line in refused:
            print(line)
        print("golden.json not written")
        return 1
    golden = load_golden()
    for name in names:
        golden[name] = {k: first[name][k] for k in GOLDEN_FIELDS}
    write_golden(golden)
    print(f"wrote {GOLDEN} ({len(names)} scenario(s) re-recorded)")
    return 0


def do_measure(names, args):
    records = run_children(names, parallel=args.parallel, seed=0,
                           count_receipts=args.count_receipts, reps=args.reps,
                           profile=not args.no_profile,
                           tracemalloc_run=not args.no_tracemalloc)
    data = {"meta": {"code_root": str(ROOT), "git_head": _git_head(),
                     "python": platform.python_version(), "reps": args.reps,
                     "count_receipts": args.count_receipts,
                     "generated_utc": datetime.datetime.now(datetime.timezone.utc).strftime(
                         "%Y-%m-%d %H:%M:%SZ")},
            "scenarios": records}
    out = Path(args.out) if args.out else SCRATCH / "latest.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_bytes((json.dumps(data, indent=2, sort_keys=True) + "\n").encode("utf-8"))
    bad = []
    for name in names:
        rec = records[name]
        cpu = rec["info"]["process_time_s"]
        print(f"{name}: calls={rec['exact']['provider_calls']} "
              f"cpu_median={cpu['median']:.3f}s" if cpu else f"{name}: calls={rec['exact']['provider_calls']}",
              file=sys.stderr)
        if not rec["deterministic"] or rec["timing_affected"]:
            bad.append(name)
    print(f"wrote {out}", file=sys.stderr)
    if bad:
        print(f"not valid runs (nondeterministic or timing-affected): {bad}", file=sys.stderr)
        return 1
    return 0


def parse_args(argv):
    ap = argparse.ArgumentParser(description="Offline benchmark and byte-identity gate for DBH.")
    ap.add_argument("--scenario", action="append", choices=sorted(SCENARIOS),
                    help="scenario to run (repeatable; default every scenario)")
    mode = ap.add_mutually_exclusive_group()
    mode.add_argument("--check", action="store_true",
                      help="fingerprints against golden.json; exit 1 on any difference")
    mode.add_argument("--gate", action="store_true",
                      help="fingerprints, exact values and gated counters against golden.json")
    mode.add_argument("--update-golden", action="store_true",
                      help="re-record golden.json; refuses unless hash seeds 0 and 1 agree")
    mode.add_argument("--markdown", metavar="FILE",
                      help="print the scenario table from golden.json or a result file")
    mode.add_argument("--compare", nargs=2, metavar=("OLD", "NEW"),
                      help="compare two golden-format or result files")
    ap.add_argument("--count-receipts", choices=("memory", "disk"), default="memory",
                    help="receipt store for the counting run (default memory: same bytes, "
                         "no temp/fsync/rename syscalls)")
    ap.add_argument("--parallel", type=int, default=1,
                    help="run scenarios as N concurrent subprocesses (counts are unaffected)")
    ap.add_argument("--reps", type=int, default=3,
                    help="timed repetitions for a plain measurement (default 3)")
    ap.add_argument("--no-profile", action="store_true", help="skip the cProfile run")
    ap.add_argument("--no-tracemalloc", action="store_true", help="skip the tracemalloc run")
    ap.add_argument("--out", help="result file (default under the temp directory)")
    ap.add_argument("--worker", metavar="RECORD_JSON", help=argparse.SUPPRESS)
    return ap.parse_args(argv)


def main(argv=None):
    args = parse_args(argv)
    if args.worker:
        if not args.scenario or len(args.scenario) != 1:
            raise SystemExit("--worker needs exactly one --scenario")
        record = measure(args.scenario[0], count_receipts=args.count_receipts,
                         reps=args.reps, profile=not args.no_profile,
                         tracemalloc_run=not args.no_tracemalloc)
        Path(args.worker).write_bytes((json.dumps(record, sort_keys=True) + "\n").encode("utf-8"))
        return 0
    if args.markdown:
        print(markdown(_scenarios_of(args.markdown)), end="")
        return 0
    if args.compare:
        compare(*args.compare)
        return 0
    names = args.scenario or list(SCENARIOS)
    try:
        if args.check:
            return do_check(names, args)
        if args.gate:
            return do_gate(names, args)
        if args.update_golden:
            return do_update(names, args)
        return do_measure(names, args)
    except ChildFailed as exc:
        print(f"bench: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
