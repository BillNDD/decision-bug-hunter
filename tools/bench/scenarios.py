"""Benchmark scenarios: inputs and configuration only, no measurement.

Each scenario names what runs. ``kind`` is ``engine`` (``core.scan`` over a
real ``ValidatedGateway``) or ``cli`` (``__main__.main`` with its
``make_provider`` seam replaced). ``jobs`` is a synthetic line count, or
``catalog`` (every labeled case of ``tools/eval/catalog.py``) or
``catalog-4`` (its first four cases). ``config`` holds Config overrides.
"""
from __future__ import annotations

from pathlib import Path
import sys

#: The labeled catalog lives beside the eval tooling.
EVAL_DIR = Path(__file__).resolve().parents[1] / "eval"

SYNTH_SPEC = ("Every function returns the documented value for all valid inputs. "
              "Counters are inclusive of their upper bound. "
              "Constants are informational and carry no behavioral requirement.\n")

SCENARIOS = {
    "synth-200": {"kind": "engine", "jobs": 200, "config": {},
                  "doc": "200-line synthetic file, three planted off-by-one spans, defaults"},
    "synth-1000": {"kind": "engine", "jobs": 1000, "config": {},
                   "doc": "1000-line synthetic file, defaults (mass choice gate)"},
    "synth-1000-legacy-gate": {"kind": "engine", "jobs": 1000,
                               "config": {"choice_gate": "legacy"},
                               "doc": "1000 lines, legacy choice gate"},
    "synth-1000-state": {"kind": "engine", "jobs": 1000,
                         "config": {"policy_placement": "state"},
                         "doc": "1000 lines, policy placement in state"},
    "synth-1000-nocanary": {"kind": "engine", "jobs": 1000, "config": {"canaries": "off"},
                            "doc": "1000 lines, canaries off"},
    "synth-5000": {"kind": "engine", "jobs": 5000, "config": {},
                   "doc": "5000-line synthetic file, defaults"},
    "catalog-legacy": {"kind": "engine", "jobs": "catalog", "config": {},
                       "doc": "every labeled catalog case, legacy-v1 search"},
    "catalog-scoped": {"kind": "engine", "jobs": "catalog",
                       "config": {"search_policy": "scoped-v2-beta"},
                       "doc": "every labeled catalog case, scoped-v2-beta search"},
    "cli-1000": {"kind": "cli", "jobs": 1000, "config": {},
                 "doc": "1000 lines through the CLI entry point, defaults"},
    "catalog-4": {"kind": "engine", "jobs": "catalog-4", "config": {},
                  "doc": "the first four catalog cases, legacy-v1 (fast unit-test subset)"},
}


def synthetic_text(n):
    """Deterministic Python-like file; planted bugs at about 20%, 50% (two lines) and 80%."""
    lines = []
    i = 0
    while len(lines) < n:
        i += 1
        block = [f"def helper_{i:05d}(value, limit={i % 97 + 3}):",
                 f"    \"\"\"Return value scaled by {i % 13 + 2}, bounded by limit.\"\"\"",
                 f"    scaled = value * {i % 13 + 2}",
                 "    if scaled >= limit:",
                 "        return limit",
                 "    return scaled",
                 ""]
        lines.extend(block)
    lines = lines[:n]
    bugs = []
    for frac, size in ((0.2, 1), (0.5, 2), (0.8, 1)):
        start = max(1, int(n * frac))
        for k in range(size):
            lines[start - 1 + k] = f"    return scaled + {k + 1}  # planted off-by-one"
        bugs.append((start, start + size - 1))
    return "\n".join(lines) + "\n", bugs


def _encoded(text, encoding):
    if encoding == "utf-8-bom-crlf":
        return b"\xef\xbb\xbf" + text.replace("\n", "\r\n").encode("utf-8")
    return text.encode("utf-8")


SCOPES = {"standalone": "declared_standalone", "isolate": "owner_isolated",
          "project": "project"}


def catalog_jobs(base: Path, limit: int | None = None):
    """One job per labeled catalog case, written under ``base``."""
    if str(EVAL_DIR) not in sys.path:
        sys.path.insert(0, str(EVAL_DIR))
    import catalog
    jobs = []
    for case in catalog.cases()[:limit]:
        root = base / case["id"]
        scanned = root / "scanned"
        scanned.mkdir(parents=True)
        subject = scanned / case["name"]
        subject.write_bytes(_encoded(case["source"], case["encoding"]))
        for name, text in case["helpers"].items():
            (scanned / name).write_bytes(text.encode("utf-8"))
        spec = root / "requirement.txt"
        spec.write_bytes(case["requirement"].encode("utf-8"))
        bugs = [(b["line"], b["line"]) for b in case["bugs"]]
        jobs.append({"id": case["id"], "file": subject, "spec": spec, "scope": case["scope"],
                     "project_root": scanned if case["scope"] == "project" else None,
                     "bugs": bugs, "config": {"max_calls": case["max_calls"]}})
    return jobs


def synth_job(base: Path, n):
    text, bugs = synthetic_text(n)
    path = base / f"synthetic_{n}.py"
    path.write_bytes(text.encode("utf-8"))
    spec = base / "requirement.txt"
    spec.write_bytes(SYNTH_SPEC.encode("utf-8"))
    return {"id": f"synth-{n}", "file": path, "spec": spec, "scope": "standalone",
            "project_root": None, "bugs": bugs, "config": {}}


def prepare(name, base: Path):
    """The jobs of one scenario, with their inputs written under ``base``."""
    jobs = SCENARIOS[name]["jobs"]
    if jobs == "catalog":
        return catalog_jobs(base)
    if jobs == "catalog-4":
        return catalog_jobs(base, limit=4)
    return [synth_job(base, jobs)]
