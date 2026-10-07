"""Run DBH's CLI over the labeled development catalog and score the reports.

Each case is written to a fresh temporary directory: the scanned directory
holds only the subject file (and helper files for project-scope cases); the
requirement is written outside it; labels are never written anywhere. The
installed or source-tree CLI is run once per case, and its saved report is
scored with the upstream Jev Bug Hunter outcome rules:

- defect: complete scan, and every labeled bug line lies inside a finding
  whose range sits within that bug's allowed region;
- clear: complete scan with no findings;
- unresolved: incomplete scan with no findings.

The strict score additionally requires a requirement citation on each
covering finding and, for project cases that name one, a read-with citation
of the helper file, as upstream did.

    python tools/eval/run_catalog.py --dry-run
    python tools/eval/run_catalog.py --only C001,C002 -- --provider openrouter
    python tools/eval/run_catalog.py --summarize smoke-results/eval-YYYYmmdd-HHMMSS

Arguments after `--` are passed to every CLI invocation. Live scans bill the
configured provider; the CLI's own budgets bound each case.
"""
from __future__ import annotations

import argparse
from collections import Counter
from datetime import datetime, timezone
from decimal import Decimal
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(Path(__file__).resolve().parent))

import catalog  # noqa: E402

SCOPE_FLAG = {"standalone": "standalone", "project": "project", "isolate": "isolate"}
#: A report's USD amounts are plain decimal strings (engine ``_spend``).
USD_AMOUNT = re.compile(r"[0-9]{1,6}(?:\.[0-9]{1,40})?")


def provider_reported_usd(report: dict | None) -> str | None:
    """The report's ``spend.provider_reported_usd`` decimal string, else None."""
    spend = report.get("spend") if isinstance(report, dict) else None
    amount = spend.get("provider_reported_usd") if isinstance(spend, dict) else None
    return amount if isinstance(amount, str) and USD_AMOUNT.fullmatch(amount) else None


def write_source(path: Path, text: str, encoding: str) -> None:
    if encoding == "utf-8-bom-crlf":
        path.write_bytes(b"\xef\xbb\xbf" + text.replace("\n", "\r\n").encode("utf-8"))
    else:
        path.write_bytes(text.encode("utf-8"))


def materialize(case: dict, base: Path) -> tuple[list[str], Path]:
    scanned = base / "scanned"
    scanned.mkdir()
    spec_dir = base / "requirement"
    spec_dir.mkdir()
    subject = scanned / case["name"]
    write_source(subject, case["source"], case["encoding"])
    for name, text in case["helpers"].items():
        write_source(scanned / name, text, "utf-8")
    spec = spec_dir / "requirement.txt"
    spec.write_bytes(case["requirement"].encode("utf-8"))
    out = base / "runs"
    argv = [str(subject), "--scope", SCOPE_FLAG[case["scope"]], "--spec-file", str(spec),
            "--output-dir", str(out), "--output-format", "json",
            "--max-calls", str(case["max_calls"])]
    if case["scope"] == "project":
        argv += ["--project-root", str(scanned)]
    return argv, out


def judge(case: dict, report: dict | None, exit_code: int) -> dict:
    if report is None:
        return {"location_pass": False, "strict_pass": False, "status": "missing",
                "failures": ["no_report"], "covered": 0, "findings": [],
                "provider_reported_usd": None}
    status = report.get("status")
    findings = report.get("handoff", {}).get("findings", [])
    spans = [row["suspect"] for row in findings]
    failures, strict_failures = [], []
    covered = 0
    for bug in case["bugs"]:
        lo, hi = bug["allowed_region"]
        matches = [row for row in findings
                   if lo <= row["suspect"][0] <= bug["line"] <= row["suspect"][1] <= hi]
        if matches:
            covered += 1
            if not any(row.get("relevant_requirement", {}).get("ranges") for row in matches):
                strict_failures.append("missing_requirement_citation")
    if case["expected"] == "defect":
        if covered != len(case["bugs"]):
            failures.append("missed_or_unhelpfully_broad_defect")
        if status != "complete":
            failures.append("defect_case_incomplete")
        if case["citation"]:
            refs = [ref for row in findings for ref in row.get("read_with", {}).get("refs", [])]
            if not any(ref.get("file") == case["citation"] for ref in refs):
                strict_failures.append("missing_helper_citation")
    elif case["expected"] == "clear":
        if spans:
            failures.append("false_positive_on_corrected_program")
        if status != "complete":
            failures.append("correct_program_unresolved")
    else:
        if status != "incomplete":
            failures.append("missing_evidence_not_expressed")
        if spans:
            failures.append("missing_information_reported_as_defect")
    expected_exit = (1 if spans else 0) if status == "complete" else 2
    if exit_code != expected_exit:
        failures.append(f"unexpected_exit_{exit_code}")
    issues = [i.get("code") for i in report.get("issues", []) if i.get("affects_completion")]
    usage = report.get("usage", {})
    return {"location_pass": not failures, "strict_pass": not failures and not strict_failures,
            "status": status, "failures": sorted(set(failures + strict_failures)), "covered": covered,
            "findings": spans, "issues": sorted(Counter(issues).items()),
            "calls": report.get("calls_attempted"), "usage": usage,
            "provider_reported_usd": provider_reported_usd(report),
            "provider": report.get("provider"), "model": report.get("model")}


def run_case(case: dict, extra: list[str], keep: Path) -> dict:
    with tempfile.TemporaryDirectory(prefix="dbh-eval-") as temp:
        base = Path(temp)
        argv, out = materialize(case, base)
        started = time.monotonic()
        process = subprocess.run([sys.executable, "-m", "decision_bug_hunter", *argv, *extra],
                                 cwd=ROOT, capture_output=True, text=True, timeout=3600,
                                 env={**os.environ, "PYTHONPATH": str(ROOT)})
        elapsed = time.monotonic() - started
        reports = sorted(out.glob("run-*/report.json"))
        report = json.loads(reports[-1].read_text(encoding="utf-8")) if reports else None
        if report is not None:
            (keep / f"{case['id']}-report.json").write_text(json.dumps(report, indent=1), encoding="utf-8")
        stderr_tail = process.stderr.strip().splitlines()[-4:]
    result = judge(case, report, process.returncode)
    result.update(id=case["id"], family=case["family"], expected=case["expected"],
                  exit_code=process.returncode, elapsed_s=round(elapsed, 2), stderr_tail=stderr_tail)
    return result


def summarize(out: Path) -> None:
    results = json.loads((out / "results.json").read_text(encoding="utf-8"))
    rows = results["cases"]
    lines = [f"# Catalog evaluation ({out.name})", "",
             f"CLI arguments: `{' '.join(results['cli_args']) or '(defaults)'}`", ""]
    def tally(expected, key):
        subset = [r for r in rows if r["expected"] == expected]
        return f"{sum(r[key] for r in subset)}/{len(subset)}"
    defect_rows = [r for r in rows if r["expected"] == "defect"]
    bugs_total = sum(len(c["bugs"]) for c in catalog.cases() if c["id"] in {r["id"] for r in defect_rows})
    lines += ["| Outcome class | Location score | Strict score |", "|---|---:|---:|",
              f"| Defective programs detected | {tally('defect', 'location_pass')} | {tally('defect', 'strict_pass')} |",
              f"| Individual defects covered | {sum(r['covered'] for r in defect_rows)}/{bugs_total} | |",
              f"| Corrected controls clear | {tally('clear', 'location_pass')} | {tally('clear', 'strict_pass')} |",
              f"| Missing evidence incomplete | {tally('unresolved', 'location_pass')} | {tally('unresolved', 'strict_pass')} |",
              f"| Entire case checks | {sum(r['location_pass'] for r in rows)}/{len(rows)} | "
              f"{sum(r['strict_pass'] for r in rows)}/{len(rows)} |", ""]
    tokens = sum((r.get("usage") or {}).get("input_tokens", 0) or 0 for r in rows)
    out_tokens = sum((r.get("usage") or {}).get("output_tokens", 0) or 0 for r in rows)
    amounts = [r.get("provider_reported_usd") for r in rows]
    known = [Decimal(a) for a in amounts if isinstance(a, str) and USD_AMOUNT.fullmatch(a)]
    cost = format(sum(known, Decimal(0)), "f")
    unknown = len(rows) - len(known)
    cost_note = f" ({unknown} case(s) without a provider-reported cost)" if unknown else ""
    calls = sum(r.get("calls") or 0 for r in rows)
    lines += [f"Calls: {calls}. Input tokens: {tokens}. Output tokens: {out_tokens}. "
              f"Provider-reported cost: ${cost}{cost_note}.", "",
              "| Case | Family | Expected | Status | Location | Strict | Findings | Failures | Calls | s |",
              "|---|---|---|---|---|---|---|---|---|---|"]
    for r in rows:
        lines.append(f"| {r['id']} | {r['family']} | {r['expected']} | {r['status']} | "
                     f"{'pass' if r['location_pass'] else 'FAIL'} | {'pass' if r['strict_pass'] else 'FAIL'} | "
                     f"{r['findings']} | {', '.join(r['failures']) or '-'} | {r.get('calls')} | {r['elapsed_s']} |")
    issues = Counter()
    for r in rows:
        for code, count in r.get("issues", []):
            issues[code] += count
    lines += ["", f"Completion-affecting issue codes: {dict(issues.most_common()) or 'none'}"]
    (out / "summary.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"Summary written to {out / 'summary.md'}")


def main() -> int:
    argv = sys.argv[1:]
    extra = argv[argv.index("--") + 1:] if "--" in argv else []
    own = argv[:argv.index("--")] if "--" in argv else argv
    parser = argparse.ArgumentParser(description="Score DBH on the labeled development catalog")
    parser.add_argument("--only", help="Comma-separated case ids")
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--out", help="Output directory (default smoke-results/eval-<UTC stamp>)")
    parser.add_argument("--summarize", help="Rebuild summary.md for an existing output directory")
    args = parser.parse_args(own)
    if args.summarize:
        summarize(Path(args.summarize))
        return 0
    cases = catalog.cases()
    if args.only:
        wanted = {c.strip() for c in args.only.split(",")}
        cases = [c for c in cases if c["id"] in wanted]
    if args.dry_run:
        for case in cases:
            with tempfile.TemporaryDirectory() as temp:
                cli, _ = materialize(case, Path(temp))
            shown = [Path(a).name if os.sep in a or "/" in a else a for a in cli]
            print(case["id"], case["expected"], "decision-bug-hunter", " ".join(shown + extra))
        return 0
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    out = Path(args.out) if args.out else ROOT / "smoke-results" / f"eval-{stamp}"
    keep = out / "reports"
    keep.mkdir(parents=True, exist_ok=True)
    rows = []
    for case in cases:
        result = run_case(case, extra, keep)
        rows.append(result)
        print(f"{case['id']} {case['expected']:<10} status={result['status']} "
              f"location={'pass' if result['location_pass'] else 'FAIL'} calls={result.get('calls')} "
              f"{result['elapsed_s']}s {','.join(result['failures'])}")
        (out / "results.json").write_text(json.dumps({"catalog_revision": catalog.CATALOG_REVISION,
                                                      "cli_args": extra, "cases": rows}, indent=1),
                                          encoding="utf-8")
    summarize(out)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
