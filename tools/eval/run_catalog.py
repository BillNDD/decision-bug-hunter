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

    python tools/eval/run_catalog.py --dry-run -- --judge openai
    python tools/eval/run_catalog.py --only C001,C002 -- --judge openai --provider openrouter
    python tools/eval/run_catalog.py --search-policy tile-sieve-beta --max-total-cost 0.05 \
        -- --judge openai --provider openrouter --max-cost 0.02
    python tools/eval/run_catalog.py --summarize smoke-results/eval-YYYYmmdd-HHMMSS

Arguments after `--` are passed to every CLI invocation. The runner reads them
with the CLI's own parser (abbreviations included) and still forwards them: a
missing judge is reported up front as the CLI reports it, a rejected argument is
refused as the CLI refuses it (without echoing the value), and the judge, route
and model are recorded in results.json and summary.md. Live scans bill the
configured provider; the CLI's own budgets bound each case.

`--search-policy` is the runner's own flag and is forwarded to every call.
With tile-sieve-beta, `--dry-run` plans every case with the Tile Sieve
planner, builds no provider and opens no socket, and prints the tile requests,
the projected bytes and a projected cost bound at the judge's list price.
`--max-total-cost USD` stops before the next case once the summed case costs
reach the limit. A case's cost is its report's spend upper bound (provider-reported
+ list-price estimate + unknown-usage bound), so it binds on a route that reports no
cost; with no report it is the CLI's stderr spend line, and with neither the
forwarded `--max-cost` (else `--max-calls` full-size requests at list price).
"""
from __future__ import annotations

import argparse
from collections import Counter
from contextlib import redirect_stderr
from datetime import datetime, timezone
from decimal import ROUND_CEILING, Decimal, InvalidOperation
import io
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import time
from typing import NamedTuple

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(ROOT))

import catalog  # noqa: E402
from decision_bug_hunter import __main__ as cli  # noqa: E402
from decision_bug_hunter import decisions, foundry, openrouter  # noqa: E402
from decision_bug_hunter import tile_sieve_plan as plans  # noqa: E402
from decision_bug_hunter.core import SEARCH_POLICIES, Source  # noqa: E402
from decision_bug_hunter.judges import JUDGE_CHOICES, JUDGES, judge_route  # noqa: E402
from decision_bug_hunter.protocol import ProviderError  # noqa: E402
from decision_bug_hunter.providers import (ALL_ROUTES, attempt_cost_bound,  # noqa: E402
                                           validate_max_cost)
from decision_bug_hunter.repository import ProjectIndex  # noqa: E402
from decision_bug_hunter.tile_sieve_fusion import load_thresholds  # noqa: E402

TILE_SIEVE = "tile-sieve-beta"
#: The route specs that carry each route's list prices; the only price source.
ROUTE_SPECS = {"openai": decisions.ROUTE, "openrouter": openrouter.ROUTE,
               "foundry": foundry.ROUTE}
#: The CLI's context scopes and input limits, so a dry run plans a case as a real run would.
CONTEXT_SCOPE = {"project": "project", "standalone": "declared_standalone",
                 "isolate": "owner_isolated"}
SPEC_MAX_BYTES, SPEC_MAX_LINES = 8192, 2000
PROJECT_LIMITS = {"max_files": 128, "max_file_bytes": 1048576, "max_total_bytes": 16777216}
SCOPE_FLAG = {"standalone": "standalone", "project": "project", "isolate": "isolate"}
#: A report's USD amounts are plain decimal strings (engine ``_spend``).
USD_AMOUNT = re.compile(r"[0-9]{1,6}(?:\.[0-9]{1,40})?")


#: The spend block's USD amounts; each is recorded under its own name in a case row.
SPEND_FIELDS = ("provider_reported_usd", "estimated_usd", "unknown_usage_upper_bound_usd",
                "upper_bound_usd")
#: A case id as the runner writes it into a report's file name.
SAVED_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_-]*")
#: The CLI's stderr spend line, the only source of a case's spend when no report was saved.
SPEND_LINE = re.compile(
    r"Spend \(USD\): provider-reported (?P<provider_reported_usd>[0-9.]+), "
    r"estimated (?P<estimated_usd>[0-9.]+), "
    r"unknown-usage bound (?P<unknown_usage_upper_bound_usd>[0-9.]+)\.")


def spend_amounts(report: dict | None) -> dict[str, str | None]:
    """The report's ``spend`` USD amounts (decimal strings), None for one that is absent."""
    spend = report.get("spend") if isinstance(report, dict) else None
    amounts = {key: spend.get(key) if isinstance(spend, dict) else None for key in SPEND_FIELDS}
    return {key: amount if isinstance(amount, str) and USD_AMOUNT.fullmatch(amount) else None
            for key, amount in amounts.items()}


def provider_reported_usd(report: dict | None) -> str | None:
    """The report's ``spend.provider_reported_usd`` decimal string, else None."""
    return spend_amounts(report)["provider_reported_usd"]


def estimated_usd(report: dict | None) -> str | None:
    """The report's ``spend.estimated_usd`` decimal string, else None."""
    return spend_amounts(report)["estimated_usd"]


def stderr_spend(stderr: str) -> dict[str, str | None]:
    """The spend amounts of the CLI's last ``Spend (USD): ...`` stderr line.

    The line prints the three components, not the report's ``upper_bound_usd``; that
    field is their sum (reported + estimated + unknown-usage bound). Every amount is
    None when the line is absent or malformed.
    """
    empty: dict[str, str | None] = dict.fromkeys(SPEND_FIELDS)
    for line in reversed(stderr.splitlines()):
        found = SPEND_LINE.fullmatch(line.strip())
        if found is None:
            continue
        parts = [found["provider_reported_usd"], found["estimated_usd"],
                 found["unknown_usage_upper_bound_usd"]]
        if not all(USD_AMOUNT.fullmatch(part) for part in parts):
            return empty
        total = sum((Decimal(part) for part in parts), Decimal(0))
        return {"provider_reported_usd": parts[0], "estimated_usd": parts[1],
                "unknown_usage_upper_bound_usd": parts[2], "upper_bound_usd": format(total, "f")}
    return empty


def tile_block(report: dict | None) -> dict:
    """The report's ``tile_sieve`` block (tile-sieve-beta only), else an empty dict."""
    block = report.get("tile_sieve") if isinstance(report, dict) else None
    return block if isinstance(block, dict) else {}


def models_returned(report: dict | None) -> list[str]:
    """The models the provider echoed in this report, from its route provenance."""
    provenance = report.get("provenance") if isinstance(report, dict) else None
    named = provenance.get("models_returned") if isinstance(provenance, dict) else None
    return sorted({m for m in named if isinstance(m, str)}) if isinstance(named, list) else []


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
                **spend_amounts(None), "mode": None, "models_returned": []}
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
            **spend_amounts(report),
            "mode": tile_block(report).get("mode"),
            "fallback_reason": tile_block(report).get("reason"),
            "models_returned": models_returned(report),
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
    if report is None:
        # No report was saved: the CLI's stderr spend line is the only record of the spend.
        stderr_amounts = stderr_spend(process.stderr)
        result.update(stderr_amounts)
        if stderr_amounts["upper_bound_usd"] is not None:
            result["spend_source"] = "stderr"
    result.update(id=case["id"], family=case["family"], expected=case["expected"],
                  exit_code=process.returncode, elapsed_s=round(elapsed, 2), stderr_tail=stderr_tail)
    return result


def saved_report(out: Path, case_id: object) -> dict | None:
    """The case's saved ``reports/<id>-report.json`` under *out*, else None."""
    if not isinstance(case_id, str) or not SAVED_ID.fullmatch(case_id):
        return None
    try:
        report = json.loads((out / "reports" / f"{case_id}-report.json").read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    return report if isinstance(report, dict) else None


def with_saved_spend(rows: list[dict], out: Path) -> list[dict]:
    """Copies of *rows*; an older row without an upper bound takes its spend from its saved report.

    An older runner wrote the reported and estimated amounts into a row but not the
    unknown-usage bound or the upper bound; the case's saved report holds them.
    Only the spend fields a row lacks are filled in. A row whose spend came from the
    CLI's stderr line has no report to read.
    """
    filled = []
    for row in rows:
        row = dict(row)
        if row_amount(row, "upper_bound_usd") is None and row.get("spend_source") != "stderr":
            saved = spend_amounts(saved_report(out, row.get("id")))
            for key in SPEND_FIELDS:
                if row_amount(row, key) is None and saved[key] is not None:
                    row[key] = saved[key]
        filled.append(row)
    return filled


def summarize(out: Path) -> None:
    results = json.loads((out / "results.json").read_text(encoding="utf-8"))
    rows = with_saved_spend(results["cases"], out)
    lines = [f"# Catalog evaluation ({out.name})", "",
             f"CLI arguments: `{' '.join(results['cli_args']) or '(defaults)'}`", ""]
    if results.get("judge") is not None:
        returned = sorted({m for r in rows for m in r.get("models_returned") or ()})
        requested = results.get("model_requested") or ", ".join(
            sorted({r["model"] for r in rows if isinstance(r.get("model"), str)})) or "not recorded"
        lines += [f"Judge: {results['judge']}. Route: {results.get('provider') or 'not given'}. "
                  f"Search policy: {results.get('search_policy') or 'legacy-v1'}.",
                  f"Model requested: {requested}. Models returned: {', '.join(returned) or 'none'}.",
                  ""]
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
    unknown = len(rows) - len(known)
    cost_note = f" ({unknown} case(s) without a provider-reported cost)" if unknown else ""
    calls = sum(r.get("calls") or 0 for r in rows)
    spend = spend_totals(rows, results)
    # A row from before the unknown-usage bound was kept, with no saved report to read it from.
    unrecorded = sum(1 for r in rows if r.get("cost_basis") is None
                     and row_amount(r, "unknown_usage_upper_bound_usd") is None)
    bound_note = f" ({unrecorded} case(s) recorded before it was kept)" if unrecorded else ""
    counted_note = (f" The unknown-usage bound is missing for {unrecorded} case(s), so this may "
                    "be low." if unrecorded else "")
    lines += [f"Calls: {calls}. Input tokens: {tokens}. Output tokens: {out_tokens}. "
              f"Provider-reported cost: ${spend['provider_reported_usd']}{cost_note}.", "",
              f"List-price estimate: ${spend['estimated_usd']}. "
              f"Unknown-usage bound: ${spend['unknown_usage_upper_bound_usd']}{bound_note}. "
              f"Reported-or-estimated cost: ${spend['reported_or_estimated_usd']}.", "",
              f"Spend counted toward --max-total-cost (each case's upper bound): "
              f"${spend['counted_usd']}{basis_note(spend['cost_bases'])}.{counted_note}", ""]
    if results.get("stopped_at_case") is not None:
        lines += [f"Stopped before {results['stopped_at_case']}: the summed cost reached "
                  f"--max-total-cost ${results.get('max_total_cost')}; later cases did not run.", ""]
    if results.get("search_policy") == TILE_SIEVE or any(r.get("mode") for r in rows):
        whole = sum(r.get("mode") == "whole-file" for r in rows)
        fallbacks = sum(r.get("mode") == "legacy-fallback" for r in rows)
        lines += [f"Whole-file cases: {whole}. Legacy-v1 fallbacks: {fallbacks}.", ""]
    lines += ["| Case | Family | Expected | Mode | Status | Location | Strict | Findings | Failures | Calls | s |",
              "|---|---|---|---|---|---|---|---|---|---|---|"]
    for r in rows:
        lines.append(f"| {r['id']} | {r['family']} | {r['expected']} | {r.get('mode') or '-'} | "
                     f"{r['status']} | "
                     f"{'pass' if r['location_pass'] else 'FAIL'} | {'pass' if r['strict_pass'] else 'FAIL'} | "
                     f"{r['findings']} | {', '.join(r['failures']) or '-'} | {r.get('calls')} | {r['elapsed_s']} |")
    issues = Counter()
    for r in rows:
        for code, count in r.get("issues", []):
            issues[code] += count
    lines += ["", f"Completion-affecting issue codes: {dict(issues.most_common()) or 'none'}"]
    (out / "summary.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"Summary written to {out / 'summary.md'}")


#: How a case's counted cost was found, when it was not its report's upper bound.
BASIS_TEXT = {"stderr": "the CLI's spend line", "max-cost": "the forwarded --max-cost",
              "call-cap": "--max-calls full-size requests at list price",
              "recorded": "the recorded cost", "unknown": "no spend record"}


def basis_note(bases: dict) -> str:
    """A parenthesis naming the cases counted from something other than a report."""
    named = [f"{count} from {BASIS_TEXT[basis]}" for basis, count in bases.items()
             if basis in BASIS_TEXT]
    return f" ({', '.join(named)})" if named else ""


def usd_argument(text: str) -> Decimal:
    try:
        value = Decimal(text)
    except InvalidOperation:
        raise argparse.ArgumentTypeError("expected a decimal USD amount") from None
    if not value.is_finite() or value <= 0:
        raise argparse.ArgumentTypeError("expected a positive USD amount")
    return value


#: Stands in for the CLI's required scanned-file argument when reading forwarded options.
SUBJECT_PLACEHOLDER = "subject"


def forwarded_choices(extra: list[str]) -> argparse.Namespace:
    """The CLI's own reading of the forwarded arguments (after ``--``).

    They are read, not consumed: the whole list still goes to every CLI call. The CLI's
    parser reads them, so an unambiguous abbreviation (``--judg``) means what it means
    there and a refusal is the CLI's, which never echoes the rejected value. Building it
    has no side effects. An option the CLI did not get reads as None, so a default is
    never mistaken for a choice. Raises ``SystemExit`` as the CLI would.
    """
    reader = cli.parser()
    reader.set_defaults(search_policy=None, max_calls=None)
    return reader.parse_known_args([SUBJECT_PLACEHOLDER, *extra])[0]


#: The CLI's accepted ``--max-calls`` range (ScanConfig validates the same bounds).
MAX_CALLS_RANGE = (1, 100000)


class Selection(NamedTuple):
    judge: str
    #: The route selector given (--provider or DBH_PROVIDER), else None.
    provider: str | None
    #: The price route: the one given, else the judge's first.
    route: str
    model_requested: str | None
    search_policy: str
    encoding: str
    #: The forwarded --max-calls and --max-cost; None when not given.
    max_calls: int | None = None
    max_cost: Decimal | None = None


def select(chosen: argparse.Namespace, own_policy: str | None) -> Selection | int:
    """The judge, route and policy of the run, or the exit code of an up-front refusal.

    The refusals are the CLI's own, in its order: a missing judge is NEED_USER_INPUT
    (exit 3), then (owner decision 12A) tile-sieve-beta with a judge that has no
    calibrated threshold set is refused as the CLI refuses it (exit 2), then a route
    outside the judge's is NEED_USER_INPUT judge_route. A forwarded ``--max-calls`` or
    ``--max-cost`` outside the CLI's range is refused first, as the CLI refuses it, so
    no case is ever counted at a value the CLI would not accept. Nothing is read or
    sent first, and a rejected value is never echoed.
    """
    policy = own_policy or chosen.search_policy or "legacy-v1"
    if own_policy and chosen.search_policy and own_policy != chosen.search_policy:
        print("run_catalog: --search-policy differs between the runner and the "
              "forwarded arguments.", file=sys.stderr)
        return 2
    low, high = MAX_CALLS_RANGE
    if chosen.max_calls is not None and not low <= chosen.max_calls <= high:
        return cli.failure("invalid_input_or_configuration")
    try:
        validate_max_cost(chosen.max_cost)
    except ProviderError:
        return cli.failure("invalid_request")
    try:
        judge = cli.selected_judge(chosen)
    except cli.JudgeChoiceNeeded:
        return cli.need_user_input("judge", cli.JUDGE_CHOICE_HINT)
    except ProviderError:
        return cli.failure("invalid_judge")
    if policy == TILE_SIEVE:
        try:
            load_thresholds(judge)
        except LookupError:
            print(f"Scan failed (invalid_search_configuration: {TILE_SIEVE} has no "
                  f"calibrated thresholds for judge {judge}).", file=sys.stderr)
            return 2
    try:
        provider = cli.selected_provider(chosen)
    except cli.ProviderChoiceNeeded:
        provider = None
    except ProviderError:
        return cli.failure("invalid_provider", judge=judge)
    try:
        route = judge_route(judge, provider or JUDGES[judge].routes[0].selector)
    except ProviderError:
        return cli.need_user_input("judge_route", cli.route_mismatch_hint(judge))
    return Selection(judge, provider, route.selector, chosen.model or route.model, policy,
                     chosen.encoding, chosen.max_calls, chosen.max_cost)


def route_prices(judge: str, selector: str) -> tuple[Decimal, Decimal]:
    """The judge's list prices (USD per million input and output tokens) on a route."""
    route = judge_route(judge, selector)
    spec = ROUTE_SPECS[route.selector].model(route.model)
    return spec.price_in_per_mtok, spec.price_out_upper_per_mtok


def judge_prices(selection: Selection) -> tuple[Decimal, Decimal]:
    """The judge's list prices on its route."""
    return route_prices(selection.judge, selection.route)


def call_cap_bound(calls: int, prices: tuple[Decimal, Decimal]) -> Decimal:
    """The cost bound of *calls* requests of the full request size, one attempt each."""
    return calls * attempt_cost_bound(plans.ENVELOPE_BYTES, plans.MAX_QUESTIONS, *prices)


def limit_bound(case_calls: int, max_calls: int | None, max_cost: Decimal | None,
                prices: tuple[Decimal, Decimal]) -> tuple[Decimal, str]:
    """What a case with no spend record is counted at, and why; never zero.

    The forwarded ``--max-cost`` is the bound the CLI held the case to. The CLI has no
    default cost limit, so without one the case's ``--max-calls`` (the forwarded value,
    else the catalog's) bounds it: that many requests of the full request size at the
    judge's list price.
    """
    if max_cost is not None:
        return max_cost, "max-cost"
    return call_cap_bound(max_calls or case_calls, prices), "call-cap"


def row_amount(row: dict, key: str) -> Decimal | None:
    """A row's decimal-string USD field as a Decimal, else None."""
    amount = row.get(key)
    return Decimal(amount) if isinstance(amount, str) and USD_AMOUNT.fullmatch(amount) else None


def case_cost(result: dict, limit: tuple[Decimal, str]) -> tuple[Decimal, str]:
    """A finished case's cost for ``--max-total-cost`` and ``spent_usd``, and its basis.

    The upper bound of the case's spend: the report's ``upper_bound_usd`` (reported +
    list-price estimate + unknown-usage bound), else those amounts summed, whether they
    came from the report or from the CLI's stderr line (``spend_source``); with no
    spend record at all, *limit*. A provider-reported cost alone is not enough: OpenAI
    direct reports none, so its spend is the estimate.
    """
    upper = row_amount(result, "upper_bound_usd")
    source = result.get("spend_source") or "report"
    if upper is not None:
        return upper, source
    known = [amount for key in ("provider_reported_usd", "estimated_usd",
                                "unknown_usage_upper_bound_usd")
             if (amount := row_amount(result, key)) is not None]
    if known:
        return sum(known, Decimal(0)), source
    return limit


def recorded_limit(results: dict, case_id: str) -> tuple[Decimal, str] | None:
    """The *limit* of a recorded case, rebuilt from its results.json; None when it cannot be."""
    judge_name = results.get("judge")
    if judge_name not in JUDGES:
        return None
    case = next((c for c in catalog.cases() if c["id"] == case_id), None)
    cli_args = results.get("cli_args")
    if case is None or not isinstance(cli_args, list):
        return None
    try:
        with redirect_stderr(io.StringIO()):
            chosen = forwarded_choices([str(arg) for arg in cli_args])
        selector = results.get("provider") or JUDGES[judge_name].routes[0].selector
        prices = route_prices(judge_name, selector)
    except (SystemExit, ProviderError, KeyError, ValueError):
        return None
    return limit_bound(case["max_calls"], chosen.max_calls, chosen.max_cost, prices)


def spend_totals(rows: list[dict], results: dict | None = None) -> dict:
    """The run's spend: each component summed, and the counted total.

    A row that has a ``cost_basis`` carries its own counted cost; an older row (a
    results.json written before the upper bound was recorded) is counted the new way
    from its spend amounts, then its limit rebuilt from *results*.
    """
    parts = {key: Decimal(0) for key in
             ("provider_reported_usd", "estimated_usd", "unknown_usage_upper_bound_usd")}
    counted, bases = Decimal(0), Counter()
    for row in rows:
        for key in parts:
            parts[key] += row_amount(row, key) or Decimal(0)
        cost, basis = row_amount(row, "cost_usd"), row.get("cost_basis")
        if cost is None or basis is None:
            limit = None if results is None else recorded_limit(results, str(row.get("id")))
            fallback = (cost or Decimal(0), "recorded" if cost is not None else "unknown")
            cost, basis = case_cost(row, limit or fallback)
        counted += cost
        bases[basis] += 1
    return {**{key: format(value, "f") for key, value in parts.items()},
            "reported_or_estimated_usd": format(
                parts["provider_reported_usd"] + parts["estimated_usd"], "f"),
            "counted_usd": format(counted, "f"),
            "cost_bases": dict(sorted(bases.items()))}


def money(amount: Decimal) -> str:
    return format(amount.quantize(Decimal("0.000001"), rounding=ROUND_CEILING), "f")


def plan_case(case: dict, encoding: str) -> object:
    """The Tile Sieve plan (or Fallback) of a case, built from the files a live run reads."""
    with tempfile.TemporaryDirectory(prefix="dbh-eval-") as temp:
        base = Path(temp)
        argv, out = materialize(case, base)
        subject, spec_file = Path(argv[0]), Path(argv[argv.index("--spec-file") + 1])
        source = Source.read(subject, encoding=encoding)
        spec = Source.read(spec_file, encoding=encoding, max_bytes=SPEC_MAX_BYTES,
                           max_lines=SPEC_MAX_LINES)
        entries = ()
        if case["scope"] == "project":
            entries = ProjectIndex.read(base / "scanned", primary_path=subject,
                                        encoding=encoding, exclude_paths=(out, spec_file),
                                        **PROJECT_LIMITS).entries
        return plans.plan_whole_file(source, spec, entries, CONTEXT_SCOPE[case["scope"]])


def dry_run_tile_sieve(cases: list[dict], selection: Selection) -> int:
    """Plan every case offline and print the requests, bytes and a cost bound.

    No provider is built and no socket is opened; the planner only assembles bytes.
    """
    price_in, price_out = judge_prices(selection)
    print(f"Dry run: {TILE_SIEVE}, judge {selection.judge}, route {selection.route}; "
          "no provider is built and nothing is sent.")
    tiles = fits = fallbacks = 0
    worst = 0
    bound = Decimal(0)
    for case in cases:
        plan = plan_case(case, selection.encoding)
        if isinstance(plan, plans.Fallback):
            # A fallback case runs legacy-v1: at most max_calls requests of the cap size.
            fallbacks += 1
            worst += case["max_calls"] * plans.ENVELOPE_BYTES
            bound += case["max_calls"] * attempt_cost_bound(
                plans.ENVELOPE_BYTES, plans.MAX_QUESTIONS, price_in, price_out)
            detail = json.dumps(plan.detail, sort_keys=True)
            print(f"{case['id']} {case['expected']} legacy-fallback: {plan.reason} {detail}; "
                  "this case would scan with legacy-v1")
            continue
        requests = plan.looks
        fits += 1
        tiles += len(requests)
        worst += sum(r.request_bytes for r in requests)
        bound += sum((attempt_cost_bound(r.request_bytes, r.nq, price_in, price_out)
                      for r in requests), Decimal(0))
        print(f"{case['id']} {case['expected']} whole-file: {len(requests)} tile request(s), "
              f"{sum(r.nq for r in requests)} questions, max "
              f"{max(r.request_bytes for r in requests):,} B")
    # The focus count is the pilot's projection of one focus request per whole-file case,
    # each of at most the request caps. The engine sends one per flagged cluster and has no
    # limit of its own on them (a longer file can have more clusters); the only hard bound
    # is its call budget, --max-calls per case, which the worst-case line below uses.
    worst += fits * plans.MAX_REQUEST_BYTES
    bound += fits * attempt_cost_bound(plans.MAX_REQUEST_BYTES, plans.MAX_QUESTIONS,
                                       price_in, price_out)
    calls = sum(selection.max_calls or case["max_calls"] for case in cases)
    limit = (f"; --max-cost ${selection.max_cost} per case, if lower, binds first"
             if selection.max_cost is not None else "")
    print(f"Worst case: the engine has no fixed limit on focus requests per case; the call "
          f"budget (--max-calls per case) is the hard bound, so at most {calls:,} requests "
          f"over {len(cases)} case(s), at most ${money(call_cap_bound(calls, (price_in, price_out)))} "
          f"with every request at the full request size and one attempt each{limit}.")
    print(f"Totals: {tiles} tile requests, {fits} focus requests projected (one per "
          f"whole-file case), {fallbacks} legacy fallback(s); projected request bytes {worst:,}; "
          f"projected cost bound ${money(bound)} at {selection.judge} "
          f"${format(price_in, 'f')} per million input tokens "
          "(one attempt per request, one focus per case as the pilot projected).")
    return 0


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    extra = argv[argv.index("--") + 1:] if "--" in argv else []
    own = argv[:argv.index("--")] if "--" in argv else argv
    parser = argparse.ArgumentParser(description="Score DBH on the labeled development catalog")
    parser.add_argument("--only", help="Comma-separated case ids")
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--out", help="Output directory (default smoke-results/eval-<UTC stamp>)")
    parser.add_argument("--summarize", help="Rebuild summary.md for an existing output directory")
    parser.add_argument("--search-policy", choices=SEARCH_POLICIES,
                        help="Search policy forwarded to every CLI call")
    parser.add_argument("--max-total-cost", type=usd_argument, metavar="USD",
                        help="Stop before the next case once the summed cost reaches this")
    args = parser.parse_args(own)
    if args.summarize:
        summarize(Path(args.summarize))
        return 0
    try:
        chosen = forwarded_choices(extra)
    except SystemExit as stop:
        # The CLI parser's refusal, already printed (it never echoes the rejected value).
        return stop.code if isinstance(stop.code, int) else 2
    selection = select(chosen, args.search_policy)
    if isinstance(selection, int):
        return selection
    if args.search_policy:
        extra = ["--search-policy", args.search_policy, *extra]
    cases = catalog.cases()
    if args.only:
        wanted = {c.strip() for c in args.only.split(",")}
        cases = [c for c in cases if c["id"] in wanted]
    if args.dry_run:
        if selection.search_policy == TILE_SIEVE:
            return dry_run_tile_sieve(cases, selection)
        for case in cases:
            with tempfile.TemporaryDirectory() as temp:
                cli_argv, _ = materialize(case, Path(temp))
            shown = [Path(a).name if os.sep in a or "/" in a else a for a in cli_argv]
            print(case["id"], case["expected"], "decision-bug-hunter", " ".join(shown + extra))
        return 0
    prices = judge_prices(selection)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    out = Path(args.out) if args.out else ROOT / "smoke-results" / f"eval-{stamp}"
    keep = out / "reports"
    keep.mkdir(parents=True, exist_ok=True)
    rows: list[dict] = []
    spent = Decimal(0)
    stopped = None

    def save() -> None:
        limit = args.max_total_cost
        record = {"catalog_revision": catalog.CATALOG_REVISION, "cli_args": extra,
                  "judge": selection.judge, "provider": selection.provider,
                  "model_requested": selection.model_requested,
                  "search_policy": selection.search_policy,
                  "max_total_cost": None if limit is None else str(limit),
                  "spent_usd": format(spent, "f"), "spend": spend_totals(rows),
                  "stopped_at_case": stopped, "cases": rows}
        (out / "results.json").write_text(json.dumps(record, indent=1), encoding="utf-8")

    for case in cases:
        if args.max_total_cost is not None and spent >= args.max_total_cost:
            stopped = case["id"]
            print(f"Stopping before {stopped}: the summed cost ${money(spent)} reached "
                  f"--max-total-cost ${args.max_total_cost}.")
            break
        result = run_case(case, extra, keep)
        cost, basis = case_cost(result, limit_bound(case["max_calls"], selection.max_calls,
                                                    selection.max_cost, prices))
        result["cost_usd"], result["cost_basis"] = format(cost, "f"), basis
        spent += cost
        rows.append(result)
        print(f"{case['id']} {case['expected']:<10} status={result['status']} "
              f"mode={result.get('mode') or '-'} "
              f"location={'pass' if result['location_pass'] else 'FAIL'} calls={result.get('calls')} "
              f"{result['elapsed_s']}s {','.join(result['failures'])}")
        save()
    save()
    summarize(out)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
