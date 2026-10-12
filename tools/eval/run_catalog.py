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

Arguments after `--` are passed to every CLI invocation. The runner parses
(and still forwards) the `--judge`, `--provider`, `--model` and `--encoding`
among them: a missing judge is reported up front as the CLI reports it, and the
judge, route and model are recorded in results.json and summary.md. Live scans
bill the configured provider; the CLI's own budgets bound each case.

`--search-policy` is the runner's own flag and is forwarded to every call.
With tile-sieve-beta, `--dry-run` plans every case with the Tile Sieve
planner, builds no provider and opens no socket, and prints the tile requests,
the projected bytes and a projected cost bound at the judge's list price.
`--max-total-cost USD` stops before the next case once the summed reported (or
estimated) cost reaches the limit.
"""
from __future__ import annotations

import argparse
from collections import Counter
from datetime import datetime, timezone
from decimal import ROUND_CEILING, Decimal, InvalidOperation
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import time
from typing import NamedTuple, NoReturn

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
from decision_bug_hunter.providers import (  # noqa: E402
    ALL_ROUTES, attempt_cost_bound, list_price)
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


def provider_reported_usd(report: dict | None) -> str | None:
    """The report's ``spend.provider_reported_usd`` decimal string, else None."""
    spend = report.get("spend") if isinstance(report, dict) else None
    amount = spend.get("provider_reported_usd") if isinstance(spend, dict) else None
    return amount if isinstance(amount, str) and USD_AMOUNT.fullmatch(amount) else None


def estimated_usd(report: dict | None) -> str | None:
    """The report's ``spend.estimated_usd`` decimal string, else None."""
    spend = report.get("spend") if isinstance(report, dict) else None
    amount = spend.get("estimated_usd") if isinstance(spend, dict) else None
    return amount if isinstance(amount, str) and USD_AMOUNT.fullmatch(amount) else None


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
                "provider_reported_usd": None, "estimated_usd": None, "mode": None,
                "models_returned": []}
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
            "estimated_usd": estimated_usd(report),
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
    result.update(id=case["id"], family=case["family"], expected=case["expected"],
                  exit_code=process.returncode, elapsed_s=round(elapsed, 2), stderr_tail=stderr_tail)
    return result


def summarize(out: Path) -> None:
    results = json.loads((out / "results.json").read_text(encoding="utf-8"))
    rows = results["cases"]
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
    cost = format(sum(known, Decimal(0)), "f")
    unknown = len(rows) - len(known)
    cost_note = f" ({unknown} case(s) without a provider-reported cost)" if unknown else ""
    calls = sum(r.get("calls") or 0 for r in rows)
    lines += [f"Calls: {calls}. Input tokens: {tokens}. Output tokens: {out_tokens}. "
              f"Provider-reported cost: ${cost}{cost_note}.", ""]
    if results.get("spent_usd") is not None:
        lines += [f"Reported-or-estimated cost: ${results['spent_usd']}.", ""]
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


def usd_argument(text: str) -> Decimal:
    try:
        value = Decimal(text)
    except InvalidOperation:
        raise argparse.ArgumentTypeError("expected a decimal USD amount") from None
    if not value.is_finite() or value <= 0:
        raise argparse.ArgumentTypeError("expected a positive USD amount")
    return value


class ForwardedParser(argparse.ArgumentParser):
    """Reads the choices among the forwarded arguments; the CLI still parses them all."""

    def error(self, message: str) -> NoReturn:
        self.exit(2, f"run_catalog: invalid forwarded arguments (after --): {message}\n")


def forwarded_choices(extra: list[str]) -> argparse.Namespace:
    """The judge, route, model, search policy and encoding among the forwarded arguments.

    They are read, not consumed: the whole list still goes to every CLI call.
    """
    reader = ForwardedParser(add_help=False, allow_abbrev=False)
    reader.add_argument("--judge", choices=JUDGE_CHOICES)
    reader.add_argument("--provider", choices=tuple(ALL_ROUTES))
    reader.add_argument("--model")
    reader.add_argument("--search-policy", choices=SEARCH_POLICIES)
    reader.add_argument("--encoding", default="utf-8-sig")
    return reader.parse_known_args(extra)[0]


class Selection(NamedTuple):
    judge: str
    #: The route selector given (--provider or DBH_PROVIDER), else None.
    provider: str | None
    #: The price route: the one given, else the judge's first.
    route: str
    model_requested: str | None
    search_policy: str
    encoding: str


def select(chosen: argparse.Namespace, own_policy: str | None) -> Selection | int:
    """The judge, route and policy of the run, or the exit code of an up-front refusal.

    The refusals are the CLI's own, in its order: a missing judge is NEED_USER_INPUT
    (exit 3), then (owner decision 12A) tile-sieve-beta with a judge that has no
    calibrated threshold set is refused as the CLI refuses it (exit 2), then a route
    outside the judge's is NEED_USER_INPUT judge_route. Nothing is read or sent first.
    """
    policy = own_policy or chosen.search_policy or "legacy-v1"
    if own_policy and chosen.search_policy and own_policy != chosen.search_policy:
        print("run_catalog: --search-policy differs between the runner and the "
              "forwarded arguments.", file=sys.stderr)
        return 2
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
                     chosen.encoding)


def judge_prices(selection: Selection) -> tuple[Decimal, Decimal]:
    """The judge's list prices (USD per million input and output tokens) on its route."""
    route = judge_route(selection.judge, selection.route)
    spec = ROUTE_SPECS[route.selector].model(route.model)
    return spec.price_in_per_mtok, spec.price_out_upper_per_mtok


def case_cost(result: dict, prices: tuple[Decimal, Decimal]) -> Decimal:
    """A finished case's cost: the provider-reported amount, else the report's estimate,
    else its token usage at the judge's list price."""
    for key in ("provider_reported_usd", "estimated_usd"):
        amount = result.get(key)
        if isinstance(amount, str) and USD_AMOUNT.fullmatch(amount):
            return Decimal(amount)
    usage = result.get("usage") or {}
    tokens_in, tokens_out = usage.get("input_tokens"), usage.get("output_tokens") or 0
    if (type(tokens_in) is int and type(tokens_out) is int
            and tokens_in >= 0 and tokens_out >= 0):
        return list_price(tokens_in, tokens_out, *prices)
    return Decimal(0)


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
    # each of at most the request caps. The engine sends one per flagged cluster, so a
    # longer file can send more: the CLI's --max-calls and --max-cost are the hard per-case
    # bounds, and these totals are projections, not a worst case.
    worst += fits * plans.MAX_REQUEST_BYTES
    bound += fits * attempt_cost_bound(plans.MAX_REQUEST_BYTES, plans.MAX_QUESTIONS,
                                       price_in, price_out)
    print(f"Totals: {tiles} tile requests, <= {fits} focus, {fallbacks} legacy fallback(s); "
          f"projected request bytes {worst:,}; projected cost bound ${money(bound)} at "
          f"{selection.judge} ${format(price_in, 'f')} per million input tokens "
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
    selection = select(forwarded_choices(extra), args.search_policy)
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
                  "spent_usd": format(spent, "f"), "stopped_at_case": stopped, "cases": rows}
        (out / "results.json").write_text(json.dumps(record, indent=1), encoding="utf-8")

    for case in cases:
        if args.max_total_cost is not None and spent >= args.max_total_cost:
            stopped = case["id"]
            print(f"Stopping before {stopped}: the summed cost ${money(spent)} reached "
                  f"--max-total-cost ${args.max_total_cost}.")
            break
        result = run_case(case, extra, keep)
        result["cost_usd"] = format(case_cost(result, prices), "f")
        spent += Decimal(result["cost_usd"])
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
