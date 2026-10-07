"""Command line entry point; importing this module performs no review."""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
from decimal import Decimal, InvalidOperation
import json
import os
from pathlib import Path
import sys
import tempfile
import time

from .core import (Config, Source, format_findings, scan, STATE_LAYOUTS,
                   DEFAULT_STATE_LAYOUT, CHOICE_GATES, LOCALIZATION_MENUS,
                   CANARY_MODES, DEFAULT_CANARIES)
from .handoff import compact_report, format_handoff
from .protocol import (ProviderError, DEFAULT_CHOICE_ROUNDING_PLACES, POLICY_PLACEMENTS,
                       DEFAULT_POLICY_PLACEMENT)
from .providers import (ROUTES, RetryPolicy, ValidatedGateway, validate_call_deadline,
                        validate_max_cost)
from . import providers
from .decisions import (CREDENTIAL_VARIABLE, ORGANIZATION_VARIABLE, PROJECT_VARIABLE,
                        DecisionsProvider)
from .hosted import CREDENTIAL_VARIABLES
from .openrouter import (CREDENTIAL_VARIABLE as OPENROUTER_CREDENTIAL_VARIABLE,
                         DEFAULT_ROUTING, ROUTING_CHOICES)
from .repository import CACHEDIR_SIGNATURE, ProjectIndex
from . import secret_scan

#: Explicit route selection; never inferred from which key happens to be set.
PROVIDER_VARIABLE = "DBH_PROVIDER"
PROVIDER_CHOICES = tuple(ROUTES)
_CREDENTIALS = {"openai": CREDENTIAL_VARIABLE, "openrouter": OPENROUTER_CREDENTIAL_VARIABLE}
ACCOUNT_DEFAULT_DISCLOSURE = (
    "OpenRouter routing: account default. The request carries no data_collection "
    "deny and no fallback restriction; your OpenRouter account settings decide "
    "which providers may receive the source.")


class SafeParser(argparse.ArgumentParser):
    """Do not echo arbitrary arguments, paths, or possible secrets on failure."""

    def error(self, message: str) -> None:
        self.exit(2, "Invalid command-line arguments; use --help for usage.\n")


def decimal_argument(value: str) -> Decimal:
    try:
        result = Decimal(value)
    except InvalidOperation:
        raise argparse.ArgumentTypeError("Expected a decimal number.") from None
    if not result.is_finite():
        raise argparse.ArgumentTypeError("Expected a finite number.")
    return result


def parser() -> argparse.ArgumentParser:
    result = SafeParser(
        prog="decision-bug-hunter",
        description=(
            "Use bounded finite-answer judgments to locate suspected bugs in a text "
            "file. Findings are suspicions, not verified defects."
        ),
    )
    result.add_argument("file", type=Path)
    result.add_argument("--spec-file", type=Path)
    result.add_argument("--encoding", default="utf-8-sig")
    result.add_argument("--width", type=int, default=48)
    result.add_argument("--min-width", type=int, default=12)
    result.add_argument("--max-depth", type=int, default=4)
    result.add_argument("--context-lines", type=int, default=12)
    result.add_argument("--inspect-threshold", "--drill-threshold", dest="drill_threshold",
                        help="Detailed-search threshold; does not gate speculative screening.",
                        type=decimal_argument,
                        default=Decimal("0.60"))
    result.add_argument("--report-threshold", type=decimal_argument,
                        default=Decimal("0.80"))
    result.add_argument("--search-policy", choices=("legacy-v1", "scoped-v2-beta"),
                        default="legacy-v1", help="Opt in to scoped verification and exploratory beams.")
    result.add_argument("--refute-threshold", type=decimal_argument, default=Decimal("0.80"),
                        help="Explicit-refutation threshold for scoped-v2-beta only.")
    result.add_argument("--state-layout", choices=STATE_LAYOUTS, default=DEFAULT_STATE_LAYOUT,
                        help="Request state layout and matching policy preamble "
                             "(default: %(default)s, the pre-release layout; v2 puts the "
                             "DBH-written fields first and warns about envelope imitation). "
                             "Recorded in the report configuration.")
    result.add_argument("--policy-placement", choices=POLICY_PLACEMENTS,
                        default=DEFAULT_POLICY_PLACEMENT,
                        help="Where the policy preamble goes (default: %(default)s, prefixed "
                             "to every question, the b1 request bytes). state sends it once as "
                             "the first state key; on OpenRouter those requests may then hold "
                             "up to 200 questions and 48 KiB (OpenAI direct keeps 64 and "
                             "24 KiB). Answers shift under state placement, so compare it only "
                             "with runs that used it; recorded in the report configuration and "
                             "request_geometry.")
    result.add_argument("--max-calls", type=int, default=1000)
    result.add_argument("--max-questions", type=int, default=20000)
    result.add_argument("--max-windows", type=int, default=50000)
    result.add_argument("--max-context-packets", type=int, default=8)
    result.add_argument("--max-localizations", type=int, default=4)
    result.add_argument("--context-threshold", type=decimal_argument,
                        default=Decimal("0.60"))
    result.add_argument("--choice-confidence", type=decimal_argument,
                        default=Decimal("0.50"))
    profiles = result.add_mutually_exclusive_group()
    profiles.add_argument("--choice-rounding-places", type=int, choices=range(2, 9),
                        default=DEFAULT_CHOICE_ROUNDING_PLACES,
                        help="Opt-in Choice mass tolerance for nearest rounding at N places "
                             "(default: strict mass).")
    profiles.add_argument("--strict-choice-mass", action="store_true",
                        help="Compatibility no-op: strict Choice mass is already the default.")
    result.add_argument("--localization-beam-width", type=int, default=3,
                        help="Maximum candidate intervals per localization round; each keeps the confidence gate.")
    result.add_argument("--choice-gate", choices=CHOICE_GATES, default="legacy",
                        help="Localization gate (default: %(default)s, min(confidence, p[choice]) "
                             ">= --choice-confidence). mass selects up to --localization-beam-width "
                             "line runs whose lower-bound overlap mass reaches --choice-mass while "
                             "none + unlocalized stays below 0.5; legacy-v1 only (scoped-v2-beta "
                             "does not gate localization). Rank, context and action choices keep "
                             "the legacy gate.")
    result.add_argument("--choice-mass", type=decimal_argument, default=Decimal("0.5"),
                        help="Per-line overlap mass for --choice-gate mass, in (0, 1] "
                             "(default: %(default)s).")
    result.add_argument("--localization-menu", choices=LOCALIZATION_MENUS, default="intervals",
                        help="Localization options (default: %(default)s, every complete "
                             "interval of the target; singletons offers one option per line).")
    result.add_argument("--choice-rounding-caps", action="store_true",
                        help="With --choice-rounding-places N, cap choice menus so options x "
                             "half-quantum <= 0.125: smaller rank and context pages, singleton "
                             "localization menus over the cap, and a choice_mass_diffuse count. "
                             "No effect under strict mass (default: off).")
    result.add_argument("--canaries", choices=CANARY_MODES, default=DEFAULT_CANARIES,
                        help="Judge controls (default: %(default)s): two yes/no questions "
                             "with known answers ride in every request; a request whose "
                             "controls fail (must-true < 0.90 or must-false > 0.10) has all "
                             "its answers withheld and leaves the scan incomplete "
                             "(judge_control_failed). off sends the pre-control request bytes.")
    result.add_argument("--polarity-twin", action="store_true",
                        help="Diagnostic only (default: off): also ask each screened window "
                             "the inverted question and report |P(bug) + P(correct) - 1| in "
                             "judge_diagnostics.polarity_twin; never changes findings.")
    result.add_argument("--max-handoff-candidates", type=int, default=64,
                        help="Candidate cap per reference kind per finding; omissions are flagged.")
    result.add_argument("--no-bug-lenses", action="store_true",
                        help="Disable the additional parallel bug-lens questions.")
    result.add_argument("--max-action-steps", type=int, default=4)
    result.add_argument("--max-action-targets", type=int, default=32)
    result.add_argument("--evidence-min-width", type=int, default=8)
    result.add_argument("--evidence-beam-width", type=int, default=3)
    result.add_argument("--evidence-max-depth", type=int, default=4)
    result.add_argument("--max-evidence-candidates", type=int, default=96)
    result.add_argument("--relation-threshold", type=decimal_argument,
                        default=Decimal("0.70"))
    result.add_argument("--max-relationships", type=int, default=4)
    result.add_argument("--scope", choices=("project", "standalone", "isolate"),
                        default=None,
                        help="Required caller declaration: project (related "
                             "files may be searched), standalone (none exist), "
                             "isolate (judge this file only). Never inferred.")
    result.add_argument("--project-root", type=Path,
                        help="Related directory; required with --scope project, "
                             "forbidden otherwise.")
    result.add_argument("--max-project-files", type=int, default=128)
    result.add_argument("--max-project-file-bytes", type=int, default=1048576)
    result.add_argument("--max-project-total-bytes", type=int, default=16777216)
    result.add_argument("--max-project-candidates", type=int, default=128)
    result.add_argument("--output-format", choices=("compact", "ranges", "json"),
                        default="compact", help="Stdout only; all formats are also saved.")
    result.add_argument("--no-whole-file", action="store_true")
    result.add_argument("--output-dir", type=Path,
                        default=Path("dbh_runs"))
    result.add_argument("--provider", choices=PROVIDER_CHOICES, default=None,
                        help="Required route: openai (OPENAI_API_KEY, api.openai.com) or "
                             "openrouter (OPENROUTER_API_KEY, openrouter.ai); "
                             f"or set {PROVIDER_VARIABLE}. Never inferred.")
    result.add_argument("--model", default=None,
                        help="Allow-listed model id for the route (default: gpt-6-luna "
                             "for openai, openai/gpt-6-luna-decisions for openrouter).")
    result.add_argument("--openrouter-routing", choices=ROUTING_CHOICES,
                        default=DEFAULT_ROUTING,
                        help="deny (default) sends allow_fallbacks false and "
                             "data_collection deny; account-default omits them.")
    result.add_argument("--openrouter-zdr", action="store_true",
                        help="Also request zero-data-retention endpoints (none "
                             "existed on 2026-10-06).")
    result.add_argument("--deadline-seconds", type=float, default=30.0)
    result.add_argument("--run-deadline-seconds", type=float, default=1800.0,
                        help="Cooperative run work deadline, including indexing; hosted calls use remaining time.")
    result.add_argument("--no-retry", action="store_true",
                        help="One attempt per request: no retries after connect failures, "
                             "rate limits, overload or a stale keep-alive connection.")
    result.add_argument("--max-cost", type=decimal_argument, default=None, metavar="USD",
                        help="Stop before any attempt (retries included) whose cost bound "
                             "could take reported, estimated and unknown-usage spend above "
                             "USD (default: unset).")
    result.add_argument("--allow-secrets", action="store_true",
                        help="Send the file and specification even when they hold "
                             "credential-shaped text (default: refuse with "
                             "secret_detected). Project files with such text are "
                             "always skipped.")
    return result


def write_new(path: Path, text: str) -> None:
    """Only create new private files inside the unique run directory."""
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as handle:
        handle.write(text)


#: Marks DBH output as untracked and as a cache for backup and index tools.
GITIGNORE_TEXT = "*\n"
CACHEDIR_TAG_TEXT = (CACHEDIR_SIGNATURE.decode("ascii") + "\n"
                     "# This file is a cache directory tag created by decision-bug-hunter.\n"
                     "# For information about cache directory tags see "
                     "https://bford.info/cachedir/\n")


def mark_output_directory(directory: Path) -> None:
    """Keep run output out of version control, backups and DBH's own indexer."""
    write_new(directory / ".gitignore", GITIGNORE_TEXT)
    write_new(directory / "CACHEDIR.TAG", CACHEDIR_TAG_TEXT)


def make_output_parent(parent: Path) -> bool:
    """Create the output parent if needed; True only if this call created it.

    A parent that already existed is never written to: a ``.gitignore`` there
    could hide a user's own repository content.
    """
    parent.parent.mkdir(parents=True, exist_ok=True)
    try:
        parent.mkdir(mode=0o700)
    except FileExistsError:
        return False
    return True


def failure(code: str, provider: str | None = None) -> int:
    print(f"Scan failed ({code}).", file=sys.stderr)
    if code == "provider_unavailable":
        if provider in _CREDENTIALS:
            print(f"Set {_CREDENTIALS[provider]} in the environment to enable the "
                  f"{provider} route; see README.md.", file=sys.stderr)
        else:
            print(f"Set {CREDENTIAL_VARIABLE} (--provider openai) or "
                  f"{OPENROUTER_CREDENTIAL_VARIABLE} (--provider openrouter) in the "
                  "environment; see README.md.", file=sys.stderr)
    elif code == "invalid_provider":
        # The value is never echoed.
        print(f"{PROVIDER_VARIABLE} must be one of: {', '.join(PROVIDER_CHOICES)}.",
              file=sys.stderr)
    elif code == "secret_detected":
        print("Remove the credential-shaped text, or pass --allow-secrets if it is "
              "not a live credential; nothing was sent.", file=sys.stderr)
    elif code == "routing_invalid":
        # Name the variables only; their values are never printed.
        print(f"{ORGANIZATION_VARIABLE} or {PROJECT_VARIABLE} is set but is not a "
              "single-line printable token; correct or unset it.", file=sys.stderr)
    return 2


def need_user_input(field: str, hint: str) -> int:
    """Machine-readable scope contract for human and AI callers."""
    print(f"NEED_USER_INPUT {field}: {hint}", file=sys.stderr)
    return 3


class ProviderChoiceNeeded(Exception):
    """No route was selected; the caller must choose the data processor."""


def selected_provider(args: argparse.Namespace,
                      environ: dict[str, str] | None = None) -> str:
    """``--provider``, else ``DBH_PROVIDER``; never inferred from set keys.

    An unknown ``DBH_PROVIDER`` raises ``invalid_provider``; neither source
    raises ``ProviderChoiceNeeded``.
    """
    choice = getattr(args, "provider", None)
    if choice is not None:
        if choice not in PROVIDER_CHOICES:
            raise ProviderError("invalid_provider")
        return str(choice)
    env = os.environ if environ is None else environ
    value = env.get(PROVIDER_VARIABLE, "")
    if not value:
        raise ProviderChoiceNeeded()
    if value not in PROVIDER_CHOICES:
        raise ProviderError("invalid_provider")
    return value


def provider_choice_hint(environ: dict[str, str] | None = None) -> str:
    """Route names and the names (never values) of credential variables set."""
    env = os.environ if environ is None else environ
    present = [name for name in CREDENTIAL_VARIABLES if env.get(name)]
    return " | ".join(PROVIDER_CHOICES) + f" (set: {', '.join(present) or 'none'})"


def make_provider(args: argparse.Namespace) -> providers.DecisionProvider:
    """The provider for this run; the single construction point tests replace.

    Selection is explicit (``--provider`` or ``DBH_PROVIDER``); ``--model``
    is checked against the route's allow-list. Construction reads the
    environment once and never touches the network.
    """
    route = selected_provider(args)
    args.selected_provider = route
    model = getattr(args, "model", None)
    if route == "openai":
        if (getattr(args, "openrouter_routing", DEFAULT_ROUTING) != DEFAULT_ROUTING
                or getattr(args, "openrouter_zdr", False)):
            # OpenRouter privacy options never silently apply to another route.
            raise ProviderError("invalid_request")
        if model is None:
            # The documented construction, kept as the patchable name.
            return DecisionsProvider()
        return providers.make_provider("openai", model=model)
    return providers.make_provider(
        "openrouter", model=model,
        routing=getattr(args, "openrouter_routing", DEFAULT_ROUTING),
        zdr=bool(getattr(args, "openrouter_zdr", False)),
        policy_placement=getattr(args, "policy_placement", DEFAULT_POLICY_PLACEMENT))


def check_secrets(source: Source, spec: Source | None, allow: bool) -> str:
    """Scan the target and specification before anything else uses them.

    Returns ``"clean"`` or, with *allow*, ``"overridden"``; otherwise a hit
    raises ``secret_detected`` after naming pattern ids and line numbers
    (never the matched text) on stderr.
    """
    found = False
    for label, item in (("file", source), ("specification", spec)):
        if item is None:
            continue
        hits = secret_scan.scan_lines(item.lines)
        if hits:
            found = True
            print(secret_scan.describe(label, hits), file=sys.stderr)
    if not found:
        return "clean"
    if not allow:
        raise ProviderError("secret_detected")
    print("--allow-secrets: the credential-shaped text above will be sent.",
          file=sys.stderr)
    return "overridden"


def make_gateway(provider, receipt_dir, **kwargs):
    return ValidatedGateway(provider, receipt_dir, **kwargs)


def execute(args: argparse.Namespace) -> int:
    # Scope is the caller's explicit contract; the tool never infers it.
    if args.scope is None:
        return need_user_input(
            "project_scope", "provide project directory | standalone | isolate")
    if args.scope == "project" and args.project_root is None:
        return need_user_input("project_root", "provide related directory")
    if args.scope != "project" and args.project_root is not None:
        return need_user_input(
            "conflicting_options",
            "--project-root conflicts with --scope standalone | isolate")
    if args.scope == "project" and not args.project_root.is_dir():
        print("Scan failed (project_root_invalid).", file=sys.stderr)
        return 2
    started_at = datetime.now(timezone.utc).isoformat()
    started_monotonic = time.monotonic()
    config = Config(
        width=args.width,
        min_width=args.min_width,
        max_depth=args.max_depth,
        context_lines=args.context_lines,
        drill_threshold=args.drill_threshold,
        report_threshold=args.report_threshold,
        search_policy=args.search_policy,
        refute_threshold=args.refute_threshold,
        state_layout=args.state_layout,
        max_calls=args.max_calls,
        max_questions=args.max_questions,
        max_windows=args.max_windows,
        max_context_packets=args.max_context_packets,
        max_localizations=args.max_localizations,
        context_threshold=args.context_threshold,
        choice_confidence=args.choice_confidence,
        whole_file=not args.no_whole_file,
        max_handoff_candidates=args.max_handoff_candidates,
        bug_lenses=not args.no_bug_lenses,
        max_action_steps=args.max_action_steps,
        max_action_targets=args.max_action_targets,
        evidence_min_width=args.evidence_min_width,
        evidence_beam_width=args.evidence_beam_width,
        evidence_max_depth=args.evidence_max_depth,
        max_evidence_candidates=args.max_evidence_candidates,
        relation_threshold=args.relation_threshold,
        max_relationships=args.max_relationships,
        max_project_candidates=args.max_project_candidates,
        localization_beam_width=args.localization_beam_width,
        run_deadline_seconds=args.run_deadline_seconds,
        choice_gate=args.choice_gate,
        choice_mass=args.choice_mass,
        localization_menu=args.localization_menu,
        choice_rounding_caps=args.choice_rounding_caps,
        canaries=args.canaries,
        polarity_twin=args.polarity_twin,
        policy_placement=args.policy_placement,
    )
    deadline_at = started_monotonic + config.run_deadline_seconds
    # Validated before any output directory exists, never after mkdtemp.
    call_deadline = validate_call_deadline(args.deadline_seconds)
    max_cost = validate_max_cost(getattr(args, "max_cost", None))
    # The route is the caller's explicit choice of data processor; it and
    # availability are checked before source reads, indexing, or output writes.
    try:
        provider = make_provider(args)
    except ProviderChoiceNeeded:
        return need_user_input("provider", provider_choice_hint())
    provider.require_available()
    if getattr(provider, "routing", None) == "account-default":
        print(ACCOUNT_DEFAULT_DISCLOSURE, file=sys.stderr)
    source = Source.read(args.file, encoding=args.encoding)
    spec = None
    if args.spec_file is not None:
        spec_source = Source.read(
            args.spec_file, encoding=args.encoding,
            max_bytes=8192, max_lines=2000,
        )
        spec = spec_source
    target_scan = check_secrets(source, spec, bool(getattr(args, "allow_secrets", False)))
    parent = args.output_dir.resolve()
    project = None
    if args.scope == "project":
        project = ProjectIndex.read(
            args.project_root, primary_path=args.file, encoding=args.encoding,
            max_files=args.max_project_files,
            max_file_bytes=args.max_project_file_bytes,
            max_total_bytes=args.max_project_total_bytes,
            exclude_paths=(parent, args.spec_file),
            deadline_at=deadline_at,
        )

    # Check all source content, including text outside any submitted window.
    # Checking the output path before mkdir also prevents secret-bearing paths.
    provider.check_sensitive(
        source.name, "\n".join(source.lines),
        "\n".join(spec.lines) if spec is not None else None,
        str(args.file), str(args.spec_file), str(parent),
        *([item for entry in project.entries for item in
           (entry.relpath, "\n".join(entry.source.lines))] if project else []),
    )
    if make_output_parent(parent):
        mark_output_directory(parent)
    run_dir = Path(tempfile.mkdtemp(prefix="run-", dir=parent))
    mark_output_directory(run_dir)
    print(f"Results run: {json.dumps(run_dir.name)}", file=sys.stderr)
    gateway = make_gateway(
        provider, run_dir / "receipts", deadline_seconds=call_deadline,
        rounding_places=(None if args.strict_choice_mass
                         else args.choice_rounding_places),
        retry_policy=RetryPolicy.none() if getattr(args, "no_retry", False) else RetryPolicy(),
        progress=sys.stderr,
        max_cost=max_cost,
    )
    result = None
    try:
        if spec is None:
            print(
                "Intent is inferred from the file; no specification was supplied.",
                file=sys.stderr,
            )
        result = scan(source, gateway, config=config, spec=spec, project=project,
                      context_scope={"project": "project",
                                     "standalone": "declared_standalone",
                                     "isolate": "owner_isolated"}[args.scope],
                      deadline_at=deadline_at,
                      secret_scan={"target": target_scan,
                                   "project_files_skipped":
                                       project.skipped_secret_content if project else 0})
    finally:
        # The CLI owns this gateway. Finish cleanup before saving or printing
        # any complete report; a library scan instead borrows its gateway.
        cleanup_error = None
        try:
            gateway.close()
        except ProviderError as exc:
            cleanup_error = exc.code
        except Exception:
            cleanup_error = "transport_failed"
        if cleanup_error:
            print(f"Transport cleanup failed ({cleanup_error}); scan is incomplete.",
                  file=sys.stderr)
            if result is not None:
                # Preserve every finding and known usage counter. Cleanup is
                # an execution limitation, not a fabricated semantic answer.
                result["cleanup_error"] = cleanup_error
                if source.lines:
                    result["issues"].append({"code": cleanup_error,
                        "range": [1, len(source.lines)], "phase": "transport-cleanup",
                        "affects_completion": True})
                result["status"] = result["scan_status"] = result["handoff_status"] = "incomplete"
                if "execution_status" in result:
                    result["execution_status"] = "incomplete"
                result["handoff"] = compact_report(result)
    result["run_id"] = run_dir.name
    result["started_at_utc"] = started_at
    result["finished_at_utc"] = datetime.now(timezone.utc).isoformat()
    report_text = json.dumps(
        result, ensure_ascii=True, indent=2, allow_nan=False,
    ) + "\n"
    findings_text = format_handoff(result["handoff"])
    ranges_text = format_findings(result)
    handoff_text = json.dumps(result["handoff"], ensure_ascii=True,
                              separators=(",", ":"), allow_nan=False) + "\n"
    gateway.check_sensitive(report_text, findings_text, ranges_text, handoff_text)
    write_new(run_dir / "report.json", report_text)
    write_new(run_dir / "findings.txt", findings_text)
    write_new(run_dir / "handoff.json", handoff_text)
    write_new(run_dir / "ranges.txt", ranges_text)
    sys.stdout.write({"compact": findings_text, "ranges": ranges_text,
                      "json": handoff_text}[args.output_format])
    if result.get("stop_reason"):
        # A fixed DBH code; never a provider message.
        print(f"Provider stopped ({result['stop_reason']}); remaining work was not sent.",
              file=sys.stderr)
    spend = result.get("spend")
    if isinstance(spend, dict) and spend.get("upper_bound_usd") is not None:
        print(f"Spend (USD): provider-reported {spend['provider_reported_usd']}, "
              f"estimated {spend['estimated_usd']}, unknown-usage bound "
              f"{spend['unknown_usage_upper_bound_usd']}.", file=sys.stderr)
    complete = result["status"] == "complete"
    count = len(result["findings"])
    status = "complete" if complete else "incomplete"
    attempted = result["calls_attempted"]
    assessed = result["coverage"]["assessed_lines"]
    print(
        f"Scan {status}; {count} suspected region(s); {attempted} call(s) "
        f"attempted; {assessed}/{len(source.lines)} source lines assessed.",
        file=sys.stderr,
    )
    if not complete:
        return 2
    return 1 if count else 0


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    try:
        return execute(args)
    except ProviderError as error:
        return failure(error.code, getattr(args, "selected_provider", None)
                       or getattr(args, "provider", None))
    except (UnicodeError, LookupError):
        return failure("input_encoding_error")
    except OSError:
        return failure("file_io_error")
    except (ValueError, TypeError):
        return failure("invalid_input_or_configuration")
    except KeyboardInterrupt:
        return failure("interrupted")
    except Exception:
        # Never expose exception text or its chained provider/source content.
        return failure("unexpected_error")


if __name__ == "__main__":
    raise SystemExit(main())
