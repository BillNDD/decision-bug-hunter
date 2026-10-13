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
                   DEFAULT_STATE_LAYOUT, CHOICE_GATES, DEFAULT_CHOICE_GATE,
                   LOCALIZATION_MENUS, SEARCH_POLICIES,
                   CANARY_MODES, DEFAULT_CANARIES)
from .handoff import compact_report, format_handoff
from .protocol import (ProviderError, DEFAULT_CHOICE_ROUNDING_PLACES, POLICY_PLACEMENTS,
                       DEFAULT_POLICY_PLACEMENT)
from .providers import (ALL_ROUTES, RetryPolicy, ValidatedGateway, validate_call_deadline,
                        validate_max_cost)
from . import providers
from .decisions import (CREDENTIAL_VARIABLE, ORGANIZATION_VARIABLE, PROJECT_VARIABLE,
                        DecisionsProvider)
from .foundry import (API_KEY_VARIABLE as FOUNDRY_API_KEY_VARIABLE, AUTH_MODES,
                      DEPLOYMENT_VARIABLE as FOUNDRY_DEPLOYMENT_VARIABLE,
                      ENDPOINT_VARIABLE as FOUNDRY_ENDPOINT_VARIABLE,
                      TOKEN_VARIABLE as FOUNDRY_TOKEN_VARIABLE)
from .hosted import CREDENTIAL_VARIABLES
from .judges import JUDGE_CHOICES, JUDGES, judge_route
from .openrouter import (CREDENTIAL_VARIABLE as OPENROUTER_CREDENTIAL_VARIABLE,
                         DEFAULT_ROUTING, ROUTING_CHOICES)
from .repository import CACHEDIR_SIGNATURE, ProjectIndex
from . import secret_scan

#: Explicit judge selection; never implied by the route or by which key is set.
JUDGE_VARIABLE = "DBH_JUDGE"
#: Explicit route selection; never inferred from which key happens to be set.
PROVIDER_VARIABLE = "DBH_PROVIDER"
PROVIDER_CHOICES = tuple(ALL_ROUTES)
_CREDENTIALS = {"openai": CREDENTIAL_VARIABLE, "openrouter": OPENROUTER_CREDENTIAL_VARIABLE}
#: The key variables each route reads, for the NEED_USER_INPUT provider hint.
_ROUTE_VARIABLES = {"openai": (CREDENTIAL_VARIABLE,),
                    "openrouter": (OPENROUTER_CREDENTIAL_VARIABLE,),
                    "foundry": (FOUNDRY_API_KEY_VARIABLE, FOUNDRY_TOKEN_VARIABLE)}
_FOUNDRY_VARIABLES = {"api-key": FOUNDRY_API_KEY_VARIABLE,
                      "entra-token": FOUNDRY_TOKEN_VARIABLE}
JUDGE_CHOICE_HINT = (
    "openai (OpenAI Decisions gpt-6-luna; routes openai | openrouter) | "
    "microsoft (Microsoft-Decision-1; routes openrouter | foundry)")
#: The opt-in whole-file search policy; its options and judge are checked up front.
TILE_SIEVE = "tile-sieve-beta"
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
    result.add_argument("--search-policy", choices=SEARCH_POLICIES, default="legacy-v1",
                        help="Search policy (default: %(default)s). scoped-v2-beta opts in to "
                             "scoped verification and exploratory beams. tile-sieve-beta is an "
                             "opt-in whole-file beta calibrated for the OpenAI judge only: a "
                             "file that fits in one request (about 200 lines of typical code) "
                             "is read in one or two whole-file looks, then each flagged "
                             "region gets one focus request (no stage 2); strong regions "
                             "report at a lower bar. A larger file is scanned with "
                             "legacy-v1, and stderr and the report say so. It needs "
                             "--canaries on, --state-layout v1 and "
                             "--policy-placement instructions, refuses --polarity-twin, "
                             "--require-verification and --judge microsoft, and uses the other "
                             "options only for that fallback.")
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
                        default=Decimal("0.50"),
                        help="Confidence gate for rank, context and action choices, and for "
                             "localization under --choice-gate legacy (default: %(default)s).")
    profiles = result.add_mutually_exclusive_group()
    profiles.add_argument("--choice-rounding-places", type=int, choices=range(2, 9),
                        default=DEFAULT_CHOICE_ROUNDING_PLACES,
                        help="Opt-in Choice mass tolerance for nearest rounding at N places "
                             "(default: strict mass).")
    profiles.add_argument("--strict-choice-mass", action="store_true",
                        help="Compatibility no-op: strict Choice mass is already the default.")
    result.add_argument("--localization-beam-width", type=int, default=3,
                        help="Maximum candidate intervals (line runs under --choice-gate mass) "
                             "per localization round; each must pass the localization gate.")
    result.add_argument("--choice-gate", choices=CHOICE_GATES, default=DEFAULT_CHOICE_GATE,
                        help="Localization gate (default: %(default)s). mass selects up to "
                             "--localization-beam-width line runs whose lower-bound overlap mass "
                             "reaches --choice-mass while none + unlocalized stays below 0.5; "
                             "legacy is min(confidence, p[choice]) >= --choice-confidence. "
                             "legacy-v1 only (scoped-v2-beta does not gate localization). Rank, "
                             "context and action choices keep the legacy gate.")
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
    result.add_argument("--require-verification", action="store_true",
                        help="Report only suspicions supported by a second look (a direct "
                             "recheck, a relationship recheck, or a scoped verification); "
                             "screen-only suspicions are listed as unverified_suspicions in "
                             "report.json and handoff.json, not as findings (default: off).")
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
    result.add_argument("--judge", choices=JUDGE_CHOICES, default=None,
                        help="Required decision model: openai (OpenAI Decisions gpt-6-luna; "
                             "routes openai | openrouter) or microsoft (Microsoft-Decision-1, "
                             "experimental; routes openrouter | foundry); "
                             f"or set {JUDGE_VARIABLE}. Never inferred.")
    result.add_argument("--provider", choices=PROVIDER_CHOICES, default=None,
                        help="Required route of the judge: openai (OPENAI_API_KEY, "
                             "api.openai.com), openrouter (OPENROUTER_API_KEY, openrouter.ai) "
                             "or foundry (Microsoft Foundry, Microsoft judge only; "
                             f"{FOUNDRY_API_KEY_VARIABLE} or {FOUNDRY_TOKEN_VARIABLE}; not yet "
                             f"verified live); or set {PROVIDER_VARIABLE}. Never inferred.")
    result.add_argument("--model", default=None,
                        help="Allow-listed model id for the judge's route (default: gpt-6-luna "
                             "for openai, openai/gpt-6-luna-decisions or "
                             "microsoft/microsoft-decision-1 for openrouter, by judge). Not "
                             "used with foundry: the deployment names the model there.")
    result.add_argument("--foundry-endpoint", default=None, metavar="URL",
                        help="Microsoft Foundry resource endpoint, https://<resource>."
                             "services.ai.azure.com (foundry only; or set "
                             f"{FOUNDRY_ENDPOINT_VARIABLE}). Not yet verified live.")
    result.add_argument("--foundry-deployment", default=None, metavar="NAME",
                        help="Microsoft Foundry deployment name, sent as the model (foundry "
                             f"only; or set {FOUNDRY_DEPLOYMENT_VARIABLE}). Not yet verified "
                             "live.")
    result.add_argument("--foundry-auth", choices=AUTH_MODES, default=None,
                        help=f"Foundry credential: api-key ({FOUNDRY_API_KEY_VARIABLE}) or "
                             f"entra-token ({FOUNDRY_TOKEN_VARIABLE}, a pre-acquired token that "
                             "DBH never refreshes). Needed only when both variables are set.")
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
    except OSError:
        # Windows raises PermissionError, not FileExistsError, for an
        # existing drive root (and some shares do the same).
        if parent.is_dir():
            return False
        raise
    return True


def failure(code: str, provider: str | None = None, judge: str | None = None,
            auth: str | None = None, detail: str | None = None) -> int:
    # The detail is fixed DBH text naming a flag or a judge, never user input.
    shown = code if detail is None else f"{code}: {detail}"
    print(f"Scan failed ({shown}).", file=sys.stderr)
    if code == "provider_unavailable":
        if provider == "foundry":
            print(f"Set {FOUNDRY_API_KEY_VARIABLE} (--foundry-auth api-key) or "
                  f"{FOUNDRY_TOKEN_VARIABLE} (--foundry-auth entra-token) in the "
                  "environment to enable the foundry route; see README.md.", file=sys.stderr)
        elif provider in _CREDENTIALS:
            print(f"Set {_CREDENTIALS[provider]} in the environment to enable the "
                  f"{provider} route; see README.md.", file=sys.stderr)
        else:
            print(f"Set {CREDENTIAL_VARIABLE} (--provider openai) or "
                  f"{OPENROUTER_CREDENTIAL_VARIABLE} (--provider openrouter) in the "
                  "environment; see README.md.", file=sys.stderr)
    elif code == "invalid_provider":
        # The value is never echoed; the routes are those of the chosen judge.
        print(f"{PROVIDER_VARIABLE} must be one of: "
              f"{', '.join(judge_selectors(judge))}.", file=sys.stderr)
    elif code == "invalid_judge":
        # The value is never echoed.
        print(f"{JUDGE_VARIABLE} must be one of: {', '.join(JUDGE_CHOICES)}.",
              file=sys.stderr)
    elif code == "endpoint_invalid":
        # The value is never echoed: it names the owner's resource.
        print("The Foundry endpoint must be https://<resource>.services.ai.azure.com "
              "(or .cognitiveservices.azure.com or .openai.azure.com) with no path, "
              "query or port; see README.md.", file=sys.stderr)
    elif code == "http_unauthorized" and auth == "entra-token":
        print(unauthorized_hint(), file=sys.stderr)
    elif code == "secret_detected":
        print("Remove the credential-shaped text, or pass --allow-secrets if it is "
              "not a live credential; nothing was sent.", file=sys.stderr)
    elif code == "routing_invalid":
        # Name the variables only; their values are never printed.
        print(f"{ORGANIZATION_VARIABLE} or {PROJECT_VARIABLE} is set but is not a "
              "single-line printable token; correct or unset it.", file=sys.stderr)
    return 2


def unauthorized_hint() -> str:
    """What to do when a pre-acquired Entra token was refused (it may have expired)."""
    return (f"The {FOUNDRY_TOKEN_VARIABLE} token was refused; it may have expired. "
            "DBH never refreshes it: acquire a new one and run again.")


def need_user_input(field: str, hint: str) -> int:
    """Machine-readable scope contract for human and AI callers."""
    print(f"NEED_USER_INPUT {field}: {hint}", file=sys.stderr)
    return 3


class SearchPolicyRefused(Exception):
    """The search policy cannot run with these options or this judge."""

    def __init__(self, detail: str) -> None:
        super().__init__(detail)
        self.detail = detail


class JudgeChoiceNeeded(Exception):
    """No judge was selected; the caller must choose the decision model."""


class ProviderChoiceNeeded(Exception):
    """No route was selected; the caller must choose the data processor."""


class JudgeRouteMismatch(Exception):
    """The route is not one of the selected judge's routes."""


class FoundryInputNeeded(Exception):
    """A Foundry setting the caller must supply: its field name and a hint."""

    def __init__(self, field: str, hint: str) -> None:
        super().__init__(field)
        self.field = field
        self.hint = hint


def tile_sieve_conflict(args: argparse.Namespace) -> str | None:
    """Why the options conflict with tile-sieve-beta, as the text after the
    colon of ``invalid_search_configuration``; None when they do not.

    The thresholds were measured with canaries on and layout v1, the policy
    always travels in the request state, and the polarity twin and verification
    gating have no meaning there: ``Config`` refuses the same combinations.
    """
    if args.search_policy != TILE_SIEVE:
        return None
    if args.canaries != "on":
        return f"{TILE_SIEVE} needs --canaries on"
    if args.state_layout != "v1":
        return f"{TILE_SIEVE} needs --state-layout v1"
    if args.policy_placement != DEFAULT_POLICY_PLACEMENT:
        return f"{TILE_SIEVE} needs --policy-placement {DEFAULT_POLICY_PLACEMENT}"
    if args.polarity_twin:
        return f"{TILE_SIEVE} does not support --polarity-twin"
    if args.require_verification:
        return f"{TILE_SIEVE} does not support --require-verification"
    return None


def require_calibrated_judge(search_policy: str, judge: str) -> None:
    """Refuse tile-sieve-beta for a judge with no calibrated threshold set.

    The refusal is permanent for the Microsoft judge in this beta: it is made
    right after the judge is chosen, before any read or output, on every route.
    """
    if search_policy != TILE_SIEVE:
        return
    from .tile_sieve_fusion import load_thresholds
    try:
        load_thresholds(judge)
    except LookupError:
        raise SearchPolicyRefused(
            f"{TILE_SIEVE} has no calibrated thresholds for judge {judge}") from None


def fallback_notice(source: Source, spec: Source | None, project: ProjectIndex | None,
                    context_scope: str) -> str | None:
    """The stderr line for a file that does not fit one request, else None.

    It calls the planner the engine calls, on the same inputs, so the two agree
    on whether the scan falls back and why. A planner integrity failure is not
    a fallback: it propagates and the run ends as ``unexpected_error``.
    """
    from .tile_sieve_plan import Fallback, plan_whole_file
    plan = plan_whole_file(source, spec, project.entries if project is not None else (),
                           context_scope)
    if not isinstance(plan, Fallback):
        return None
    if plan.reason == "empty_file":
        return f"Search policy {TILE_SIEVE}: the file is empty; scanning with legacy-v1."
    detail = plan.detail
    reason = plan.reason
    if "bytes" in detail and "limit" in detail:
        least = "at least " if detail.get("at_least") else ""
        reason += f": {least}{detail['bytes']:,} B > {detail['limit']:,} B"
    elif "questions" in detail and "limit" in detail:
        reason += f": {detail['questions']} > {detail['limit']} questions"
    elif "batches" in detail:
        reason += f": {detail['batches']} batches"
    return (f"Search policy {TILE_SIEVE}: the file does not fit in one request "
            f"({reason}); scanning with legacy-v1.")


def judge_selectors(judge: str | None) -> tuple[str, ...]:
    """The ``--provider`` values of *judge*; every route when no judge is known."""
    if judge is None or judge not in JUDGES:
        return PROVIDER_CHOICES
    return tuple(route.selector for route in JUDGES[judge].routes)


def selected_judge(args: argparse.Namespace,
                   environ: dict[str, str] | None = None) -> str:
    """``--judge``, else ``DBH_JUDGE``; never inferred from the route or a key.

    An unknown ``DBH_JUDGE`` raises ``invalid_judge`` (the value is never
    echoed); neither source raises ``JudgeChoiceNeeded``. The flag wins.
    """
    choice = getattr(args, "judge", None)
    if choice is not None:
        if type(choice) is not str or choice not in JUDGE_CHOICES:
            raise ProviderError("invalid_judge")
        return choice
    env = os.environ if environ is None else environ
    value = env.get(JUDGE_VARIABLE, "")
    if not value:
        raise JudgeChoiceNeeded()
    if value not in JUDGE_CHOICES:
        raise ProviderError("invalid_judge")
    return value


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


def provider_choice_hint(environ: dict[str, str] | None = None,
                         judge: str = "openai") -> str:
    """The judge's route names and the names (never values) of the key
    variables of those routes that are set."""
    env = os.environ if environ is None else environ
    selectors = judge_selectors(judge)
    names = {name for selector in selectors for name in _ROUTE_VARIABLES[selector]}
    present = [name for name in CREDENTIAL_VARIABLES if name in names and env.get(name)]
    return " | ".join(selectors) + f" (set: {', '.join(present) or 'none'})"


def route_mismatch_hint(judge: str) -> str:
    return f"{judge} routes: {' | '.join(judge_selectors(judge))}"


def judge_of_provider(provider: object) -> str | None:
    """The judge a provider serves, from its model spec; None for a custom one."""
    judge = getattr(getattr(provider, "model_spec", None), "judge", None)
    return judge if type(judge) is str and judge in JUDGES else None


def foundry_provider(args: argparse.Namespace, judge: str,
                     model: str | None) -> providers.DecisionProvider:
    """The Foundry provider (Microsoft judge): endpoint, deployment and auth
    from the flags, else the environment; a missing one is NEED_USER_INPUT.

    The endpoint and the credentials are never printed or journaled.
    """
    if (model is not None
            or getattr(args, "openrouter_routing", DEFAULT_ROUTING) != DEFAULT_ROUTING
            or getattr(args, "openrouter_zdr", False)):
        # The deployment names the model; OpenRouter options never apply here.
        raise ProviderError("invalid_request")
    endpoint = (getattr(args, "foundry_endpoint", None)
                or os.environ.get(FOUNDRY_ENDPOINT_VARIABLE, ""))
    if not endpoint:
        raise FoundryInputNeeded(
            "foundry_endpoint", f"provide --foundry-endpoint or {FOUNDRY_ENDPOINT_VARIABLE} "
            "(https://<resource>.services.ai.azure.com)")
    deployment = (getattr(args, "foundry_deployment", None)
                  or os.environ.get(FOUNDRY_DEPLOYMENT_VARIABLE, ""))
    if not deployment:
        raise FoundryInputNeeded(
            "foundry_deployment",
            f"provide --foundry-deployment or {FOUNDRY_DEPLOYMENT_VARIABLE}")
    auth = getattr(args, "foundry_auth", None)
    has_key = bool(os.environ.get(FOUNDRY_API_KEY_VARIABLE))
    has_token = bool(os.environ.get(FOUNDRY_TOKEN_VARIABLE))
    if auth is None and has_key and has_token:
        raise FoundryInputNeeded(
            "foundry_auth", "provide --foundry-auth api-key | entra-token "
            f"({FOUNDRY_API_KEY_VARIABLE} and {FOUNDRY_TOKEN_VARIABLE} are both set)")
    args.selected_auth = auth or ("entra-token" if has_token and not has_key else "api-key")
    return providers.make_provider(
        "foundry", judge=judge, foundry_endpoint=endpoint, foundry_deployment=deployment,
        foundry_auth=auth,
        policy_placement=getattr(args, "policy_placement", DEFAULT_POLICY_PLACEMENT))


def make_provider(args: argparse.Namespace) -> providers.DecisionProvider:
    """The provider for this run; the single construction point tests replace.

    Selection is explicit and ordered: the judge (``--judge`` or
    ``DBH_JUDGE``), then the route (``--provider`` or ``DBH_PROVIDER``), then
    that the route belongs to the judge, then ``--model`` against the pair's
    allow-list, then the route's own options. Every check precedes any read of
    the source and any output. Construction reads the environment once and
    never touches the network.
    """
    judge = selected_judge(args)
    args.selected_judge = judge
    require_calibrated_judge(getattr(args, "search_policy", "legacy-v1"), judge)
    route = selected_provider(args)
    args.selected_provider = route
    try:
        judge_route(judge, route)
    except ProviderError:
        raise JudgeRouteMismatch() from None
    model = getattr(args, "model", None)
    if route != "foundry" and any(
            getattr(args, name, None) is not None
            for name in ("foundry_endpoint", "foundry_deployment", "foundry_auth")):
        # Foundry settings never silently apply to another route.
        raise ProviderError("invalid_request")
    if route == "foundry":
        return foundry_provider(args, judge, model)
    if route == "openai":
        if (getattr(args, "openrouter_routing", DEFAULT_ROUTING) != DEFAULT_ROUTING
                or getattr(args, "openrouter_zdr", False)):
            # OpenRouter privacy options never silently apply to another route.
            raise ProviderError("invalid_request")
        if model is None:
            # The documented construction, kept as the patchable name.
            return DecisionsProvider()
        return providers.make_provider("openai", model=model, judge=judge)
    return providers.make_provider(
        "openrouter", model=model, judge=judge,
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
    conflict = tile_sieve_conflict(args)
    if conflict is not None:
        return failure("invalid_search_configuration", detail=conflict)
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
        require_verification=args.require_verification,
    )
    deadline_at = started_monotonic + config.run_deadline_seconds
    # Validated before any output directory exists, never after mkdtemp.
    call_deadline = validate_call_deadline(args.deadline_seconds)
    max_cost = validate_max_cost(getattr(args, "max_cost", None))
    # The judge and the route are the caller's explicit choices of decision
    # model and data processor; they and availability are checked before source
    # reads, indexing, or output writes.
    try:
        provider = make_provider(args)
    except JudgeChoiceNeeded:
        return need_user_input("judge", JUDGE_CHOICE_HINT)
    except ProviderChoiceNeeded:
        return need_user_input(
            "provider", provider_choice_hint(judge=getattr(args, "selected_judge", "openai")))
    except JudgeRouteMismatch:
        return need_user_input(
            "judge_route", route_mismatch_hint(getattr(args, "selected_judge", "openai")))
    except FoundryInputNeeded as needed:
        return need_user_input(needed.field, needed.hint)
    provider.require_available()
    judge = judge_of_provider(provider)
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
    context_scope = {"project": "project", "standalone": "declared_standalone",
                     "isolate": "owner_isolated"}[args.scope]
    # Every selection, option and input check has passed: the run starts.
    notice = None if judge is None else JUDGES[judge].notice
    if notice is not None:
        print(notice, file=sys.stderr)
    if config.search_policy == TILE_SIEVE:
        # Once, before the run directory exists; the engine plans the same way.
        fallback = fallback_notice(source, spec, project, context_scope)
        if fallback is not None:
            print(fallback, file=sys.stderr)
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
                      context_scope=context_scope,
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
            what = "Receipt journal" if cleanup_error == "receipt_failed" else "Transport"
            print(f"{what} cleanup failed ({cleanup_error}); scan is incomplete.",
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
        if (result["stop_reason"] == "http_unauthorized"
                and getattr(provider, "auth", None) == "entra-token"):
            print(unauthorized_hint(), file=sys.stderr)
    spend = result.get("spend")
    if isinstance(spend, dict) and spend.get("upper_bound_usd") is not None:
        print(f"Spend (USD): provider-reported {spend['provider_reported_usd']}, "
              f"estimated {spend['estimated_usd']}, unknown-usage bound "
              f"{spend['unknown_usage_upper_bound_usd']}.", file=sys.stderr)
    banners = [banner for banner in result.get("banners") or ()
               if banner in ("judge_inconsistent", "judge_semantics_changed")]
    if banners:
        # Fixed DBH codes (ADR-4): the judge behaved unlike its observed contract.
        print(f"Judge warning ({', '.join(banners)}); see judge_diagnostics in report.json.",
              file=sys.stderr)
    complete = result["status"] == "complete"
    count = len(result["findings"])
    status = "complete" if complete else "incomplete"
    attempted = result["calls_attempted"]
    assessed = result["coverage"]["assessed_lines"]
    withheld = ""
    if "unverified_suspicions" in result:
        withheld = (f" ({len(result['unverified_suspicions'])} unverified suspicion(s) "
                    "withheld by --require-verification)")
    # Named only for a judge other than OpenAI: absent means OpenAI.
    judged = f" (judge {judge})" if judge not in (None, "openai") else ""
    searched = ""
    tile_block = result.get("tile_sieve")
    if tile_block is not None:
        searched = (f" ({TILE_SIEVE} whole-file)" if tile_block["mode"] == "whole-file"
                    else f" ({TILE_SIEVE}: legacy-v1 fallback)")
    print(
        f"Scan {status}; {count} suspected region(s){withheld}; {attempted} call(s) "
        f"attempted; {assessed}/{len(source.lines)} source lines assessed{judged}{searched}.",
        file=sys.stderr,
    )
    if not complete:
        return 2
    return 1 if count else 0


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    try:
        return execute(args)
    except SearchPolicyRefused as refused:
        return failure("invalid_search_configuration", detail=refused.detail)
    except ProviderError as error:
        return failure(error.code, getattr(args, "selected_provider", None)
                       or getattr(args, "provider", None),
                       getattr(args, "selected_judge", None),
                       getattr(args, "selected_auth", None))
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
