"""Run the OpenAI-direct Decisions smoke requests (O01-O05) through DBH's code path.

Replaces the former tools/live_probe.py. Requests go to
https://api.openai.com/v1/decisions through
``decision_bug_hunter.exchange.HttpsExchange`` and ``DecisionsProvider``
(its translation, routing headers from OPENAI_ORG_ID / OPENAI_PROJECT_ID,
decoder and status table). Output, sanitizing and summary are shared with
run_openrouter.py (see smoke_common): no message text, no header value
other than the allow-listed ones, ``x-request-id`` only as ``<request-id>``.

    O01  a DBH screening batch (shape, model echo, usage)
    O02  the S02s production batches of the OpenRouter suite (same local bytes)
    O03  the S11 confidence sweep (choice vectors, precision, confidence)
    O04  an unknown request field: status and the error.param path shape
    O05  optional: a fixed invalid token (401 handling; the message is dropped)
    O06  not a request: the summary counts responses carrying x-request-id

The key comes from OPENAI_API_KEY, or from --env-file (only that variable is
read). It is never printed or written. Every request bills the account.

    python tools/smoke/run_openai.py --dry-run
    python tools/smoke/run_openai.py --only O01
"""
from __future__ import annotations

import argparse
from collections.abc import Callable, Mapping, Sequence
import json
from pathlib import Path
import re
import sys
import time
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent))

import smoke_common as common  # noqa: E402

from decision_bug_hunter import decisions, questions  # noqa: E402
from decision_bug_hunter.core import Source, Span  # noqa: E402
from decision_bug_hunter.protocol import encode_request  # noqa: E402

SUITE = Path(__file__).resolve().parent / "openrouter"
MODEL_PATTERN = re.compile(re.escape(decisions.MODEL)
                           + r"(?:-[0-9]{8}|-[0-9]{4}-[0-9]{2}-[0-9]{2})?")
SAMPLE = """\
def average(values):
    total = 0
    for value in values:
        total += value
    return total / len(values)


def first_positive(values):
    for index in range(1, len(values)):
        if values[index] > 0:
            return values[index]
    return None
"""


def _provider(api_key: str, *, exchange: Any, environ: Mapping[str, str]
              ) -> decisions.DecisionsProvider:
    return decisions.DecisionsProvider(api_key, environ=environ, exchange=exchange)


def _decode(raw: bytes, local_questions: Mapping[str, Any], credentials: Sequence[str]) -> Any:
    return decisions.translate_response(raw, local_questions, credentials)


ROUTE = common.Route(name="openai", host=decisions.HOST, path=decisions.PATH,
                     variable=decisions.CREDENTIAL_VARIABLE, model_pattern=MODEL_PATTERN,
                     make_provider=_provider, decode=_decode,
                     status_code=decisions.status_code, error_fields=decisions.error_fields)
common.register_model_pattern(ROUTE.name, MODEL_PATTERN)


def _compact(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode("utf-8")


def build_entries(suite: Path = SUITE) -> list[common.Entry]:
    """The O-requests, built from DBH's own question code; no network use."""
    pack, _ = questions.load_pack()
    source = Source.from_text(SAMPLE, name="probe.py")
    region = Span(1, len(source.lines))
    state = questions.state_for(source, region, 0, None, context_scope="declared_standalone")
    screen = questions.screening(pack, region, [Span(1, 5), Span(8, 12), region],
                                 bug_lenses=True, state=state)
    entries = [common.Entry(id="O01", send="splice", data=encode_request(state, screen),
                            purpose="DBH screening batch: shape, model echo, usage.")]
    manifest = json.loads((suite / "manifest.json").read_text(encoding="utf-8"))
    for item in manifest["entries"]:
        if item.get("family") == "S02s":
            number = item["id"].rsplit("-", 1)[1]
            entries.append(common.Entry(
                id=f"O02-{number}", family="O02", send="splice",
                data=(suite / item["file"]).read_bytes(), file=item["file"],
                purpose="S02s production batch on the direct route.",
                meta={"labels": item.get("labels")}))
        elif item["id"] == "S11":
            sweep = json.loads((suite / item["file"]).read_text(encoding="utf-8"))
            entries.append(common.Entry(
                id="O03", send="splice", data=encode_request(sweep["state"], sweep["questions"]),
                purpose="S11 analog: choice vectors, precision, confidence."))
    tiny = [{"type": "predicate", "name": "q",
             "instructions": "Does the text contain a greeting?\nAnswer true if: Yes, the "
                             "statement holds.\nAnswer false if: No, the statement does not hold."}]
    entries.append(common.Entry(
        id="O04", send="body", expect="error",
        data=_compact({"model": decisions.MODEL, "input": "Hello there.",
                       "questions": [{**tiny[0], "unexpected_field": True}]}),
        purpose="Unknown request field: status and the error.param path shape."))
    entries.append(common.Entry(
        id="O05", send="body", expect="error", optional=True, auth="invalid",
        data=_compact({"model": decisions.MODEL, "input": "Hello there.", "questions": tiny}),
        purpose="Optional: fixed invalid token; 401 handling."))
    return sorted(entries, key=lambda entry: entry.id)


def main(argv: Sequence[str] | None = None, *, environ: Mapping[str, str] | None = None,
         exchange: Any = None, sleep: Callable[[float], None] = time.sleep,
         clock: Callable[[], float] = time.monotonic,
         echo: Callable[[str], None] = print) -> int:
    parser = argparse.ArgumentParser(description="OpenAI-direct Decisions smoke requests")
    parser.add_argument("--dry-run", action="store_true", help="List the requests; no network.")
    parser.add_argument("--only", help="Comma-separated ids or families, e.g. O01,O02")
    parser.add_argument("--include-optional", action="store_true",
                        help="Also send O05 (fixed invalid token).")
    parser.add_argument("--env-file", help="Read only OPENAI_API_KEY from this dotenv file.")
    parser.add_argument("--out", help="Output directory (default smoke-results/openai-<UTC stamp>).")
    parser.add_argument("--timeout", type=float, default=60.0, help="Per-request deadline, seconds.")
    parser.add_argument("--pause", type=float, default=0.5, help="Seconds between requests.")
    parser.add_argument("--keep-raw", action="store_true",
                        help="Also keep raw response bodies under <out>/raw/ (off by default).")
    args = parser.parse_args(argv)
    entries = common.select(build_entries(), args.only, args.include_optional)
    if not entries:
        echo("No request matches --only.")
        return 2
    if args.dry_run:
        common.dry_run(entries, echo)
        return 0
    env = common.environment(environ)
    key = common.load_key(ROUTE.variable, args.env_file, env)
    out = Path(args.out) if args.out else common.default_out(ROUTE.name)
    meta = {e.id: {**e.meta, "family": e.family, "questions": len(e.questions)} for e in entries}
    common.run_suite(ROUTE, entries, out, key=key, environ=env, exchange=exchange,
                     timeout=args.timeout, pause=args.pause, keep_raw=args.keep_raw,
                     sleep=sleep, clock=clock,
                     builder=common.builder_info(None, questions.state_layout()),
                     meta=meta, echo=echo)
    echo(f"Results in {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
