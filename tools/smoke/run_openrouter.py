"""Run the OpenRouter Decisions smoke suite through DBH's shipped code path.

Posts each request in tools/smoke/openrouter/manifest.json to
https://openrouter.ai/api/alpha/decisions through
``decision_bug_hunter.exchange.HttpsExchange`` (the shipped TLS context, no
proxy, no redirects, an absolute deadline). ``splice`` entries are DBH local
envelopes handed to ``OpenRouterProvider`` (its splice, routing default and
decoder); ``body`` entries are complete probe bodies sent byte for byte.
Writes:

    <out>/results.jsonl   one sanitized record per attempt (status, DBH code,
                          phase, submission, timing, reuse, allow-listed
                          headers, answer numbers); see smoke_common
    <out>/summary.md      S-IDs, statuses, codes, counts and numbers only
    <out>/raw/            only with --keep-raw; never read by the sanitizer,
                          by Hermes or by any agent

The key comes from OPENROUTER_API_KEY, or from --env-file (only that one
variable is read). It is never printed or written. Every request bills your
OpenRouter credits (the full suite is a few cents at $0.10 per 1M input
tokens). The suite continues after any network failure.

    python tools/smoke/run_openrouter.py --dry-run
    python tools/smoke/run_openrouter.py --env-file ~/.hermes/.env
    python tools/smoke/run_openrouter.py --only S01h,S02s,S19b
    python tools/smoke/run_openrouter.py --summarize smoke-results/openrouter-YYYYmmdd-HHMMSS
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

from decision_bug_hunter import openrouter  # noqa: E402

SUITE = Path(__file__).resolve().parent / "openrouter"
MODEL_PATTERN = re.compile(re.escape(openrouter.MODEL) + r"(?:-[0-9]{8})?")


def _provider(api_key: str, *, exchange: Any, environ: Mapping[str, str],
              routing: str = openrouter.DEFAULT_ROUTING) -> openrouter.OpenRouterProvider:
    return openrouter.OpenRouterProvider(api_key, environ=environ, exchange=exchange,
                                         routing=routing)


def _decode(raw: bytes, questions: Mapping[str, Any], credentials: Sequence[str]) -> Any:
    return openrouter.decode_response(raw, questions, credentials)


ROUTE = common.Route(name="openrouter", host=openrouter.HOST, path=openrouter.PATH,
                     variable=openrouter.CREDENTIAL_VARIABLE, model_pattern=MODEL_PATTERN,
                     make_provider=_provider, decode=_decode,
                     status_code=openrouter.status_code, error_fields=openrouter.error_fields)
common.register_model_pattern(ROUTE.name, MODEL_PATTERN)


def load_manifest(suite: Path = SUITE) -> tuple[dict[str, Any], bytes]:
    raw = (suite / "manifest.json").read_bytes()
    return json.loads(raw.decode("utf-8")), raw


def load_entries(suite: Path = SUITE) -> list[common.Entry]:
    manifest, _raw = load_manifest(suite)
    entries = []
    for item in manifest["entries"]:
        entries.append(common.Entry(
            id=item["id"], send=item.get("send", "body"), data=(suite / item["file"]).read_bytes(),
            purpose=item.get("purpose", ""), family=item.get("family", item["id"]),
            repeat=int(item.get("repeat", 1)), pause=item.get("pause"), auth=item.get("auth"),
            optional=bool(item.get("optional", False)), expect=item.get("expect", "ok"),
            file=item["file"], meta={k: item[k] for k in ("labels", "truth", "compare", "cell")
                                     if k in item}))
    return entries


def meta_for(entries: list[common.Entry]) -> dict[str, dict[str, Any]]:
    return {e.id: {**e.meta, "family": e.family, "questions": len(e.questions)} for e in entries}


def summarize(directory: Path, suite: Path = SUITE) -> Path:
    """Rebuild summary.md from results.jsonl; records are sanitized first."""
    import sanitize  # local tool module; reuses the record sanitizer

    records = sanitize.read_records(directory / "results.jsonl")
    return common.write_summary(directory, records, meta_for(load_entries(suite)))


def main(argv: Sequence[str] | None = None, *, environ: Mapping[str, str] | None = None,
         exchange: Any = None, sleep: Callable[[float], None] = time.sleep,
         clock: Callable[[], float] = time.monotonic,
         echo: Callable[[str], None] = print) -> int:
    parser = argparse.ArgumentParser(description="OpenRouter Decisions smoke suite (v2)")
    parser.add_argument("--dry-run", action="store_true", help="List the requests; no network.")
    parser.add_argument("--only", help="Comma-separated ids or families, e.g. S01h,S02s,S14-1")
    parser.add_argument("--include-optional", action="store_true",
                        help="Also send the optional probes (S21 invalid token, S22 provider pin).")
    parser.add_argument("--env-file", help="Read only OPENROUTER_API_KEY from this dotenv file.")
    parser.add_argument("--out", help="Output directory (default smoke-results/openrouter-<UTC stamp>).")
    parser.add_argument("--timeout", type=float, default=60.0, help="Per-request deadline, seconds.")
    parser.add_argument("--pause", type=float, default=0.5, help="Seconds between requests.")
    parser.add_argument("--routing", choices=openrouter.ROUTING_CHOICES,
                        default=openrouter.DEFAULT_ROUTING,
                        help="Routing object for splice entries (default: deny).")
    parser.add_argument("--keep-raw", action="store_true",
                        help="Also keep raw response bodies under <out>/raw/ (off by default).")
    parser.add_argument("--summarize", help="Only rebuild summary.md for an existing output directory.")
    args = parser.parse_args(argv)
    if args.summarize:
        path = summarize(Path(args.summarize))
        echo(f"Summary written to {path}")
        return 0
    entries = common.select(load_entries(), args.only, args.include_optional)
    if not entries:
        echo("No manifest entry matches --only.")
        return 2
    if args.dry_run:
        common.dry_run(entries, echo)
        return 0
    env = common.environment(environ)
    key = common.load_key(ROUTE.variable, args.env_file, env)
    manifest, raw_manifest = load_manifest()
    out = Path(args.out) if args.out else common.default_out(ROUTE.name)
    common.run_suite(ROUTE, entries, out, key=key, environ=env, exchange=exchange,
                     timeout=args.timeout, pause=args.pause, keep_raw=args.keep_raw,
                     sleep=sleep, clock=clock,
                     builder=common.builder_info(raw_manifest, manifest.get("state_layout")),
                     provider_options={"routing": args.routing}, meta=meta_for(entries),
                     echo=echo)
    echo(f"Results in {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
