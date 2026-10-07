"""Sanitize smoke results and promote reviewed fixtures (no network use).

Reads a results.jsonl written by either runner generation:

* v1 (the pre-hardening urllib runner of 2026-10-06): full parsed bodies and
  selected headers, including ``cf-ray`` and generation ids;
* v2 (``smoke_common``): already sanitized; sanitizing again is a no-op.

Every record is reduced to the v2 schema: S-ID, status, DBH code, timing,
allow-listed headers (``x-generation-id`` as ``<gen-id>``), dropped header
names (never ``cf-ray``), ADR-8 error fields, and the body reduced to answer
numbers, DBH-authored names, model, upstream provider and usage. Messages,
metadata values and ids are dropped. S15 (a model DBH no longer targets) is
dropped entirely and can never be promoted.

    python tools/smoke/sanitize.py RUN_DIR
        writes RUN_DIR/sanitized/results.jsonl and summary.md
    python tools/smoke/sanitize.py RUN_DIR --in-place
        moves the originals to RUN_DIR/raw/ and writes the sanitized
        results.jsonl and a v2 summary.md in their place (D11)
    python tools/smoke/sanitize.py RUN_DIR --promote 2026-10-06 --ids S01,S02 [--builder-layout v1]
        writes tests/fixtures/openrouter/observed/<date>/<id>.json
"""
from __future__ import annotations

import argparse
from collections.abc import Callable, Iterable, Sequence
import json
import os
from pathlib import Path
import re
import sys
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent))

import smoke_common as common  # noqa: E402

from decision_bug_hunter import openrouter  # noqa: E402
from decision_bug_hunter.hosted import configured_credentials  # noqa: E402

#: Never summarized, never promoted (Decisions-only).
EXCLUDED_IDS = frozenset({"S15"})
FIXTURES = common.ROOT / "tests" / "fixtures" / "openrouter" / "observed"
_DATE = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}\Z")
#: A promotable smoke id: also a safe file name inside the fixture folder.
_PROMOTE_ID = re.compile(r"[A-Za-z0-9-]{1,32}\Z")
_SHA = re.compile(r"[0-9a-f]{64}\Z")
_INT_FIELDS = ("status", "repeat", "attempt", "questions", "wire_bytes")
_FLOAT_FIELDS = ("elapsed_s", "waited_s")
_BOOL_FIELDS = ("reused", "late")
_TOKEN_FIELDS = ("schema", "route", "id", "family", "file", "send", "code", "phase", "exception",
                 "submission", "retry_reason", "error_body")
_HASH_FIELDS = ("request_sha256", "wire_sha256")


def _token(value: Any) -> Any:
    if value is None:
        return None
    if type(value) is str and common._RECORD_TOKEN.fullmatch(value) and not common._leaks(value):
        return value
    return common.WITHHELD


def _builder(value: Any) -> dict[str, Any] | None:
    if type(value) is not dict:
        return None
    commit, layout, digest = (value.get("commit"), value.get("state_layout"),
                              value.get("manifest_sha256"))
    result: dict[str, Any] = {
        "commit": commit if type(commit) is str and re.fullmatch(r"[0-9a-f]{7,40}", commit) else None,
        "state_layout": layout if layout in ("v1", "v2") else None}
    if digest is not None:
        result["manifest_sha256"] = digest if type(digest) is str and _SHA.fullmatch(digest) else None
    return result


def _v1_code(status: Any, body: Any) -> str | None:
    if type(status) is not int:
        return None
    error = body.get("error") if type(body) is dict and type(body.get("error")) is dict else None
    if status != 200:
        return openrouter.status_code(status, error)
    # A v1 record carries no questions, so its answers were never decoded.
    return "provider_error_in_body" if error is not None else None


def sanitize_record(record: Any, credentials: Iterable[str] = ()) -> dict[str, Any] | None:
    """One record in the v2 schema, or None for an excluded or unusable record."""
    credentials = tuple(credentials)
    if type(record) is not dict or type(record.get("id")) is not str:
        return None
    if record["id"] in EXCLUDED_IDS:
        return None
    result: dict[str, Any] = {}
    if "response" in record:  # v1 runner record
        response = record.get("response")
        body = None if type(response) is not dict or "_non_json" in response else response
        status = record.get("status")
        headers = record.get("headers") if type(record.get("headers")) is dict else {}
        kept, dropped = common.capture_headers(headers.items())
        result.update(schema=common.SCHEMA, route="openrouter", id=record["id"],
                      family=record["id"], file=record.get("file"), send="body",
                      request_sha256=record.get("request_sha256"),
                      wire_sha256=record.get("request_sha256"),
                      wire_bytes=record.get("request_bytes"), status=status,
                      code=_v1_code(status, body), phase="complete", exception=None,
                      submission="sent", elapsed_s=record.get("elapsed_s"), reused=None,
                      headers=kept, dropped_header_names=dropped,
                      repeat=record.get("repeat", 0), attempt=record.get("attempt", 1),
                      sanitized_from="v1")
        if type(status) is int and status != 200 and body is not None:
            error = body.get("error") if type(body.get("error")) is dict else None
            result["error"] = openrouter.error_fields(status, error)
        if body is not None:
            result["body"] = common.sanitize_body(body, credentials)
        # Validate the converted record exactly like a v2 one.
        return sanitize_record(result, credentials)
    else:
        for key in _TOKEN_FIELDS:
            if key in record:
                result[key] = _token(record[key])
        for key in _HASH_FIELDS:
            if key in record:
                value = record[key]
                result[key] = value if type(value) is str and _SHA.fullmatch(value) else None
        for key in _INT_FIELDS:
            if key in record:
                value = record[key]
                result[key] = value if type(value) is int and type(value) is not bool else None
        for key in _FLOAT_FIELDS:
            if key in record:
                value = record[key]
                result[key] = value if type(value) in (int, float) else None
        for key in _BOOL_FIELDS:
            if key in record:
                value = record[key]
                result[key] = value if value is None or type(value) is bool else None
        headers = record.get("headers") if type(record.get("headers")) is dict else {}
        names = record.get("dropped_header_names")
        kept, dropped = common.capture_headers(
            headers.items(), names if type(names) is list else ())
        result["headers"], result["dropped_header_names"] = kept, dropped
        for key in ("error", "body"):
            if key in record:
                result[key] = common.sanitize_body(record[key], credentials)
        if "builder" in record:
            result["builder"] = _builder(record["builder"])
        if record.get("sanitized_from") == "v1":
            result["sanitized_from"] = "v1"
    result["schema"] = common.SCHEMA
    return result


def read_records(path: Path, credentials: Iterable[str] = ()) -> list[dict[str, Any]]:
    """Sanitized records of a results.jsonl (any runner generation)."""
    records = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        try:
            record = json.loads(line)
        except ValueError:
            continue
        clean = sanitize_record(record, credentials)
        if clean is not None:
            records.append(clean)
    return records


def write_records(path: Path, records: Iterable[dict[str, Any]]) -> None:
    with path.open("w", encoding="utf-8", newline="\n") as sink:
        for record in records:
            sink.write(common.dumps(record) + "\n")


def _local_credentials() -> tuple[str, ...]:
    """Every configured provider key, so no record can keep one (values are
    only compared, never printed or written)."""
    return configured_credentials(os.environ, None)


def _meta() -> dict[str, dict[str, Any]]:
    import run_openrouter

    return run_openrouter.meta_for(run_openrouter.load_entries())


def sanitize_copy(run: Path) -> Path:
    records = read_records(run / "results.jsonl", _local_credentials())
    target = run / "sanitized"
    target.mkdir(exist_ok=True)
    common.mark_output(target)
    write_records(target / "results.jsonl", records)
    common.write_summary(target, records, _meta())
    return target


def sanitize_in_place(run: Path) -> Path:
    """Move the originals under raw/ and write sanitized results and summary."""
    raw = run / "raw"
    moved = [(run / "results.jsonl", raw / "results.unsanitized.jsonl"),
             (run / "summary.md", raw / "summary.unsanitized.md")]
    if any(target.exists() for _source, target in moved):
        raise SystemExit("raw/ already holds unsanitized originals; refusing to overwrite them.")
    records = read_records(run / "results.jsonl", _local_credentials())
    raw.mkdir(exist_ok=True)
    for source, target in moved:
        if source.exists():
            source.replace(target)
    common.mark_output(run)
    write_records(run / "results.jsonl", records)
    common.write_summary(run, records, _meta())
    return run


def promote(run: Path, date: str, ids: Sequence[str], *, layout: str | None = None,
            fixtures: Path = FIXTURES) -> list[Path]:
    """Write one reviewed fixture per id: repeat 0, final attempt."""
    if not _DATE.fullmatch(date):
        raise SystemExit("--promote takes a date as YYYY-MM-DD")
    wanted = [item.strip() for item in ids if item.strip()]
    unsafe = [sid for sid in wanted if not _PROMOTE_ID.fullmatch(sid)]
    if unsafe:
        raise SystemExit("--ids takes smoke ids such as S01,S10b (letters, digits, '-').")
    refused = sorted(set(wanted) & EXCLUDED_IDS)
    if refused:
        raise SystemExit(f"Refusing to promote {', '.join(refused)} (Decisions-only).")
    finals = {r["id"]: r for r in common.final_records(read_records(run / "results.jsonl", _local_credentials()))
              if r.get("repeat", 0) == 0}
    missing = [sid for sid in wanted if sid not in finals]
    if missing:
        raise SystemExit(f"No record for {', '.join(missing)}.")
    folder = fixtures / date
    folder.mkdir(parents=True, exist_ok=True)
    written = []
    for sid in wanted:
        record = finals[sid]
        builder = record.get("builder") if type(record.get("builder")) is dict else {}
        fixture = {"id": sid, "route": record.get("route"),
                   "request_sha256": record.get("request_sha256"), "status": record.get("status"),
                   "code": record.get("code"), "headers": record.get("headers", {}),
                   "dropped_header_names": record.get("dropped_header_names", []),
                   "error": record.get("error"), "body": record.get("body"),
                   "builder": {"state_layout": layout or builder.get("state_layout")}}
        path = folder / f"{sid}.json"
        path.write_text(common.dumps(fixture, indent=1) + "\n", encoding="utf-8", newline="\n")
        written.append(path)
    index = {"date": date, "route": "openrouter", "ids": wanted,
             "builder_state_layout": layout,
             "note": "Sanitized by tools/smoke/sanitize.py; shape evidence only."}
    (folder / "index.json").write_text(json.dumps(index, indent=1) + "\n", encoding="utf-8",
                                       newline="\n")
    return written


def main(argv: Sequence[str] | None = None, *, echo: Callable[[str], None] = print) -> int:
    parser = argparse.ArgumentParser(description="Sanitize smoke results; promote fixtures")
    parser.add_argument("run", help="A smoke output directory holding results.jsonl")
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--in-place", action="store_true",
                      help="Move originals under raw/ and sanitize in place (D11).")
    mode.add_argument("--promote", metavar="DATE", help="Write fixtures for --ids under DATE.")
    parser.add_argument("--ids", default="", help="Comma-separated S-IDs to promote.")
    parser.add_argument("--builder-layout", choices=("v1", "v2"),
                        help="STATE_LAYOUT the builder used for these requests.")
    parser.add_argument("--fixtures", help="Fixture root (default tests/fixtures/openrouter/observed).")
    args = parser.parse_args(argv)
    run = Path(args.run)
    if not (run / "results.jsonl").is_file():
        echo("No results.jsonl in that directory.")
        return 2
    if args.promote:
        written = promote(run, args.promote, args.ids.split(","), layout=args.builder_layout,
                          fixtures=Path(args.fixtures) if args.fixtures else FIXTURES)
        echo(f"Promoted {len(written)} fixture(s) to {written[0].parent if written else '-'}")
    elif args.in_place:
        echo(f"Sanitized in place: {sanitize_in_place(run)}")
    else:
        echo(f"Sanitized copy: {sanitize_copy(run)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
