"""Shared code of the live smoke runners and the sanitizer (tools only).

Everything that reaches a disk here is structural: S-ID, status, DBH code,
phase, submission class, timing, connection reuse, allow-listed response
headers, and response bodies reduced to answer numbers, DBH-authored names,
model, upstream provider and usage. Message text, metadata values, ids and
every other header value are dropped at capture (ADR-8, ADR-11):

* Headers: only ``ALLOWED_HEADERS`` and ``x-ratelimit-*`` keep a value.
  ``x-generation-id`` and ``x-request-id`` become placeholders. Every other
  header keeps only its name in ``dropped_header_names``; ``cf-ray`` is not
  even named, because its suffix is the Cloudflare edge's airport code.
* Bodies: numbers and booleans stay; a string stays only under a key whose
  value is a DBH-authored token (``type``, ``name``, ``choice``, ``value``,
  error ``code``, ``error_type``, ``provider_code``) or a charset-limited
  ``model`` or ``provider``. ``message`` is removed, ids become
  placeholders and every other string becomes ``"<withheld>"``.

Requests travel through ``decision_bug_hunter.exchange.HttpsExchange``: the
shipped TLS context (no key log), no proxy, no redirects, an absolute
deadline per call. Nothing here imports urllib.
"""
from __future__ import annotations

from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass, field
from datetime import datetime, timezone
from decimal import Decimal, InvalidOperation
import hashlib
import json
import math
import os
from pathlib import Path
import re
import subprocess
import sys
import time
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from decision_bug_hunter.__main__ import CACHEDIR_TAG_TEXT, GITIGNORE_TEXT  # noqa: E402
from decision_bug_hunter.decisions import param_path  # noqa: E402
from decision_bug_hunter.exchange import ExchangeError, HttpsExchange  # noqa: E402
from decision_bug_hunter.hosted import (configured_credentials, error_object,  # noqa: E402
                                        parse_retry_after, token, transport_failure)
from decision_bug_hunter.protocol import ProviderError, _secret_in  # noqa: E402
from decision_bug_hunter.providers import ProviderRequest, classify  # noqa: E402

SCHEMA = "dbh-smoke-v2"
WITHHELD = "<withheld>"
#: The only response headers whose values are captured (ADR-11(2)).
ALLOWED_HEADERS = ("content-type", "content-length", "transfer-encoding",
                   "content-encoding", "connection", "retry-after")
ALLOWED_PREFIX = "x-ratelimit-"
#: Identifiers kept as presence only.
PLACEHOLDER_HEADERS = {"x-generation-id": "<gen-id>", "x-request-id": "<request-id>"}
#: Dropped without even recording the name.
UNNAMED_HEADERS = frozenset({"cf-ray"})
#: The shape of a ``cf-ray`` value: hex, a hyphen, an IATA airport code.
EDGE_CODE = re.compile(r"[0-9a-f]+-[A-Z]{3}")
GENERATION_PREFIX = "gen-dec-"
#: A fixed, obviously invalid bearer token for the optional 401 probes.
INVALID_TOKEN = "dbh-smoke-invalid-token-0000"
#: Statuses retried once, after Retry-After (at most 30 s) or 5 s.
RETRY_CODES = frozenset({"http_rate_limited", "http_overloaded", "http_unavailable"})
MAX_RETRY_WAIT = 30.0
DEFAULT_RETRY_WAIT = 5.0

_HEADER_NAME = re.compile(r"[a-z0-9-]{1,64}\Z")
_HEADER_VALUE = re.compile(r"[ -~]{0,256}\Z")
_TOKEN = re.compile(r"[A-Za-z0-9_.:-]{1,96}\Z")
_MODEL = re.compile(r"[A-Za-z0-9_.:/-]{1,128}\Z")
_UPSTREAM = re.compile(r"[A-Za-z0-9 _.-]{1,64}\Z")
_LABEL_KEYS = frozenset({"type", "name", "choice", "value", "code", "error_type",
                         "error_code", "provider_code", "provider_error_type"})
_NAMED_STRINGS = {"model": _MODEL, "provider": _UPSTREAM, "provider_name": _UPSTREAM}
_DROPPED_KEYS = frozenset({"message"})
_MAX_DEPTH = 32
_RECORD_TOKEN = re.compile(r"[A-Za-z0-9_.:<>/ -]{0,128}\Z")


# -- capture and sanitizing ----------------------------------------------------
def _leaks(value: str) -> bool:
    return GENERATION_PREFIX in value or EDGE_CODE.search(value) is not None


def capture_headers(pairs: Iterable[tuple[str, Any]], dropped: Iterable[str] = ()
                    ) -> tuple[dict[str, str], list[str]]:
    """(allow-listed headers, names of the dropped ones) from (name, value) pairs."""
    kept: dict[str, str] = {}
    names = {name for name in dropped if type(name) is str and _HEADER_NAME.fullmatch(name)}
    for name, value in pairs:
        if type(name) is not str:
            continue
        lower = name.lower()
        if lower in UNNAMED_HEADERS:
            continue
        if lower in PLACEHOLDER_HEADERS:
            kept[lower] = PLACEHOLDER_HEADERS[lower]
        elif ((lower in ALLOWED_HEADERS or lower.startswith(ALLOWED_PREFIX))
              and _HEADER_NAME.fullmatch(lower) and type(value) is str
              and _HEADER_VALUE.fullmatch(value) and not _leaks(value)):
            kept[lower] = value.strip()
        elif _HEADER_NAME.fullmatch(lower):
            names.add(lower)
    return kept, sorted((names - UNNAMED_HEADERS) - set(kept))


def _id_placeholder(value: Any) -> str:
    return "<gen-id>" if type(value) is str and value.startswith("gen-") else "<id>"


def sanitize_body(value: Any, credentials: Iterable[str] = (), *, _key: str | None = None,
                  _depth: int = 0) -> Any:
    """A response body reduced to numbers, DBH-authored tokens and placeholders.

    Idempotent: sanitizing a sanitized body returns an equal value.
    """
    credentials = tuple(credentials)
    if _depth > _MAX_DEPTH:
        return WITHHELD
    if value is None or type(value) is bool:
        return value
    if type(value) is int:
        return value
    if type(value) is float:
        return value if math.isfinite(value) else WITHHELD
    if isinstance(value, Decimal):
        return float(value) if value.is_finite() else WITHHELD
    if type(value) is str:
        if value in (WITHHELD, "<gen-id>", "<id>"):
            return value
        if _key is not None and (_key == "id" or _key.endswith("_id")):
            return _id_placeholder(value)
        if _leaks(value) or any(c and c in value for c in credentials):
            return WITHHELD
        if _key in _NAMED_STRINGS:
            return value if _NAMED_STRINGS[_key].fullmatch(value) else WITHHELD
        if _key == "param":
            return value if param_path(value) is not None else WITHHELD
        if _key in _LABEL_KEYS and _TOKEN.fullmatch(value):
            return value
        return WITHHELD
    if type(value) is dict:
        result: dict[str, Any] = {}
        for key, item in value.items():
            if (type(key) is not str or key in _DROPPED_KEYS or key in UNNAMED_HEADERS
                    or not _TOKEN.fullmatch(key) or _leaks(key)
                    or any(c and c in key for c in credentials)):
                continue
            result[key] = sanitize_body(item, credentials, _key=key, _depth=_depth + 1)
        return result
    if type(value) is list:
        return [sanitize_body(item, credentials, _key=_key, _depth=_depth + 1)
                for item in value]
    return WITHHELD


def parse_body(raw: bytes | None) -> Any:
    """JSON bytes to Python values (floats kept as Decimal), or None."""
    if not raw:
        return None
    try:
        return json.loads(raw.decode("utf-8"), parse_float=Decimal)
    except (UnicodeError, ValueError, InvalidOperation):
        return None


def json_default(value: Any) -> Any:
    if isinstance(value, Decimal):
        return float(value)
    raise TypeError(type(value).__name__)


def dumps(value: Any, **kwargs: Any) -> str:
    return json.dumps(value, ensure_ascii=False, default=json_default, **kwargs)


# -- suite entries and routes --------------------------------------------------
@dataclass
class Entry:
    """One request of a suite: ``send`` is ``splice`` (local envelope) or ``body``."""

    id: str
    send: str
    data: bytes
    purpose: str = ""
    family: str = ""
    repeat: int = 1
    pause: float | None = None
    auth: str | None = None
    optional: bool = False
    expect: str = "ok"
    file: str | None = None
    meta: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.send not in ("splice", "body"):
            raise ValueError("send")
        self.family = self.family or self.id

    @property
    def request_sha256(self) -> str:
        return hashlib.sha256(self.data).hexdigest()

    @property
    def questions(self) -> dict[str, Any]:
        data = parse_body(self.data)
        questions = data.get("questions") if type(data) is dict else None
        return questions if type(questions) is dict else {}


@dataclass
class Route:
    """What differs between the OpenRouter and the OpenAI-direct route."""

    name: str
    host: str
    path: str
    variable: str
    model_pattern: re.Pattern[str]
    make_provider: Callable[..., Any]
    decode: Callable[..., Any]
    status_code: Callable[[int, Mapping[str, Any] | None], str]
    error_fields: Callable[[int, Mapping[str, Any] | None], dict[str, Any]]


def select(entries: list[Entry], only: str | None, include_optional: bool) -> list[Entry]:
    wanted = None if not only else {item.strip() for item in only.split(",") if item.strip()}
    chosen = []
    for entry in entries:
        if wanted is not None:
            if entry.id in wanted or entry.family in wanted:
                chosen.append(entry)
        elif include_optional or not entry.optional:
            chosen.append(entry)
    return chosen


def load_key(variable: str, env_file: str | None, environ: Mapping[str, str]) -> str:
    """The credential from ``environ`` or, failing that, only ``variable`` in ``env_file``."""
    key = environ.get(variable, "")
    if not key and env_file:
        for line in Path(env_file).expanduser().read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if line.startswith("export "):
                line = line[7:].lstrip()
            if line.startswith(variable + "="):
                key = line.split("=", 1)[1].strip().strip('"').strip("'")
    if token(key) is None:
        raise SystemExit(f"Set {variable} or pass --env-file pointing at a file that defines it.")
    return key


def mark_output(directory: Path) -> None:
    """Keep smoke output out of git, backups and DBH's own indexer."""
    for name, text in ((".gitignore", GITIGNORE_TEXT), ("CACHEDIR.TAG", CACHEDIR_TAG_TEXT)):
        path = directory / name
        if not path.exists():
            path.write_text(text, encoding="utf-8", newline="\n")


def builder_info(manifest_bytes: bytes | None, layout: str | None) -> dict[str, Any]:
    commit = None
    try:
        result = subprocess.run(["git", "rev-parse", "--short", "HEAD"], cwd=ROOT,
                                capture_output=True, text=True, timeout=5)
        if result.returncode == 0 and re.fullmatch(r"[0-9a-f]{7,40}", result.stdout.strip()):
            commit = result.stdout.strip()
    except (OSError, subprocess.SubprocessError):
        commit = None
    info: dict[str, Any] = {"commit": commit, "state_layout": layout}
    if manifest_bytes is not None:
        info["manifest_sha256"] = hashlib.sha256(manifest_bytes).hexdigest()
    return info


class Recorder:
    """Wraps an ``HttpsExchange``; remembers the last outcome or transport error."""

    def __init__(self, exchange: HttpsExchange) -> None:
        self.exchange = exchange
        self.outcome: Any = None
        self.error: ExchangeError | None = None

    def reset(self) -> None:
        self.outcome, self.error = None, None

    def deadline(self, seconds: float) -> Any:
        return self.exchange.deadline(seconds)

    def post(self, body: bytes, headers: Mapping[str, str], deadline: Any,
             **kwargs: Any) -> Any:
        try:
            outcome = self.exchange.post(body, headers, deadline, **kwargs)
        except ExchangeError as exc:
            self.error = exc
            raise
        self.outcome = outcome
        return outcome

    def close(self) -> None:
        self.exchange.close()


# -- one attempt -----------------------------------------------------------------
def attempt(route: Route, provider: Any, recorder: Recorder, entry: Entry, *,
            key: str, credentials: tuple[str, ...], timeout: float,
            clock: Callable[[], float]) -> dict[str, Any]:
    """Send ``entry`` once and return its sanitized record; never raises for I/O."""
    recorder.reset()
    record: dict[str, Any] = {"schema": SCHEMA, "route": route.name, "id": entry.id,
                              "family": entry.family, "file": entry.file, "send": entry.send,
                              "request_sha256": entry.request_sha256,
                              "questions": len(entry.questions), "status": None,
                              "code": None, "phase": "local", "exception": None,
                              "submission": "not_sent", "elapsed_s": None, "reused": None}
    started = clock()
    code: str | None = None
    submission: str | None = None
    dispatched = False
    try:
        if entry.send == "splice":
            wire, _expected = provider.encode(entry.data)
            record["wire_sha256"] = hashlib.sha256(wire).hexdigest()
            record["wire_bytes"] = len(wire)
            dispatched = True
            try:
                response = provider.decide(ProviderRequest(entry.data, timeout))
            except ProviderError as exc:
                code = exc.code
                if exc.classification is not None:
                    submission = exc.classification.submission
            else:
                code = response.error or ("ok_partial" if response.scoped else "ok")
        else:
            record["wire_sha256"] = entry.request_sha256
            record["wire_bytes"] = len(entry.data)
            headers = {"Authorization": "Bearer " + key, "Content-Type": "application/json",
                       "Accept": "application/json", "Accept-Encoding": "identity",
                       **provider.extra_headers()}
            dispatched = True
            try:
                outcome = recorder.post(entry.data, headers, recorder.deadline(timeout),
                                        read_errors=True, credentials=credentials)
            except ExchangeError as exc:
                classification = transport_failure(exc)
                code, submission = classification.code, classification.submission
            except ProviderError as exc:
                code = exc.code
            else:
                if outcome.status == 200 and not entry.questions:
                    code = "ok_unchecked"  # a probe body without local questions
                elif outcome.status == 200:
                    try:
                        decoded = route.decode(outcome.body, entry.questions, credentials)
                        code = decoded.error or ("ok_partial" if decoded.scoped else "ok")
                    except ProviderError as exc:
                        code = exc.code
                else:
                    code = route.status_code(outcome.status, error_object(outcome.error_raw))
                    submission = classify(code).submission
    except ProviderError as exc:
        code = exc.code
    except Exception as exc:  # noqa: BLE001 - recorded by class name; the suite continues
        record["exception"] = type(exc).__name__
        code = "runner_error"
    record["code"] = code
    outcome, error = recorder.outcome, recorder.error
    if outcome is not None:
        kept, dropped = capture_headers(outcome.headers, outcome.dropped_header_names)
        record.update(status=outcome.status, phase="complete", elapsed_s=round(outcome.elapsed, 4),
                      reused=outcome.reused, late=outcome.late, headers=kept,
                      dropped_header_names=dropped,
                      submission="sent" if outcome.status == 200 else (submission or "sent"))
        raw = outcome.body if outcome.status == 200 else outcome.error_raw
        if outcome.status != 200:
            record["error_body"] = outcome.error_body_state
            record["error"] = route.error_fields(outcome.status, error_object(outcome.error_raw))
        if code != "response_sensitive" and raw and not any(
                c and _secret_in(c, [raw]) for c in credentials):
            body = parse_body(raw)
            if body is not None:
                record["body"] = sanitize_body(body, credentials)
    elif error is not None:
        record.update(phase=error.phase, exception=error.kind, reused=error.reused,
                      submission=transport_failure(error).submission,
                      elapsed_s=round(max(0.0, clock() - started), 4))
    else:
        # No status line: refused locally (not sent), or a framing failure
        # after the request went out (possibly processed).
        record["elapsed_s"] = round(max(0.0, clock() - started), 4)
        record["submission"] = submission or ("possible" if dispatched else "not_sent")
        if dispatched and submission != "not_sent":
            record["phase"] = "receive"
    return record


def _retry_wait(record: dict[str, Any]) -> float | None:
    if record.get("code") not in RETRY_CODES:
        return None
    if (record.get("error") or {}).get("routing_metadata"):
        return None
    seconds = parse_retry_after((record.get("headers") or {}).get("retry-after"))
    return DEFAULT_RETRY_WAIT if seconds is None else min(MAX_RETRY_WAIT, seconds)


def run_suite(route: Route, entries: list[Entry], out: Path, *, key: str,
              environ: Mapping[str, str], exchange: HttpsExchange | None = None,
              timeout: float = 60.0, pause: float = 0.5, keep_raw: bool = False,
              sleep: Callable[[float], None] = time.sleep,
              clock: Callable[[], float] = time.monotonic,
              builder: dict[str, Any] | None = None,
              provider_options: Mapping[str, Any] | None = None,
              meta: Mapping[str, Mapping[str, Any]] | None = None,
              echo: Callable[[str], None] = print) -> list[dict[str, Any]]:
    """Send every entry in order, continuing after any failure; write the results."""
    out.mkdir(parents=True, exist_ok=True)
    mark_output(out)
    register_model_pattern(route.name, route.model_pattern)
    recorder = Recorder(exchange if exchange is not None else HttpsExchange(route.host, route.path))
    options = dict(provider_options or {})
    provider = route.make_provider(key, exchange=recorder, environ=environ, **options)
    invalid = route.make_provider(INVALID_TOKEN, exchange=recorder, environ=environ, **options)
    credentials = configured_credentials(environ, key)
    records: list[dict[str, Any]] = []
    try:
        with (out / "results.jsonl").open("w", encoding="utf-8", newline="\n") as sink:
            for entry in entries:
                chosen = invalid if entry.auth == "invalid" else provider
                chosen_key = INVALID_TOKEN if entry.auth == "invalid" else key
                for repeat in range(entry.repeat):
                    for number in (1, 2):
                        record = attempt(route, chosen, recorder, entry, key=chosen_key,
                                         credentials=credentials, timeout=timeout, clock=clock)
                        record.update(repeat=repeat, attempt=number, builder=builder)
                        wait = _retry_wait(record) if number == 1 else None
                        if wait is not None:
                            record["retry_reason"] = record["code"]
                            record["waited_s"] = wait
                        sink.write(dumps(record) + "\n")
                        sink.flush()
                        records.append(record)
                        if keep_raw:
                            _keep_raw(out, record, recorder, credentials)
                        echo(f"{entry.id:<18} r{repeat} a{number} status={record['status']} "
                             f"code={record['code']} {record['elapsed_s']}s")
                        if wait is None:
                            break
                        sleep(wait)
                    gap = pause if entry.pause is None else entry.pause
                    if gap > 0:
                        sleep(gap)
    finally:
        recorder.close()
    write_summary(out, records, meta or {})
    return records


def _keep_raw(out: Path, record: dict[str, Any], recorder: Recorder,
              credentials: tuple[str, ...]) -> None:
    """Opt-in raw body under ``raw/`` (never read by the sanitizer or Hermes)."""
    outcome = recorder.outcome
    if outcome is None:
        return
    raw = outcome.body if outcome.status == 200 else outcome.error_raw
    if not raw or any(c and _secret_in(c, [raw]) for c in credentials):
        return
    folder = out / "raw"
    folder.mkdir(exist_ok=True)
    name = f"{record['id']}-r{record['repeat']}-a{record['attempt']}.json"
    (folder / name).write_bytes(raw)


# -- summary ---------------------------------------------------------------------
def final_records(records: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """The last attempt of every (id, repeat), in first-seen order."""
    last: dict[tuple[str, int], dict[str, Any]] = {}
    for record in records:
        last[(record["id"], record.get("repeat", 0))] = record
    return list(last.values())


def _number(value: Any) -> Decimal | None:
    if type(value) is bool or not isinstance(value, (int, float, Decimal)):
        return None
    number = Decimal(str(value))
    return number if number.is_finite() else None


def _places(value: Decimal) -> int:
    exponent = value.as_tuple().exponent
    return -exponent if isinstance(exponent, int) and exponent < 0 else 0


def answers_of(body: Any) -> dict[str, dict[str, Any]]:
    """{name: {"type", "p" | "probabilities", "choice", "confidence"}} for both routes."""
    if type(body) is not dict:
        return {}
    items = body.get("answers")
    pairs: list[tuple[Any, Any]]
    if type(items) is dict:
        pairs = list(items.items())
    elif type(items) is list:
        pairs = [(item.get("name"), item) for item in items if type(item) is dict]
    else:
        return {}
    result: dict[str, dict[str, Any]] = {}
    for name, item in pairs:
        if type(name) is not str or type(item) is not dict:
            continue
        kind = item.get("type")
        if kind == "noul" or kind == "predicate":
            result[name] = {"type": "noul",
                            "p": _number(item.get("noul", item.get("probability")))}
        elif kind in ("choice", "score"):
            probs = item.get("probabilities")
            if type(probs) is list:
                probs = {entry.get("value"): entry.get("probability")
                         for entry in probs if type(entry) is dict}
            result[name] = {"type": kind, "choice": item.get("choice"),
                            "confidence": _number(item.get("confidence")),
                            "probabilities": ({str(k): _number(v) for k, v in probs.items()}
                                              if type(probs) is dict else None)}
        else:
            result[name] = {"type": "refusal" if kind == "refusal" else "other"}
    return result


def _fmt(value: Any) -> str:
    if value is None:
        return "-"
    if isinstance(value, Decimal):
        return format(value.normalize(), "f") if value == value.to_integral() else str(value)
    if isinstance(value, float):
        return f"{value:.4f}"
    return str(value)


def _family_answers(finals: list[dict[str, Any]], family: str) -> dict[str, Decimal]:
    merged: dict[str, Decimal] = {}
    for record in finals:
        if record.get("family", record["id"]) == family and record.get("repeat", 0) == 0:
            for name, answer in answers_of(record.get("body")).items():
                if answer["type"] == "noul" and answer.get("p") is not None:
                    merged[name] = answer["p"]
    return merged


def _max_delta(base: dict[str, Decimal], other: dict[str, Decimal]) -> tuple[Any, int]:
    common = [name for name in base if name in other]
    if not common:
        return None, 0
    return max(abs(base[n] - other[n]) for n in common), len(common)


def summary_lines(name: str, records: list[dict[str, Any]],
                  meta: Mapping[str, Mapping[str, Any]]) -> list[str]:
    """Numbers and codes only: no header value, no body text, no model string."""
    finals = final_records(records)
    route = records[0].get("route", "?") if records else "?"
    statuses: dict[str, int] = {}
    for record in finals:
        statuses[str(record.get("status"))] = statuses.get(str(record.get("status")), 0) + 1
    costs = [_number(((r.get("body") or {}).get("usage") or {}).get("cost")) for r in records
             if type(r.get("body")) is dict and type(r["body"].get("usage")) is dict]
    spend = sum((c for c in costs if c is not None), Decimal(0))
    lines = [f"# Smoke summary ({name})", "",
             f"Route: {route}. Attempts: {len(records)}; final: {len(finals)}. "
             f"Reported cost (USD): {_fmt(spend)}. Final statuses: "
             + ", ".join(f"{k}={v}" for k, v in sorted(statuses.items())) + ".", "",
             "| S-ID | r | a | status | code | phase | submission | s | reused | answers/questions "
             "| in tok | out tok | cost |",
             "|---|---|---|---|---|---|---|---|---|---|---|---|---|"]
    for record in records:
        body = record.get("body") if type(record.get("body")) is dict else {}
        usage = body.get("usage") if type(body.get("usage")) is dict else {}
        questions = record.get("questions") or (meta.get(record["id"]) or {}).get("questions")
        lines.append(
            f"| {record['id']} | {record.get('repeat', 0)} | {record.get('attempt', 1)} "
            f"| {_fmt(record.get('status'))} | {_fmt(record.get('code'))} "
            f"| {_fmt(record.get('phase'))} | {_fmt(record.get('submission'))} "
            f"| {_fmt(record.get('elapsed_s'))} | {_fmt(record.get('reused'))} "
            f"| {len(answers_of(body))}/{_fmt(questions)} | {_fmt(_number(usage.get('input_tokens')))} "
            f"| {_fmt(_number(usage.get('output_tokens')))} | {_fmt(_number(usage.get('cost')))} |")
    lines += ["", "## Shape, framing and precision", ""] + _shape_lines(finals, records)
    lines += ["", "## Decision readouts", ""] + _readout_lines(finals, meta)
    return lines


def _shape_lines(finals: list[dict[str, Any]], records: list[dict[str, Any]]) -> list[str]:
    ok = [r for r in finals if r.get("status") == 200 and type(r.get("body")) is dict]
    echo = cost_exact = out_zero = with_usage = 0
    pattern = None
    for record in ok:
        body = record["body"]
        model = body.get("model")
        route_pattern = _MODEL_PATTERNS.get(record.get("route", ""))
        pattern = route_pattern or pattern
        if type(model) is str and route_pattern is not None and route_pattern.fullmatch(model):
            echo += 1
        usage = body.get("usage") if type(body.get("usage")) is dict else None
        if usage is not None:
            with_usage += 1
            tokens, cost = _number(usage.get("input_tokens")), _number(usage.get("cost"))
            if tokens is not None and cost is not None and cost == tokens * Decimal("1e-7"):
                cost_exact += 1
            if _number(usage.get("output_tokens")) == 0:
                out_zero += 1
    headers = [r.get("headers") or {} for r in records if r.get("status") is not None]
    counts = {"x-generation-id": 0, "x-request-id": 0, "retry-after": 0, "x-ratelimit": 0,
              "identity": 0, "chunked": 0, "dropped": 0}
    for record, kept in zip([r for r in records if r.get("status") is not None], headers):
        counts["x-generation-id"] += "x-generation-id" in kept
        counts["x-request-id"] += "x-request-id" in kept
        counts["retry-after"] += "retry-after" in kept
        counts["x-ratelimit"] += any(k.startswith(ALLOWED_PREFIX) for k in kept)
        counts["identity"] += kept.get("content-encoding", "identity").lower() == "identity"
        counts["chunked"] += kept.get("transfer-encoding", "").lower() == "chunked"
        counts["dropped"] += bool(record.get("dropped_header_names"))
    noul_places: dict[int, int] = {}
    choice_places: dict[int, int] = {}
    kinds: dict[str, int] = {}
    vectors = exact = argmax = identity = 0
    worst = Decimal(0)
    for record in ok:
        for answer in answers_of(record["body"]).values():
            kinds[answer["type"]] = kinds.get(answer["type"], 0) + 1
            if answer["type"] == "noul" and answer.get("p") is not None:
                places = _places(answer["p"])
                noul_places[places] = noul_places.get(places, 0) + 1
            probs = answer.get("probabilities")
            if answer["type"] != "choice" or not probs or None in probs.values():
                continue
            vectors += 1
            values = sorted(probs.values(), reverse=True)
            total = sum(values, Decimal(0))
            worst = max(worst, abs(total - 1))
            exact += total == 1
            places = max(_places(v) for v in values)
            choice_places[places] = choice_places.get(places, 0) + 1
            argmax += probs.get(str(answer.get("choice"))) == values[0]
            k = len(values)
            confidence = answer.get("confidence")
            if confidence is not None and k > 1:
                predicted = (values[0] - Decimal(1) / k) / (1 - Decimal(1) / k)
                identity += abs(confidence - predicted) <= Decimal("0.015")
    total_headers = len(headers)
    return [
        f"- 200 bodies: {len(ok)}; model echo accepted: {echo}/{len(ok)}"
        + ("" if pattern is not None else " (no route pattern)"),
        f"- usage present: {with_usage}; cost == input_tokens x 1e-7: {cost_exact}; "
        f"output_tokens == 0: {out_zero}",
        f"- responses with headers: {total_headers}; generation id header: "
        f"{counts['x-generation-id']}; request id header: {counts['x-request-id']}; "
        f"retry-after: {counts['retry-after']}; x-ratelimit-*: {counts['x-ratelimit']}",
        f"- content-encoding identity or absent: {counts['identity']}/{total_headers}; "
        f"chunked: {counts['chunked']}; responses with dropped headers: {counts['dropped']}",
        f"- answer types: " + (", ".join(f"{k}={v}" for k, v in sorted(kinds.items())) or "none"),
        f"- noul decimal places: {dict(sorted(noul_places.items()))}; "
        f"choice max decimal places: {dict(sorted(choice_places.items()))}",
        f"- choice vectors: {vectors}; exact mass: {exact}; max |sum-1|: {_fmt(worst)}; "
        f"choice == argmax: {argmax}; chance-normalized confidence within 0.015: {identity}",
    ]


def _readout_lines(finals: list[dict[str, Any]], meta: Mapping[str, Mapping[str, Any]]
                   ) -> list[str]:
    lines: list[str] = []
    by_id: dict[str, list[dict[str, Any]]] = {}
    for record in finals:
        by_id.setdefault(record["id"], []).append(record)
    families = {record.get("family", record["id"]) for record in finals}
    production = _family_answers(finals, "S02s")
    for family in ("S02", "S12b", "S12c"):
        if family in families and production:
            other = _family_answers(finals, family)
            delta, count = _max_delta(production, other)
            lines.append(f"- {family} vs S02s: max |delta| {_fmt(delta)} over {count} noul answers "
                         "(rule: above 0.02 flips the default)")
    repeats = [record for record in by_id.get("S12", []) if record.get("status") == 200]
    if len(repeats) >= 2:
        maps = [{n: a.get("p") for n, a in answers_of(r.get("body")).items()} for r in repeats]
        identical = sum(1 for m in maps[1:] if m == maps[0])
        lines.append(f"- S12 retest: {identical}/{len(maps) - 1} repeats identical to the first")
    for family in ("S12c", "S13a", "S13b", "S13c", "S13c-pis"):
        for record in finals:
            if record.get("family", record["id"]) != family or record.get("status") != 200:
                continue
            answers = answers_of(record.get("body"))
            canary = {n: answers[n].get("p") for n in ("canary_true", "canary_false") if n in answers}
            screens = [a["p"] for n, a in answers.items()
                       if n.startswith("screen_") and a.get("p") is not None]
            lenses = [a["p"] for n, a in answers.items()
                      if n.startswith("lens_") and a.get("p") is not None]
            lines.append(f"- {record['id']}: canary_true {_fmt(canary.get('canary_true'))}, "
                         f"canary_false {_fmt(canary.get('canary_false'))}, max screen "
                         f"{_fmt(max(screens, default=None))}, max lens {_fmt(max(lenses, default=None))}")
    bugs, clean = [], []
    for sid, records in sorted(by_id.items()):
        labels = (meta.get(sid) or {}).get("labels") or {}
        if not sid.startswith("S14-") or records[0].get("status") != 200 or "buggy" not in labels:
            continue
        screens = [a["p"] for n, a in answers_of(records[0].get("body")).items()
                   if n.startswith("screen_") and a.get("p") is not None]
        if screens:
            (bugs if labels["buggy"] else clean).append(max(screens))
    if bugs and clean:
        lines.append(f"- S14 separation: min bug screen {_fmt(min(bugs))}, max clean screen "
                     f"{_fmt(max(clean))}, separated {min(bugs) > max(clean)}")
    truth = (meta.get("S07") or {}).get("truth")
    if truth and by_id.get("S07") and by_id["S07"][0].get("status") == 200:
        answers = answers_of(by_id["S07"][0].get("body"))
        scored = [(answers[n]["p"] >= Decimal("0.5")) == bool(t) for n, t in truth.items()
                  if n in answers and answers[n].get("p") is not None]
        lines.append(f"- S07 objective accuracy: {sum(scored)}/{len(scored)}")
    for sid in ("S08", "S16", "S18", "S19", "S19b", "S19c", "S21", "S22", "O04", "O05"):
        for record in by_id.get(sid, []):
            error = record.get("error") or {}
            lines.append(f"- {sid}: status {_fmt(record.get('status'))}, code "
                         f"{_fmt(record.get('code'))}, routing metadata "
                         f"{_fmt(error.get('routing_metadata'))}, param "
                         f"{'kept' if 'param' in error else ('withheld' if error.get('param_withheld') else '-')}")
    reuse = [record.get("reused") for record in finals if record.get("family") == "S20"]
    if reuse:
        lines.append(f"- S20 keep-alive: reused per request {reuse}")
    for sid in ("S10", "S10b"):
        for record in by_id.get(sid, []):
            where = answers_of(record.get("body")).get("where") or {}
            probs = where.get("probabilities") or {}
            values = sorted((v for v in probs.values() if v is not None), reverse=True)
            lines.append(f"- {sid} where: k {len(probs)}, p1 {_fmt(values[0] if values else None)}, "
                         f"confidence {_fmt(where.get('confidence'))}")
    return lines or ["- none"]


_MODEL_PATTERNS: dict[str, re.Pattern[str]] = {}


def register_model_pattern(route: str, pattern: re.Pattern[str]) -> None:
    _MODEL_PATTERNS[route] = pattern


def write_summary(out: Path, records: list[dict[str, Any]],
                  meta: Mapping[str, Mapping[str, Any]]) -> Path:
    path = out / "summary.md"
    path.write_text("\n".join(summary_lines(out.name, records, meta)) + "\n",
                    encoding="utf-8", newline="\n")
    return path


def default_out(route: str) -> Path:
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    return ROOT / "smoke-results" / f"{route}-{stamp}"


def dry_run(entries: list[Entry], echo: Callable[[str], None] = print) -> None:
    total = sum(len(e.data) * e.repeat for e in entries)
    requests = sum(e.repeat for e in entries)
    echo(f"{requests} request(s), {total} local bytes, about {total // 4} input tokens, "
         f"about ${total / 4 * 0.10 / 1_000_000:.4f} at the listed Luna rate. No network use.")
    for e in entries:
        flag = " (optional)" if e.optional else ""
        echo(f"  {e.id:<18} x{e.repeat} {e.send:<6} {e.file or '-'}{flag} - {e.purpose}")


def environment(environ: Mapping[str, str] | None) -> Mapping[str, str]:
    return os.environ if environ is None else environ
