"""Parse application log lines and compute statistics over them.

A log line has the shape::

    2024-03-05T10:15:30.123Z ERROR db.pool [req=ab12] connect failed retries=3

The module parses such lines into records, then offers percentiles, fixed
time windows, request sessions, burst detection, latency buckets and a
short text report.
"""

from __future__ import annotations

import datetime as dt
import math
import re
from bisect import bisect_left, bisect_right
from collections import Counter
from dataclasses import dataclass, field
from decimal import ROUND_CEILING, ROUND_HALF_UP, Decimal, InvalidOperation
from typing import Any, Iterable, Optional, Sequence

LEVELS = ("TRACE", "DEBUG", "INFO", "WARN", "ERROR", "FATAL")
LEVEL_RANK = {name: rank for rank, name in enumerate(LEVELS)}
LEVEL_ALIASES = {"WARNING": "WARN"}
ERROR_RANK = LEVEL_RANK["ERROR"]
MAX_KEPT_ERRORS = 50
DEFAULT_IDLE_MS = 30_000
FLOAT_PLACES = 3
EPOCH = dt.datetime(1970, 1, 1, tzinfo=dt.timezone.utc)
DURATION_UNITS_US = {
    "us": 1,
    "ms": 1_000,
    "s": 1_000_000,
    "m": 60_000_000,
    "h": 3_600_000_000,
}

_TS_RE = re.compile(
    r"^([0-9]{4})-([0-9]{2})-([0-9]{2})T([0-9]{2}):([0-9]{2}):([0-9]{2})(?:\.([0-9]{1,3}))?Z$"
)
_LINE_RE = re.compile(
    r"^(?P<ts>\S+)\s+(?P<level>[A-Z]+)\s+(?P<component>[a-z][a-z0-9_.-]*)"
    r"(?:\s+\[req=(?P<req>[A-Za-z0-9_-]{1,32})\])?(?:\s+(?P<rest>.*))?$"
)
_FIELD_RE = re.compile(r'(?<!\S)([A-Za-z_][A-Za-z0-9_.]*)=("(?:[^"\\]|\\.)*"|\S*)')
_DURATION_RE = re.compile(r"^([0-9]+(?:\.[0-9]+)?)(us|ms|s|m|h)$")


class LogParseError(ValueError):
    """Raised when a line or a value cannot be parsed."""


def parse_timestamp(text: str) -> int:
    """Convert ``YYYY-MM-DDTHH:MM:SS[.fff]Z`` to epoch milliseconds."""
    match = _TS_RE.match(text)
    if match is None:
        raise LogParseError(f"bad timestamp: {text!r}")
    parts = [int(match.group(i)) for i in range(1, 7)]
    fraction = (match.group(7) or "0").ljust(3, "0")
    try:
        moment = dt.datetime(*parts, tzinfo=dt.timezone.utc)
    except ValueError as exc:
        raise LogParseError(f"bad timestamp: {text!r}") from exc
    if moment < EPOCH:
        raise LogParseError(f"timestamp before 1970: {text!r}")
    seconds = (moment - EPOCH) // dt.timedelta(seconds=1)
    return seconds * 1000 + int(fraction)


def format_timestamp(ts_ms: int) -> str:
    """Format epoch milliseconds the way log lines write them."""
    seconds, millis = divmod(ts_ms, 1000)
    moment = EPOCH + dt.timedelta(seconds=seconds)
    return moment.strftime("%Y-%m-%dT%H:%M:%S") + f".{millis:03d}Z"


def parse_duration_us(text: str) -> int:
    """Parse ``250us``, ``12ms``, ``1.5s``, ``2m`` or ``1h`` to microseconds."""
    match = _DURATION_RE.match(text.strip())
    if match is None:
        raise LogParseError(f"bad duration: {text!r}")
    try:
        amount = Decimal(match.group(1))
    except InvalidOperation as exc:
        raise LogParseError(f"bad duration: {text!r}") from exc
    micros = amount * DURATION_UNITS_US[match.group(2)]
    return int(micros.to_integral_value(rounding=ROUND_HALF_UP))


def _unquote(raw: str) -> str:
    if len(raw) >= 2 and raw.startswith('"') and raw.endswith('"'):
        return re.sub(r"\\(.)", r"\1", raw[1:-1])
    return raw


def extract_fields(rest: str) -> tuple[str, dict[str, str]]:
    """Split the text after the component into a message and trailing fields."""
    matches = list(_FIELD_RE.finditer(rest))
    end = len(rest)
    taken = []
    for match in reversed(matches):
        if rest[match.end():end].strip():
            break
        taken.append(match)
        end = match.start()
    fields = {m.group(1): _unquote(m.group(2)) for m in reversed(taken)}
    return rest[:end].strip(), fields


@dataclass(frozen=True)
class LogRecord:
    """One parsed log line."""

    line_no: int
    ts_ms: int
    level: str
    component: str
    req_id: Optional[str]
    message: str
    fields: dict[str, str] = field(default_factory=dict)

    @property
    def rank(self) -> int:
        return LEVEL_RANK[self.level]

    @property
    def is_error(self) -> bool:
        return self.rank >= ERROR_RANK


def parse_line(line: str, line_no: int) -> LogRecord:
    """Parse one non-blank line or raise :class:`LogParseError`."""
    match = _LINE_RE.match(line.strip())
    if match is None:
        raise LogParseError("line does not match the log format")
    level = LEVEL_ALIASES.get(match.group("level"), match.group("level"))
    if level not in LEVEL_RANK:
        raise LogParseError(f"unknown level {match.group('level')!r}")
    ts_ms = parse_timestamp(match.group("ts"))
    message, fields = extract_fields(match.group("rest") or "")
    return LogRecord(
        line_no=line_no,
        ts_ms=ts_ms,
        level=level,
        component=match.group("component"),
        req_id=match.group("req"),
        message=message,
        fields=fields,
    )


@dataclass
class ParseResult:
    """Records plus the problems met while reading."""

    records: list[LogRecord] = field(default_factory=list)
    errors: list[tuple[int, str]] = field(default_factory=list)
    error_count: int = 0
    out_of_order: int = 0
    blank_lines: int = 0


def read_lines(lines: Iterable[str]) -> ParseResult:
    """Parse many lines. Records come back sorted by timestamp, stably."""
    result = ParseResult()
    latest: Optional[int] = None
    for line_no, raw in enumerate(lines, start=1):
        if not raw.strip():
            result.blank_lines += 1
            continue
        try:
            record = parse_line(raw, line_no)
        except LogParseError as exc:
            result.error_count += 1
            if len(result.errors) < MAX_KEPT_ERRORS:
                result.errors.append((line_no, str(exc)))
            continue
        if latest is not None and record.ts_ms < latest:
            result.out_of_order += 1
        if latest is None or record.ts_ms > latest:
            latest = record.ts_ms
        result.records.append(record)
    result.records.sort(key=lambda rec: rec.ts_ms)
    return result


def _round(value: float) -> float:
    return round(value, FLOAT_PLACES)


def percentile(values: Sequence[float], p: float) -> Optional[float]:
    """Nearest-rank percentile, ``0 <= p <= 100``. Empty input gives None."""
    if p < 0 or p > 100:
        raise ValueError("percentile must be between 0 and 100")
    if not values:
        return None
    ordered = sorted(values)
    if p == 0:
        return ordered[0]
    exact = Decimal(str(p)) * len(ordered) / 100
    rank = int(exact.to_integral_value(rounding=ROUND_CEILING))
    return ordered[rank - 1]


def median(values: Sequence[float]) -> Optional[float]:
    if not values:
        return None
    ordered = sorted(values)
    mid = len(ordered) // 2
    if len(ordered) % 2:
        return ordered[mid]
    return _round((ordered[mid - 1] + ordered[mid]) / 2)


class RunningStats:
    """Streaming count, mean and variance (Welford), mergeable."""

    def __init__(self) -> None:
        self.count = 0
        self.mean = 0.0
        self._m2 = 0.0
        self.minimum: Optional[float] = None
        self.maximum: Optional[float] = None

    def add(self, value: float) -> None:
        self.count += 1
        delta = value - self.mean
        self.mean += delta / self.count
        self._m2 += delta * (value - self.mean)
        if self.minimum is None or value < self.minimum:
            self.minimum = value
        if self.maximum is None or value > self.maximum:
            self.maximum = value

    def merge(self, other: "RunningStats") -> None:
        if other.count == 0:
            return
        if self.count == 0:
            self.count, self.mean, self._m2 = other.count, other.mean, other._m2
            self.minimum, self.maximum = other.minimum, other.maximum
            return
        total = self.count + other.count
        delta = other.mean - self.mean
        self._m2 += other._m2 + delta * delta * self.count * other.count / total
        self.mean += delta * other.count / total
        self.count = total
        self.minimum = min(self.minimum, other.minimum)
        self.maximum = max(self.maximum, other.maximum)

    @property
    def stddev(self) -> Optional[float]:
        if self.count < 2:
            return None
        return _round(math.sqrt(self._m2 / (self.count - 1)))

    def summary(self) -> dict[str, Any]:
        return {
            "count": self.count,
            "mean": _round(self.mean) if self.count else None,
            "stddev": self.stddev,
            "min": self.minimum,
            "max": self.maximum,
        }


def bucket_start(ts_ms: int, width_s: int) -> int:
    """Start of the epoch-aligned window that holds ``ts_ms``."""
    if width_s < 1:
        raise ValueError("window width must be at least one second")
    width_ms = width_s * 1000
    return ts_ms - ts_ms % width_ms


@dataclass(frozen=True)
class WindowRow:
    """Level counts for one window."""

    start_ms: int
    counts: dict[str, int]

    @property
    def total(self) -> int:
        return sum(self.counts.values())


def count_by_window(
    records: Iterable[LogRecord], width_s: int, fill_gaps: bool = True
) -> list[WindowRow]:
    """Count records per level in fixed windows, ascending by start."""
    tallies: dict[int, Counter[str]] = {}
    for record in records:
        start = bucket_start(record.ts_ms, width_s)
        tallies.setdefault(start, Counter())[record.level] += 1
    if not tallies:
        return []
    starts = sorted(tallies)
    if fill_gaps:
        step = width_s * 1000
        starts = list(range(starts[0], starts[-1] + 1, step))
    rows = []
    for start in starts:
        counts = {name: 0 for name in LEVELS}
        counts.update(tallies.get(start, {}))
        rows.append(WindowRow(start, counts))
    return rows


def error_rate_per_minute(records: Sequence[LogRecord]) -> float:
    """Errors per minute over the span of the records, at least one minute."""
    if not records:
        return 0.0
    errors = sum(1 for rec in records if rec.is_error)
    span_ms = records[-1].ts_ms - records[0].ts_ms
    minutes = max(1.0, span_ms / 60_000)
    return _round(errors / minutes)


@dataclass
class Session:
    """The lines of one request id, as one continuous burst of activity."""

    req_id: str
    start_ms: int
    end_ms: int
    lines: int = 0
    failed: bool = False
    components: set[str] = field(default_factory=set)

    @property
    def duration_ms(self) -> int:
        return self.end_ms - self.start_ms


class SessionTracker:
    """Builds sessions from records fed in timestamp order."""

    def __init__(self, idle_ms: int = DEFAULT_IDLE_MS) -> None:
        if idle_ms < 0:
            raise ValueError("idle_ms must not be negative")
        self.idle_ms = idle_ms
        self._open: dict[str, Session] = {}
        self._done: list[Session] = []

    def feed(self, record: LogRecord) -> None:
        if record.req_id is None:
            return
        session = self._open.get(record.req_id)
        if session is not None and record.ts_ms - session.end_ms > self.idle_ms:
            self._done.append(session)
            session = None
        if session is None:
            session = Session(record.req_id, record.ts_ms, record.ts_ms)
            self._open[record.req_id] = session
        session.end_ms = record.ts_ms
        session.lines += 1
        session.components.add(record.component)
        if record.is_error:
            session.failed = True

    def finish(self) -> list[Session]:
        everything = self._done + list(self._open.values())
        return sorted(everything, key=lambda s: (s.start_ms, s.req_id))


def build_sessions(
    records: Iterable[LogRecord], idle_ms: int = DEFAULT_IDLE_MS
) -> list[Session]:
    tracker = SessionTracker(idle_ms)
    for record in records:
        tracker.feed(record)
    return tracker.finish()


@dataclass(frozen=True)
class Burst:
    """A dense run of events."""

    start_ms: int
    end_ms: int
    count: int


def detect_bursts(times: Sequence[int], window_ms: int, threshold: int) -> list[Burst]:
    """Find runs where at least ``threshold`` events fall in ``window_ms``."""
    if window_ms < 1 or threshold < 2:
        raise ValueError("window_ms must be positive and threshold at least 2")
    ordered = sorted(times)
    spans: list[list[int]] = []
    for start in ordered:
        inside = bisect_right(ordered, start + window_ms - 1) - bisect_left(ordered, start)
        if inside < threshold:
            continue
        stop = start + window_ms
        if spans and start < spans[-1][1]:
            spans[-1][1] = max(spans[-1][1], stop)
        else:
            spans.append([start, stop])
    bursts = []
    for first, stop in spans:
        lo = bisect_right(ordered, first - 1)
        hi = bisect_right(ordered, stop - 1)
        bursts.append(Burst(first, ordered[hi - 1], hi - lo))
    return bursts


class LatencyBuckets:
    """Counts durations into ascending edges with under and over counters."""

    def __init__(self, edges_ms: Sequence[float]) -> None:
        if len(edges_ms) < 2:
            raise ValueError("need at least two edges")
        if any(a >= b for a, b in zip(edges_ms, edges_ms[1:])):
            raise ValueError("edges must be strictly ascending")
        self.edges = list(edges_ms)
        self.counts = [0] * (len(edges_ms) - 1)
        self.under = 0
        self.over = 0

    def add_us(self, micros: int) -> None:
        value = micros / 1000
        if value < self.edges[0]:
            self.under += 1
        elif value >= self.edges[-1]:
            self.over += 1
        else:
            self.counts[bisect_right(self.edges, value) - 1] += 1

    @property
    def total(self) -> int:
        return self.under + self.over + sum(self.counts)

    def labels(self) -> list[str]:
        return [f"[{a}, {b})" for a, b in zip(self.edges, self.edges[1:])]


def collect_latencies_us(
    records: Iterable[LogRecord], key: str = "dur"
) -> tuple[list[int], int]:
    """Read durations from a field. Returns the values and the bad-value count."""
    values: list[int] = []
    bad = 0
    for record in records:
        raw = record.fields.get(key)
        if raw is None:
            continue
        try:
            values.append(parse_duration_us(raw))
        except LogParseError:
            bad += 1
    return values, bad


def top_error_components(records: Iterable[LogRecord], n: int) -> list[tuple[str, int]]:
    """Components ranked by ERROR and FATAL lines, ties by name."""
    if n < 1:
        raise ValueError("n must be at least 1")
    counts = Counter(rec.component for rec in records if rec.is_error)
    ranked = sorted(counts.items(), key=lambda item: (-item[1], item[0]))
    return ranked[:n]


def level_histogram(records: Iterable[LogRecord]) -> dict[str, int]:
    counts = Counter(rec.level for rec in records)
    return {name: counts.get(name, 0) for name in LEVELS}


@dataclass
class Analysis:
    """The combined result of :func:`analyze`."""

    parsed: ParseResult
    levels: dict[str, int]
    sessions: list[Session]
    windows: list[WindowRow]
    bursts: list[Burst]
    latency_p50_us: Optional[float]
    latency_p95_us: Optional[float]
    top_errors: list[tuple[str, int]]
    error_rate: float
    report: str = ""


def analyze(
    lines: Iterable[str],
    window_s: int = 60,
    idle_ms: int = DEFAULT_IDLE_MS,
    burst_window_ms: int = 5000,
    burst_threshold: int = 5,
) -> Analysis:
    """Parse ``lines`` and compute every statistic in one pass."""
    parsed = read_lines(lines)
    records = parsed.records
    error_times = [rec.ts_ms for rec in records if rec.is_error]
    latencies, _ = collect_latencies_us(records)
    analysis = Analysis(
        parsed=parsed,
        levels=level_histogram(records),
        sessions=build_sessions(records, idle_ms),
        windows=count_by_window(records, window_s),
        bursts=detect_bursts(error_times, burst_threshold, burst_window_ms),
        latency_p50_us=percentile(latencies, 50),
        latency_p95_us=percentile(latencies, 95),
        top_errors=top_error_components(records, 3),
        error_rate=error_rate_per_minute(records),
    )
    analysis.report = render_report(analysis)
    return analysis


def render_report(analysis: Analysis) -> str:
    """Render a few summary lines."""
    parsed = analysis.parsed
    out = [
        f"lines parsed: {len(parsed.records)}",
        f"parse errors: {parsed.error_count}",
        f"out of order: {parsed.out_of_order}",
    ]
    for name in LEVELS:
        if analysis.levels[name]:
            out.append(f"{name}: {analysis.levels[name]}")
    failed = sum(1 for s in analysis.sessions if s.failed)
    out.append(f"sessions: {len(analysis.sessions)} ({failed} failed)")
    out.append(f"errors per minute: {analysis.error_rate}")
    if analysis.latency_p50_us is not None:
        out.append(f"latency p50: {analysis.latency_p50_us / 1000:.3f} ms")
        out.append(f"latency p95: {analysis.latency_p95_us / 1000:.3f} ms")
    for burst in analysis.bursts:
        out.append(
            f"burst: {format_timestamp(burst.start_ms)} "
            f"to {format_timestamp(burst.end_ms)} ({burst.count} events)"
        )
    for component, count in analysis.top_errors:
        out.append(f"top error component: {component} ({count})")
    return "\n".join(out) + "\n"
