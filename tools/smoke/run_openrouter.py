"""Run the OpenRouter Decisions smoke suite and summarize what it reveals.

Posts each request in tools/smoke/openrouter/manifest.json to
https://openrouter.ai/api/alpha/decisions, one at a time, and writes:

    <out>/results.jsonl   one record per attempt: status, latency, selected
                          headers and the parsed response (key scrubbed)
    <out>/summary.md      analysis keyed to the smoke-test questions

The key comes from OPENROUTER_API_KEY, or from --env-file (only that one
variable is read). It is never printed or written. No leaderboard headers are
sent. Every request bills your OpenRouter credits (the full suite is a few
cents at the listed $0.10 per 1M input tokens).

    python tools/smoke/run_openrouter.py --dry-run
    python tools/smoke/run_openrouter.py --env-file ~/.hermes/.env
    python tools/smoke/run_openrouter.py --only S01,S02 --include-optional
    python tools/smoke/run_openrouter.py --summarize smoke-results/openrouter-YYYYmmdd-HHMMSS
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
from decimal import Decimal
import hashlib
import json
import math
import os
from pathlib import Path
import ssl
import statistics
import sys
import time
import urllib.error
import urllib.request

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
SUITE = Path(__file__).resolve().parent / "openrouter"
ENDPOINT = "https://openrouter.ai/api/alpha/decisions"
VARIABLE = "OPENROUTER_API_KEY"
PRICE_PER_TOKEN = 0.10 / 1_000_000
KEEP_HEADERS = ("content-type", "retry-after", "x-request-id", "x-generation-id", "cf-ray")


def load_key(env_file: str | None) -> str:
    key = os.environ.get(VARIABLE, "")
    if not key and env_file:
        path = Path(env_file).expanduser()
        for line in path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if line.startswith("export "):
                line = line[7:].lstrip()
            if line.startswith(VARIABLE + "="):
                key = line.split("=", 1)[1].strip().strip('"').strip("'")
    if not key or any(c.isspace() for c in key) or not key.isascii():
        raise SystemExit(f"Set {VARIABLE} or pass --env-file pointing at a file that defines it.")
    return key


def scrub(value, key: str):
    if isinstance(value, str):
        return value.replace(key, "[key]")
    if isinstance(value, list):
        return [scrub(v, key) for v in value]
    if isinstance(value, dict):
        return {scrub(k, key): scrub(v, key) for k, v in value.items()}
    return value


def post(body: bytes, key: str, timeout: float) -> tuple[int, dict, bytes, float]:
    request = urllib.request.Request(ENDPOINT, data=body, method="POST", headers={
        "Authorization": "Bearer " + key, "Content-Type": "application/json",
        "Accept": "application/json"})
    started = time.monotonic()
    try:
        with urllib.request.urlopen(request, timeout=timeout,
                                    context=ssl.create_default_context()) as response:
            raw = response.read(4 * 1024 * 1024)
            status, headers = response.status, response.headers
    except urllib.error.HTTPError as error:
        raw = error.read(256 * 1024)
        status, headers = error.code, error.headers
    elapsed = time.monotonic() - started
    kept = {name: headers.get(name) for name in KEEP_HEADERS if headers.get(name)}
    kept.update({name.lower(): value for name, value in headers.items()
                 if name.lower().startswith(("x-ratelimit", "openrouter-"))})
    return status, kept, raw, elapsed


def run(args) -> Path:
    manifest = json.loads((SUITE / "manifest.json").read_text(encoding="utf-8"))
    only = {s.strip() for s in args.only.split(",")} if args.only else None
    entries = [e for e in manifest["entries"]
               if (only is None or e["id"] in only) and (args.include_optional or not e["optional"]
                                                          or (only and e["id"] in only))]
    total_bytes = sum((SUITE / e["file"]).stat().st_size * e["repeat"] for e in entries)
    requests = sum(e["repeat"] for e in entries)
    print(f"{requests} request(s), {total_bytes} bytes, about {total_bytes // 4} input tokens, "
          f"about ${total_bytes / 4 * PRICE_PER_TOKEN:.4f} at the listed Luna rate.")
    if args.dry_run:
        for e in entries:
            print(f"  {e['id']:<6} x{e['repeat']}  {e['file']}  - {e['purpose']}")
        raise SystemExit(0)
    key = load_key(args.env_file)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    out = Path(args.out) if args.out else ROOT / "smoke-results" / f"openrouter-{stamp}"
    out.mkdir(parents=True, exist_ok=True)
    with (out / "results.jsonl").open("w", encoding="utf-8") as sink:
        for e in entries:
            body = (SUITE / e["file"]).read_bytes()
            digest = hashlib.sha256(body).hexdigest()
            for repeat in range(e["repeat"]):
                for attempt in (1, 2):
                    status, headers, raw, elapsed = post(body, key, args.timeout)
                    try:
                        parsed = json.loads(raw.decode("utf-8"))
                    except ValueError:
                        parsed = {"_non_json": raw.decode("utf-8", "replace")[:4000]}
                    record = {"id": e["id"], "file": e["file"], "repeat": repeat, "attempt": attempt,
                              "request_sha256": digest, "request_bytes": len(body), "status": status,
                              "elapsed_s": round(elapsed, 4), "headers": headers,
                              "response": scrub(parsed, key)}
                    sink.write(json.dumps(record, ensure_ascii=False) + "\n")
                    sink.flush()
                    print(f"{e['id']:<6} r{repeat} a{attempt} status={status} {elapsed:.2f}s")
                    wait = headers.get("retry-after")
                    retryable = status in (429, 503, 529) and attempt == 1
                    if retryable and wait and wait.isdigit() and int(wait) <= 30:
                        time.sleep(int(wait))
                        continue
                    if retryable and not wait:
                        time.sleep(5)
                        continue
                    break
                time.sleep(args.pause)
    summarize(out)
    return out


def places(value) -> int:
    text = repr(value) if isinstance(value, float) else str(value)
    if "e" in text.lower():
        return -1
    return len(text.split(".", 1)[1]) if "." in text else 0


def entropy_conf(probs) -> float:
    k = len(probs)
    h = -sum(p * math.log(p) for p in probs if p > 0)
    return 1 - h / math.log(k) if k > 1 else 1.0


def mass_policies(name, answer, question) -> str:
    from decision_bug_hunter.protocol import ProviderError, validate_answer_objects
    accepted, rejected = [], []
    for policy in (None, 2, 3, 4, 6, 8):
        label = "strict" if policy is None else f"{policy}dp"
        try:
            local = json.loads(json.dumps(answer), parse_float=Decimal)
            validate_answer_objects({name: local}, {name: question}, policy)
            accepted.append(label)
        except ProviderError as exc:
            rejected.append(f"{label}:{exc.code}")
        except Exception as exc:  # noqa: BLE001 - diagnostic only
            rejected.append(f"{label}:{type(exc).__name__}")
    return "accepts " + (",".join(accepted) or "none") + ("; rejects " + ",".join(rejected) if rejected else "")


def corr(xs, ys):
    if len(xs) < 3 or statistics.pstdev(xs) == 0 or statistics.pstdev(ys) == 0:
        return float("nan")
    return statistics.correlation(xs, ys)


def summarize(out: Path) -> None:
    manifest = {e["id"]: e for e in json.loads((SUITE / "manifest.json").read_text(encoding="utf-8"))["entries"]}
    records = [json.loads(line) for line in (out / "results.jsonl").read_text(encoding="utf-8").splitlines()]
    final = [r for r in records if not any(o["id"] == r["id"] and o["repeat"] == r["repeat"]
                                           and o["attempt"] > r["attempt"] for o in records)]
    lines = [f"# OpenRouter Decisions smoke summary ({out.name})", ""]
    spend = sum((r["response"].get("usage") or {}).get("cost") or 0 for r in records
                if isinstance(r["response"], dict))
    lines += [f"Requests: {len(records)} attempts, {len(final)} final. Reported cost: ${spend:.6f}.", "",
              "| id | status | s | model | provider | in tok | out tok | cost | answers/questions |",
              "|---|---|---|---|---|---|---|---|---|"]
    conf_rows, noul_places, choice_places, sums = [], [], [], []
    by_id: dict[str, list] = {}
    for r in final:
        resp = r["response"] if isinstance(r["response"], dict) else {}
        body = json.loads((SUITE / r["file"]).read_text(encoding="utf-8"))
        usage = resp.get("usage") or {}
        answers = resp.get("answers") if isinstance(resp.get("answers"), dict) else {}
        lines.append(f"| {r['id']} r{r['repeat']} | {r['status']} | {r['elapsed_s']} | {resp.get('model')} | "
                     f"{resp.get('provider')} | {usage.get('input_tokens')} | {usage.get('output_tokens')} | "
                     f"{usage.get('cost')} | {len(answers)}/{len(body['questions'])} |")
        by_id.setdefault(r["id"], []).append((r, body, answers))
    lines += ["", "## Errors and non-200 bodies", ""]
    for r in final:
        if r["status"] != 200:
            lines.append(f"- {r['id']}: status {r['status']}, headers {r['headers']}, body "
                         f"`{json.dumps(r['response'])[:600]}`")
    lines += ["", "## Answer shapes, precision, mass, argmax and confidence", ""]
    unknown_types, missing, extra = set(), [], []
    for sid, rows in by_id.items():
        for r, body, answers in rows:
            qs = body["questions"]
            if r["status"] == 200:
                missing += [f"{sid}:{n}" for n in qs if n not in answers]
            extra += [f"{sid}:{n}" for n in answers if n not in qs]
            for name, ans in answers.items():
                kind = ans.get("type") if isinstance(ans, dict) else None
                if kind == "noul":
                    noul_places.append(places(ans.get("noul")))
                elif kind == "choice":
                    probs = ans.get("probabilities")
                    if not isinstance(probs, dict):
                        lines.append(f"- {sid} {name}: choice WITHOUT probabilities map: `{json.dumps(ans)[:300]}`")
                        continue
                    values = sorted(probs.values(), reverse=True)
                    total = sum(probs.values())
                    top = max(probs, key=probs.get)
                    choice_places.append(max(places(v) for v in probs.values()))
                    sums.append(total)
                    margin = values[0] - (values[1] if len(values) > 1 else 0)
                    conf = ans.get("confidence")
                    if isinstance(conf, (int, float)):
                        conf_rows.append((conf, margin, values[0], entropy_conf(values)))
                    q = qs.get(name, {})
                    policy_note = mass_policies(name, ans, q) if q.get("type") == "choice" else ""
                    if len(probs) >= 10 or sid in {"S01", "S02", "S10", "S10b"} or probs.get(ans.get("choice")) != values[0]:
                        lines.append(f"- {sid} {name}: k={len(probs)}/{len(q.get('criteria', {}))} "
                                     f"choice={ans.get('choice')} argmax={top} match={ans.get('choice') == top or probs.get(ans.get('choice')) == values[0]} "
                                     f"p1={values[0]} p2={values[1] if len(values) > 1 else None} sum={round(total, 6)} "
                                     f"conf={conf} {policy_note}")
                elif kind == "score":
                    lines.append(f"- {sid} {name}: score answer `{json.dumps(ans)[:400]}`")
                else:
                    unknown_types.add(json.dumps(ans)[:200])
    lines += ["", f"Noul decimal places histogram: { {p: noul_places.count(p) for p in sorted(set(noul_places))} }",
              f"Choice max decimal places histogram: { {p: choice_places.count(p) for p in sorted(set(choice_places))} }",
              f"Choice mass |sum-1|: max {max((abs(s - 1) for s in sums), default=None)}, "
              f"mean {statistics.fmean([abs(s - 1) for s in sums]) if sums else None}",
              f"Missing answers ({len(missing)}): {missing[:40] or 'none'}",
              f"Extra answers ({len(extra)}): {extra[:40] or 'none'}",
              f"Unrecognized answer objects (possible refusal representation): {sorted(unknown_types) or 'none'}"]
    if conf_rows:
        c, m, p1, e = zip(*conf_rows)
        lines += ["", "## Confidence semantics", "",
                  f"{len(conf_rows)} choice answers. corr(conf, top-two margin)={corr(c, m):.3f}; "
                  f"corr(conf, p1)={corr(c, p1):.3f}; corr(conf, 1-normalized entropy)={corr(c, e):.3f}; "
                  f"mean |conf-margin|={statistics.fmean(abs(a - b) for a, b in zip(c, m)):.4f}; "
                  f"mean |conf-p1|={statistics.fmean(abs(a - b) for a, b in zip(c, p1)):.4f}"]
    lines += ["", "## Test-specific readouts", ""]

    def noul_map(sid, repeat=0):
        for r, body, answers in by_id.get(sid, []):
            if r["repeat"] == repeat:
                return {n: a.get("noul") for n, a in answers.items() if isinstance(a, dict) and a.get("type") == "noul"}
        return {}

    base = noul_map("S02")
    for sid in ("S03", "S04", "S05", "S15"):
        other = noul_map(sid)
        common = [n for n in base if n in other and base[n] is not None and other[n] is not None]
        if common:
            diffs = [abs(base[n] - other[n]) for n in common]
            lines.append(f"- {sid} vs S02 noul: mean |diff| {statistics.fmean(diffs):.4f}, max {max(diffs):.4f} over {len(common)}")
    for sid in ("S02", "S03", "S04", "S05", "S15"):
        rows = by_id.get(sid, [])
        if rows and rows[0][2]:
            screens = {n: v for n, v in noul_map(sid).items() if n.startswith("screen_")}
            lines.append(f"- {sid} screens (bug on line 5): {screens}")
    repeats = [noul_map("S12", k) for k in range(5)]
    repeats = [r for r in repeats if r]
    if len(repeats) >= 2:
        sds = [statistics.pstdev([r[n] for r in repeats]) for n in repeats[0] if all(n in r for r in repeats)]
        lines.append(f"- S12 retest over {len(repeats)} runs: mean per-question SD {statistics.fmean(sds):.4f}, "
                     f"max SD {max(sds):.4f}, identical-run fraction "
                     f"{sum(1 for s in sds if s == 0) / len(sds):.2f}")
    truth = manifest.get("S07", {}).get("truth")
    s07 = noul_map("S07")
    if truth and s07:
        correct = [(s07[n] >= 0.5) == truth[n] for n in truth if n in s07]
        pos = [s07[n] for n in truth if n in s07 and truth[n]]
        neg = [s07[n] for n in truth if n in s07 and not truth[n]]
        lines.append(f"- S07 objective accuracy {sum(correct)}/{len(correct)}; mean P on true {statistics.fmean(pos):.3f}, "
                     f"on false {statistics.fmean(neg):.3f}")
    s06 = noul_map("S06")
    if s06:
        twin = [abs(s06[f"line_bug_L{i}"] + s06[f"line_ok_L{i}"] - 1) for i in range(1, 17)
                if f"line_bug_L{i}" in s06 and f"line_ok_L{i}" in s06]
        top = sorted(((s06.get(f"line_bug_L{i}", 0), i) for i in range(1, 17)), reverse=True)[:3]
        lines.append(f"- S06 polarity twin mean |P(bug)+P(ok)-1| {statistics.fmean(twin):.3f}; top line_bug lines {top} (truth: line 5)")
    for sid in ("S13a", "S13b"):
        m = noul_map(sid)
        if m:
            lines.append(f"- {sid} canary_true={m.get('canary_true')} canary_false={m.get('canary_false')} "
                         f"screens={ {n: v for n, v in m.items() if n.startswith(('screen_', 'lens_'))} }")
    known = []
    for sid, rows in sorted(by_id.items()):
        if sid.startswith("S14-") and rows[0][2]:
            m = noul_map(sid)
            screen = next((v for n, v in m.items() if n.startswith("screen_")), None)
            lenses = max((v for n, v in m.items() if n.startswith("lens_")), default=None)
            known.append(f"{sid} buggy={manifest[sid]['labels']['buggy']} screen={screen} max_lens={lenses} verify={m.get('verify')}")
    if known:
        lines.append("- S14 known-answer pairs: " + "; ".join(known))
    (out / "summary.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"Summary written to {out / 'summary.md'}")


def main() -> int:
    parser = argparse.ArgumentParser(description="OpenRouter Decisions smoke suite")
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--only", help="Comma-separated ids, e.g. S01,S02,S14-1")
    parser.add_argument("--include-optional", action="store_true", help="Also run S15 (Jev).")
    parser.add_argument("--env-file", help="Read only OPENROUTER_API_KEY from this dotenv file.")
    parser.add_argument("--out", help="Output directory (default smoke-results/openrouter-<UTC stamp>).")
    parser.add_argument("--timeout", type=float, default=120.0)
    parser.add_argument("--pause", type=float, default=0.5)
    parser.add_argument("--summarize", help="Only rebuild summary.md for an existing output directory.")
    args = parser.parse_args()
    if args.summarize:
        summarize(Path(args.summarize))
        return 0
    out = run(args)
    print(f"Results in {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
