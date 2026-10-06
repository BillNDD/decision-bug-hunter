"""Operator-run first-contact probe for the live Decisions API.

Sends a small number of DBH-shaped requests to the documented endpoint and
prints sanitized diagnostics only: HTTP status, documented error type/code/
param, request id, model, usage, latency, answer shapes, probability sums and
precision, and which local probability-mass policy accepts each choice vector.
The credential is never printed; request and response bodies are printed only
with --show-bodies. ``--dry-run`` builds the requests and exits without any
network use.

Every live request bills input tokens (listed at $0.10 per 1M when written).
Run it only with your own key and an authorized budget. The CLI never uses
this module.
"""
from __future__ import annotations

import argparse
from decimal import Decimal
import http.client
import json
import os
import ssl
import sys
import time

from decision_bug_hunter import decisions, questions
from decision_bug_hunter.core import Source, Span
from decision_bug_hunter.protocol import (MAX_QUESTIONS, MAX_RESPONSE_BYTES, QUESTION,
                                          ProviderError, encode_request,
                                          validate_answer_objects)

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


def build(kind: str) -> tuple[dict, dict]:
    """Return (state, questions) for one probe shape built by the engine's code."""
    source = Source.from_text(SAMPLE, name="probe.py")
    region = Span(1, len(source.lines))
    pack, _ = questions.load_pack()
    state = questions.state_for(source, region, 0, None, context_scope="declared_standalone")
    if kind == "shape":
        targets = [Span(1, 5), Span(8, 12), region]
        return state, questions.screening(pack, region, targets, bug_lenses=True, state=state)
    if kind == "count":
        # Short instructions so that the maximum local batch fits the 24 KiB cap.
        return state, {f"probe_{i}": {
            "type": "noul", "criteria": dict(QUESTION["criteria"]),
            "instructions": f"Probe {i}: can average in probe.py lines 1 through 5 fail "
                            "when values is empty? Judge the code as evidence."}
            for i in range(MAX_QUESTIONS)}
    if kind == "long":
        long_question = dict(QUESTION)
        long_question["instructions"] = QUESTION["instructions"] + " " + ("Context. " * 1200)
        return state, {"long": long_question, "screen_L1-12": questions.noul(pack, "screen", region)}
    raise ValueError(kind)


def body_for(payload: bytes, form: str) -> bytes:
    wire = decisions.translate_request(payload)
    if form == "string":
        return wire
    data = json.loads(wire)
    data["input"] = [{"role": "user", "type": "message",
                      "content": [{"type": "input_text", "text": data["input"]}]}]
    return json.dumps(data, ensure_ascii=False, separators=(",", ":")).encode("utf-8")


def scrub(text: str, key: str) -> str:
    return text.replace(key, "[key]") if key else text


def exchange(body: bytes, key: str, timeout: float) -> tuple[int, dict, bytes, float]:
    headers = {"Authorization": "Bearer " + key, "Content-Type": "application/json",
               "Accept": "application/json", "Accept-Encoding": "identity",
               "Connection": "close"}
    for variable, header in ((decisions.ORGANIZATION_VARIABLE, "OpenAI-Organization"),
                             (decisions.PROJECT_VARIABLE, "OpenAI-Project")):
        if os.environ.get(variable):
            headers[header] = os.environ[variable]
    connection = http.client.HTTPSConnection(decisions.HOST, decisions.PORT, timeout=timeout,
                                             context=ssl.create_default_context())
    started = time.monotonic()
    try:
        connection.request("POST", decisions.PATH, body=body, headers=headers)
        response = connection.getresponse()
        raw = response.read(MAX_RESPONSE_BYTES + 1)
        meta = {name.lower(): value for name, value in response.getheaders()
                if name.lower() in {"x-request-id", "openai-processing-ms", "retry-after",
                                    "content-type", "content-length",
                                    "x-ratelimit-limit-requests", "x-ratelimit-remaining-requests",
                                    "x-ratelimit-limit-tokens", "x-ratelimit-remaining-tokens",
                                    "x-ratelimit-reset-requests", "x-ratelimit-reset-tokens"}}
        return response.status, meta, raw, time.monotonic() - started
    finally:
        connection.close()


def places(value: Decimal) -> int:
    exponent = value.as_tuple().exponent
    return -exponent if isinstance(exponent, int) and exponent < 0 else 0


def report_answers(raw: bytes, local_questions: dict, key: str) -> None:
    response = decisions.translate_response(raw, local_questions, key)
    print(f"  usage: {response.usage}")
    if response.error:
        print(f"  adapter rejection: {response.error}")
        if response.error == "response_model":
            try:
                print(f"  model string: {json.loads(raw).get('model')!r}")
            except ValueError:
                pass
        return
    for name, answer in response.answers.items():
        if answer["type"] == "noul":
            print(f"  predicate {name}: p={answer['noul']} ({places(answer['noul'])} places)")
        else:
            values = answer["probabilities"]
            total = sum(values.values(), Decimal(0))
            width = max(places(v) for v in values.values())
            top = max(values, key=lambda k: values[k])
            print(f"  choice {name}: choice={answer['choice']!r} argmax={top!r} "
                  f"options={len(values)} sum={total} max_places={width} "
                  f"confidence={answer['confidence']} "
                  f"max_p={values[top]}")
    accepted = []
    for policy in (None, 2, 3, 4, 5, 6, 7, 8):
        try:
            validate_answer_objects(response.answers, local_questions, policy)
            accepted.append("strict" if policy is None else str(policy))
        except ProviderError as exc:
            accepted.append(f"{'strict' if policy is None else policy}:{exc.code}")
    print(f"  mass policies: {' '.join(accepted)}")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--requests", default="shape",
                        choices=("shape", "count", "long", "all"),
                        help="shape: a realistic screening batch; count: 64 predicates; "
                             "long: a 12 KB instruction; all: the three in order.")
    parser.add_argument("--input-form", default="string", choices=("string", "message"),
                        help="Send evidence as the documented input string (what DBH does) "
                             "or as one user message with an input_text part.")
    parser.add_argument("--timeout", type=float, default=30.0)
    parser.add_argument("--dry-run", action="store_true", help="Build only; no network.")
    parser.add_argument("--show-bodies", action="store_true",
                        help="Print request and response bodies (never the key).")
    args = parser.parse_args()
    kinds = ("shape", "count", "long") if args.requests == "all" else (args.requests,)
    key = os.environ.get(decisions.CREDENTIAL_VARIABLE, "")
    if not args.dry_run and decisions.DecisionsProvider(environ=os.environ)._api_key is None:
        print(f"Set {decisions.CREDENTIAL_VARIABLE} to run live, or pass --dry-run.",
              file=sys.stderr)
        return 2
    for kind in kinds:
        state, local_questions = build(kind)
        payload = encode_request(state, local_questions)
        body = body_for(payload, args.input_form)
        print(f"[{kind}] questions={len(local_questions)} local_envelope={len(payload)} B "
              f"body={len(body)} B (~{len(body) // 4} tokens, ~${len(body) / 4 / 1e6 * 0.10:.5f})")
        if args.show_bodies:
            print(scrub(body.decode("utf-8"), key))
        if args.dry_run:
            continue
        status, meta, raw, elapsed = exchange(body, key, args.timeout)
        print(f"  status={status} elapsed={elapsed:.3f}s headers={meta}")
        if status != 200:
            try:
                error = json.loads(raw.decode("utf-8")).get("error", {})
            except ValueError:
                error = {}
            summary = {k: error.get(k) for k in ("type", "code", "param")}
            print(f"  error: {summary}")
            message = str(error.get("message", ""))[:300]
            if message:
                print(f"  message: {scrub(message, key)}")
            continue
        if args.show_bodies:
            print(scrub(raw.decode("utf-8", "replace"), key))
        try:
            report_answers(raw, local_questions, key)
        except ProviderError as exc:
            print(f"  adapter rejection: {exc.code}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
