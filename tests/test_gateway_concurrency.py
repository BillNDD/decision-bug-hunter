"""The gateway's concurrent calls (plan B1): ``max_in_flight`` and ``_submit_prepared``.

The engine still calls the gateway one request at a time, so these tests drive
``_submit_prepared`` directly with a thread-safe fake provider (an optional
barrier, injected latency, scripted holds and outcomes). Nothing here opens a
socket or waits on a wall clock beyond a few milliseconds of injected latency;
every wait has a timeout, so a broken run fails instead of hanging, and every
held call is released at cleanup because the workers are not daemon threads.

What they hold the gateway to: each handle gets its own answers, summary and
receipts; the counters equal the sums over the calls; no more than
``max_in_flight`` calls run at once; the cost bound of every call in flight is
reserved; a rate-limit wait pauses every worker; a failed receipt write or a
stop refuses new calls while calls in flight settle; an interrupt leaves every
receipt settled or recording a possible submission; at ``max_in_flight`` 1 the
call runs in the calling thread and writes the receipts ``_evaluate_prepared``
writes; and a scan with ``--concurrency 4`` through the serial engine is
byte-identical to one without.
"""
from contextlib import redirect_stderr, redirect_stdout
from decimal import Decimal
import hashlib
import io
import json
from pathlib import Path
import random
import signal
import tempfile
import _thread
import threading
import time
import unittest
from unittest.mock import patch

from decision_bug_hunter import __main__ as cli
from decision_bug_hunter import providers
from decision_bug_hunter.core import MAX_CONCURRENCY, Config
from decision_bug_hunter.hosted import MAX_CONNECTIONS
from decision_bug_hunter.protocol import QUESTION, ProviderError, encode_request
from decision_bug_hunter.providers import (MAX_IN_FLIGHT, CallHandle, CallResult,
                                           ProviderIdentity, ProviderResponse,
                                           RetryPolicy, ValidatedGateway,
                                           attempt_cost_bound, classify)
from tests.fakes import FakeClock
from tests.support import FixtureProvider, clean_provider_env, scan, source
from tests.test_call_summary import canonical, scrub
from tests.test_cost_accounting import SPEC
from tests.test_prepared_path import pinned, receipt_scrub
from tests.test_provider_boundary import SyntheticProvider

QUESTIONS = {"q": QUESTION}
#: Seconds any wait for another thread may take before the test fails.
PATIENCE = 20.0


def wire_for(index):
    """The prepared wire and key of call ``index``: only its state text differs."""
    state = {"text": f"call {index:02d}", "context_scope": "declared_standalone"}
    wire = encode_request(state, QUESTIONS)
    return wire, hashlib.sha256(wire).hexdigest()


def metadata_for(index):
    return {"sequence": index + 1, "phase": "test"}


def noul_for(index):
    """The answer call ``index`` gets, so a handle's answer says whose it is."""
    return Decimal("0.50") + Decimal(index) / 100


def usage_for(index):
    return {"input_tokens": 1000 + index, "output_tokens": index}


def cost_for(index):
    return Decimal(index + 1) / Decimal(1_000_000)


def read_receipt(path):
    """One receipt file. A file a worker has just renamed into place can be
    briefly locked on Windows, so a refused read is retried."""
    for _attempt in range(300):
        try:
            return json.loads(Path(path).read_text(encoding="utf-8"))
        except PermissionError:
            time.sleep(0.01)
    raise AssertionError(f"{path} stayed unreadable")


def wait_until(predicate, what="the condition"):
    end = time.monotonic() + PATIENCE
    while not predicate():
        if time.monotonic() > end:
            raise AssertionError(f"timed out waiting for {what}")
        time.sleep(0.002)


class ConcurrentProvider:
    """A thread-safe offline provider that answers call ``i`` with ``noul_for(i)``.

    ``barrier`` makes every call wait for the others, ``latency`` sleeps that
    long, ``holds`` (call index -> event) keeps a call inside ``decide`` until
    the event is set, and ``script`` (call index -> outcomes) gives the
    exceptions to raise on that call's first attempts, in order. ``on_send``
    sees the call index when its request is handed over; ``on_dispatching``
    sees the index of a call whose dispatching receipt is being checked (the
    step before its bytes may leave). Cost and usage are reported, so receipts
    carry them.
    """

    identity = ProviderIdentity("offline-concurrency", model="offline-priced", synthetic=True)
    model_spec = SPEC

    def __init__(self, *, barrier=None, latency=0.0, holds=None, script=None,
                 on_send=None, on_dispatching=None, report_cost=True):
        self._cond = threading.Condition()
        self.barrier = barrier
        self.latency = latency
        self.holds = holds or {}
        self.script = {index: list(outcomes) for index, outcomes in (script or {}).items()}
        self.on_send = on_send
        self.on_dispatching = on_dispatching
        self.report_cost = report_cost
        self.requests = []
        self.threads = []
        self.in_flight = 0
        self.peak = 0
        self.closed = False

    def require_available(self):
        return None

    def check_sensitive(self, *values):
        if (self.on_dispatching is not None and len(values) == 2
                and isinstance(values[1], dict) and values[1].get("status") == "dispatching"):
            self.on_dispatching(values[1]["metadata"]["sequence"] - 1)

    def close(self):
        self.closed = True

    def wait_for_requests(self, count):
        with self._cond:
            if not self._cond.wait_for(lambda: len(self.requests) >= count, PATIENCE):
                raise AssertionError(f"only {len(self.requests)} of {count} requests arrived")

    def decide(self, request):
        index = int(json.loads(request.payload)["state"]["text"].split()[1])
        with self._cond:
            self.requests.append(index)
            self.threads.append(threading.get_ident())
            self.in_flight += 1
            self.peak = max(self.peak, self.in_flight)
            self._cond.notify_all()
        try:
            if self.on_send is not None:
                self.on_send(index)
            if self.barrier is not None:
                self.barrier.wait(PATIENCE)
            if self.latency:
                time.sleep(self.latency)
            hold = self.holds.get(index)
            if hold is not None and not hold.wait(PATIENCE):
                raise AssertionError("a held call was never released")
            with self._cond:
                outcomes = self.script.get(index)
                outcome = outcomes.pop(0) if outcomes else None
            if outcome is not None:
                raise outcome
            return ProviderResponse(
                {"q": {"type": "noul", "noul": noul_for(index)}}, usage_for(index),
                cost_usd=cost_for(index) if self.report_cost else None)
        finally:
            with self._cond:
                self.in_flight -= 1


class GatedSleep:
    """An injected sleep that records each wait and blocks until the test opens it."""

    def __init__(self):
        self.calls = []
        self.opened = threading.Event()
        self._lock = threading.Lock()

    def __call__(self, seconds):
        with self._lock:
            self.calls.append(seconds)
        if not self.opened.wait(PATIENCE):
            raise AssertionError("a backoff was never released")


def failure(code, **kwargs):
    return ProviderError(code, classification=classify(code, **kwargs))


class Base(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        environment = clean_provider_env()
        environment.__enter__()
        self.addCleanup(environment.__exit__, None, None, None)
        self.releases = []
        self.addCleanup(self.release_everything)

    def release_everything(self):
        """Runs before the temporary directory goes: free every held call."""
        for event in self.releases:
            event.set()

    def hold(self, count):
        """``count`` events a provider keeps its calls on, released at cleanup."""
        events = [threading.Event() for _ in range(count)]
        self.releases.extend(events)
        return events

    def gateway(self, provider, label="receipts", **kwargs):
        kwargs.setdefault("rng", random.Random(5))
        gateway = ValidatedGateway(provider, self.root / label, **kwargs)

        def close():
            try:
                gateway.close()
            except ProviderError:
                pass

        # Registered after release_everything, so it runs first: close() joins
        # workers, which must not still be held.
        self.addCleanup(close)
        self.addCleanup(self.release_everything)
        return gateway

    def submit(self, gateway, index):
        wire, key = wire_for(index)
        return gateway._submit_prepared(wire, key, metadata=metadata_for(index))

    def receipts(self, label="receipts"):
        directory = self.root / label
        if not directory.exists():
            return []
        return [read_receipt(path) for path in sorted(directory.glob("*.json"))]

    def free_places(self, gateway, count):
        """Every one of the ``count`` places can be taken again, then is given back."""
        slots = gateway._slots
        taken = 0
        try:
            for _ in range(count):
                self.assertTrue(slots.acquire(timeout=PATIENCE), "a place was never freed")
                taken += 1
            self.assertFalse(slots.acquire(blocking=False))
        finally:
            for _ in range(taken):
                slots.release()

    def holding_dispatch(self, index):
        """(entered, release, hook): the hook holds call ``index`` in its dispatching write."""
        entered, release = self.hold(2)

        def on_dispatching(seen):
            if seen == index:
                entered.set()
                if not release.wait(PATIENCE):
                    raise AssertionError("the held call was never released")

        return entered, release, on_dispatching

    def holding_retry_dispatch(self, index):
        """(entered, release, hook): the hook holds the second dispatching write of ``index``."""
        entered, release = self.hold(2)
        seen = []

        def on_dispatching(which):
            if which == index:
                seen.append(which)
                if len(seen) == 2:
                    entered.set()
                    if not release.wait(PATIENCE):
                        raise AssertionError("the held retry was never released")

        return entered, release, on_dispatching

    def refused(self, handle, code):
        """The handle ended with ``code`` before any receipt."""
        with self.assertRaises(ProviderError) as caught:
            handle.result()
        self.assertEqual(caught.exception.code, code)
        self.assertEqual(handle.receipts, ())
        self.assertIsNone(handle.summary)
        self.assertTrue(handle.done())


class ConcurrentSubmitTests(Base):
    def test_eight_submits_at_four_and_eight_give_each_handle_its_own_results(self):
        for limit in (4, 8):
            with self.subTest(max_in_flight=limit):
                label = f"receipts-{limit}"
                seen = {}

                def on_send(index, label=label, seen=seen):
                    # The dispatching receipt is durable before the bytes leave.
                    mine = [(receipt["status"], receipt["submission"])
                            for receipt in self.receipts(label)
                            if receipt["metadata"]["sequence"] == index + 1]
                    seen[index] = mine

                provider = ConcurrentProvider(barrier=threading.Barrier(limit), latency=0.01,
                                              on_send=on_send)
                gateway = self.gateway(provider, label, max_in_flight=limit)
                handles = [self.submit(gateway, index) for index in range(8)]
                results = [handle.result() for handle in handles]
                self.assertEqual(provider.peak, limit)
                self.assertEqual(sorted(provider.requests), list(range(8)))
                self.assertNotIn(threading.get_ident(), provider.threads)
                paths = set()
                for index, (handle, result) in enumerate(zip(handles, results)):
                    wire, key = wire_for(index)
                    self.assertIsInstance(result, CallResult)
                    self.assertEqual(result.answers["q"]["noul"], noul_for(index))
                    self.assertEqual(result.summary["request_sha256"], key)
                    self.assertEqual(result.summary["usage"], usage_for(index))
                    self.assertEqual(result.summary["logical_usage"], usage_for(index))
                    self.assertIs(result.summary["answer_order_mismatch"], False)
                    self.assertEqual(result.defects, {})
                    self.assertEqual(len(result.receipts), 1)
                    self.assertEqual(result.receipts, handle.receipts)
                    self.assertEqual(handle.sequence, index + 1)
                    paths.update(result.receipts)
                    saved = read_receipt(result.receipts[0])
                    self.assertEqual((saved["status"], saved["request_sha256"]),
                                     ("validated", key))
                    self.assertEqual(saved["metadata"]["sequence"], index + 1)
                    self.assertEqual(saved["usage"], usage_for(index))
                    self.assertEqual(saved["cost_usd"], providers.usd(cost_for(index)))
                    self.assertEqual(seen[index], [("dispatching", "possible")])
                self.assertEqual(len(paths), 8)
                self.assertEqual(len(self.receipts(label)), 8)
                total = sum((cost_for(index) for index in range(8)), Decimal(0))
                self.assertEqual(gateway.logical_requests, 8)
                self.assertEqual((gateway.attempts, gateway.attempts_transmitted,
                                  gateway.retries), (8, 8, 0))
                self.assertEqual(gateway._dispatch_writes, 8)
                spend = gateway.spend
                self.assertEqual(spend["provider_reported_usd"], providers.usd(total))
                self.assertEqual(spend["upper_bound_usd"], providers.usd(total))
                self.assertEqual(spend["attempts"]["provider_reported"], 8)
                self.assertIsNone(gateway.stop_reason)

    def test_never_more_than_the_limit_in_flight(self):
        provider = ConcurrentProvider(latency=0.01)
        gateway = self.gateway(provider, max_in_flight=3)
        handles = [self.submit(gateway, index) for index in range(16)]
        for index, handle in enumerate(handles):
            self.assertEqual(handle.result().answers["q"]["noul"], noul_for(index))
        self.assertLessEqual(provider.peak, 3)
        self.assertEqual(len(provider.requests), 16)

    def test_failed_calls_give_their_places_back(self):
        # More failures than places: a place kept by a failed call would wedge
        # the gateway before the sixth call could start.
        provider = ConcurrentProvider(
            script={index: [failure("response_probability")] for index in range(5)})
        gateway = self.gateway(provider, max_in_flight=2)
        handles = [self.submit(gateway, index) for index in range(5)]
        for handle in handles:
            with self.assertRaises(ProviderError) as caught:
                handle.result()
            self.assertEqual(caught.exception.code, "response_probability")
        self.assertIsNone(gateway.stop_reason)
        good = self.submit(gateway, 5)
        self.assertEqual(good.result().answers["q"]["noul"], noul_for(5))
        self.free_places(gateway, 2)

    def test_result_waits_for_the_settlement_write(self):
        release = threading.Event()
        self.releases.append(release)
        real = providers._write_receipt

        def slow(path, receipt):
            if receipt["status"] != "dispatching":
                if not release.wait(PATIENCE):
                    raise AssertionError("the settlement was never released")
            return real(path, receipt)

        gateway = self.gateway(ConcurrentProvider(), max_in_flight=2)
        with patch.object(providers, "_write_receipt", slow):
            handle = self.submit(gateway, 0)
            wait_until(lambda: len(self.receipts()) == 1, "the dispatching receipt")
            time.sleep(0.05)
            # The provider answered long ago, but nothing is settled yet.
            self.assertFalse(handle.done())
            self.assertEqual(self.receipts()[0]["status"], "dispatching")
            release.set()
            result = handle.result()
        self.assertEqual(result.answers["q"]["noul"], noul_for(0))
        self.assertEqual(self.receipts()[0]["status"], "validated")

    def test_a_failed_call_still_reports_its_summary_and_receipts(self):
        provider = ConcurrentProvider(script={0: [failure("response_schema")]})
        gateway = self.gateway(provider, max_in_flight=2, retry_policy=RetryPolicy.none())
        handle = self.submit(gateway, 0)
        with self.assertRaises(ProviderError) as caught:
            handle.result()
        self.assertEqual(caught.exception.code, "response_schema")
        self.assertEqual(len(handle.receipts), 1)
        self.assertEqual(handle.summary["request_sha256"], wire_for(0)[1])
        saved = read_receipt(handle.receipts[0])
        self.assertEqual((saved["status"], saved["error"]), ("failed", "response_schema"))

    def test_the_serial_surface_stays_single_call_and_thread_owned(self):
        provider = ConcurrentProvider()
        gateway = self.gateway(provider, max_in_flight=4)
        state = {"text": "call 00", "context_scope": "declared_standalone"}
        answers = gateway.evaluate(state, QUESTIONS, metadata=metadata_for(0))
        self.assertEqual(answers["q"]["noul"], noul_for(0))
        owned = (gateway.last_receipt, gateway.last_receipts, gateway.last_call_summary)
        self.assertEqual(len(owned[1]), 1)
        # Submitted calls leave what evaluate left untouched.
        for index in range(1, 5):
            self.submit(gateway, index).result()
        self.assertEqual((gateway.last_receipt, gateway.last_receipts,
                          gateway.last_call_summary), owned)
        box = []
        other = threading.Thread(target=lambda: box.append(
            (gateway.last_receipt, gateway.last_receipts, gateway.last_call_summary,
             gateway.last_call_stats, gateway.last_defects)))
        other.start()
        other.join()
        self.assertEqual(box, [(None, (), None, None, {})])

    def test_evaluate_is_refused_while_a_call_holds_the_only_free_place(self):
        hold, = self.hold(1)
        provider = ConcurrentProvider(holds={0: hold})
        gateway = self.gateway(provider, max_in_flight=2)
        first = self.submit(gateway, 0)
        provider.wait_for_requests(1)
        # One place is still free, so a serial evaluate may run beside it.
        state = {"text": "call 01", "context_scope": "declared_standalone"}
        self.assertEqual(
            gateway.evaluate(state, QUESTIONS, metadata=metadata_for(1))["q"]["noul"],
            noul_for(1))
        second_hold, = self.hold(1)
        provider.holds[2] = second_hold
        second = self.submit(gateway, 2)
        provider.wait_for_requests(3)
        # Both places are taken: a serial call is refused, as a busy one is.
        with self.assertRaises(ProviderError) as caught:
            gateway.evaluate(state, QUESTIONS, metadata=metadata_for(1))
        self.assertEqual(caught.exception.code, "transport_failed")
        hold.set()
        second_hold.set()
        first.result()
        second.result()

    def test_a_concurrent_serial_call_is_refused_with_transport_failed(self):
        hold, = self.hold(1)
        provider = ConcurrentProvider(holds={0: hold})
        gateway = self.gateway(provider, max_in_flight=4)
        wire, key = wire_for(0)
        outcome = []

        def run():
            outcome.append(gateway._evaluate_prepared(wire, key, metadata=metadata_for(0)))

        thread = threading.Thread(target=run)
        thread.start()
        provider.wait_for_requests(1)
        for call in (lambda: gateway._evaluate_prepared(*wire_for(1), metadata=metadata_for(1)),
                     lambda: gateway.close()):
            with self.assertRaises(ProviderError) as caught:
                call()
            self.assertEqual(caught.exception.code, "transport_failed")
        hold.set()
        thread.join(PATIENCE)
        self.assertEqual(outcome[0]["q"]["noul"], noul_for(0))
        self.assertEqual(provider.requests, [0])

    def test_the_limit_is_validated(self):
        for bad in (0, 9, -1, True, False, 1.0, 2.5, "2", None, (2,)):
            with self.subTest(max_in_flight=bad):
                with self.assertRaises(ProviderError) as caught:
                    ValidatedGateway(ConcurrentProvider(), self.root / "bad", max_in_flight=bad)
                self.assertEqual(caught.exception.code, "invalid_request")
        for good in range(1, MAX_IN_FLIGHT + 1):
            gateway = self.gateway(ConcurrentProvider(), f"good-{good}", max_in_flight=good)
            self.assertEqual(gateway.max_in_flight, good)
        self.assertEqual(self.gateway(ConcurrentProvider(), "default").max_in_flight, 1)
        self.assertEqual(MAX_IN_FLIGHT, MAX_CONCURRENCY)
        self.assertEqual(MAX_IN_FLIGHT, MAX_CONNECTIONS)


class CostReservationTests(Base):
    def bound(self):
        """The attempt bound of every call here: their wires have one size."""
        wire, _key = wire_for(0)
        return attempt_cost_bound(len(wire), 1, SPEC.price_in_per_mtok,
                                  SPEC.price_out_upper_per_mtok)

    def run_to_the_limit(self, max_cost, submissions, label):
        """Submit ``submissions`` calls that stay in flight; (gateway, handles, holds)."""
        holds = self.hold(submissions)
        provider = ConcurrentProvider(holds=dict(enumerate(holds)))
        gateway = self.gateway(provider, label, max_in_flight=4, max_cost=max_cost)
        handles = []
        for index in range(submissions):
            handles.append(self.submit(gateway, index))
            # One at a time: the reservation of the one before is made.
            wait_until(lambda: handles[-1].done() or len(provider.requests) == index + 1,
                       "the call to be sent or refused")
        return gateway, provider, handles, holds

    def test_calls_in_flight_count_against_the_budget(self):
        bound = self.bound()
        for calls in (1, 2, 3):
            with self.subTest(calls_that_fit=calls):
                # Room for exactly ``calls`` bounds, none spent: the next call
                # would make spent + reserved + bound exceed the limit.
                gateway, provider, handles, holds = self.run_to_the_limit(
                    bound * calls, calls + 1, f"fit-{calls}")
                self.refused(handles[calls], "cost_budget_exhausted")
                self.assertEqual(sorted(provider.requests), list(range(calls)))
                self.assertEqual(len(self.receipts(f"fit-{calls}")), calls)
                self.assertEqual(gateway.stop_reason, "cost_budget_exhausted")
                # The refusal was not a call, as in the serial path.
                self.assertEqual(gateway.logical_requests, calls)
                for event in holds:
                    event.set()
                for index in range(calls):
                    self.assertEqual(handles[index].result().answers["q"]["noul"],
                                     noul_for(index))

    def test_one_microdollar_under_the_bounds_refuses_the_last_call(self):
        bound = self.bound()
        gateway, provider, handles, holds = self.run_to_the_limit(
            bound * 3 - Decimal("0.000001"), 3, "under")
        self.refused(handles[2], "cost_budget_exhausted")
        self.assertEqual(sorted(provider.requests), [0, 1])
        for event in holds:
            event.set()
        for index in (0, 1):
            handles[index].result()

    def test_the_stop_refuses_later_submissions_at_once(self):
        bound = self.bound()
        gateway, provider, handles, holds = self.run_to_the_limit(bound * 2, 3, "latched")
        self.refused(handles[2], "cost_budget_exhausted")
        late = self.submit(gateway, 3)
        self.refused(late, "provider_stopped")
        self.assertEqual(sorted(provider.requests), [0, 1])
        self.assertEqual(len(self.receipts("latched")), 2)
        for event in holds:
            event.set()
        for index in (0, 1):
            handles[index].result()

    def test_settlement_gives_the_reservation_back(self):
        bound = self.bound()
        provider = ConcurrentProvider()
        # One bound of room: calls run one after another and each settles
        # (at its small reported cost) before the next is reserved.
        gateway = self.gateway(provider, max_in_flight=4, max_cost=bound * 2)
        for index in range(5):
            self.assertEqual(self.submit(gateway, index).result().answers["q"]["noul"],
                             noul_for(index))
        self.assertEqual(gateway._reserved, 0)
        self.assertIsNone(gateway.stop_reason)

    def test_a_failed_call_gives_its_reservation_back(self):
        bound = self.bound()
        real = providers._write_receipt

        def refuse_dispatching(path, receipt):
            if receipt["status"] == "dispatching" and receipt["metadata"]["sequence"] == 1:
                raise ProviderError("receipt_failed")
            return real(path, receipt)

        gateway = self.gateway(ConcurrentProvider(), max_in_flight=4, max_cost=bound * 2)
        with patch.object(providers, "_write_receipt", refuse_dispatching):
            handle = self.submit(gateway, 0)
            with self.assertRaises(ProviderError) as caught:
                handle.result()
        self.assertEqual(caught.exception.code, "receipt_failed")
        self.assertEqual(gateway._reserved, 0)

    def test_a_retry_reserves_its_bound_and_is_refused_over_the_limit(self):
        bound = self.bound()
        clock = FakeClock()
        sleeps = []

        def sleep(seconds):
            sleeps.append(seconds)
            clock.advance(seconds)

        provider = ConcurrentProvider(script={0: [failure("transport_failed")]})
        # Room for the first attempt only. It may have been billed, so its
        # bound counts as spent, and the retry's bound would exceed the limit.
        gateway = self.gateway(provider, max_in_flight=2, max_cost=bound,
                               clock=clock, sleep=sleep, retry_policy=RetryPolicy(possible=1))
        handle = self.submit(gateway, 0)
        with self.assertRaises(ProviderError) as caught:
            handle.result()
        self.assertEqual(caught.exception.code, "transport_failed")
        self.assertEqual(sleeps, [])
        saved = read_receipt(handle.receipts[-1])
        self.assertEqual(saved["retry_abandoned"], "cost_budget")
        self.assertEqual(gateway.stop_reason, "cost_budget_exhausted")
        self.assertEqual(gateway._reserved, 0)

    def test_a_planned_retry_keeps_its_bound_reserved_while_it_waits(self):
        bound = self.bound()
        clock, sleep = FakeClock(), GatedSleep()
        self.releases.append(sleep.opened)
        provider = ConcurrentProvider(script={0: [failure("connect_failed")]})
        # Room for exactly one attempt. Call 0 failed without being sent, so it
        # spent nothing, but its retry holds the one bound while it waits.
        gateway = self.gateway(provider, max_in_flight=2, max_cost=bound,
                               clock=clock, sleep=sleep)
        first = self.submit(gateway, 0)
        wait_until(lambda: len(sleep.calls) == 1, "the backoff")
        self.assertEqual(gateway._reserved, bound)
        self.refused(self.submit(gateway, 1), "cost_budget_exhausted")
        sleep.opened.set()
        self.assertEqual(first.result().answers["q"]["noul"], noul_for(0))
        self.assertEqual(provider.requests, [0, 0])
        self.assertEqual(gateway._reserved, 0)


class TotalsTests(Base):
    def mixed_provider(self, holds):
        """Calls that settle with a reported cost, a list-price estimate, or neither."""
        class Mixed(ConcurrentProvider):
            def decide(self, request):
                index = int(json.loads(request.payload)["state"]["text"].split()[1])
                response = super().decide(request)
                if index % 3 == 1:
                    return ProviderResponse(response.answers, response.usage)
                if index % 3 == 2:
                    return ProviderResponse(response.answers, None)
                return response

        return Mixed(holds=dict(enumerate(holds)))

    def run_in_order(self, order, label):
        holds = self.hold(8)
        gateway = self.gateway(self.mixed_provider(holds), label, max_in_flight=8)
        handles = [self.submit(gateway, index) for index in range(8)]
        wait_until(lambda: gateway.attempts == 8, "all eight attempts")
        for index in order:
            holds[index].set()
            wait_until(handles[index].done, f"call {index} to settle")
        for handle in handles:
            handle.result()
        return gateway

    def serial_gateway(self, label):
        gateway = self.gateway(self.mixed_provider(()), label)
        for index in range(8):
            self.submit(gateway, index).result()
        return gateway

    def test_totals_do_not_depend_on_the_order_calls_finish(self):
        orders = {"forward": list(range(8)), "reverse": list(range(7, -1, -1)),
                  "shuffled": [3, 6, 0, 7, 2, 5, 1, 4]}
        spends = {}
        for name, order in orders.items():
            gateway = self.run_in_order(order, name)
            spends[name] = gateway.spend
            self.assertEqual((gateway.attempts, gateway.attempts_transmitted,
                              gateway.logical_requests), (8, 8, 8))
        serial = self.serial_gateway("serial").spend
        for name, spend in spends.items():
            with self.subTest(order=name):
                self.assertEqual(spend, serial)
        # All three sources took part, so the equality is not trivial.
        counts = serial["attempts"]
        self.assertGreater(counts["provider_reported"], 0)
        self.assertGreater(counts["list_price_estimate"], 0)
        self.assertGreater(counts["unknown_bounded"], 0)
        self.assertEqual(sum(counts.values()), 8)

    def test_decimal_adds_are_exact_in_any_order(self):
        # Costs a binary float would round differently by order.
        values = [Decimal("0.1"), Decimal("0.2"), Decimal("0.3"), Decimal("1e-20")]
        for order in (values, values[::-1], [values[2], values[0], values[3], values[1]]):
            total = Decimal(0)
            for value in order:
                total = providers._COST.add(total, value)
            self.assertEqual(total, Decimal("0.60000000000000000001"))


class BackoffGateTests(Base):
    def setUp(self):
        super().setUp()
        self.clock = FakeClock()
        self.sleep = GatedSleep()
        self.releases.append(self.sleep.opened)

    def gateway(self, provider, label="receipts", **kwargs):
        kwargs.setdefault("clock", self.clock)
        kwargs.setdefault("sleep", self.sleep)
        return super().gateway(provider, label, **kwargs)

    def test_one_rate_limit_pauses_every_new_send(self):
        limited = failure("http_rate_limited", retry_after=5.0)
        provider = ConcurrentProvider(script={0: [limited]})
        gateway = self.gateway(provider, max_in_flight=4)
        first = self.submit(gateway, 0)
        # Call 0 is backing off for the 5 s the service asked.
        wait_until(lambda: len(self.sleep.calls) == 1, "the first backoff")
        self.assertEqual(self.sleep.calls, [5.0])
        later = [self.submit(gateway, index) for index in (1, 2, 3)]
        # Each waits at the gate for the time that is left; none is sent.
        wait_until(lambda: len(self.sleep.calls) == 4, "the others at the gate")
        self.assertEqual(self.sleep.calls, [5.0, 5.0, 5.0, 5.0])
        time.sleep(0.05)
        self.assertEqual(provider.requests, [0])
        self.assertEqual(len(self.receipts()), 1)
        self.assertFalse(any(handle.done() for handle in [first, *later]))
        self.clock.advance(5.0)
        self.sleep.opened.set()
        for index, handle in enumerate([first, *later]):
            self.assertEqual(handle.result().answers["q"]["noul"], noul_for(index))
        # Nobody waited twice: the gate time was honored once per call.
        self.assertEqual(len(self.sleep.calls), 4)
        # A call that waited at the gate still has its whole deadline: it
        # starts when that call's request is sent, not when it was submitted.
        waited = next(read_receipt(path)
                      for path in later[0].receipts)
        self.assertEqual((waited["deadline_seconds"], waited["timeout_seconds"]), (30.0, 30.0))
        self.assertEqual(sorted(provider.requests), [0, 0, 1, 2, 3])
        self.assertEqual((gateway.retries, gateway.attempts), (1, 5))
        self.assertEqual(len(first.receipts), 2)

    def test_a_rate_limit_during_the_dispatching_write_holds_that_send(self):
        entered, release, on_dispatching = self.holding_dispatch(1)
        provider = ConcurrentProvider(on_dispatching=on_dispatching,
                                      script={0: [failure("http_rate_limited", retry_after=5.0)]})
        gateway = self.gateway(provider, max_in_flight=4)
        slow = self.submit(gateway, 1)
        self.assertTrue(entered.wait(PATIENCE))
        # Call 1 passed the gate while it was open; call 0 then closes it.
        first = self.submit(gateway, 0)
        wait_until(lambda: len(self.sleep.calls) == 1, "the first backoff")
        release.set()
        wait_until(lambda: len(self.sleep.calls) == 2, "the slow call at the gate")
        self.assertEqual(self.sleep.calls, [5.0, 5.0])
        time.sleep(0.05)
        # Its dispatching receipt is written (a send may follow), but nothing
        # left inside the Retry-After.
        self.assertEqual(provider.requests, [0])
        self.assertFalse(slow.done())
        self.clock.advance(5.0)
        self.sleep.opened.set()
        self.assertEqual(slow.result().answers["q"]["noul"], noul_for(1))
        self.assertEqual(first.result().answers["q"]["noul"], noul_for(0))
        self.assertEqual(sorted(provider.requests), [0, 0, 1])
        # The attempt's deadline starts at its send, after the wait.
        saved, = (read_receipt(path) for path in slow.receipts)
        self.assertEqual((saved["deadline_seconds"], saved["timeout_seconds"]), (30.0, 30.0))
        self.assertEqual(saved["status"], "validated")

    def test_a_block_ends_the_wait_at_the_gate_with_no_receipt(self):
        hold, = self.hold(1)
        provider = ConcurrentProvider(
            holds={2: hold},
            script={0: [failure("http_rate_limited", retry_after=5.0)],
                    2: [failure("http_unauthorized")]})
        gateway = self.gateway(provider, max_in_flight=4)
        # Call 2 is in flight (past the gate) when call 0 closes the gate.
        bad = self.submit(gateway, 2)
        provider.wait_for_requests(1)
        first = self.submit(gateway, 0)
        wait_until(lambda: len(self.sleep.calls) == 1, "the first backoff")
        waiter = self.submit(gateway, 1)
        wait_until(lambda: len(self.sleep.calls) == 2, "the waiting call at the gate")
        hold.set()
        with self.assertRaises(ProviderError) as caught:
            bad.result()
        self.assertEqual(caught.exception.code, "http_unauthorized")
        self.sleep.opened.set()
        self.refused(waiter, "http_unauthorized")
        with self.assertRaises(ProviderError):
            first.result()
        # Neither the waiting call nor the abandoned retry was sent.
        self.assertEqual(provider.requests, [2, 0])

    def test_a_close_ends_the_wait_at_the_gate_with_no_receipt(self):
        provider = ConcurrentProvider(
            script={0: [failure("http_rate_limited", retry_after=5.0)]})
        gateway = self.gateway(provider, max_in_flight=4)
        first = self.submit(gateway, 0)
        wait_until(lambda: len(self.sleep.calls) == 1, "the first backoff")
        waiter = self.submit(gateway, 1)
        wait_until(lambda: len(self.sleep.calls) == 2, "the waiting call at the gate")
        box = []
        closer = threading.Thread(target=lambda: box.append(StopTests._close(gateway)))
        closer.start()
        time.sleep(0.05)
        self.sleep.opened.set()
        closer.join(PATIENCE)
        self.refused(waiter, "transport_failed")
        with self.assertRaises(ProviderError):
            first.result()
        self.assertEqual(provider.requests, [0])
        self.assertEqual(box, [None])

    def test_a_serial_call_waits_at_the_gate_too(self):
        provider = ConcurrentProvider(
            script={0: [failure("http_rate_limited", retry_after=5.0)]})
        gateway = self.gateway(provider, max_in_flight=4)
        first = self.submit(gateway, 0)
        wait_until(lambda: len(self.sleep.calls) == 1, "the first backoff")
        state = {"text": "call 01", "context_scope": "declared_standalone"}
        box = []
        serial = threading.Thread(target=lambda: box.append(
            gateway.evaluate(state, QUESTIONS, metadata=metadata_for(1))))
        serial.start()
        wait_until(lambda: len(self.sleep.calls) == 2, "the serial call at the gate")
        self.assertEqual(provider.requests, [0])
        self.clock.advance(5.0)
        self.sleep.opened.set()
        serial.join(PATIENCE)
        first.result()
        self.assertEqual(box[0]["q"]["noul"], noul_for(1))

    def test_a_storm_keeps_each_retry_count_with_its_own_request(self):
        provider = ConcurrentProvider(
            barrier=threading.Barrier(4),
            script={index: [failure("http_rate_limited", retry_after=2.0)]
                    for index in range(4)})
        gateway = self.gateway(provider, max_in_flight=4)
        handles = [self.submit(gateway, index) for index in range(4)]
        wait_until(lambda: len(self.sleep.calls) == 4, "four backoffs")
        self.assertEqual(self.sleep.calls, [2.0] * 4)
        self.clock.advance(2.0)
        self.sleep.opened.set()
        for index, handle in enumerate(handles):
            result = handle.result()
            self.assertEqual(result.answers["q"]["noul"], noul_for(index))
            self.assertEqual(len(result.receipts), 2)
            self.assertEqual(result.summary["logical_usage"], usage_for(index))
            first, second = (read_receipt(path)
                             for path in result.receipts)
            self.assertEqual((first["attempt"], first["error"]), (1, "http_rate_limited"))
            self.assertEqual((second["attempt"], second["retry_reason"]),
                             (2, "http_rate_limited"))
            self.assertEqual(second["logical_attempts"], 2)
            self.assertEqual(second["waited_seconds"], 2.0)
        self.assertEqual((gateway.retries, gateway.attempts), (4, 8))
        self.assertEqual(len(self.sleep.calls), 4)

    def test_a_longer_wait_extends_the_gate(self):
        holds = self.hold(2)
        provider = ConcurrentProvider(holds=dict(enumerate(holds)),
                                      script={0: [failure("http_rate_limited", retry_after=2.0)],
                                              1: [failure("http_rate_limited", retry_after=9.0)]})
        gateway = self.gateway(provider, max_in_flight=4)
        first, second = self.submit(gateway, 0), self.submit(gateway, 1)
        provider.wait_for_requests(2)
        for event in holds:
            event.set()
        wait_until(lambda: len(self.sleep.calls) == 2, "two backoffs")
        self.assertEqual(sorted(self.sleep.calls), [2.0, 9.0])
        third = self.submit(gateway, 2)
        wait_until(lambda: len(self.sleep.calls) == 3, "the third at the gate")
        # The new call waits for the later of the two times.
        self.assertEqual(sorted(self.sleep.calls), [2.0, 9.0, 9.0])
        self.clock.advance(9.0)
        self.sleep.opened.set()
        for handle in (first, second, third):
            handle.result()


class StopTests(Base):
    def test_a_receipt_write_failure_blocks_while_the_others_settle(self):
        real = providers._write_receipt

        def refuse_second_settlement(path, receipt):
            if receipt["metadata"]["sequence"] == 2 and receipt["status"] != "dispatching":
                raise ProviderError("receipt_failed")
            return real(path, receipt)

        provider = ConcurrentProvider(barrier=threading.Barrier(4), latency=0.01)
        gateway = self.gateway(provider, max_in_flight=4)
        with patch.object(providers, "_write_receipt", refuse_second_settlement):
            handles = [self.submit(gateway, index) for index in range(4)]
            outcomes = []
            for handle in handles:
                try:
                    outcomes.append(handle.result().answers["q"]["noul"])
                except ProviderError as exc:
                    outcomes.append(exc.code)
        self.assertEqual(outcomes, [noul_for(0), "receipt_failed", noul_for(2), noul_for(3)])
        self.assertEqual(gateway.stop_reason, "blocked:receipt_failed")
        by_sequence = {receipt["metadata"]["sequence"]: receipt for receipt in self.receipts()}
        self.assertEqual([by_sequence[n]["status"] for n in (1, 3, 4)], ["validated"] * 3)
        # The failed settlement leaves the journal's truth: sent, outcome unknown.
        self.assertEqual((by_sequence[2]["status"], by_sequence[2]["submission"]),
                         ("dispatching", "possible"))
        late = self.submit(gateway, 4)
        self.refused(late, "receipt_failed")
        self.assertEqual(len(provider.requests), 4)
        self.assertEqual(len(self.receipts()), 4)

    def test_a_blocking_failure_refuses_new_calls_but_not_those_in_flight(self):
        hold, = self.hold(1)
        provider = ConcurrentProvider(holds={1: hold},
                                      script={0: [failure("http_unauthorized")]})
        gateway = self.gateway(provider, max_in_flight=4)
        slow = self.submit(gateway, 1)
        provider.wait_for_requests(1)
        bad = self.submit(gateway, 0)
        with self.assertRaises(ProviderError) as caught:
            bad.result()
        self.assertEqual(caught.exception.code, "http_unauthorized")
        self.assertEqual(gateway.stop_reason, "blocked:http_unauthorized")
        late = self.submit(gateway, 2)
        self.refused(late, "http_unauthorized")
        self.assertFalse(slow.done())
        hold.set()
        self.assertEqual(slow.result().answers["q"]["noul"], noul_for(1))
        self.assertEqual(sorted(provider.requests), [0, 1])
        self.assertEqual({r["status"] for r in self.receipts()}, {"validated", "failed"})

    def test_a_call_in_its_dispatching_write_is_not_sent_after_a_block(self):
        entered, release, on_dispatching = self.holding_dispatch(1)
        provider = ConcurrentProvider(on_dispatching=on_dispatching,
                                      script={0: [failure("http_unauthorized")]})
        gateway = self.gateway(provider, max_in_flight=4)
        slow = self.submit(gateway, 1)
        self.assertTrue(entered.wait(PATIENCE))
        bad = self.submit(gateway, 0)
        with self.assertRaises(ProviderError) as caught:
            bad.result()
        self.assertEqual(caught.exception.code, "http_unauthorized")
        self.assertFalse(slow.done())
        release.set()
        # The slow call had begun, so it has its dispatching receipt; the
        # gateway blocked before its bytes could leave, and its journal says
        # so: not sent, never a possible submission.
        with self.assertRaises(ProviderError) as refused:
            slow.result()
        self.assertEqual(refused.exception.code, "http_unauthorized")
        self.assertEqual(provider.requests, [0])
        saved, = (read_receipt(path) for path in slow.receipts)
        self.assertEqual((saved["status"], saved["submission"], saved["submission_possible"],
                          saved["error"]), ("failed", "not_sent", False, "http_unauthorized"))
        self.assertEqual(saved["elapsed_seconds"], 0.0)
        self.assertEqual(gateway.stop_reason, "blocked:http_unauthorized")

    def test_a_call_in_its_dispatching_write_is_not_sent_after_a_stop(self):
        entered, release, on_dispatching = self.holding_dispatch(1)
        provider = ConcurrentProvider(on_dispatching=on_dispatching)
        gateway = self.gateway(provider, max_in_flight=4)
        slow = self.submit(gateway, 1)
        self.assertTrue(entered.wait(PATIENCE))
        gateway.stop("provider_moderation_sustained")
        release.set()
        # A stop refuses a first attempt that has not been sent: the journal
        # says not sent, with no time spent and no possible submission.
        with self.assertRaises(ProviderError) as refused:
            slow.result()
        self.assertEqual(refused.exception.code, "provider_stopped")
        self.assertEqual(provider.requests, [])
        saved, = (read_receipt(path) for path in slow.receipts)
        self.assertEqual((saved["status"], saved["submission"], saved["submission_possible"],
                          saved["error"]), ("failed", "not_sent", False, "provider_stopped"))
        self.assertEqual(saved["elapsed_seconds"], 0.0)

    def retrying_gateway(self, provider):
        """A gateway whose injected sleep moves a fake clock instead of waiting."""
        clock = FakeClock()
        return self.gateway(provider, max_in_flight=4, clock=clock,
                            sleep=lambda seconds: clock.advance(seconds))

    def assert_retry_not_sent(self, handle, code):
        with self.assertRaises(ProviderError) as refused:
            handle.result()
        self.assertEqual(refused.exception.code, code)
        first, second = (read_receipt(path) for path in handle.receipts)
        self.assertEqual((first["attempt"], first["submission"]), (1, "rejected_unprocessed"))
        self.assertEqual((second["attempt"], second["status"], second["submission"],
                          second["submission_possible"], second["error"]),
                         (2, "failed", "not_sent", False, code))
        self.assertEqual(second["elapsed_seconds"], 0.0)

    def test_a_retry_in_its_dispatching_write_is_not_sent_after_a_block(self):
        entered, release, on_dispatching = self.holding_retry_dispatch(0)
        provider = ConcurrentProvider(
            on_dispatching=on_dispatching,
            script={0: [failure("http_rate_limited", retry_after=1.0)],
                    1: [failure("http_unauthorized")]})
        gateway = self.retrying_gateway(provider)
        retrying = self.submit(gateway, 0)
        self.assertTrue(entered.wait(PATIENCE))
        self.assertEqual(provider.requests, [0])
        bad = self.submit(gateway, 1)
        with self.assertRaises(ProviderError) as caught:
            bad.result()
        self.assertEqual(caught.exception.code, "http_unauthorized")
        self.assertFalse(retrying.done())
        release.set()
        # Another call's blocking failure ends a retry that has not been sent.
        self.assert_retry_not_sent(retrying, "http_unauthorized")
        self.assertEqual(provider.requests, [0, 1])

    def test_a_retry_in_its_dispatching_write_is_not_sent_after_a_close(self):
        entered, release, on_dispatching = self.holding_retry_dispatch(0)
        provider = ConcurrentProvider(
            on_dispatching=on_dispatching,
            script={0: [failure("http_rate_limited", retry_after=1.0)]})
        gateway = self.retrying_gateway(provider)
        retrying = self.submit(gateway, 0)
        self.assertTrue(entered.wait(PATIENCE))
        box = []
        closer = threading.Thread(target=lambda: box.append(self._close(gateway)))
        closer.start()
        wait_until(lambda: gateway._closing, "the close to begin")
        release.set()
        closer.join(PATIENCE)
        self.assert_retry_not_sent(retrying, "transport_failed")
        self.assertEqual(provider.requests, [0])

    def test_a_retry_in_its_dispatching_write_still_goes_after_a_stop(self):
        # A stop refuses calls that have not begun; a request that has begun
        # runs to settlement, so its retry is sent.
        entered, release, on_dispatching = self.holding_retry_dispatch(0)
        provider = ConcurrentProvider(
            on_dispatching=on_dispatching,
            script={0: [failure("http_rate_limited", retry_after=1.0)]})
        gateway = self.retrying_gateway(provider)
        retrying = self.submit(gateway, 0)
        self.assertTrue(entered.wait(PATIENCE))
        gateway.stop("provider_moderation_sustained")
        release.set()
        self.assertEqual(retrying.result().answers["q"]["noul"], noul_for(0))
        self.assertEqual(provider.requests, [0, 0])
        self.refused(self.submit(gateway, 1), "provider_stopped")

    def test_a_provider_stop_refuses_new_calls_and_lets_calls_settle(self):
        hold, = self.hold(1)
        provider = ConcurrentProvider(holds={0: hold})
        gateway = self.gateway(provider, max_in_flight=4)
        running = self.submit(gateway, 0)
        provider.wait_for_requests(1)
        gateway.stop("provider_moderation_sustained")
        self.refused(self.submit(gateway, 1), "provider_stopped")
        hold.set()
        self.assertEqual(running.result().answers["q"]["noul"], noul_for(0))
        self.assertEqual(provider.requests, [0])
        self.assertEqual(len(self.receipts()), 1)

    def test_a_call_that_waited_for_a_place_is_refused_by_a_stop_meanwhile(self):
        holds = self.hold(2)
        provider = ConcurrentProvider(holds=dict(enumerate(holds)))
        gateway = self.gateway(provider, max_in_flight=2)
        running = [self.submit(gateway, 0), self.submit(gateway, 1)]
        provider.wait_for_requests(2)
        box = []
        waiter = threading.Thread(target=lambda: box.append(self.submit(gateway, 2)))
        waiter.start()
        time.sleep(0.05)
        self.assertEqual(box, [])
        # The third submission is waiting for a place when the gateway stops.
        gateway.stop("provider_moderation_sustained")
        waiter.join(PATIENCE)
        self.refused(box[0], "provider_stopped")
        for event in holds:
            event.set()
        for handle in running:
            handle.result()
        self.assertEqual(sorted(provider.requests), [0, 1])

    def test_the_run_deadline_and_reserve_refuse_at_dispatch(self):
        provider = ConcurrentProvider()
        gateway = self.gateway(provider, max_in_flight=4)
        # Less than the 3 s reserve is left: refused before any receipt, and
        # not counted as a call, as in the serial path.
        gateway.set_run_deadline(time.monotonic() + 1.0)
        handles = [self.submit(gateway, index) for index in range(3)]
        for handle in handles:
            self.refused(handle, "run_deadline_reserved")
        self.assertEqual((gateway.logical_requests, gateway.attempts), (0, 0))
        gateway.set_run_deadline(time.monotonic() - 1.0)
        self.refused(self.submit(gateway, 3), "run_deadline_exceeded")
        self.assertEqual(provider.requests, [])
        self.assertEqual(self.receipts(), [])
        self.assertIsNone(gateway.stop_reason)

    def test_a_close_abandons_a_retry_that_waits_and_settles_its_journal(self):
        clock = FakeClock()
        sleep = GatedSleep()
        self.releases.append(sleep.opened)
        provider = ConcurrentProvider(script={0: [failure("http_rate_limited", retry_after=5.0)]})
        gateway = self.gateway(provider, max_in_flight=2, clock=clock, sleep=sleep)
        handle = self.submit(gateway, 0)
        wait_until(lambda: len(sleep.calls) == 1, "the backoff")
        box = []
        closer = threading.Thread(target=lambda: box.append(self._close(gateway)))
        closer.start()
        time.sleep(0.05)
        # The injected sleep ends when the test says; the retry is then
        # abandoned, not sent, because the gateway is closing.
        sleep.opened.set()
        closer.join(PATIENCE)
        with self.assertRaises(ProviderError) as caught:
            handle.result()
        self.assertEqual(caught.exception.code, "transport_failed")
        self.assertEqual(provider.requests, [0])
        last = read_receipt(handle.receipts[-1])
        self.assertEqual((last["status"], last["submission"], last["attempt"]),
                         ("failed", "not_sent", 2))
        self.assertEqual(box, [None])

    @staticmethod
    def _close(gateway):
        try:
            gateway.close()
        except ProviderError as exc:
            return exc.code
        return None


class InterruptTests(Base):
    def setUp(self):
        super().setUp()
        # interrupt_main does nothing when SIGINT was ignored at startup, as
        # in a background job: install Python's own handler for the test.
        try:
            previous = signal.signal(signal.SIGINT, signal.default_int_handler)
        except ValueError:
            self.skipTest("signal handlers can only be set from the main thread")
        self.addCleanup(signal.signal, signal.SIGINT, previous)

    def interrupt_soon(self, delay=0.05):
        timer = threading.Timer(delay, _thread.interrupt_main)
        self.addCleanup(timer.cancel)
        timer.start()

    def test_an_interrupt_with_four_in_flight_blocks_and_every_receipt_settles(self):
        holds = self.hold(4)
        provider = ConcurrentProvider(holds=dict(enumerate(holds)))
        gateway = self.gateway(provider, max_in_flight=4)
        handles = [self.submit(gateway, index) for index in range(4)]
        provider.wait_for_requests(4)
        self.interrupt_soon()
        with self.assertRaises(KeyboardInterrupt):
            handles[0].result()
        self.assertEqual(gateway.stop_reason, "blocked:interrupted")
        # New submissions are refused at once, without a receipt.
        self.refused(self.submit(gateway, 4), "interrupted")
        self.assertEqual(len(provider.requests), 4)
        # The calls in flight run to settlement.
        for event in holds:
            event.set()
        for index, handle in enumerate(handles):
            self.assertEqual(handle.result().answers["q"]["noul"], noul_for(index))
        gateway.close()
        saved = self.receipts()
        self.assertEqual(len(saved), 4)
        self.assertEqual({receipt["status"] for receipt in saved}, {"validated"})

    def test_an_interrupt_raised_in_a_worker_blocks_while_the_others_settle(self):
        for exit_type in (KeyboardInterrupt, SystemExit):
            with self.subTest(exit_type=exit_type.__name__):
                label = exit_type.__name__
                holds = self.hold(4)
                provider = ConcurrentProvider(holds=dict(enumerate(holds)),
                                              script={2: [exit_type()]})
                gateway = self.gateway(provider, label, max_in_flight=4)
                handles = [self.submit(gateway, index) for index in range(4)]
                provider.wait_for_requests(4)
                for event in holds:
                    event.set()
                outcomes = []
                for handle in handles:
                    try:
                        outcomes.append(handle.result().answers["q"]["noul"])
                    except BaseException as exc:
                        outcomes.append(type(exc))
                self.assertEqual(outcomes, [noul_for(0), noul_for(1), exit_type, noul_for(3)])
                self.assertEqual(gateway.stop_reason, "blocked:interrupted")
                by_sequence = {r["metadata"]["sequence"]: r for r in self.receipts(label)}
                self.assertEqual([by_sequence[n]["status"] for n in (1, 2, 4)], ["validated"] * 3)
                # The send may have happened: the journal says so.
                self.assertEqual((by_sequence[3]["status"], by_sequence[3]["error"],
                                  by_sequence[3]["submission_possible"]),
                                 ("failed", "interrupted", True))
                self.refused(self.submit(gateway, 4), "interrupted")
                self.assertEqual(sorted(provider.requests), [0, 1, 2, 3])
                self.free_places(gateway, 4)

    def test_an_exit_raised_before_a_call_begins_in_a_worker_blocks_the_gateway(self):
        # Raised by the pre-flight check, so the attempt loop never sees it:
        # the worker itself must block the gateway.
        class Exiting(ConcurrentProvider):
            def check_sensitive(self, *values):
                if len(values) == 3 and values[2]["sequence"] == 3:
                    raise SystemExit
                return super().check_sensitive(*values)

        provider = Exiting()
        gateway = self.gateway(provider, max_in_flight=4)
        self.submit(gateway, 0).result()
        doomed = self.submit(gateway, 2)
        with self.assertRaises(SystemExit):
            doomed.result()
        self.assertEqual(gateway.stop_reason, "blocked:interrupted")
        self.assertEqual(doomed.receipts, ())
        self.refused(self.submit(gateway, 3), "interrupted")
        self.assertEqual(provider.requests, [0])
        self.free_places(gateway, 4)

    def test_an_interrupt_before_the_worker_exists_keeps_the_places(self):
        provider = ConcurrentProvider()
        gateway = self.gateway(provider, max_in_flight=2)
        with patch.object(providers.threading, "Thread", side_effect=KeyboardInterrupt):
            with self.assertRaises(KeyboardInterrupt):
                self.submit(gateway, 0)
        self.assertEqual(gateway.stop_reason, "blocked:interrupted")
        self.free_places(gateway, 2)
        self.assertEqual(gateway._workers, set())
        self.refused(self.submit(gateway, 1), "interrupted")
        self.assertEqual(provider.requests, [])

    def test_an_interrupt_as_the_worker_starts_keeps_the_places(self):
        provider = ConcurrentProvider()
        gateway = self.gateway(provider, max_in_flight=2)
        with patch.object(threading.Thread, "start", side_effect=KeyboardInterrupt):
            with self.assertRaises(KeyboardInterrupt):
                self.submit(gateway, 0)
        self.assertEqual(gateway.stop_reason, "blocked:interrupted")
        self.free_places(gateway, 2)
        self.assertEqual(gateway._workers, set())
        self.assertEqual(provider.requests, [])

    def test_a_worker_that_cannot_start_ends_the_handle_and_stops_the_gateway(self):
        provider = ConcurrentProvider()
        gateway = self.gateway(provider, max_in_flight=2)
        with patch.object(threading.Thread, "start", side_effect=RuntimeError("no threads")):
            handle = self.submit(gateway, 0)
        with self.assertRaises(ProviderError) as caught:
            handle.result()
        self.assertEqual(caught.exception.code, "internal_error")
        self.assertEqual(gateway.stop_reason, "blocked:internal_error")
        self.free_places(gateway, 2)
        self.assertEqual(gateway._workers, set())

    def test_an_interrupt_while_waiting_for_a_place_blocks_the_gateway(self):
        holds = self.hold(2)
        provider = ConcurrentProvider(holds=dict(enumerate(holds)))
        gateway = self.gateway(provider, max_in_flight=2)
        handles = [self.submit(gateway, index) for index in range(2)]
        provider.wait_for_requests(2)
        self.interrupt_soon()
        with self.assertRaises(KeyboardInterrupt):
            self.submit(gateway, 2)
        self.assertEqual(gateway.stop_reason, "blocked:interrupted")
        for event in holds:
            event.set()
        for handle in handles:
            handle.result()
        self.assertEqual(sorted(provider.requests), [0, 1])
        self.assertEqual(len(self.receipts()), 2)

    def test_an_interrupt_unwinding_a_with_block_blocks_and_waits_for_the_calls(self):
        holds = self.hold(2)
        provider = ConcurrentProvider(holds=dict(enumerate(holds)))
        gateway = ValidatedGateway(provider, self.root / "receipts", max_in_flight=2)
        handles = []
        with self.assertRaises(KeyboardInterrupt):
            with gateway:
                handles = [self.submit(gateway, index) for index in range(2)]
                provider.wait_for_requests(2)
                release = threading.Timer(0.2, lambda: [event.set() for event in holds])
                self.addCleanup(release.cancel)
                release.start()
                raise KeyboardInterrupt
        # close() ran on the way out and waited for both calls to settle.
        self.assertEqual(gateway.stop_reason, "blocked:interrupted")
        self.assertTrue(all(handle.done() for handle in handles))
        self.assertEqual({r["status"] for r in self.receipts()}, {"validated"})
        self.assertTrue(provider.closed)
        self.refused(self.submit(gateway, 2), "interrupted")

    def test_an_interrupt_unwinding_through_a_finally_close_blocks_the_gateway(self):
        # The CLI closes its gateway in a ``finally``, not in a ``with``.
        holds = self.hold(2)
        provider = ConcurrentProvider(holds=dict(enumerate(holds)))
        gateway = ValidatedGateway(provider, self.root / "receipts", max_in_flight=2)
        handles = []
        with self.assertRaises(KeyboardInterrupt):
            try:
                handles = [self.submit(gateway, index) for index in range(2)]
                provider.wait_for_requests(2)
                release = threading.Timer(0.2, lambda: [event.set() for event in holds])
                self.addCleanup(release.cancel)
                release.start()
                raise KeyboardInterrupt
            finally:
                gateway.close()
        self.assertEqual(gateway.stop_reason, "blocked:interrupted")
        self.assertTrue(all(handle.done() for handle in handles))
        self.assertEqual({r["status"] for r in self.receipts()}, {"validated"})
        self.refused(self.submit(gateway, 2), "interrupted")

    def test_a_close_without_an_interrupt_does_not_block(self):
        holds = self.hold(1)
        provider = ConcurrentProvider(holds=dict(enumerate(holds)))
        gateway = ValidatedGateway(provider, self.root / "receipts", max_in_flight=2)
        handle = self.submit(gateway, 0)
        provider.wait_for_requests(1)
        release = threading.Timer(0.2, holds[0].set)
        self.addCleanup(release.cancel)
        release.start()
        try:
            raise ValueError("an ordinary failure")
        except ValueError:
            gateway.close()
        self.assertIsNone(gateway.stop_reason)
        self.assertTrue(handle.done())

    def test_a_backoff_in_flight_is_abandoned_by_an_interrupt(self):
        clock = FakeClock()
        wake = threading.Event()
        self.releases.append(wake)
        waits = []

        def sleep(seconds):
            waits.append(seconds)
            wake.wait(PATIENCE)

        provider = ConcurrentProvider(script={0: [failure("http_rate_limited", retry_after=5.0)]})
        gateway = self.gateway(provider, max_in_flight=2, clock=clock, sleep=sleep)
        handle = self.submit(gateway, 0)
        wait_until(lambda: len(waits) == 1, "the backoff")
        self.interrupt_soon()
        with self.assertRaises(KeyboardInterrupt):
            handle.result()
        wake.set()
        with self.assertRaises(ProviderError) as caught:
            handle.result()
        self.assertEqual(caught.exception.code, "interrupted")
        # The first attempt is settled; the retry never left, and says so.
        statuses = [(r["attempt"], r["status"], r["submission"])
                    for r in sorted(self.receipts(), key=lambda r: r["attempt"])]
        self.assertEqual(statuses, [(1, "failed", "rejected_unprocessed"),
                                    (2, "failed", "not_sent")])
        self.assertEqual(provider.requests, [0])

    def test_close_waits_for_the_attempt_deadline_and_keeps_possible_submissions(self):
        hold, = self.hold(1)
        provider = ConcurrentProvider(holds={0: hold})
        gateway = self.gateway(provider, max_in_flight=2, deadline_seconds=3.0)
        handle = self.submit(gateway, 0)
        provider.wait_for_requests(1)
        started = time.monotonic()
        with self.assertRaises(ProviderError) as caught:
            gateway.close()
        self.assertEqual(caught.exception.code, "transport_failed")
        self.assertGreaterEqual(time.monotonic() - started, 2.5)
        # The provider ignored its deadline: the journal still says the
        # request may have been processed.
        saved, = self.receipts()
        self.assertEqual((saved["status"], saved["submission"], saved["submission_possible"]),
                         ("dispatching", "possible", True))
        self.assertTrue(provider.closed)
        self.assertFalse(handle.done())
        hold.set()
        handle.result()


class SerialSubmitTests(Base):
    def paths_agree(self, provider_factory, **options):
        """(_evaluate_prepared outcome, _submit_prepared outcome) of the same request."""
        outcomes = []
        for label, via_submit in (("direct", False), ("submit", True)):
            provider = provider_factory()
            gateway = self.gateway(provider, label, clock=lambda: 0.0,
                                   sleep=lambda seconds: None, **options)
            wire, key = wire_for(0)
            if via_submit:
                handle = gateway._submit_prepared(wire, key, metadata=metadata_for(0))
                self.assertTrue(handle.done())
                try:
                    outcome = ("ok", handle.result().answers)
                except ProviderError as exc:
                    outcome = ("error", exc.code)
                self.assertEqual(handle.summary, gateway.last_call_summary)
                self.assertEqual(handle.receipts, gateway.last_receipts)
                self.assertEqual(handle.defects, gateway.last_defects)
            else:
                try:
                    outcome = ("ok", gateway._evaluate_prepared(wire, key,
                                                                metadata=metadata_for(0)))
                except ProviderError as exc:
                    outcome = ("error", exc.code)
            outcomes.append((outcome, sorted(
                canonical(receipt_scrub(receipt)) for receipt in self.receipts(label))))
        return outcomes

    def test_submit_is_synchronous_and_writes_the_receipts_evaluate_writes(self):
        direct, submitted = self.paths_agree(ConcurrentProvider)
        self.assertEqual(direct[0][0], "ok")
        self.assertEqual(direct, submitted)
        self.assertEqual(len(direct[1]), 1)

    def test_a_failure_and_a_retry_are_the_same_on_both_paths(self):
        for name, script in (("terminal", [failure("http_unauthorized")]),
                             ("retried", [failure("connect_failed")]),
                             ("exhausted", [failure("connect_failed")] * 4),
                             ("defect", [failure("response_schema")])):
            with self.subTest(name):
                direct, submitted = self.paths_agree(
                    lambda script=script: ConcurrentProvider(script={0: list(script)}))
                self.assertEqual(direct, submitted)

    def test_no_worker_thread_is_created_and_the_provider_runs_in_the_caller(self):
        provider = ConcurrentProvider()
        gateway = self.gateway(provider)

        def refuse(*_args, **_kwargs):
            raise AssertionError("a worker thread was started at max_in_flight 1")

        with patch.object(threading, "Thread", refuse):
            handle = self.submit(gateway, 0)
        self.assertTrue(handle.done())
        self.assertEqual(provider.threads, [threading.get_ident()])
        self.assertEqual(handle.result().answers["q"]["noul"], noul_for(0))
        self.assertEqual(gateway._workers, set())
        self.assertIsNone(gateway._slots)

    def test_a_busy_gateway_reports_transport_failed_in_the_handle(self):
        gateway = self.gateway(ConcurrentProvider())
        with gateway._call_lock:
            handle = self.submit(gateway, 0)
        self.refused(handle, "transport_failed")
        # The refused call did not become what last_* describes.
        self.assertIsNone(gateway.last_receipt)

    def test_a_stopped_gateway_refuses_through_the_handle(self):
        gateway = self.gateway(ConcurrentProvider())
        gateway.stop("provider_moderation_sustained")
        handle = self.submit(gateway, 0)
        self.refused(handle, "provider_stopped")

    def test_an_interrupt_in_the_provider_propagates_and_blocks(self):
        gateway = self.gateway(ConcurrentProvider(script={0: [KeyboardInterrupt()]}))
        with self.assertRaises(KeyboardInterrupt):
            self.submit(gateway, 0)
        self.assertEqual(gateway.stop_reason, "blocked:interrupted")
        saved, = self.receipts()
        self.assertEqual((saved["status"], saved["error"]), ("failed", "interrupted"))


class ConfigAndReportTests(Base):
    def test_concurrency_defaults_to_one_and_is_validated(self):
        self.assertEqual(Config().concurrency, 1)
        for value in range(1, MAX_CONCURRENCY + 1):
            self.assertEqual(Config(concurrency=value).concurrency, value)
        for bad in (0, 9, -1, True, 2.0, "2", None):
            with self.subTest(concurrency=bad):
                with self.assertRaises(ValueError):
                    Config(concurrency=bad)

    def test_the_hashed_configuration_never_holds_concurrency(self):
        for value in (1, 4):
            self.assertNotIn("concurrency", Config(concurrency=value).as_dict())
        self.assertEqual(Config(concurrency=4).as_dict(), Config().as_dict())

    def scan_report(self, concurrency, label, **config):
        """(report, receipts) of a small scan: screening and the first recheck."""
        provider = SyntheticProvider(fixture=FixtureProvider(((2, 3), (6, 6))))
        options = pinned(max_in_flight=concurrency) if concurrency > 1 else pinned()
        gateway = ValidatedGateway(provider, self.root / label, **options)
        config = {"whole_file": False, "bug_lenses": False, "max_action_steps": 0, **config}
        with gateway:
            report = scan(source(8), gateway, config=Config(concurrency=concurrency, **config))
        return report, self.receipts(label)

    def test_a_scan_with_concurrency_is_the_same_scan(self):
        one, receipts_one = self.scan_report(1, "one")
        # Recorded only above 1, and then as the number asked for.
        self.assertNotIn("concurrency", one["configuration"])
        for value in (2, MAX_CONCURRENCY):
            with self.subTest(concurrency=value):
                other, receipts_other = self.scan_report(value, f"c{value}")
                self.assertEqual(other["configuration"].pop("concurrency"), value)
                self.assertEqual(canonical(scrub(other)), canonical(scrub(one)))
                self.assertEqual(sorted(canonical(receipt_scrub(r)) for r in receipts_other),
                                 sorted(canonical(receipt_scrub(r)) for r in receipts_one))

    def test_the_scoped_policy_hash_does_not_move_with_concurrency(self):
        one, _ = self.scan_report(1, "scoped-one", search_policy="scoped-v2-beta")
        four, _ = self.scan_report(4, "scoped-four", search_policy="scoped-v2-beta")
        self.assertIn("policy_sha256", one)
        self.assertEqual(four["policy_sha256"], one["policy_sha256"])


class ProviderPoolTests(Base):
    def test_the_library_entry_point_passes_the_pool_size_to_the_route(self):
        for route in ("openai", "openrouter"):
            with self.subTest(route=route):
                single = providers.make_provider(route, api_key="offline-synthetic-key-xyz")
                self.assertIsNone(single._pool)
                pooled = providers.make_provider(route, api_key="offline-synthetic-key-xyz",
                                                 max_connections=3)
                self.assertEqual(pooled._pool._size, 3)
                for bad in (0, 9, True, "2"):
                    with self.assertRaises(ProviderError) as caught:
                        providers.make_provider(route, api_key="offline-synthetic-key-xyz",
                                                max_connections=bad)
                    self.assertEqual(caught.exception.code, "invalid_request")


class CliScanTests(Base):
    """A whole CLI scan through the offline provider, with and without concurrency."""

    def setUp(self):
        super().setUp()
        self.source = self.root / "sample.txt"
        self.source.write_text("".join(f"line {number}\n" for number in range(1, 41)),
                               encoding="utf-8")

    def run_scan(self, label, *extra):
        out, err = io.StringIO(), io.StringIO()
        output = self.root / label
        provider = SyntheticProvider(fixture=FixtureProvider(((12, 13), (30, 30))))
        argv = [str(self.source), "--scope", "standalone", "--output-dir", str(output),
                "--output-format", "json",
                # A slow disk must not turn the run deadline into a difference.
                "--run-deadline-seconds", "86400", *extra]
        with redirect_stdout(out), redirect_stderr(err), \
                patch.object(cli, "make_provider", return_value=provider):
            code = cli.main(argv)
        run, = output.glob("run-*")
        files = {name: (run / name).read_bytes()
                 for name in ("findings.txt", "handoff.json", "ranges.txt")}
        report = json.loads((run / "report.json").read_text(encoding="utf-8"))
        receipts = [json.loads(path.read_text(encoding="utf-8"))
                    for path in sorted((run / "receipts").glob("*.json"))]
        return code, out.getvalue(), files, report, receipts, len(provider.requests)

    def test_concurrency_four_is_byte_identical_to_one(self):
        base = self.run_scan("one")
        for flags in (("--concurrency", "1"), ("--concurrency", "4")):
            with self.subTest(flags=flags):
                other = self.run_scan("c" + flags[1], *flags)
                self.assertEqual(other[:3], base[:3])
                self.assertEqual(other[5], base[5])
                report = other[3]
                if flags[1] == "1":
                    self.assertNotIn("concurrency", report["configuration"])
                else:
                    self.assertEqual(report["configuration"].pop("concurrency"),
                                     int(flags[1]))
                self.assertEqual(canonical(scrub(report)), canonical(scrub(base[3])))
                self.assertEqual(sorted(canonical(receipt_scrub(r)) for r in other[4]),
                                 sorted(canonical(receipt_scrub(r)) for r in base[4]))
        self.assertGreater(base[5], 3)


class HandleTests(Base):
    def test_a_handle_is_not_done_until_its_call_settles(self):
        hold, = self.hold(1)
        provider = ConcurrentProvider(holds={0: hold})
        gateway = self.gateway(provider, max_in_flight=2)
        handle = self.submit(gateway, 0)
        self.assertIsInstance(handle, CallHandle)
        provider.wait_for_requests(1)
        self.assertFalse(handle.done())
        self.assertEqual(len(handle.receipts), 1)
        hold.set()
        handle.result()
        self.assertTrue(handle.done())
        # Asking again gives the same outcome.
        self.assertEqual(handle.result().answers, handle.result().answers)

    def test_workers_are_not_daemon_threads_and_are_gone_after_close(self):
        hold, = self.hold(1)
        provider = ConcurrentProvider(holds={0: hold})
        gateway = self.gateway(provider, max_in_flight=2)
        handle = self.submit(gateway, 0)
        provider.wait_for_requests(1)
        workers = [thread for thread in threading.enumerate()
                   if thread.name == "dbh-gateway-call"]
        self.assertEqual(len(workers), 1)
        self.assertFalse(workers[0].daemon)
        hold.set()
        handle.result()
        gateway.close()
        wait_until(lambda: not workers[0].is_alive(), "the worker to end")
        self.assertTrue(provider.closed)


if __name__ == "__main__":
    unittest.main()
