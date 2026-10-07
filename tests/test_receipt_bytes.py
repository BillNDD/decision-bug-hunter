"""Receipt serializer parity with the frozen old encoder, and receipt directory creation.

The oracle below is a frozen copy of ``protocol.plain`` and ``protocol._json`` as
they were before the receipt serializer seam. ``_receipt_bytes`` must match it
byte for byte on every receipt shape, including the receipts of a real gateway run.
"""
from copy import deepcopy
from decimal import Decimal
import json
from pathlib import Path
import pathlib
import random
import shutil
import tempfile
import unittest
from unittest.mock import patch

from decision_bug_hunter import protocol
from decision_bug_hunter import providers as p
from decision_bug_hunter.core import Config, Source, scan
from decision_bug_hunter.protocol import QUESTION, ProviderError
from decision_bug_hunter.providers import ProviderResponse, ValidatedGateway
from tests.support import FixtureProvider
from tests.test_provider_boundary import SyntheticProvider


def frozen_plain(value):
    """Frozen copy of the pre-seam ``protocol.plain``."""
    if isinstance(value, Decimal):
        return str(value)
    if isinstance(value, dict):
        return {k: frozen_plain(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [frozen_plain(v) for v in value]
    return value


def frozen_json(value):
    """Frozen copy of the pre-seam ``protocol._json``."""
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"),
                      allow_nan=False).encode("utf-8")


def old_bytes(value):
    return frozen_json(frozen_plain(value))


TEXT_ALPHABET = ("a", "Z", "0", " ", '"', "\\", "/", "\n", "\r", "\t", "\b", "\f",
                 "\x00", "\x1f", "\x7f", "é", "ß", "中", "😀", " ", " ", "﻿")
FIXED_DECIMALS = (Decimal("0.000123"), Decimal("1E-7"), Decimal("-0"),
                  Decimal("12345678901234567890.1"), Decimal("0E-10"), Decimal("NaN"),
                  Decimal("-Infinity"), Decimal("1.50"))
FIXED_FLOATS = (-0.0, 0.0, 5e-324, 1e308, 0.1, 2.5e-5, -1234.5678)


class Ints(int):
    pass


class Texts(str):
    pass


class Floats(float):
    pass


class Mapped(dict):
    pass


class Listed(list):
    pass


def random_text(rng):
    return "".join(rng.choice(TEXT_ALPHABET) for _ in range(rng.randint(0, 12)))


def random_decimal(rng):
    if rng.random() < 0.3:
        return rng.choice(FIXED_DECIMALS)
    digits = "".join(rng.choice("0123456789") for _ in range(rng.randint(1, 25)))
    sign = rng.choice(("", "-"))
    return Decimal(f"{sign}{digits}E{rng.randint(-12, 12)}")


def random_int(rng):
    magnitude = rng.getrandbits(rng.randint(1, 96))
    return magnitude if rng.random() < 0.5 else -magnitude


def random_float(rng):
    if rng.random() < 0.3:
        return rng.choice(FIXED_FLOATS)
    return rng.uniform(-1e6, 1e6) * 10 ** rng.randint(-200, 200)


def random_key(rng):
    if rng.random() < 0.2:
        return rng.randint(-50, 50)
    return random_text(rng)


def random_value(rng, depth=0):
    kinds = ["text", "int", "float", "bool", "none", "decimal", "int_sub", "text_sub"]
    if depth < 4:
        kinds += ["dict", "list", "tuple", "dict_sub", "list_sub", "float_sub"]
    kind = rng.choice(kinds)
    if kind == "text":
        return random_text(rng)
    if kind == "int":
        return random_int(rng)
    if kind == "float":
        return random_float(rng)
    if kind == "bool":
        return rng.random() < 0.5
    if kind == "none":
        return None
    if kind == "decimal":
        return random_decimal(rng)
    if kind == "int_sub":
        return Ints(random_int(rng))
    if kind == "text_sub":
        return Texts(random_text(rng))
    if kind == "float_sub":
        return Floats(random_float(rng))
    if kind == "dict":
        return {random_key(rng): random_value(rng, depth + 1)
                for _ in range(rng.randint(0, 4))}
    if kind == "dict_sub":
        return Mapped({random_key(rng): random_value(rng, depth + 1)
                       for _ in range(rng.randint(0, 3))})
    if kind == "list":
        return [random_value(rng, depth + 1) for _ in range(rng.randint(0, 4))]
    if kind == "list_sub":
        return Listed(random_value(rng, depth + 1) for _ in range(rng.randint(0, 3)))
    return tuple(random_value(rng, depth + 1) for _ in range(rng.randint(0, 4)))


def random_receipt(rng):
    """A receipt-shaped tree: a str-keyed dict with nested usage, answers and lists."""
    receipt = {random_text(rng) or "k": random_value(rng, 1)
               for _ in range(rng.randint(1, 6))}
    receipt["usage"] = {"input_tokens": random_int(rng), "output_tokens": random_int(rng),
                        "cost": random_decimal(rng)}
    receipt["answers"] = {f"q{i}": {"type": "noul", "noul": random_decimal(rng)}
                          for i in range(rng.randint(0, 3))}
    return receipt


class SerializerParityTests(unittest.TestCase):
    def assert_same(self, value):
        try:
            expected = old_bytes(value)
        except Exception as exc:
            with self.assertRaises(type(exc)):
                p._receipt_bytes(value)
            return
        self.assertEqual(p._receipt_bytes(value), expected)

    def test_frozen_oracle_matches_the_live_protocol_encoder(self):
        rng = random.Random(20261007)
        for _ in range(300):
            value = random_receipt(rng)
            self.assertEqual(old_bytes(value), protocol._json(protocol.plain(value)))

    def test_random_receipt_shapes_match_the_old_encoding(self):
        rng = random.Random(20261007)
        for index in range(2400):
            with self.subTest(index=index):
                self.assert_same(random_receipt(rng))

    def test_serializer_does_not_mutate_receipts(self):
        rng = random.Random(7)
        for _ in range(100):
            value = random_receipt(rng)
            before = deepcopy(value)
            p._receipt_bytes(value)
            self.assertEqual(repr(value), repr(before))

    def test_decimal_values_are_exact_strings(self):
        for value in FIXED_DECIMALS:
            with self.subTest(value=str(value)):
                receipt = {"usage": {"cost": value}, "pair": (value, [value])}
                self.assertEqual(p._receipt_bytes(receipt), old_bytes(receipt))
                self.assertIn(str(value).encode(), p._receipt_bytes(receipt))

    def test_tuples_subclasses_and_scalars_match(self):
        receipt = {"tuple": (1, (2, 3)), "int": Ints(9), "text": Texts("é\n"),
                   "float": Floats(2.5), "mapped": Mapped(a=1), "listed": Listed([True, None]),
                   "bool": False, "none": None, "big": 2 ** 80, "neg": -0.0}
        self.assertEqual(p._receipt_bytes(receipt), old_bytes(receipt))

    def test_non_finite_floats_raise_value_error_in_both(self):
        for bad in (float("nan"), float("inf"), float("-inf")):
            with self.subTest(value=bad):
                value = {"usage": {"x": bad}}
                with self.assertRaises(ValueError):
                    old_bytes(value)
                with self.assertRaises(ValueError):
                    p._receipt_bytes(value)

    def test_unserializable_and_unencodable_values_fail_the_same_way(self):
        for value, error in (({"x": {1, 2}}, TypeError),
                             ({"x": object()}, TypeError),
                             ({(1, 2): "tuple key"}, TypeError),
                             ({Decimal("1"): "decimal key"}, TypeError),
                             ({"x": "\udc80"}, UnicodeEncodeError)):
            with self.subTest(error=error.__name__):
                with self.assertRaises(error):
                    old_bytes(value)
                with self.assertRaises(error):
                    p._receipt_bytes(value)


class RealRunReceiptTests(unittest.TestCase):
    SOURCE = ("def total(a, b):\n    return a - b\n\n"
              "def mean(values):\n    return sum(values) / len(values)\n")

    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)

    def test_every_receipt_of_a_fixture_run_matches_the_old_encoding(self):
        seen = []
        real = p._write_receipt

        def recording(path, receipt):
            expected = old_bytes(receipt)
            real(path, receipt)
            written = Path(path).read_bytes()
            self.assertEqual(written, expected)
            seen.append(Path(path))

        provider = SyntheticProvider(fixture=FixtureProvider([(2, 2)]))
        with patch.object(p, "_write_receipt", recording):
            with ValidatedGateway(provider, self.root / "receipts") as gateway:
                scan(Source.from_text(self.SOURCE), gateway,
                     Config(whole_file=False, bug_lenses=False, max_action_steps=0),
                     context_scope="declared_standalone")
        # An attempt's dispatching and settled writes share one path: the file
        # on disk is the settled receipt, and every write was compared above.
        self.assertGreaterEqual(len(seen), 4)
        on_disk = sorted((self.root / "receipts").iterdir())
        self.assertEqual(sorted(set(seen)), on_disk)


class ReceiptWriteFailureTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)

    def test_serialization_failure_raises_receipt_failed_and_leaves_no_file(self):
        directory = self.root / "serial"
        directory.mkdir()
        path = directory / "receipt.json"
        for bad in (float("nan"), float("inf")):
            with self.subTest(value=bad):
                with self.assertRaises(ProviderError) as caught:
                    p._write_receipt(path, {"usage": {"x": bad}})
                self.assertEqual(caught.exception.code, "receipt_failed")
                self.assertEqual(list(directory.iterdir()), [])
                self.assertFalse(path.exists())


STATE = {"source": "L1: def total(a, b):\nL2:     return a - b\n"}
META = {"window_id": "W1", "start_line": 1, "end_line": 2}
GOOD = {"q": {"type": "noul", "noul": .82}}
USAGE = {"input_tokens": 80, "output_tokens": 3}


class ReceiptDirectoryTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.real_mkdir = pathlib.Path.mkdir

    def gateway(self, name="receipts"):
        provider = SyntheticProvider(ProviderResponse(GOOD, USAGE))
        gateway = ValidatedGateway(provider, self.root / name)
        self.addCleanup(gateway.close)
        return gateway, provider

    def evaluate(self, gateway):
        return gateway.evaluate(STATE, {"q": QUESTION}, metadata=META)

    def counting_mkdir(self, calls):
        real = self.real_mkdir

        def counting(path, *args, **kwargs):
            calls.append(Path(path))
            return real(path, *args, **kwargs)
        return counting

    def test_receipt_directory_is_created_once_per_gateway(self):
        gateway, provider = self.gateway()
        calls = []
        with patch.object(pathlib.Path, "mkdir", self.counting_mkdir(calls)):
            for _ in range(5):
                self.evaluate(gateway)
        self.assertEqual(len(provider.requests), 5)
        self.assertEqual(calls, [gateway.receipt_dir])

    def test_deleted_receipt_directory_is_recreated_for_the_next_write(self):
        gateway, provider = self.gateway()
        self.evaluate(gateway)
        shutil.rmtree(gateway.receipt_dir)
        calls = []
        with patch.object(pathlib.Path, "mkdir", self.counting_mkdir(calls)):
            self.evaluate(gateway)
        self.assertEqual(len(provider.requests), 2)
        self.assertEqual(calls, [gateway.receipt_dir])
        self.assertEqual(len(list(gateway.receipt_dir.iterdir())), 1)
        saved = json.loads(Path(gateway.last_receipt).read_text())
        self.assertEqual(saved["status"], "validated")
        self.assertEqual(saved["answers"], {"q": {"type": "noul", "noul": "0.82"}})

    def test_failed_directory_recovery_takes_the_receipt_failed_path(self):
        gateway, provider = self.gateway()
        self.evaluate(gateway)
        shutil.rmtree(gateway.receipt_dir)
        writes = []
        real_write = p._write_receipt

        def failing(path, receipt):
            if receipt["status"] == "dispatching":
                writes.append(Path(path))
                raise ProviderError("receipt_failed")
            return real_write(path, receipt)

        with patch.object(p, "_write_receipt", failing):
            with self.assertRaises(ProviderError) as caught:
                self.evaluate(gateway)
        self.assertEqual(caught.exception.code, "receipt_failed")
        self.assertEqual(len(writes), 2)
        self.assertEqual(len(provider.requests), 1)
        self.assertEqual(gateway.last_call_stats["submission"], "not_sent")

    def test_other_dispatch_write_failures_are_not_retried(self):
        gateway, provider = self.gateway()
        self.evaluate(gateway)
        writes = []
        real_write = p._write_receipt

        def failing(path, receipt):
            if receipt["status"] == "dispatching":
                writes.append(Path(path))
                raise ProviderError("receipt_failed")
            return real_write(path, receipt)

        calls = []
        with patch.object(pathlib.Path, "mkdir", self.counting_mkdir(calls)), \
                patch.object(p, "_write_receipt", failing):
            with self.assertRaises(ProviderError) as caught:
                self.evaluate(gateway)
        self.assertEqual(caught.exception.code, "receipt_failed")
        self.assertEqual(len(writes), 1)
        self.assertEqual(calls, [])
        self.assertEqual(len(provider.requests), 1)
        self.assertEqual(gateway.last_call_stats["submission"], "not_sent")

    def test_failing_directory_creation_still_fails_closed(self):
        gateway, provider = self.gateway()
        real = self.real_mkdir

        def failing(path, *args, **kwargs):
            if Path(path) == gateway.receipt_dir:
                raise OSError("synthetic mkdir failure")
            return real(path, *args, **kwargs)

        with patch.object(pathlib.Path, "mkdir", failing):
            with self.assertRaises(ProviderError) as caught:
                self.evaluate(gateway)
        self.assertEqual(caught.exception.code, "receipt_failed")
        self.assertEqual(provider.requests, [])
        self.assertEqual(gateway.last_call_stats["submission"], "not_sent")
        with self.assertRaises(ProviderError):
            self.evaluate(gateway)
        self.assertEqual(provider.requests, [])


if __name__ == "__main__":
    unittest.main()
