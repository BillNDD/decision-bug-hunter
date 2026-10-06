"""Small local provider boundary. No endpoint or SDK assumptions live here."""
from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass
import hashlib
import math
import os
from pathlib import Path
import re
import tempfile
import threading
import time
from typing import Any, Protocol
import uuid

from .protocol import (ERROR_CODES, ProviderError, _json, _metadata, encode_request,
                       plain, validate_answer_objects, validate_usage,
                       _rounding_profile)


@dataclass(frozen=True)
class ProviderIdentity:
    """Public provenance only; never put a credential or private path here."""

    name: str
    model: str | None = None
    synthetic: bool = False

    def __post_init__(self) -> None:
        if type(self.name) is not str:
            raise ProviderError("invalid_metadata")
        for value in (self.name, self.model):
            if value is not None and (type(value) is not str or
                    re.fullmatch(r"[A-Za-z0-9_.:-]{1,128}", value) is None):
                raise ProviderError("invalid_metadata")
        if type(self.synthetic) is not bool:
            raise ProviderError("invalid_metadata")


@dataclass(frozen=True)
class ProviderRequest:
    """Owned immutable DBH JSON bytes and an effective cooperative timeout.

    Decode payload to obtain `state` and `questions`. This is a local envelope,
    not a service request. The adapter translates it into a documented API.
    """

    payload: bytes
    timeout_seconds: float


@dataclass(frozen=True)
class ProviderResponse:
    """Provider-normalized local answers. Unknown usage stays None.

    `error` carries a fixed failure code for a documented whole-batch
    rejection learned after usage; the gateway journals both.
    """

    answers: dict[str, Any]
    usage: dict[str, int] | None = None
    complete: bool = True
    error: str | None = None


class DecisionProvider(Protocol):
    identity: ProviderIdentity

    def require_available(self) -> None: ...
    def decide(self, request: ProviderRequest) -> ProviderResponse: ...
    def check_sensitive(self, *values: Any) -> None: ...
    def close(self) -> None: ...


def _write_receipt(path: Path, receipt: dict[str, Any]) -> None:
    """Durable atomic journal transition; no request or raw response bodies."""
    temp: Path | None = None
    error = False
    try:
        with tempfile.NamedTemporaryFile(dir=path.parent, delete=False) as stream:
            temp = Path(stream.name)
            stream.write(_json(plain(receipt)))
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temp, path)
        temp = None
        if os.name == "posix":
            directory = os.open(path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
    except Exception:
        error = True
    finally:
        # Control-flow interruption must also release the temporary file.
        if temp is not None:
            try:
                temp.unlink(missing_ok=True)
            except Exception:
                error = True
    if error:
        raise ProviderError("receipt_failed")


class ValidatedGateway:
    """Serial, one-attempt evaluation with exact validation and local receipts.

    A dispatching receipt records possible submission. Failed persistence or
    interrupted dispatch prevents further use of this gateway; there is no retry.
    Provider timeouts are cooperative until an actual transport is implemented.
    """

    def __init__(self, provider: DecisionProvider, receipt_dir: Path | str, *,
                 deadline_seconds: float = 30.0,
                 rounding_places: int | None = None) -> None:
        if (type(deadline_seconds) not in (int, float) or
                not math.isfinite(deadline_seconds) or not 0 < deadline_seconds <= 300):
            raise ProviderError("invalid_deadline")
        _rounding_profile(rounding_places)
        if type(provider.identity) is not ProviderIdentity:
            raise ProviderError("invalid_metadata")
        self.provider = provider
        self.provider_id = provider.identity.name
        self.model_id = provider.identity.model
        self.synthetic = provider.identity.synthetic
        self.receipt_dir = Path(receipt_dir)
        self.deadline_seconds = float(deadline_seconds)
        self.rounding_places = rounding_places
        self._deadline: float | None = None
        self._last_stats: dict[str, Any] | None = None
        self._last_receipt: str | None = None
        self._stats_owner: int | None = None
        self._busy = False
        self._blocked = False
        self._closed = False
        self._call_lock = threading.Lock()

    @property
    def last_call_stats(self) -> dict[str, Any] | None:
        if self._stats_owner != threading.get_ident():
            return None
        return deepcopy(self._last_stats)

    @property
    def last_receipt(self) -> str | None:
        if self._stats_owner != threading.get_ident():
            return None
        return self._last_receipt

    def require_available(self) -> None:
        if self._closed or self._blocked or self._busy:
            raise ProviderError("transport_failed")
        self.provider.require_available()

    def set_run_deadline(self, deadline: float) -> None:
        if type(deadline) not in (int, float) or not math.isfinite(deadline):
            raise ProviderError("invalid_deadline")
        self._deadline = float(deadline)

    def check_sensitive(self, *values: Any) -> None:
        self.provider.check_sensitive(*values)

    def __enter__(self) -> ValidatedGateway:
        self.require_available()
        return self

    def __exit__(self, *_args: Any) -> None:
        self.close()

    def close(self) -> None:
        if not self._call_lock.acquire(blocking=False):
            raise ProviderError("transport_failed")
        try:
            if not self._closed:
                error = None
                try:
                    self.provider.close()
                except ProviderError as exc:
                    error = exc.code
                except Exception:
                    error = "transport_failed"
                if error:
                    self._blocked = True
                    raise ProviderError(error)
                self._closed = True
        finally:
            self._call_lock.release()

    def evaluate(self, state: dict[str, Any], questions: dict[str, Any], *,
                 metadata: dict[str, Any]) -> dict[str, Any]:
        if not self._call_lock.acquire(blocking=False):
            raise ProviderError("transport_failed")
        try:
            self._stats_owner = threading.get_ident()
            self._last_stats = None
            self._last_receipt = None
            self.require_available()
            self._busy = True
            return self._evaluate(state, questions, metadata=metadata)
        except BaseException as exc:
            if not isinstance(exc, Exception):
                self._blocked = True
            raise
        finally:
            self._busy = False
            self._call_lock.release()

    def _evaluate(self, state: dict[str, Any], questions: dict[str, Any], *,
                  metadata: dict[str, Any]) -> dict[str, Any]:
        self._last_stats = None
        self._last_receipt = None
        wire = encode_request(state, questions)
        meta = _metadata(metadata)
        self.check_sensitive(state, questions, metadata)
        # Own the expected question schema independently of caller/provider mutation.
        expected = deepcopy(questions)
        timeout = self.deadline_seconds
        if self._deadline is not None:
            timeout = min(timeout, self._deadline - time.monotonic())
        if timeout <= 0:
            raise ProviderError("run_deadline_exceeded")
        key = hashlib.sha256(wire).hexdigest()
        receipt: dict[str, Any] = {
            "schema_version": 1, "provider": self.provider_id, "model": self.model_id,
            "synthetic": self.synthetic, "metadata": meta, "request_sha256": key,
            "question_count": len(expected), "rounding_places": self.rounding_places,
            "timeout_seconds": timeout, "status": "dispatching",
            "submission_possible": True, "usage": None, "answers": None, "error": None,
        }
        path = self.receipt_dir / (uuid.uuid4().hex + ".json")
        try:
            return self._journaled_attempt(path, wire, expected, receipt, timeout)
        except BaseException as exc:
            if not isinstance(exc, Exception):
                # Block before another filesystem operation or propagation. The
                # shared local receipt retains usage learned before interruption.
                self._fail_receipt(path, receipt, "interrupted", persist=True)
            raise

    def _fail_receipt(self, path: Path, receipt: dict[str, Any], code: str, *,
                      persist: bool) -> None:
        self._blocked = True
        receipt.update(status="failed", error=code, answers=None)
        self._last_receipt = str(path)
        self._last_stats = deepcopy(receipt)
        if persist:
            try:
                _write_receipt(path, receipt)
            except BaseException:
                # Settlement is best effort; the gateway remains blocked even
                # when storage fails again or the operator interrupts again.
                pass

    def _journaled_attempt(self, path: Path, wire: bytes, expected: dict[str, Any],
                           receipt: dict[str, Any], timeout: float) -> dict[str, Any]:
        try:
            self.receipt_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
            self.check_sensitive(str(path), receipt)
            _write_receipt(path, receipt)
        except Exception:
            self._fail_receipt(path, receipt, "receipt_failed", persist=True)
            raise ProviderError("receipt_failed") from None
        self._last_receipt = str(path)
        self._last_stats = deepcopy(receipt)
        error: str | None = None
        answers: dict[str, Any] | None = None
        started = time.monotonic()
        try:
            # Intent persistence consumes the run budget. Recheck immediately
            # before the one provider call, including a reduced positive budget.
            if self._deadline is not None:
                timeout = min(timeout, self._deadline - started)
            receipt["timeout_seconds"] = max(0.0, timeout)
            if timeout <= 0:
                raise ProviderError("run_deadline_exceeded")
            response = self.provider.decide(ProviderRequest(wire, timeout))
            if type(response) is not ProviderResponse:
                raise ProviderError("response_schema")
            if response.usage is not None:
                receipt["usage"] = validate_usage(response.usage)
            if type(response.complete) is not bool:
                raise ProviderError("response_schema")
            if not response.complete:
                raise ProviderError("response_truncated")
            if response.error is not None:
                if type(response.error) is not str or response.error not in ERROR_CODES:
                    raise ProviderError("response_schema")
                raise ProviderError(response.error)
            if time.monotonic() - started >= timeout:
                raise ProviderError("deadline_exceeded")
            answers = validate_answer_objects(response.answers, expected, self.rounding_places)
            self.check_sensitive(answers, receipt["usage"])
        except ProviderError as exc:
            error = exc.code
            # A rejected credential cannot succeed later in this run either.
            if error in {"transport_failed", "deadline_exceeded", "interrupted",
                         "http_unauthorized"}:
                self._blocked = True
        except Exception:
            error = "transport_failed"
            self._blocked = True
        receipt.update(status="failed" if error else "validated", error=error,
                       answers=plain(answers) if error is None else None,
                       elapsed_seconds=max(0.0, time.monotonic() - started))
        self._last_stats = deepcopy(receipt)
        try:
            _write_receipt(path, receipt)
        except Exception:
            self._fail_receipt(path, receipt, "receipt_failed", persist=False)
            raise ProviderError("receipt_failed") from None
        if error:
            raise ProviderError(error)
        assert answers is not None
        return answers
