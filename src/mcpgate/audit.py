"""Tamper-evident audit log (hash-chained JSON Lines).

Every security-relevant decision -- tool calls (allowed or not), catalog listings, token
rejections, HTTP-level 401/403 responses, pin alerts and upstream health changes -- becomes one
JSON object per line::

    {"seq": 41, "ts": "2026-10-25T09:12:03.123456Z", "event": "tool_call", ...,
     "prev": "<hash of record 40>", "hash": "<sha256 of this record without 'hash'>"}

``hash`` is the SHA-256 of the canonical JSON of the record minus the ``hash`` field, and
``prev`` links to the previous record (64 zeros for the first). Editing, deleting, inserting
or reordering any line breaks the chain, which :func:`verify_chain` detects and locates.
Truncating the *tail* is only detectable against an externally stored head hash
(``mcpgate audit verify --expect-head``) -- see the threat model.

Argument logging is configurable: ``digest`` (default) stores only a SHA-256 of the canonical
arguments plus their top-level keys, ``redacted`` stores values with secret-looking keys
masked and long strings truncated, ``full`` stores everything.
"""

from __future__ import annotations

import datetime as dt
import json
import logging
import os
import threading
from collections.abc import Callable, Iterable, Iterator, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from mcpgate.canonical import canonical_bytes, digest, sha256_hex
from mcpgate.config import AuditConfig
from mcpgate.errors import AuditError

__all__ = ["GENESIS", "AuditLog", "ChainReport", "summarize_arguments", "verify_chain"]

logger = logging.getLogger(__name__)

GENESIS = "0" * 64
_MAX_STRING = 256


def _utcnow() -> str:
    return dt.datetime.now(dt.UTC).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def _record_hash(record: Mapping[str, Any]) -> str:
    return sha256_hex(canonical_bytes({k: v for k, v in record.items() if k != "hash"}))


def _redact(value: Any, secret_keys: tuple[str, ...], depth: int = 0) -> Any:
    if depth > 16:
        return "[DEPTH]"
    if isinstance(value, Mapping):
        out: dict[str, Any] = {}
        for key, item in value.items():
            lowered = str(key).lower()
            if any(s in lowered for s in secret_keys):
                out[str(key)] = "[REDACTED]"
            else:
                out[str(key)] = _redact(item, secret_keys, depth + 1)
        return out
    if isinstance(value, list):
        return [_redact(v, secret_keys, depth + 1) for v in value[:50]]
    if isinstance(value, str) and len(value) > _MAX_STRING:
        return value[:_MAX_STRING] + f"...[{len(value) - _MAX_STRING} more chars]"
    return value


def summarize_arguments(
    arguments: Mapping[str, Any] | None, mode: str, secret_keys: Iterable[str]
) -> dict[str, Any]:
    """Represent call arguments in the audit record according to the configured mode."""
    args = dict(arguments or {})
    try:
        summary: dict[str, Any] = {"args_digest": digest(args), "arg_keys": sorted(args)}
    except (TypeError, ValueError):
        return {"args_digest": None, "arg_keys": sorted(map(str, args))}
    if mode == "redacted":
        summary["args"] = _redact(args, tuple(s.lower() for s in secret_keys))
    elif mode == "full":
        summary["args"] = args
    return summary


class AuditLog:
    """Append-only, hash-chained JSONL writer. Safe to call from several threads/tasks."""

    def __init__(self, config: AuditConfig, *, now: Callable[[], str] = _utcnow) -> None:
        self._cfg = config
        self._now = now
        self._lock = threading.Lock()
        self.path = config.path
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._seq, self._head = self._resume()
        fd = os.open(self.path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
        self._fh = os.fdopen(fd, "a", encoding="utf-8")
        self._listeners: list[Callable[[Mapping[str, Any]], None]] = []

    @property
    def head(self) -> str:
        """Hash of the last record written (anchor it externally to detect tail truncation)."""
        return self._head

    @property
    def config(self) -> AuditConfig:
        return self._cfg

    def subscribe(self, listener: Callable[[Mapping[str, Any]], None]) -> None:
        """Receive every record after it is durably appended (used by the demo and tests)."""
        self._listeners.append(listener)

    def _resume(self) -> tuple[int, str]:
        """Continue an existing chain; refuse to append to a log whose last line is corrupt."""
        if not self.path.exists() or self.path.stat().st_size == 0:
            return 0, GENESIS
        last = _last_line(self.path)
        try:
            record = json.loads(last)
            seq, head = int(record["seq"]), str(record["hash"])
        except (ValueError, KeyError, TypeError) as exc:
            raise AuditError(f"audit log {self.path} ends with a corrupt record; refusing to append") from exc
        if _record_hash(record) != head:
            raise AuditError(f"audit log {self.path} last record fails its own hash; refusing to append")
        return seq, head

    def write(self, event: str, **fields: Any) -> dict[str, Any]:
        """Append one record and return it (including ``seq`` and ``hash``)."""
        with self._lock:
            record: dict[str, Any] = {"seq": self._seq + 1, "ts": self._now(), "event": event}
            record.update({k: v for k, v in fields.items() if v is not None})
            record["prev"] = self._head
            try:
                record["hash"] = _record_hash(record)
                line = canonical_bytes(record).decode("utf-8")
            except (TypeError, ValueError) as exc:
                raise AuditError(f"audit record for {event!r} is not JSON-serialisable: {exc}") from exc
            try:
                self._fh.write(line + "\n")
                self._fh.flush()
                if self._cfg.fsync:
                    os.fsync(self._fh.fileno())
            except OSError as exc:
                raise AuditError(f"cannot append to audit log: {exc.strerror}") from exc
            self._seq += 1
            self._head = record["hash"]
        for listener in self._listeners:
            try:
                listener(record)
            except Exception:  # a broken observer must never break auditing
                logger.exception("audit listener failed")
        return record

    def close(self) -> None:
        with self._lock:
            self._fh.close()


def _last_line(path: Path) -> str:
    with path.open("rb") as fh:
        fh.seek(0, os.SEEK_END)
        size = fh.tell()
        block = min(size, 65_536)
        fh.seek(size - block)
        lines = fh.read().splitlines()
    return lines[-1].decode("utf-8") if lines else ""


@dataclass(frozen=True, slots=True)
class ChainReport:
    ok: bool
    records: int
    head: str
    error: str | None = None
    line: int | None = None


def iter_records(path: Path) -> Iterator[tuple[int, str]]:
    with path.open("r", encoding="utf-8") as fh:
        for number, line in enumerate(fh, start=1):
            if line.strip():
                yield number, line


def verify_chain(path: Path, *, expect_head: str | None = None) -> ChainReport:
    """Re-derive every hash and link; report the first broken line, if any."""
    prev = GENESIS
    count = 0
    expected_seq = 1
    try:
        for number, line in iter_records(path):
            try:
                record = json.loads(line)
            except ValueError:
                return ChainReport(False, count, prev, "line is not valid JSON", number)
            if not isinstance(record, dict) or "hash" not in record:
                return ChainReport(False, count, prev, "record has no hash", number)
            if record.get("seq") != expected_seq:
                return ChainReport(
                    False, count, prev, f"expected seq {expected_seq}, found {record.get('seq')}", number
                )
            if record.get("prev") != prev:
                return ChainReport(
                    False, count, prev, "prev does not match the previous record's hash", number
                )
            if _record_hash(record) != record["hash"]:
                return ChainReport(False, count, prev, "record content does not match its hash", number)
            prev = record["hash"]
            count += 1
            expected_seq += 1
    except FileNotFoundError:
        return ChainReport(False, 0, GENESIS, "audit log does not exist")
    if expect_head is not None and expect_head != prev:
        return ChainReport(
            False, count, prev, "head differs from the expected anchor (log truncated or replaced?)"
        )
    return ChainReport(True, count, prev)
