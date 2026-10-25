"""Tool-definition pinning: detect and contain upstream tool changes ("rug pulls").

Model
-----
For every upstream the pin store records the approved fingerprint of each tool. On each
catalog refresh the gateway *reconciles* what the upstream advertises against the store:

=================  ==========================================  ===========================
observation        enforce mode                                warn mode
=================  ==========================================  ===========================
first contact      trust on first use: pin everything          same
same digest        serve                                       serve
digest differs     **quarantine** + alert (pending approval)   serve + alert
new tool           quarantine + alert (or pin, if configured)  serve + alert
tool disappeared   alert; pin kept so a re-appearance is       same
                   checked against the old approval
=================  ==========================================  ===========================

Quarantine is not stored state: a tool is blocked whenever its *currently observed* digest
differs from its pinned digest. Approving a change (``mcpgate pins approve``) rewrites the
pin, and a running gateway notices the store's new mtime on its next lookup, so approval takes
effect without a restart. If the upstream reverts to the pinned definition the tool is
served again automatically.

Approval is bound to what the operator reviewed. ``pins diff`` prints the full observed digest
of each pending tool and a *review digest* over the whole pending set of an upstream; ``approve``
must be given that value and refuses, without changing anything, if what is pending now differs
(the upstream swapped definitions, or slipped in another tool, between review and approval).
The comparison and the promotion happen in one transaction under the store lock, so a
concurrent ``reconcile`` cannot interleave between them.

Store format
------------
A single JSON document written atomically (temp file + ``os.replace``) under an exclusive
``flock`` on a sidecar lock file, so the CLI and a running gateway can both update it safely.
"""

from __future__ import annotations

import contextlib
import fcntl
import json
import logging
import os
import time
from collections.abc import Callable, Iterator, Mapping
from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import Path
from typing import Any

from mcpgate.canonical import digest
from mcpgate.config import PinningConfig
from mcpgate.errors import PinApprovalMismatch, PinStoreError
from mcpgate.fingerprint import Fingerprint, describe_change

__all__ = ["PinEvent", "PinManager", "PinStatus", "PinStore", "pending_set_digest"]

logger = logging.getLogger(__name__)

STORE_VERSION = 1


class PinStatus(StrEnum):
    PINNED = "pinned"
    CHANGED = "changed"
    NEW = "new"


@dataclass(frozen=True, slots=True)
class PinEvent:
    """Something the operator should know about. ``kind`` values:

    ``tofu`` (first contact, tools pinned), ``changed``, ``new_tool``, ``new_tool_pinned``,
    ``removed``, ``reverted`` (an unapproved change went away), ``approved``.
    """

    kind: str
    upstream: str
    tool: str | None
    severity: str
    detail: Mapping[str, Any] = field(default_factory=dict)


def pending_set_digest(upstream: str, pending: Mapping[str, Any]) -> str | None:
    """Review digest of an upstream's pending set (``None`` when nothing is pending).

    Canonical-JSON SHA-256 over the upstream name and every pending ``name -> observed digest``
    pair, so it is independent of ordering and changes if any pending definition is swapped or a
    tool joins or leaves the set. ``mcpgate pins diff`` prints it; ``approve --all`` checks it.
    """
    if not pending:
        return None
    return digest({"upstream": upstream, "pending": {n: r["digest"] for n, r in pending.items()}})


class PinStore:
    """File-backed pin storage with cross-process locking."""

    def __init__(self, path: Path) -> None:
        self.path = path
        self._lock_path = path.with_name(path.name + ".lock")

    @contextlib.contextmanager
    def locked(self) -> Iterator[None]:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        fd = os.open(self._lock_path, os.O_RDWR | os.O_CREAT, 0o600)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX)
            yield
        finally:
            fcntl.flock(fd, fcntl.LOCK_UN)
            os.close(fd)

    def mtime_ns(self) -> int | None:
        try:
            return os.stat(self.path).st_mtime_ns
        except FileNotFoundError:
            return None

    def read(self) -> dict[str, Any]:
        try:
            raw = self.path.read_text(encoding="utf-8")
        except FileNotFoundError:
            return {"version": STORE_VERSION, "upstreams": {}}
        except OSError as exc:
            raise PinStoreError(f"cannot read pin store {self.path}: {exc.strerror}") from exc
        try:
            data = json.loads(raw)
        except ValueError as exc:
            raise PinStoreError(f"pin store {self.path} is not valid JSON: {exc}") from exc
        if (
            not isinstance(data, dict)
            or data.get("version") != STORE_VERSION
            or not isinstance(data.get("upstreams"), dict)
        ):
            raise PinStoreError(f"pin store {self.path} has an unsupported layout")
        return data

    def write(self, data: Mapping[str, Any]) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.path.with_name(f".{self.path.name}.{os.getpid()}.tmp")
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(data, fh, indent=2, sort_keys=True)
            fh.write("\n")
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, self.path)

    @contextlib.contextmanager
    def transaction(self) -> Iterator[dict[str, Any]]:
        """Read-modify-write under the lock; the (mutated) document is written on success."""
        with self.locked():
            data = self.read()
            yield data
            self.write(data)


class PinManager:
    """Applies the pinning model to observed tool definitions."""

    def __init__(self, config: PinningConfig, *, clock: Callable[[], float] = time.time) -> None:
        self._cfg = config
        self._clock = clock
        self.store = PinStore(config.store)
        self._data: dict[str, Any] = self.store.read()
        self._mtime = self.store.mtime_ns()

    @property
    def enabled(self) -> bool:
        return self._cfg.enabled

    def _refresh_if_stale(self) -> None:
        mtime = self.store.mtime_ns()
        if mtime != self._mtime:
            try:
                self._data = self.store.read()
                self._mtime = mtime
            except PinStoreError as exc:
                logger.warning("pin store reload failed, keeping previous pins: %s", exc)

    def _pins(self, upstream: str) -> Mapping[str, Any] | None:
        entry = self._data["upstreams"].get(upstream)
        return entry.get("tools", {}) if isinstance(entry, dict) else None

    def status(self, upstream: str, tool: str, observed: Fingerprint) -> PinStatus:
        """Compare an observed fingerprint with the pin (reloading approvals from disk)."""
        if not self._cfg.enabled:
            return PinStatus.PINNED
        self._refresh_if_stale()
        pins = self._pins(upstream)
        pin = pins.get(tool) if pins is not None else None
        if pin is None:
            return PinStatus.NEW
        return PinStatus.PINNED if pin.get("digest") == observed.digest else PinStatus.CHANGED

    def blocks(self, status: PinStatus) -> bool:
        """Whether a tool in ``status`` must be hidden and refused."""
        return self._cfg.enabled and self._cfg.mode == "enforce" and status is not PinStatus.PINNED

    def pinned_fingerprint(self, upstream: str, tool: str) -> Fingerprint | None:
        self._refresh_if_stale()
        pins = self._pins(upstream)
        pin = pins.get(tool) if pins is not None else None
        return Fingerprint.from_json(pin) if pin is not None else None

    def reconcile(self, upstream: str, observed: Mapping[str, Fingerprint]) -> list[PinEvent]:
        """Record what ``upstream`` currently advertises; return alert-worthy events.

        Alerts are de-duplicated: a pending change is reported once per distinct observed
        digest, not on every refresh.
        """
        if not self._cfg.enabled:
            return []
        now = self._clock()
        events: list[PinEvent] = []
        with self.store.transaction() as data:
            entry = data["upstreams"].get(upstream)
            if entry is None:
                data["upstreams"][upstream] = {
                    "first_seen": now,
                    "tools": {name: self._pin_record(fp, now, "tofu") for name, fp in observed.items()},
                    "pending": {},
                }
                events.append(PinEvent("tofu", upstream, None, "info", {"tools": sorted(observed)}))
            else:
                events.extend(self._reconcile_known(upstream, entry, observed, now))
            self._data = data
        self._mtime = self.store.mtime_ns()
        for event in events:
            log = logger.warning if event.severity in {"high", "medium"} else logger.info
            log("pin event %s upstream=%s tool=%s", event.kind, event.upstream, event.tool)
        return events

    def _reconcile_known(
        self, upstream: str, entry: dict[str, Any], observed: Mapping[str, Fingerprint], now: float
    ) -> list[PinEvent]:
        events: list[PinEvent] = []
        tools: dict[str, Any] = entry.setdefault("tools", {})
        pending: dict[str, Any] = entry.setdefault("pending", {})
        for name, fp in sorted(observed.items()):
            pin = tools.get(name)
            if pin is not None and pin["digest"] == fp.digest:
                if pending.pop(name, None) is not None:
                    events.append(PinEvent("reverted", upstream, name, "info"))
                continue
            previous = pending.get(name)
            already_reported = previous is not None and previous.get("digest") == fp.digest
            if pin is None and self._cfg.on_new_tool == "pin":
                tools[name] = self._pin_record(fp, now, "auto-new")
                pending.pop(name, None)
                events.append(PinEvent("new_tool_pinned", upstream, name, "low"))
                continue
            pending[name] = {**fp.to_json(), "observed_at": now, "kind": "new" if pin is None else "changed"}
            if already_reported:
                continue
            if pin is None:
                events.append(PinEvent("new_tool", upstream, name, "medium", {"digest": fp.digest}))
            else:
                detail = describe_change(Fingerprint.from_json(pin), fp)
                detail.update(pinned_digest=pin["digest"], observed_digest=fp.digest)
                events.append(PinEvent("changed", upstream, name, "high", detail))
        removed = sorted(set(tools) - set(observed))
        missing_before = set(entry.get("missing", []))
        events.extend(PinEvent("removed", upstream, n, "medium") for n in removed if n not in missing_before)
        entry["missing"] = removed
        for name in list(pending):
            if name not in observed:
                del pending[name]
        return events

    @staticmethod
    def _pin_record(fp: Fingerprint, now: float, how: str) -> dict[str, Any]:
        return {**fp.to_json(), "pinned_at": now, "approved_by": how}

    def review_digest(self, upstream: str) -> str | None:
        """Digest binding the whole pending set of ``upstream`` (``None`` if nothing is pending).

        It covers every pending tool name and observed digest, so it changes if any pending
        definition is swapped or a tool is added to or dropped from the set.
        """
        self._refresh_if_stale()
        entry = self._data["upstreams"].get(upstream)
        pending = entry.get("pending", {}) if isinstance(entry, dict) else {}
        return pending_set_digest(upstream, pending)

    def approve(
        self, upstream: str, tool: str | None = None, *, expect: str, by: str = "cli"
    ) -> list[PinEvent]:
        """Promote pending observations to pins, but only the ones the operator reviewed.

        With ``tool``, ``expect`` must equal that tool's pending observed digest; without it,
        every pending tool of ``upstream`` is approved and ``expect`` must equal
        :meth:`review_digest`. On a mismatch :class:`PinApprovalMismatch` is raised and the store
        is left untouched. Digests are compared in full; prefixes are refused.
        """
        events: list[PinEvent] = []
        now = self._clock()
        with self.store.transaction() as data:
            entry = data["upstreams"].get(upstream)
            if entry is None:
                raise PinStoreError(f"no pins recorded for upstream {upstream!r}")
            pending: dict[str, Any] = entry.get("pending", {})
            if tool is None:
                current = pending_set_digest(upstream, pending)
                if current != expect:
                    raise PinApprovalMismatch(upstream, None, expect, current)
                names = sorted(pending)
            else:
                record = pending.get(tool)
                if record is None:
                    raise PinStoreError(f"no pending change for {upstream}/{tool}")
                if record["digest"] != expect:
                    raise PinApprovalMismatch(upstream, tool, expect, str(record["digest"]))
                names = [tool]
            for name in names:
                fp = Fingerprint.from_json(pending.pop(name))
                entry["tools"][name] = self._pin_record(fp, now, by)
                events.append(PinEvent("approved", upstream, name, "info", {"digest": fp.digest}))
            self._data = data
        self._mtime = self.store.mtime_ns()
        return events

    def snapshot(self) -> dict[str, Any]:
        """The current store document (for ``mcpgate pins status``)."""
        self._refresh_if_stale()
        copied: dict[str, Any] = json.loads(json.dumps(self._data))
        return copied
