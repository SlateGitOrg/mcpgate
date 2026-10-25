from __future__ import annotations

import json
from pathlib import Path

import pytest

from mcpgate.audit import GENESIS, AuditLog, summarize_arguments, verify_chain
from mcpgate.config import AuditConfig
from mcpgate.errors import AuditError


def log_at(path: Path, **kw: object) -> AuditLog:
    return AuditLog(AuditConfig(path=path, **kw), now=lambda: "2026-01-01T00:00:00.000000Z")  # type: ignore[arg-type]


def write_three(path: Path) -> AuditLog:
    log = log_at(path)
    log.write("a", client="c1")
    log.write("b", n=2, skipped=None)
    log.write("c", nested={"k": [1, 2.5]})
    return log


def test_chain_verifies_and_resumes(tmp_path: Path) -> None:
    path = tmp_path / "audit.jsonl"
    log = write_three(path)
    head = log.head
    log.close()
    report = verify_chain(path)
    assert (report.ok, report.records, report.head) == (True, 3, head)
    assert "skipped" not in path.read_text()
    assert path.stat().st_mode & 0o777 == 0o600
    resumed = log_at(path)
    record = resumed.write("d")
    assert (record["seq"], record["prev"]) == (4, head)
    resumed.close()
    assert verify_chain(path, expect_head=record["hash"]).ok


@pytest.mark.parametrize("attack", ["edit", "delete", "swap", "insert", "garbage", "nohash"])
def test_tampering_is_detected(tmp_path: Path, attack: str) -> None:
    path = tmp_path / "audit.jsonl"
    write_three(path).close()
    lines = path.read_text().splitlines()
    if attack == "edit":
        lines[1] = lines[1].replace('"n":2', '"n":3')
    elif attack == "delete":
        del lines[1]
    elif attack == "swap":
        lines[0], lines[1] = lines[1], lines[0]
    elif attack == "insert":
        lines.insert(1, lines[0])
    elif attack == "garbage":
        lines[2] = "{not json"
    else:
        lines[2] = json.dumps({"seq": 3})
    path.write_text("\n".join(lines) + "\n")
    report = verify_chain(path)
    assert not report.ok
    assert report.line is not None
    assert report.error


def test_tail_truncation_needs_external_anchor(tmp_path: Path) -> None:
    path = tmp_path / "audit.jsonl"
    log = write_three(path)
    head = log.head
    log.close()
    path.write_text("\n".join(path.read_text().splitlines()[:2]) + "\n")
    assert verify_chain(path).ok  # undetectable without an anchor...
    report = verify_chain(path, expect_head=head)
    assert not report.ok  # ...and detected with one
    assert "anchor" in (report.error or "")


def test_refuses_to_extend_corrupt_log(tmp_path: Path) -> None:
    path = tmp_path / "audit.jsonl"
    write_three(path).close()
    path.write_text(path.read_text() + "{oops\n")
    with pytest.raises(AuditError, match="corrupt"):
        log_at(path)
    lines = path.read_text().splitlines()[:3]
    lines[2] = lines[2].replace('"k"', '"K"')
    path.write_text("\n".join(lines) + "\n")
    with pytest.raises(AuditError, match="fails its own hash"):
        log_at(path)


def test_missing_log_and_unserialisable_record(tmp_path: Path) -> None:
    assert verify_chain(tmp_path / "nope.jsonl").error == "audit log does not exist"
    log = log_at(tmp_path / "a.jsonl")
    with pytest.raises(AuditError, match="not JSON-serialisable"):
        log.write("bad", value=object())
    assert log.head == GENESIS


def test_listeners_and_failing_listener(tmp_path: Path) -> None:
    log = log_at(tmp_path / "a.jsonl")
    seen: list[str] = []
    log.subscribe(lambda r: seen.append(r["event"]))
    log.subscribe(lambda r: 1 / 0)  # type: ignore[arg-type]
    log.write("x")
    assert seen == ["x"]


def test_argument_summaries() -> None:
    args = {
        "user": "bob",
        "api_key": "sk-123",
        "body": "x" * 300,
        "nested": {"Password": "p", "ok": [1] * 60},
    }
    digest_only = summarize_arguments(args, "digest", ["api_key", "password"])
    assert set(digest_only) == {"args_digest", "arg_keys"}
    redacted = summarize_arguments(args, "redacted", ["API_KEY", "password"])["args"]
    assert redacted["api_key"] == "[REDACTED]"
    assert redacted["nested"]["Password"] == "[REDACTED]"
    assert len(redacted["nested"]["ok"]) == 50
    assert redacted["body"].endswith("[44 more chars]")
    assert summarize_arguments(args, "full", [])["args"] == args
    assert summarize_arguments({"x": float("nan")}, "digest", [])["args_digest"] is None
    assert summarize_arguments(None, "digest", [])["arg_keys"] == []
    deep: dict[str, object] = {}
    cursor = deep
    for _ in range(20):
        cursor["d"] = {}
        cursor = cursor["d"]  # type: ignore[assignment]
    assert "[DEPTH]" in json.dumps(summarize_arguments(deep, "redacted", [])["args"])
