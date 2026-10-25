"""Command-line interface: ``mcpgate <command>``.

=====================  ======================================================================
``serve``              run the gateway (Streamable HTTP with OAuth, or stdio)
``check-config``       validate a config file and print what it defines
``catalog``            connect to the upstreams once and print the namespaced catalog, pin
                       status and lint findings (no serving)
``pins``               ``status`` / ``diff`` / ``approve`` pinned tool definitions
``audit``              ``verify`` the hash chain, or ``tail`` the log
``keys`` / ``token``   development-only issuer: create a signing key + JWKS, mint tokens
=====================  ======================================================================
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import Any

import anyio

from mcpgate import __version__
from mcpgate.audit import verify_chain
from mcpgate.config import GatewayConfig, load_config
from mcpgate.devissuer import DevIssuer, generate_keys
from mcpgate.errors import GatewayError
from mcpgate.fingerprint import Fingerprint, describe_change
from mcpgate.gateway import Gateway
from mcpgate.lint import lint_definition
from mcpgate.pinning import PinManager

__all__ = ["main"]


def _out(text: str = "") -> None:
    sys.stdout.write(text + "\n")


def _config(args: argparse.Namespace) -> GatewayConfig:
    return load_config(Path(args.config))


# -- serve / check-config / catalog -----------------------------------------------------------


def cmd_serve(args: argparse.Namespace) -> int:
    cfg = _config(args)
    gateway = Gateway(cfg)

    async def run() -> None:
        async with gateway.running():
            if args.transport == "stdio":
                await gateway.serve_stdio()
            else:
                await gateway.serve_http()

    anyio.run(run)
    return 0


def cmd_check_config(args: argparse.Namespace) -> int:
    cfg = _config(args)
    _out(f"config OK: {args.config}")
    _out(f"  listen      {cfg.listen.resource_url}")
    auth = f"JWT via {cfg.auth.jwks_file.name}" if cfg.auth and cfg.auth.enabled else "DISABLED"
    _out(f"  auth        {auth}")
    for up in cfg.upstreams:
        target = getattr(up, "url", None) or " ".join(
            [Path(getattr(up, "command", "")).name, *getattr(up, "args", [])]
        )
        _out(f"  upstream    {up.name:<12} {up.transport:<5} {target}")
    _out(f"  roles       {', '.join(sorted(cfg.policy.roles)) or '(none: every call is denied)'}")
    _out(f"  clients     {', '.join(sorted(cfg.policy.clients)) or '(none)'}")
    _out(f"  pinning     {cfg.pinning.mode if cfg.pinning.enabled else 'off'} -> {cfg.pinning.store}")
    _out(f"  audit       {cfg.audit.arguments} -> {cfg.audit.path}")
    return 0


def cmd_catalog(args: argparse.Namespace) -> int:
    cfg = _config(args)
    gateway = Gateway(cfg.model_copy(update={"refresh_interval_s": 0, "auth": None}))  # no listener
    rows: list[dict[str, Any]] = []

    async def run() -> None:
        async with gateway.running(startup_timeout_s=args.timeout):
            for entry in gateway.catalog.entries():
                status = gateway.pins.status(entry.upstream, entry.original, entry.fingerprint)
                findings = lint_definition(
                    entry.fingerprint.definition, gateway.catalog.names_outside(entry.upstream)
                )
                rows.append(
                    {
                        "name": entry.name,
                        "pin": status.value,
                        "blocked": gateway.pins.blocks(status),
                        "digest": entry.fingerprint.digest,
                        "lint": [f"{f.severity}:{f.rule}@{f.location}" for f in findings],
                    }
                )

    anyio.run(run)
    if args.json:
        _out(json.dumps(rows, indent=2))
        return 0
    for row in rows:
        flag = "BLOCKED" if row["blocked"] else "ok"
        _out(f"{row['name']:<34} {row['pin']:<8} {flag:<8} {row['digest'][:19]}")
        for finding in row["lint"]:
            _out(f"    lint {finding}")
    down = [n for n, u in gateway.upstreams.items() if u.state != "ready" and u.state != "stopped"]
    if down:
        _out(f"unreachable upstreams: {', '.join(down)}")
    return 0


# -- pins ---------------------------------------------------------------------------------------


def cmd_pins(args: argparse.Namespace) -> int:
    cfg = _config(args)
    pins = PinManager(cfg.pinning)
    data = pins.snapshot()
    if args.pins_cmd == "status":
        if args.json:
            _out(json.dumps(data, indent=2))
            return 0
        for upstream, entry in sorted(data["upstreams"].items()):
            pending = entry.get("pending", {})
            _out(f"{upstream}: {len(entry.get('tools', {}))} pinned, {len(pending)} pending")
            for name, record in sorted(pending.items()):
                _out(f"  PENDING {record['kind']:<8} {name}  observed {record['digest'][:19]}")
            for name in entry.get("missing", []):
                _out(f"  MISSING          {name}")
        return 0
    if args.pins_cmd == "diff":
        shown = 0
        for upstream, entry in sorted(data["upstreams"].items()):
            if args.upstream and upstream != args.upstream:
                continue
            for name, record in sorted(entry.get("pending", {}).items()):
                if args.tool and name != args.tool:
                    continue
                shown += 1
                _out(f"== {upstream}/{name} ({record['kind']})")
                observed = Fingerprint.from_json(record)
                pinned = entry.get("tools", {}).get(name)
                if pinned is not None:
                    _out(json.dumps(describe_change(Fingerprint.from_json(pinned), observed), indent=2))
                else:
                    _out(json.dumps(observed.definition, indent=2))
                for finding in lint_definition(observed.definition):
                    _out(f"  lint {finding.severity}:{finding.rule} at {finding.location}: {finding.excerpt}")
        if not shown:
            _out("no pending changes")
        return 0
    events = pins.approve(args.upstream, None if args.all else args.tool, by=args.by)
    for event in events:
        _out(f"approved {event.upstream}/{event.tool} -> {event.detail['digest']}")
    return 0


# -- audit --------------------------------------------------------------------------------------


def _audit_path(args: argparse.Namespace) -> Path:
    return Path(args.log) if args.log else _config(args).audit.path


def cmd_audit(args: argparse.Namespace) -> int:
    path = _audit_path(args)
    if args.audit_cmd == "verify":
        report = verify_chain(path, expect_head=args.expect_head)
        if report.ok:
            _out(f"OK: {report.records} records, chain intact, head {report.head}")
            return 0
        where = f" at line {report.line}" if report.line else ""
        _out(f"FAILED{where}: {report.error} ({report.records} records verified before it)")
        return 1
    lines = path.read_text(encoding="utf-8").splitlines()[-args.n :]
    for line in lines:
        _out(line)
    return 0


# -- dev issuer ---------------------------------------------------------------------------------


def cmd_keys(args: argparse.Namespace) -> int:
    issuer = generate_keys(Path(args.dir), alg=args.alg, kid=args.kid)
    directory = Path(args.dir)
    _out(f"wrote {directory / 'signing-key.pem'} (0600) and {directory / 'jwks.json'} (kid {issuer.kid})")
    return 0


def cmd_token(args: argparse.Namespace) -> int:
    issuer = DevIssuer.load(Path(args.keys))
    token = issuer.mint(
        issuer=args.issuer,
        audience=args.audience,
        client_id=args.client_id,
        subject=args.subject,
        scopes=args.scope or ["mcp:tools"],
        ttl_s=args.ttl,
    )
    _out(token)
    return 0


# -- parser -------------------------------------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="mcpgate", description="Security gateway for MCP servers.")
    parser.add_argument("--version", action="version", version=f"mcpgate {__version__}")
    parser.add_argument("--log-level", default="WARNING", choices=["DEBUG", "INFO", "WARNING", "ERROR"])
    sub = parser.add_subparsers(dest="command", required=True)

    def with_config(p: argparse.ArgumentParser) -> argparse.ArgumentParser:
        p.add_argument(
            "-c", "--config", default="gateway.yaml", help="gateway config (default: gateway.yaml)"
        )
        return p

    serve = with_config(sub.add_parser("serve", help="run the gateway"))
    serve.add_argument("--transport", choices=["http", "stdio"], default="http")
    serve.set_defaults(func=cmd_serve)

    with_config(sub.add_parser("check-config", help="validate a config file")).set_defaults(
        func=cmd_check_config
    )

    catalog = with_config(sub.add_parser("catalog", help="print the aggregated catalog with pin status"))
    catalog.add_argument("--json", action="store_true")
    catalog.add_argument("--timeout", type=float, default=20.0, help="seconds to wait for upstreams")
    catalog.set_defaults(func=cmd_catalog)

    pins = with_config(sub.add_parser("pins", help="inspect and approve pinned tool definitions"))
    pins_sub = pins.add_subparsers(dest="pins_cmd", required=True)
    status = pins_sub.add_parser("status", help="pinned / pending / missing tools per upstream")
    status.add_argument("--json", action="store_true")
    diff = pins_sub.add_parser("diff", help="show what changed for pending tools")
    diff.add_argument("upstream", nargs="?")
    diff.add_argument("tool", nargs="?")
    approve = pins_sub.add_parser("approve", help="accept a pending definition as the new pin")
    approve.add_argument("upstream")
    approve.add_argument("tool", nargs="?")
    approve.add_argument("--all", action="store_true", help="approve every pending tool of the upstream")
    approve.add_argument("--by", default="cli", help="who approved (recorded in the store)")
    pins.set_defaults(func=cmd_pins)

    audit = with_config(sub.add_parser("audit", help="verify or tail the audit log"))
    audit.add_argument("--log", help="audit log path (overrides the config)")
    audit_sub = audit.add_subparsers(dest="audit_cmd", required=True)
    verify = audit_sub.add_parser("verify", help="check the hash chain")
    verify.add_argument("--expect-head", help="externally anchored head hash (detects tail truncation)")
    tail = audit_sub.add_parser("tail", help="print the last records")
    tail.add_argument("-n", type=int, default=20)
    audit.set_defaults(func=cmd_audit)

    keys = sub.add_parser("keys", help="(dev) create a signing key and JWKS")
    keys.add_argument("--dir", required=True)
    keys.add_argument("--alg", choices=["ES256", "EdDSA"], default="ES256")
    keys.add_argument("--kid")
    keys.set_defaults(func=cmd_keys)

    token = sub.add_parser("token", help="(dev) mint an access token")
    token.add_argument("--keys", required=True, help="directory created by `mcpgate keys`")
    token.add_argument("--issuer", required=True)
    token.add_argument("--audience", required=True, help="the gateway's resource URL")
    token.add_argument("--client-id", required=True)
    token.add_argument("--subject")
    token.add_argument("--scope", action="append", help="repeatable; default mcp:tools")
    token.add_argument("--ttl", type=int, default=900)
    token.set_defaults(func=cmd_token)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    logging.basicConfig(
        level=args.log_level, format="%(asctime)s %(levelname)s %(name)s: %(message)s", stream=sys.stderr
    )
    if getattr(args, "pins_cmd", None) == "approve" and not args.all and not args.tool:
        _out("error: name a tool or pass --all")
        return 2
    try:
        code: int = args.func(args)
    except GatewayError as exc:
        _out(f"error: {exc}")
        return 1
    return code


if __name__ == "__main__":
    raise SystemExit(main())
