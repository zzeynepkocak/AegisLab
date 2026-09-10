"""AegisLab CLI. Currently exposes only tool registry commands (no agent loop).

Usage:
    python -m aegislab tools list
    python -m aegislab tools call <name> '<json args>'
"""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import asdict

from aegislab.tools.registry import build_default_registry


def _cmd_tools_list(_args: argparse.Namespace) -> int:
    registry = build_default_registry()
    print(json.dumps(registry.list_tools(), indent=2))
    return 0


def _cmd_tools_call(args: argparse.Namespace) -> int:
    registry = build_default_registry()
    tool = registry.get(args.name)
    if tool is None:
        print(json.dumps({"ok": False, "data": {"error": f"unknown tool: {args.name}"}}), file=sys.stderr)
        return 1

    try:
        call_args = json.loads(args.json_args)
    except json.JSONDecodeError as exc:
        print(json.dumps({"ok": False, "data": {"error": f"invalid JSON args: {exc}"}}), file=sys.stderr)
        return 1

    result = tool.execute(call_args)
    print(json.dumps(asdict(result), indent=2))
    return 0 if result.ok else 1


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="aegislab")
    subparsers = parser.add_subparsers(dest="command", required=True)

    tools_parser = subparsers.add_parser("tools", help="Inspect and call mock tools.")
    tools_sub = tools_parser.add_subparsers(dest="tools_command", required=True)

    list_parser = tools_sub.add_parser("list", help="List available tools.")
    list_parser.set_defaults(func=_cmd_tools_list)

    call_parser = tools_sub.add_parser("call", help="Call a tool with JSON args.")
    call_parser.add_argument("name", help="Tool name.")
    call_parser.add_argument("json_args", help="Tool arguments as a JSON object string.")
    call_parser.set_defaults(func=_cmd_tools_call)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
