"""UOE research prototype: inspect, plan, and run one reviewed demonstration."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import subprocess
import sys
import tempfile

from .inspector import InspectionError, inspect_file
from .planner import plan_inspection


def _print(data: dict):
    print(json.dumps(data, indent=2, sort_keys=True))


def _demo():
    """Explicitly run ONLY the checked-in UOE-owned C fixture and its oracle."""
    if sys.platform != "linux":
        raise InspectionError("controlled demo currently requires Linux")
    repo = Path(__file__).resolve().parents[1]
    fixture = repo / "experiments" / "missing-capability"
    source = fixture / "src" / "client.c"
    harness = fixture / "verify.py"
    if not source.is_file() or not harness.is_file():
        raise InspectionError("checked-in demo sources unavailable; use a repository checkout")
    with tempfile.TemporaryDirectory(prefix="uoe-cli-") as tmp:
        output = Path(tmp) / "uoe-demo-client"
        compiler = subprocess.run(
            ["cc", "-std=c11", "-O2", "-Wall", "-Wextra", "-Werror",
             str(source), "-o", str(output), "-ldl"],
            capture_output=True, text=True, timeout=45, check=False
        )
        if compiler.returncode:
            raise InspectionError("demo compiler failed: " + compiler.stderr[-2000:])
        scan = inspect_file(output)
        proposed = plan_inspection(scan)
        verified = subprocess.run(
            [sys.executable, str(harness)],
            capture_output=True, text=True, timeout=120, check=False
        )
        if verified.returncode:
            raise InspectionError(
                "controlled fixture verification failed: " + verified.stderr[-2000:]
            )
        outcome = json.loads(verified.stdout)
        if outcome.get("status") != "passed":
            raise InspectionError("fixture report does not show passing tests")
        return {
            "scenario": "project-owned native Linux missing-library experiment",
            "inspection": scan,
            "plan": proposed,
            "verification": outcome,
            "execution_scope": "only checked-in fixture; no arbitrary executables",
            "warning": "This test is not a security sandbox or compatibility guarantee.",
        }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="uoe",
        description=("UOE experimental OS-neutral artifact analysis and "
                     "non-executing execution planning"),
    )
    commands = parser.add_subparsers(dest="command", required=True)
    inspect_cmd = commands.add_parser("inspect", help="Read an executable's header; never run it")
    inspect_cmd.add_argument("artifact", type=Path)
    plan_cmd = commands.add_parser("plan", help="Explain potential runners; never run software")
    plan_cmd.add_argument("artifact", type=Path)
    demo_cmd = commands.add_parser(
        "demo", help="Explicit, reviewed repository-owned Linux execution experiment"
    )
    demo_cmd.add_argument(
        "--execute-reviewed-fixture", action="store_true", required=False,
        help="Acknowledge that this command compiles and executes project-owned C code"
    )
    args = parser.parse_args(argv)

    try:
        if args.command == "inspect":
            result = inspect_file(args.artifact)
        elif args.command == "plan":
            result = plan_inspection(inspect_file(args.artifact))
        elif args.command == "demo":
            if not args.execute_reviewed_fixture:
                parser.error("demo executes local code; specify --execute-reviewed-fixture")
            result = _demo()
        else:
            parser.error("unknown command")
        _print(result)
        return 0
    except (InspectionError, OSError, subprocess.TimeoutExpired, ValueError) as exc:
        print(f"uoe: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
