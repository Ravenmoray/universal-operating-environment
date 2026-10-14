"""UOE research prototype: inspect, plan, and run one reviewed demonstration."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

from .inspector import InspectionError, inspect_file
from .claims import load_claims, plan_capabilities
from .graph import load_graph
from .planner import plan_inspection


def _print(data: dict):
    print(json.dumps(data, indent=2, sort_keys=True))


def _demo(export_dir: Path | None = None):
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
        graph_path = Path(tmp) / "controlled-graph.json"
        verified = subprocess.run(
            [sys.executable, str(harness), "--graph-output", str(graph_path)],
            capture_output=True, text=True, timeout=120, check=False
        )
        if verified.returncode:
            raise InspectionError(
                "controlled fixture verification failed: " + verified.stderr[-2000:]
            )
        outcome = json.loads(verified.stdout)
        if outcome.get("status") != "passed":
            raise InspectionError("fixture report does not show passing tests")
        graph = load_graph(graph_path)
        # This declaration is explicitly fixture-specific; it is not an
        # independent inspection of native imports or a signed attestation.
        claims = {
            "schema_version": "uoe.claims.v0.2",
            "artifact_id": "artifact:uoe.elf-client",
            "artifact_sha256": scan["artifact"]["sha256"],
            "provenance": {
                "kind": "source_document",
                "reference": "UOE reviewed fixture: include/uoe_text_v1.h",
            },
            "requirements": [{
                "capability": "capability:uoe.text.normalize@1",
                "requirement_edge": "edge:fixture-0",
                "status": "documented",
            }],
        }
        capability_plan = plan_capabilities(
            scan, claims, graph, "host:linux-fixture"
        )
        if capability_plan["status"] != "all_requirements_have_candidates":
            raise InspectionError("reviewed fixture graph did not yield candidates")
        exports = None
        if export_dir is not None:
            # Export only reviewed project-owned artifacts; never fetched or
            # generated third-party binaries. Refuse overwriting existing paths.
            export_dir = export_dir.resolve()
            if export_dir.exists():
                raise InspectionError("demo export directory must not already exist")
            export_dir.mkdir(parents=True)
            binary = export_dir / "uoe-demo-client"
            shutil.copy2(output, binary)
            graph_file = export_dir / "graph.json"
            claims_file = export_dir / "claims.json"
            graph_file.write_text(json.dumps(graph, indent=2, sort_keys=True) + "\n")
            claims_file.write_text(json.dumps(claims, indent=2, sort_keys=True) + "\n")
            exports = {
                "artifact": str(binary),
                "claims": str(claims_file),
                "graph": str(graph_file),
                "host_id": "host:linux-fixture",
            }
        return {
            "scenario": "project-owned native Linux missing-library experiment",
            "inspection": scan,
            "plan": proposed,
            "capability_graph": capability_plan,
            "exported_files": exports,
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
    inspect_cmd = commands.add_parser("inspect", help="Read headers and ELF dependencies; never run the artifact")
    inspect_cmd.add_argument("artifact", type=Path)
    plan_cmd = commands.add_parser("plan", help="Explain potential runners; never run software")
    plan_cmd.add_argument("artifact", type=Path)
    plan_cmd.add_argument("--claims", type=Path,
                          help="Digest-pinned JSON requirement declarations")
    plan_cmd.add_argument("--graph", type=Path,
                          help="Evidence graph JSON for requirement/provider joins")
    plan_cmd.add_argument("--host-id",
                          help="Explicit host node ID inside supplied graph (unattested)")
    demo_cmd = commands.add_parser(
        "demo", help="Explicit, reviewed repository-owned Linux execution experiment"
    )
    demo_cmd.add_argument(
        "--execute-reviewed-fixture", action="store_true", required=False,
        help="Acknowledge that this command compiles and executes project-owned C code"
    )
    demo_cmd.add_argument("--export-dir", type=Path,
                          help="Create a new directory with reviewed binary and JSON fixtures")
    args = parser.parse_args(argv)

    try:
        if args.command == "inspect":
            result = inspect_file(args.artifact)
        elif args.command == "plan":
            scan = inspect_file(args.artifact)
            result = plan_inspection(scan)
            graph_inputs = (args.claims, args.graph, args.host_id)
            if any(value is not None for value in graph_inputs):
                if not all(value is not None for value in graph_inputs):
                    parser.error("capability planning requires --claims, --graph and --host-id together")
                graph = load_graph(args.graph)
                claims = load_claims(args.claims, scan["artifact"]["sha256"])
                result["capability_graph"] = plan_capabilities(
                    scan, claims, graph, args.host_id
                )
        elif args.command == "demo":
            if not args.execute_reviewed_fixture:
                parser.error("demo executes local code; specify --execute-reviewed-fixture")
            result = _demo(args.export_dir)
        else:
            parser.error("unknown command")
        _print(result)
        return 0
    except (InspectionError, OSError, subprocess.TimeoutExpired, ValueError) as exc:
        print(f"uoe: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
