#!/usr/bin/env python3
"""Reproduce a known missing-library failure and check the repair contract.

Runs ONLY project-owned C fixtures, compiled locally from this repository.
Not a security sandbox; never point it at arbitrary or third-party binaries.
Requires Linux, Python 3.10+, and a C compiler. No AI or network required.
"""
from __future__ import annotations

import argparse
import ctypes
import hashlib
import json
import os
from pathlib import Path
import platform
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parent
SRC = ROOT / "src"
PREFIX = b"UOE/1:"
VECTORS = [
    (b"", PREFIX),
    (b"hello", b"UOE/1:HELLO"),
    (b"Mixed 123", b"UOE/1:MIXED 123"),
    (b"!?_-z", b"UOE/1:!?_-Z"),
    ("h\u00e9llo".encode("utf-8"), b"UOE/1:H\xc3\xa9LLO"),
]


def expect(condition: bool, description: str):
    if not condition:
        raise AssertionError(description)


def compile_fixture(output: Path, source: str, shared=False):
    compiler = os.environ.get("CC", "cc")
    args = [compiler, "-std=c11", "-O2", "-Wall", "-Wextra", "-Werror"]
    if shared:
        args += ["-fPIC", "-shared"]
    args += [str(SRC / source), "-o", str(output)]
    if not shared:
        args += ["-ldl"]
    subprocess.run(args, check=True, capture_output=True, text=True, timeout=30)


def call_client(client: Path, provider: Path, text: bytes):
    # Test source is fixed and owned by UOE; not appropriate for unknown files.
    return subprocess.run([str(client), str(provider), text.decode("utf-8")],
                          capture_output=True, timeout=5, check=False)


def direct_contract_tests(provider: Path):
    library = ctypes.CDLL(str(provider))
    call = library.uoe_text_normalize_v1
    call.argtypes = [ctypes.c_char_p, ctypes.c_void_p, ctypes.c_size_t]
    call.restype = ctypes.c_int
    count = 0
    for source, expected in VECTORS:
        dest = ctypes.create_string_buffer(1024)
        rc = call(source, dest, ctypes.sizeof(dest))
        expect(rc == 0 and dest.value == expected,
               "candidate failed contract vector: " + repr(source))
        count += 1

    small = ctypes.create_string_buffer(b"keep", 5)
    before = small.raw
    expect(call(b"hello", small, 5) == -2 and small.raw == before,
           "small-buffer failure changed output")
    count += 1

    long_input = ctypes.create_string_buffer(b"z" * 513)
    unchanged = ctypes.create_string_buffer(b"untouched", 64)
    before = unchanged.raw
    expect(call(long_input, unchanged, ctypes.sizeof(unchanged)) == -3
           and unchanged.raw == before, "overlong input mishandled")
    count += 1

    valid = ctypes.create_string_buffer(32)
    expect(call(None, valid, ctypes.sizeof(valid)) == -1,
           "NULL input accepted")
    expect(call(b"hello", None, 32) == -1, "NULL output accepted")
    count += 2
    return count


def sha256(path: Path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def run_round(directory: Path):
    directory.mkdir(parents=True, exist_ok=True)
    client = directory / "client"
    good = directory / "libuoe_text_v1.so"
    wrong = directory / "libwrong_symbol.so"
    incorrect = directory / "libincorrect.so"
    compile_fixture(client, "client.c")
    compile_fixture(good, "reference_provider.c", shared=True)
    compile_fixture(wrong, "wrong_symbol_provider.c", shared=True)
    compile_fixture(incorrect, "incorrect_provider.c", shared=True)

    missing = call_client(client, directory / "missing.so", b"hello")
    expect(missing.returncode == 40 and b"UOE_ERR_LIBRARY" in missing.stderr,
           "missing library failure not detected")

    absent_symbol = call_client(client, wrong, b"hello")
    expect(absent_symbol.returncode == 41
           and b"UOE_ERR_SYMBOL" in absent_symbol.stderr,
           "missing exported symbol failure not detected")

    bad_semantics = call_client(client, incorrect, b"hello")
    expect(bad_semantics.returncode == 0
           and bad_semantics.stdout.strip() != b"UOE/1:HELLO",
           "incorrect implementation was not detected by the oracle")

    count = direct_contract_tests(good)
    for source, expected in VECTORS:
        run = call_client(client, good, source)
        expect(run.returncode == 0 and run.stdout.rstrip(b"\n") == expected,
               "client + provider behavior failed for " + repr(source))
        count += 1
    return {
        "client_sha256": sha256(client),
        "provider_sha256": sha256(good),
        "missing_library_exit": missing.returncode,
        "missing_symbol_exit": absent_symbol.returncode,
        "incorrect_provider_rejected": True,
        "contract_assertions": count,
    }


def produce_graph(report: dict):
    """Represent this experiment's test claims in the existing graph v0."""
    host = "host:linux-fixture"
    cap = "capability:uoe.text.normalize@1"
    provider = "provider:uoe.reference-v1"
    artifact = "artifact:uoe.elf-client"
    nodes = [
        {"id": artifact, "kind": "artifact"},
        {"id": cap, "kind": "capability"},
        {"id": provider, "kind": "provider"},
        {"id": host, "kind": "host"},
    ]
    relations = [
        ("requires", artifact, cap, "inspection", "observed"),
        ("provides", provider, cap, "test", "tested"),
        ("available_on", provider, host, "test", "tested"),
    ]
    edges = []
    for i, (relation, source, target, evidence_type, status) in enumerate(relations):
        ev_id = "evidence:fixture-" + str(i)
        ev = {
            "id": ev_id, "kind": "evidence",
            "evidence_type": evidence_type,
            "reference": "local-fixture:sha256:" + report["first"]["provider_sha256"],
            "result": "pass" if evidence_type == "test" else "not_applicable",
            "scope": {"source": source, "relationship": relation, "target": target},
        }
        nodes.append(ev)
        edges.append({
            "id": "edge:fixture-" + str(i), "source": source,
            "relationship": relation, "target": target,
            "status": status, "evidence": [ev_id],
        })
    return {"schema_version": "0.1.0", "nodes": nodes, "edges": edges}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, help="Optional JSON report filename")
    args = parser.parse_args()
    if sys.platform != "linux":
        parser.error("this initial fixture only supports Linux")
    with tempfile.TemporaryDirectory(prefix="uoe-fixture-") as temp:
        base = Path(temp)
        first = run_round(base / "first")
        second = run_round(base / "clean-rebuild")

    report = {
        "experiment": "uoe-missing-capability-native-elf-v0",
        "status": "passed",
        "scope": "project-owned native Linux ELF / shared-library contract",
        "host": {"os": platform.system(), "arch": platform.machine()},
        "first": first,
        "clean_rebuild": {
            "success": True,
            "same_test_count": first["contract_assertions"] == second["contract_assertions"],
            "contract_assertions": second["contract_assertions"],
        },
        "limits": [
            "No AI produced the provider; it is a known reference implementation.",
            "Independent rebuild directories are not independent machines.",
            "No Windows/macOS compatibility or universal execution is shown.",
            "Running this fixture is not a sandbox for untrusted code.",
            "Fixture-derived evidence is not cryptographically authenticated.",
        ],
    }
    expect(report["clean_rebuild"]["same_test_count"], "rebuild assertion mismatch")
    graph = produce_graph(report)
    graph_root = ROOT.parent / "capability-graph"
    sys.path.insert(0, str(graph_root))
    from uoe_graph.__main__ import plan, validate  # pylint: disable=import-outside-toplevel
    validate(graph)
    candidate_plan = plan(graph, "artifact:uoe.elf-client", "host:linux-fixture")
    expect(candidate_plan["requirements"][0]["state"] == "test_backed_candidate",
           "verified fixture not represented in graph")
    report["graph_plan_state"] = candidate_plan["requirements"][0]["state"]
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    print(json.dumps(report, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
