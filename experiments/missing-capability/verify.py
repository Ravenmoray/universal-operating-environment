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
# Fixed, reviewed source file: do not treat input paths as trusted executable code.
AI_CANDIDATE = ROOT / "agent_candidate_v0.c"
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
    source_file = source if isinstance(source, Path) else SRC / source
    args += [str(source_file), "-o", str(output)]
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

    # Boundary behavior and output immutability are the main differentiators
    # between a working adapter and one that merely loads successfully.
    boundary_input = b"a" * 512
    exact_capacity = len(PREFIX) + len(boundary_input) + 1
    exactly_sized = ctypes.create_string_buffer(exact_capacity)
    expect(call(boundary_input, exactly_sized, exact_capacity) == 0
           and exactly_sized.value == PREFIX + b"A" * 512,
           "maximum accepted input or exact output capacity failed")
    count += 1

    too_small = ctypes.create_string_buffer(b"untouched", exact_capacity - 1)
    prior = too_small.raw
    expect(call(boundary_input, too_small, exact_capacity - 1) == -2
           and too_small.raw == prior,
           "one-byte-short output buffer was modified")
    count += 1

    # Test the entire 1..127 non-NUL ASCII byte range; avoid output NUL, which
    # is a C-string terminator. 128..255 are also meaningful as raw bytes.
    byte_input = bytes(range(1, 256))
    expected = PREFIX + bytes(
        code - 32 if 97 <= code <= 122 else code for code in byte_input
    )
    all_bytes = ctypes.create_string_buffer(1024)
    expect(call(byte_input, all_bytes, ctypes.sizeof(all_bytes)) == 0
           and all_bytes.value == expected,
           "non-ASCII bytes were unexpectedly changed")
    count += 1
    return count


def sha256(path: Path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def run_round(directory: Path):
    directory.mkdir(parents=True, exist_ok=True)
    client = directory / "client"
    good = directory / "libuoe_text_v1.so"
    wrong = directory / "libwrong_symbol.so"
    incorrect = directory / "libincorrect.so"
    agent = directory / "libagent_candidate_v0.so"
    compile_fixture(client, "client.c")
    compile_fixture(good, "reference_provider.c", shared=True)
    compile_fixture(wrong, "wrong_symbol_provider.c", shared=True)
    compile_fixture(incorrect, "incorrect_provider.c", shared=True)
    compile_fixture(agent, AI_CANDIDATE, shared=True)

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
    candidate_count = direct_contract_tests(agent)
    expect(candidate_count == count,
           "candidate did not pass the complete independent oracle")
    for source, expected in VECTORS:
        run = call_client(client, good, source)
        expect(run.returncode == 0 and run.stdout.rstrip(b"\n") == expected,
               "client + provider behavior failed for " + repr(source))
        count += 1
    for source, expected in VECTORS:
        trial = call_client(client, agent, source)
        expect(trial.returncode == 0
               and trial.stdout.rstrip(b"\n") == expected,
               "candidate failed end-to-end client behavior for " + repr(source))
        candidate_count += 1
    return {
        "client_sha256": sha256(client),
        "provider_sha256": sha256(good),
        "candidate_sha256": sha256(agent),
        "agent_candidate_contract_assertions": candidate_count,
        "candidate_matches_oracle": True,
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
    agent_provider = "provider:uoe.ai-candidate-v0"
    artifact = "artifact:uoe.elf-client"
    nodes = [
        {"id": artifact, "kind": "artifact"},
        {"id": cap, "kind": "capability"},
        {"id": provider, "kind": "provider"},
        {"id": agent_provider, "kind": "provider"},
        {"id": host, "kind": "host"},
    ]
    relations = [
        ("requires", artifact, cap, "specification", "documented"),
        ("provides", provider, cap, "test", "tested"),
        ("available_on", provider, host, "test", "tested"),
        ("provides", agent_provider, cap, "test", "tested"),
        ("available_on", agent_provider, host, "test", "tested"),
    ]
    edges = []
    for i, (relation, source, target, evidence_type, status) in enumerate(relations):
        ev_id = "evidence:fixture-" + str(i)
        ev = {
            "id": ev_id, "kind": "evidence",
            "evidence_type": evidence_type,
            "reference": (
                "repo-source:client.c;sha256:" + sha256(SRC / "client.c")
                if relation == "requires" else
                "local-test:verify.py;sha256:" + sha256(ROOT / "verify.py")
                + ";provider-sha256:"
                + (report["first"]["candidate_sha256"]
                   if source == agent_provider else report["first"]["provider_sha256"])
            ),
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
    parser.add_argument("--graph-output", type=Path,
                        help="Optional graph JSON for UOE v0.2 demo (unauthenticated fixture evidence)")
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
            "The reference provider is human-readable project code, not AI-generated.",
            "AI candidate was authored with public reference and test harness available; NOT blinded.",
            "This is an AI-assisted implementation test, not autonomous tool discovery or repair.",
            "Independent rebuild directories are not independent machines.",
            "No Windows/macOS compatibility or universal execution is shown.",
            "Running this fixture is not a sandbox for untrusted code.",
            "Fixture-derived evidence is not cryptographically authenticated.",
        ],
    }
    expect(report["clean_rebuild"]["same_test_count"], "rebuild assertion mismatch")
    expect(first["agent_candidate_contract_assertions"] == second["agent_candidate_contract_assertions"],
           "candidate contract count changed between builds")
    report["ai_candidate"] = {
        "author": "ChatGPT GPT-6 (AI-assisted, nonblind)",
        "source": "experiments/missing-capability/agent_candidate_v0.c",
        "source_sha256": sha256(AI_CANDIDATE),
        "passed_on_both_clean_builds": True,
        "tested_assertions_per_build": first["agent_candidate_contract_assertions"],
        "reference_source_existed_and_was_available": True,
        "evaluation_role": "demonstrate candidate evaluation process, not autonomous repair",
    }
    graph = produce_graph(report)
    graph_root = ROOT.parent / "capability-graph"
    sys.path.insert(0, str(graph_root))
    from uoe_graph.__main__ import plan, validate  # pylint: disable=import-outside-toplevel
    validate(graph)
    if args.graph_output:
        args.graph_output.parent.mkdir(parents=True, exist_ok=True)
        args.graph_output.write_text(json.dumps(graph, indent=2, sort_keys=True) + "\n",
                                     encoding="utf-8")
    candidate_plan = plan(graph, "artifact:uoe.elf-client", "host:linux-fixture")
    expect(candidate_plan["requirements"][0]["state"] == "test_backed_candidate",
           "verified fixture not represented in graph")
    report["graph_plan_state"] = candidate_plan["requirements"][0]["state"]
    candidates = candidate_plan["requirements"][0]["candidates"]
    providers = sorted(c["provider"] for c in candidates)
    expect(providers == sorted(["provider:uoe.reference-v1", "provider:uoe.ai-candidate-v0"]),
           "graph did not preserve both independently tested provider claims")
    expect(all(c["assessment"] == "test_backed_candidate" for c in candidates),
           "provider verification was incorrectly downgraded")
    report["graph_test_backed_providers"] = providers
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    print(json.dumps(report, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
