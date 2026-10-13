"""Shared experimental graph validator and static planner.

Temporary reuse of the v0.1 graph implementation. Version 1 should converge
all graph contracts on a single schema and package.
"""
"""Read-only, evidence-bound capability graph experiment.

This does not inspect or execute binaries and cannot establish real-world
software compatibility. Evidence in user-supplied JSON is not authenticated.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

NODE_KINDS = {"artifact", "capability", "provider", "host", "evidence"}
RELATIONS = {
    "requires": ("artifact", "capability"),
    "provides": ("provider", "capability"),
    "available_on": ("provider", "host"),
}
STATUSES = {"inferred", "documented", "observed", "tested", "rejected"}
EVIDENCE_TYPES = {
    "inspection", "specification", "test", "model_hypothesis", "operator_claim"
}
RESULTS = {"pass", "fail", "not_applicable"}
MAX_BYTES = 1_000_000
MAX_OBJECTS = 10_000


class GraphError(ValueError):
    """An invalid or internally inconsistent experimental graph."""


def _nonempty(value):
    return isinstance(value, str) and bool(value.strip())


def _fail(message):
    raise GraphError(message)


def validate(graph):
    """Validate a proposed graph, returning nodes indexed by ID.

    Internal consistency only: this does not authenticate tests or evidence.
    """
    if not isinstance(graph, dict) or set(graph) != {"schema_version", "nodes", "edges"}:
        _fail("graph must contain only schema_version, nodes and edges")
    if graph["schema_version"] != "0.1.0":
        _fail("unsupported schema version")
    if not isinstance(graph["nodes"], list) or not isinstance(graph["edges"], list):
        _fail("nodes and edges must be lists")
    if len(graph["nodes"]) > MAX_OBJECTS or len(graph["edges"]) > MAX_OBJECTS:
        _fail("graph exceeds experimental limits")

    nodes = {}
    for node in graph["nodes"]:
        if not isinstance(node, dict):
            _fail("node must be an object")
        ident, kind = node.get("id"), node.get("kind")
        if not _nonempty(ident) or not isinstance(kind, str) or kind not in NODE_KINDS:
            _fail("invalid node identity or kind")
        if ident in nodes:
            _fail("duplicate node ID: " + ident)
        if "label" in node and not isinstance(node["label"], str):
            _fail("node label must be string")
        if kind == "evidence":
            if set(node) - {"id", "kind", "label", "evidence_type", "reference", "result", "scope"}:
                _fail("unknown evidence field")
            if not isinstance(node.get("evidence_type"), str) or node["evidence_type"] not in EVIDENCE_TYPES:
                _fail("invalid evidence type")
            if (not isinstance(node.get("result"), str) or node["result"] not in RESULTS
                    or not _nonempty(node.get("reference"))):
                _fail("invalid evidence result/reference")
            scope = node.get("scope")
            if not isinstance(scope, dict) or set(scope) != {"source", "relationship", "target"}:
                _fail("invalid evidence scope")
            if (not _nonempty(scope["source"]) or not _nonempty(scope["target"])
                    or not isinstance(scope["relationship"], str)
                    or scope["relationship"] not in RELATIONS):
                _fail("invalid evidence scope triple")
        elif set(node) - {"id", "kind", "label"}:
            _fail("unexpected fields on non-evidence node")
        nodes[ident] = node

    edges_seen = set()
    for edge in graph["edges"]:
        if not isinstance(edge, dict) or set(edge) != {
            "id", "source", "relationship", "target", "status", "evidence"
        }:
            _fail("invalid edge fields")
        ident = edge["id"]
        if not _nonempty(ident) or ident in edges_seen or ident in nodes:
            _fail("duplicate or invalid edge ID")
        edges_seen.add(ident)
        relationship = edge["relationship"]
        if (not isinstance(relationship, str) or relationship not in RELATIONS
                or not isinstance(edge["status"], str) or edge["status"] not in STATUSES):
            _fail("invalid edge relation/status")
        source, target = edge["source"], edge["target"]
        if not _nonempty(source) or not _nonempty(target) or source not in nodes or target not in nodes:
            _fail("dangling edge")
        wanted_source, wanted_target = RELATIONS[relationship]
        if nodes[source]["kind"] != wanted_source or nodes[target]["kind"] != wanted_target:
            _fail("invalid edge node kinds")
        references = edge["evidence"]
        if (not isinstance(references, list) or not references
                or any(not _nonempty(r) for r in references)
                or len(references) != len(set(references))):
            _fail("invalid edge evidence references")
        matching_pass = False
        for evidence_id in references:
            ev = nodes.get(evidence_id)
            if ev is None or ev["kind"] != "evidence":
                _fail("missing evidence node")
            if ev["scope"] != {"source": source, "relationship": relationship, "target": target}:
                _fail("evidence scope does not match edge")
            if ev["evidence_type"] == "test" and ev["result"] == "pass":
                matching_pass = True
        if edge["status"] == "tested" and not matching_pass:
            _fail("tested claim lacks matching passing test evidence")
    return nodes


def plan(graph, artifact_id, host_id):
    """Return static candidates, never execution permission or compatibility proof."""
    nodes = validate(graph)
    if not _nonempty(artifact_id) or nodes.get(artifact_id, {}).get("kind") != "artifact":
        _fail("unknown artifact")
    if not _nonempty(host_id) or nodes.get(host_id, {}).get("kind") != "host":
        _fail("unknown host")

    edges = graph["edges"]
    required = sorted((e for e in edges if e["relationship"] == "requires"
                       and e["source"] == artifact_id and e["status"] != "rejected"),
                      key=lambda x: (x["target"], x["id"]))
    results = []
    for req in required:
        candidates = []
        for provided in edges:
            if not (provided["relationship"] == "provides"
                    and provided["target"] == req["target"]
                    and provided["status"] != "rejected"):
                continue
            for hosted in edges:
                if not (hosted["relationship"] == "available_on"
                        and hosted["source"] == provided["source"]
                        and hosted["target"] == host_id
                        and hosted["status"] != "rejected"):
                    continue
                is_test_backed = provided["status"] == hosted["status"] == "tested"
                candidates.append({
                    "provider": provided["source"],
                    "assessment": "test_backed_candidate" if is_test_backed
                                  else "unverified_candidate",
                    "evidence_edges": sorted([provided["id"], hosted["id"]])
                })
        candidates.sort(key=lambda c: (
            c["assessment"] != "test_backed_candidate",
            c["provider"],
            c["evidence_edges"]
        ))
        # Collapse duplicate provider candidates, preferring a test-backed path.
        seen = set()
        unique = []
        for item in candidates:
            if item["provider"] not in seen:
                seen.add(item["provider"])
                unique.append(item)
        results.append({
            "capability": req["target"],
            "requirement_status": req["status"],
            "state": ("unresolved" if not unique else unique[0]["assessment"]),
            "candidates": unique
        })
    return {
        "schema_version": "0.1.0",
        "artifact": artifact_id,
        "host": host_id,
        "requirements": results,
        "notice": "Static research candidates only; no execution or compatibility guarantee."
    }


def load_graph(path):
    candidate = Path(path)
    if candidate.stat().st_size > MAX_BYTES:
        _fail("file exceeds experimental byte limit")
    graph = json.loads(candidate.read_text(encoding="utf-8"))
    validate(graph)
    return graph


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("validate").add_argument("path")
    planner = commands.add_parser("plan")
    planner.add_argument("path")
    planner.add_argument("--artifact", required=True)
    planner.add_argument("--host", required=True)
    args = parser.parse_args(argv)
    try:
        graph = load_graph(args.path)
        result = {"valid": True, "schema_version": graph["schema_version"]}
        if args.command == "plan":
            result = plan(graph, args.artifact, args.host)
        print(json.dumps(result, sort_keys=True, indent=2))
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        parser.exit(2, f"graph error: {exc}\n")


if __name__ == "__main__":
    main()
