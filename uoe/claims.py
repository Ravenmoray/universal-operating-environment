"""Digest-bound declarations joined with an evidence-scoped capability graph.

No trust is inferred from a caller-supplied JSON file: signatures, identities,
and actual host attestations are deliberately NOT verified in v0.2.
"""
from __future__ import annotations

import json
from pathlib import Path
import re

from .graph import GraphError, load_graph, plan as graph_plan, validate as validate_graph

CLAIMS_VERSION = "uoe.claims.v0.2"
VALID_REQUIREMENT_STATES = {"documented", "observed", "inferred"}
SHA256 = re.compile(r"^[0-9a-f]{64}$")
MAX_CLAIMS_BYTES = 1_000_000
MAX_REQUIREMENTS = 64
MAX_GRAPH_NODES = 512
MAX_GRAPH_EDGES = 256


class ClaimError(ValueError):
    """Invalid, contradictory or inapplicable claimed requirements."""


def _fail(message):
    raise ClaimError(message)


def _nonempty(s):
    return isinstance(s, str) and bool(s.strip())


def validate_claims(claims: dict, actual_digest: str) -> None:
    """Validate declarative input and bind it to inspected file content."""
    if not isinstance(claims, dict) or set(claims) != {
        "schema_version", "artifact_id", "artifact_sha256", "provenance", "requirements"
    }:
        _fail("claims must contain exactly schema_version, artifact_id, "
              "artifact_sha256, provenance, requirements")
    if claims["schema_version"] != CLAIMS_VERSION:
        _fail("unsupported claims version")
    if not _nonempty(claims["artifact_id"]):
        _fail("invalid artifact identity")
    digest = claims["artifact_sha256"]
    if not isinstance(digest, str) or SHA256.fullmatch(digest) is None:
        _fail("claims artifact_sha256 must be lowercase 64-char hex")
    if digest != actual_digest:
        _fail("artifact SHA-256 mismatch: declarations do not match supplied file")
    provenance = claims["provenance"]
    if (not isinstance(provenance, dict)
            or set(provenance) != {"kind", "reference"}
            or provenance["kind"] not in ("operator_declaration", "source_document", "test_report")
            or not _nonempty(provenance["reference"])):
        _fail("invalid declaration provenance")
    rows = claims["requirements"]
    if not isinstance(rows, list) or len(rows) > MAX_REQUIREMENTS:
        _fail("requirements must be a bounded list")
    seen = set()
    for row in rows:
        if not isinstance(row, dict) or set(row) != {
            "capability", "requirement_edge", "status"
        }:
            _fail("invalid declared requirement fields")
        cap, edge, status = row["capability"], row["requirement_edge"], row["status"]
        if not _nonempty(cap) or not _nonempty(edge) or not isinstance(status, str):
            _fail("invalid declared requirement")
        if status not in VALID_REQUIREMENT_STATES:
            _fail("requirement status must be documented, observed or inferred")
        if cap in seen:
            _fail("duplicate capability requirement: " + cap)
        seen.add(cap)


def load_claims(path: str | Path, actual_digest: str) -> dict:
    path = Path(path)
    if path.stat().st_size > MAX_CLAIMS_BYTES:
        _fail("claims file exceeds 1 MiB")
    content = json.loads(path.read_text(encoding="utf-8"))
    validate_claims(content, actual_digest)
    return content


def plan_capabilities(inspection: dict, claims: dict, graph: dict,
                      host_id: str) -> dict:
    """Join one immutable artifact declaration to graph's exact host candidates.

    A graph might be internally consistent but maliciously fabricated, including
    its 'passing tests'. This operation cannot authenticate external evidence.
    """
    validate_claims(claims, inspection["artifact"]["sha256"])
    if not _nonempty(host_id):
        _fail("host_id is required")
    validate_graph(graph)
    # v0.2 deliberately limits in-memory untrusted graph size; this is not
    # a substitute for a dedicated isolated parser or a scalability review.
    if (len(graph["nodes"]) > MAX_GRAPH_NODES or
            len(graph["edges"]) > MAX_GRAPH_EDGES):
        _fail("experimental graph exceeds v0.2 planning limits")

    artifact = claims["artifact_id"]
    nodes = {n["id"]: n for n in graph["nodes"]}
    if artifact not in nodes or nodes[artifact]["kind"] != "artifact":
        _fail("graph does not contain declared artifact node")

    graph_edges = [
        edge for edge in graph["edges"]
        if edge["relationship"] == "requires"
        and edge["source"] == artifact
        and edge["status"] != "rejected"
    ]
    graph_edges_by_id = {edge["id"]: edge for edge in graph_edges}
    all_edges_by_id = {edge["id"]: edge for edge in graph["edges"]}
    if len({edge["target"] for edge in graph_edges}) != len(graph_edges):
        _fail("graph contains ambiguous duplicate capability requirements")

    rows = claims["requirements"]
    if {row["requirement_edge"] for row in rows} != set(graph_edges_by_id):
        _fail("declared requirements do not exactly match active graph requirement edges")
    for row in rows:
        edge = graph_edges_by_id[row["requirement_edge"]]
        if (row["capability"] != edge["target"] or
                row["status"] != edge["status"]):
            _fail("declared requirement disagrees with graph relation or evidence state")

    try:
        graph_result = graph_plan(graph, artifact, host_id)
    except GraphError as exc:
        raise ClaimError(str(exc)) from exc
    by_cap = {r["capability"]: r for r in graph_result["requirements"]}
    output = []
    for row in sorted(rows, key=lambda item: item["capability"]):
        edge = graph_edges_by_id[row["requirement_edge"]]
        evidence_nodes = [nodes[evid] for evid in edge["evidence"]]
        result = by_cap[row["capability"]]
        candidates = []
        for candidate in result["candidates"]:
            supporting_edges = [all_edges_by_id[eid] for eid in candidate["evidence_edges"]]
            candidates.append({
                **candidate,
                "edge_evidence": [
                    {
                        "edge_id": e["id"],
                        "status": e["status"],
                        "references": sorted([
                            {"id": evid, "type": nodes[evid]["evidence_type"],
                             "reference": nodes[evid]["reference"],
                             "result": nodes[evid]["result"]}
                            for evid in e["evidence"]
                        ], key=lambda x: x["id"])
                    }
                    for e in sorted(supporting_edges, key=lambda x: x["id"])
                ],
            })
        output.append({
            "capability": row["capability"],
            "requirement_status": row["status"],
            "requirement_evidence": sorted([
                {"id": ev["id"], "type": ev["evidence_type"],
                 "reference": ev["reference"], "result": ev["result"]}
                for ev in evidence_nodes
            ], key=lambda x: x["id"]),
            "state": result["state"],
            "candidates": candidates,
        })
    unresolved = [x["capability"] for x in output if x["state"] == "unresolved"]
    return {
        "schema_version": "uoe.capability-plan.v0.2",
        "artifact_id": artifact,
        "artifact_sha256": inspection["artifact"]["sha256"],
        "selected_host_id": host_id,
        "declaration_provenance": claims["provenance"],
        "status": ("unresolved" if unresolved else
                   "no_requirements_declared" if not output else
                   "all_requirements_have_candidates"),
        "unresolved_capabilities": unresolved,
        "requirements": output,
        "execution_attempted": False,
        "evidence_authenticated": False,
        "host_identity_attested": False,
        "notice": ("All graph claims and test results are supplied by the caller; "
                   "consistency checks do not authenticate evidence or the selected "
                   "host. No execution, compatibility or safety is established."),
    }
