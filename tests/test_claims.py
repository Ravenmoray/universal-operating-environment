"""Evidence-bound v0.2 tests. All test binaries are synthetic, never executed."""
from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
import unittest

from uoe.claims import ClaimError, load_claims, plan_capabilities
from uoe.graph import GraphError
from uoe.inspector import inspect_file


def example():
    file_data = bytearray(64)
    file_data[0:4] = b"\x7fELF"
    file_data[4] = 2
    file_data[5] = 1
    file_data[6] = 1
    struct.pack_into("<HHI", file_data, 16, 2, 62, 1)
    struct.pack_into("<H", file_data, 52, 64)
    content = bytes(file_data)
    digest = hashlib.sha256(content).hexdigest()
    capability = "capability:example.hello@1"
    artifact = "artifact:example-elf"
    provider = "provider:illustrative-only"
    host = "host:fictional-linux"
    relation_specs = [
        ("edge:requires", "requires", artifact, capability, "documented",
         "evidence:source", "specification", "not_applicable"),
        ("edge:provides", "provides", provider, capability, "tested",
         "evidence:test-provider", "test", "pass"),
        ("edge:host", "available_on", provider, host, "tested",
         "evidence:test-host", "test", "pass"),
    ]
    nodes = [
        {"id": artifact, "kind": "artifact"},
        {"id": capability, "kind": "capability"},
        {"id": provider, "kind": "provider"},
        {"id": host, "kind": "host"},
        {"id": "host:second", "kind": "host"},
    ]
    edges = []
    for ident, relation, source, target, status, eid, ev_type, outcome in relation_specs:
        nodes.append({
            "id": eid, "kind": "evidence",
            "evidence_type": ev_type,
            "result": outcome,
            "reference": "synthetic:testing-only",
            "scope": {"source": source, "relationship": relation, "target": target}
        })
        edges.append({
            "id": ident, "source": source, "target": target,
            "relationship": relation, "status": status, "evidence": [eid]
        })
    graph = {"schema_version": "0.1.0", "nodes": nodes, "edges": edges}
    claims = {
        "schema_version": "uoe.claims.v0.2",
        "artifact_id": artifact,
        "artifact_sha256": digest,
        "provenance": {"kind": "operator_declaration", "reference": "synthetic:test"},
        "requirements": [{"capability": capability,
                          "requirement_edge": "edge:requires",
                          "status": "documented"}]
    }
    return content, graph, claims


class ClaimsTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.tmp = Path(self.directory.name)
        data, self.graph, self.claims = example()
        self.artifact = self.tmp / "demo.elf"
        self.artifact.write_bytes(data)
        self.inspection = inspect_file(self.artifact)
        self.claims_path = self.tmp / "claims.json"
        self.graph_path = self.tmp / "graph.json"
        self.persist()

    def persist(self):
        self.claims_path.write_text(json.dumps(self.claims), encoding="utf-8")
        self.graph_path.write_text(json.dumps(self.graph), encoding="utf-8")

    def evaluate(self, host="host:fictional-linux"):
        return plan_capabilities(self.inspection, self.claims, self.graph, host)

    def test_valid_bind_and_traced_evidence(self):
        result = self.evaluate()
        self.assertEqual(result["status"], "all_requirements_have_candidates")
        row = result["requirements"][0]
        self.assertEqual(row["state"], "test_backed_candidate")
        self.assertEqual(row["requirement_status"], "documented")
        self.assertEqual(row["requirement_evidence"][0]["id"], "evidence:source")
        self.assertEqual(row["candidates"][0]["provider"], "provider:illustrative-only")
        self.assertEqual(len(row["candidates"][0]["edge_evidence"]), 2)
        self.assertFalse(result["evidence_authenticated"])
        self.assertFalse(result["host_identity_attested"])
        self.assertFalse(result["execution_attempted"])

    def test_digest_binding_fails_closed_on_mutation(self):
        self.artifact.write_bytes(self.artifact.read_bytes() + b"\x00")
        scan = inspect_file(self.artifact)
        with self.assertRaisesRegex(ClaimError, "SHA-256 mismatch"):
            plan_capabilities(scan, self.claims, self.graph, "host:fictional-linux")

    def test_altered_digest_rejected(self):
        self.claims["artifact_sha256"] = "f" * 64
        with self.assertRaisesRegex(ClaimError, "SHA-256 mismatch"):
            self.evaluate()

    def test_uppercase_digest_rejected(self):
        self.claims["artifact_sha256"] = self.claims["artifact_sha256"].upper()
        with self.assertRaises(ClaimError):
            self.evaluate()

    def test_mismatched_edge_id_rejected(self):
        self.claims["requirements"][0]["requirement_edge"] = "edge:fiction"
        with self.assertRaisesRegex(ClaimError, "exactly match"):
            self.evaluate()

    def test_mismatched_requirement_state_rejected(self):
        self.claims["requirements"][0]["status"] = "observed"
        with self.assertRaisesRegex(ClaimError, "disagrees"):
            self.evaluate()

    def test_requirement_cannot_claim_tested_without_test(self):
        self.claims["requirements"][0]["status"] = "tested"
        with self.assertRaisesRegex(ClaimError, "requirement status"):
            self.evaluate()

    def test_rejected_host_connection_is_unresolved(self):
        self.graph["edges"][2]["status"] = "rejected"
        r = self.evaluate()
        self.assertEqual(r["status"], "unresolved")
        self.assertEqual(r["unresolved_capabilities"], ["capability:example.hello@1"])

    def test_another_host_does_not_inherit_tests(self):
        r = self.evaluate("host:second")
        self.assertEqual(r["status"], "unresolved")
        self.assertFalse(r["host_identity_attested"])

    def test_nonexistent_host_fails(self):
        with self.assertRaises(ClaimError):
            self.evaluate("host:made-up")

    def test_forged_test_edge_fails(self):
        for node in self.graph["nodes"]:
            if node["id"] == "evidence:test-provider":
                node["evidence_type"] = "model_hypothesis"
        with self.assertRaises(GraphError):
            self.evaluate()

    def test_duplicate_claims_rejected(self):
        self.claims["requirements"].append(copy.deepcopy(self.claims["requirements"][0]))
        with self.assertRaisesRegex(ClaimError, "duplicate capability"):
            self.evaluate()

    def test_claims_and_graph_disagreement_rejected(self):
        self.claims["requirements"] = []
        with self.assertRaisesRegex(ClaimError, "exactly match"):
            self.evaluate()

    def test_empty_requirements_are_not_assumed_safe(self):
        self.claims["requirements"] = []
        self.graph["edges"] = [e for e in self.graph["edges"] if e["relationship"] != "requires"]
        r = self.evaluate()
        self.assertEqual(r["status"], "no_requirements_declared")
        self.assertEqual(r["requirements"], [])

    def test_invalid_json_and_oversized_claims_rejected(self):
        self.claims_path.write_text("not-json", encoding="utf-8")
        with self.assertRaises(ValueError):
            load_claims(self.claims_path, self.inspection["artifact"]["sha256"])
        self.claims_path.write_bytes(b" " * (1_000_001))
        with self.assertRaisesRegex(ClaimError, "exceeds"):
            load_claims(self.claims_path, self.inspection["artifact"]["sha256"])

    def test_planner_size_limit_is_explicit(self):
        # Internally valid parallel provider claims that exceed the v0.2
        # bound must be rejected rather than consuming unbounded resources.
        original = copy.deepcopy(self.graph["edges"][1])
        for i in range(256):
            extra = copy.deepcopy(original)
            extra["id"] = "edge:additional-" + str(i)
            self.graph["edges"].append(extra)
        with self.assertRaisesRegex(ClaimError, "planning limits"):
            self.evaluate()

    def test_order_invariance(self):
        baseline = self.evaluate()
        self.graph["nodes"].reverse()
        self.graph["edges"].reverse()
        self.assertEqual(self.evaluate(), baseline)

    def test_cli_without_claims_preserves_v01_behavior(self):
        p = subprocess.run([sys.executable, "-m", "uoe", "plan", str(self.artifact)],
                           capture_output=True, text=True, check=False)
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertNotIn("capability_graph", json.loads(p.stdout))

    def test_cli_json_with_claims(self):
        self.persist()
        p = subprocess.run([
            sys.executable, "-m", "uoe", "plan", str(self.artifact),
            "--claims", str(self.claims_path), "--graph", str(self.graph_path),
            "--host-id", "host:fictional-linux"
        ], capture_output=True, text=True, check=False)
        self.assertEqual(p.returncode, 0, p.stderr)
        output = json.loads(p.stdout)["capability_graph"]
        self.assertEqual(output["status"], "all_requirements_have_candidates")
        self.assertFalse(output["evidence_authenticated"])

    def test_cli_requires_all_inputs(self):
        p = subprocess.run([sys.executable, "-m", "uoe", "plan", str(self.artifact),
                            "--claims", str(self.claims_path)],
                           capture_output=True, text=True)
        self.assertNotEqual(p.returncode, 0)
        self.assertIn("--claims, --graph and --host-id", p.stderr)

    def test_cli_rejects_stale_claims(self):
        self.persist()
        self.artifact.write_bytes(self.artifact.read_bytes() + b"x")
        p = subprocess.run([
            sys.executable, "-m", "uoe", "plan", str(self.artifact),
            "--claims", str(self.claims_path), "--graph", str(self.graph_path),
            "--host-id", "host:fictional-linux"
        ], capture_output=True, text=True)
        self.assertEqual(p.returncode, 2)
        self.assertIn("SHA-256 mismatch", p.stderr)


if __name__ == "__main__":
    unittest.main()
