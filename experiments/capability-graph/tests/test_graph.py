"""Tests for the static, non-executing UOE graph experiment."""
import copy
import json
import os
from pathlib import Path
import subprocess
import unittest
from unittest.mock import patch

from uoe_graph.__main__ import GraphError, load_graph, plan, validate

ROOT = Path(__file__).resolve().parents[1]
EXAMPLE = ROOT / "fixtures" / "demo.json"


class CapabilityGraphTests(unittest.TestCase):
    def setUp(self):
        self.graph = json.loads(EXAMPLE.read_text(encoding="utf-8"))

    def test_demo_is_valid(self):
        self.assertEqual(validate(self.graph)["artifact:demo"]["kind"], "artifact")
        self.assertEqual(load_graph(EXAMPLE), self.graph)

    def test_test_backed_candidate_is_not_claim_of_compatibility(self):
        result = plan(self.graph, "artifact:demo", "host:linux")
        item = result["requirements"][0]
        self.assertEqual(item["state"], "test_backed_candidate")
        self.assertEqual(item["candidates"][0]["provider"], "provider:demo-adapter")
        self.assertIn("no execution", result["notice"])

    def test_forged_test_status_does_not_pass(self):
        graph = copy.deepcopy(self.graph)
        for node in graph["nodes"]:
            if node["id"] == "evidence:provider-test":
                node["evidence_type"] = "model_hypothesis"
        with self.assertRaisesRegex(GraphError, "passing test"):
            validate(graph)

    def test_failing_test_does_not_justify_tested_status(self):
        graph = copy.deepcopy(self.graph)
        for node in graph["nodes"]:
            if node["id"] == "evidence:host-test":
                node["result"] = "fail"
        with self.assertRaisesRegex(GraphError, "passing test"):
            validate(graph)

    def test_dangling_reference_rejected(self):
        graph = copy.deepcopy(self.graph)
        graph["edges"][0]["target"] = "capability:unknown@1"
        with self.assertRaisesRegex(GraphError, "dangling"):
            validate(graph)

    def test_evidence_scope_must_match(self):
        graph = copy.deepcopy(self.graph)
        for node in graph["nodes"]:
            if node["id"] == "evidence:provider-test":
                node["scope"]["target"] = "capability:wrong@1"
        with self.assertRaisesRegex(GraphError, "scope"):
            validate(graph)

    def test_duplicate_node_id_rejected(self):
        graph = copy.deepcopy(self.graph)
        graph["nodes"].append(copy.deepcopy(graph["nodes"][0]))
        with self.assertRaisesRegex(GraphError, "duplicate node"):
            validate(graph)

    def test_rejected_provider_does_not_match(self):
        graph = copy.deepcopy(self.graph)
        for edge in graph["edges"]:
            if edge["relationship"] == "provides":
                edge["status"] = "rejected"
        result = plan(graph, "artifact:demo", "host:linux")
        self.assertEqual(result["requirements"][0]["state"], "unresolved")

    def test_unverified_candidate_not_promoted(self):
        graph = copy.deepcopy(self.graph)
        for edge in graph["edges"]:
            if edge["relationship"] == "provides":
                edge["status"] = "documented"
        result = plan(graph, "artifact:demo", "host:linux")
        self.assertEqual(result["requirements"][0]["state"], "unverified_candidate")

    def test_capability_version_is_exact_match(self):
        graph = copy.deepcopy(self.graph)
        graph["nodes"].append({"id": "capability:echo@2", "kind": "capability"})
        for edge in graph["edges"]:
            if edge["relationship"] == "requires":
                edge["target"] = "capability:echo@2"
        for node in graph["nodes"]:
            if node["id"] == "evidence:inspection1":
                node["scope"]["target"] = "capability:echo@2"
        result = plan(graph, "artifact:demo", "host:linux")
        self.assertEqual(result["requirements"][0]["state"], "unresolved")

    def test_planning_is_order_independent(self):
        original = plan(self.graph, "artifact:demo", "host:linux")
        graph = copy.deepcopy(self.graph)
        graph["nodes"].reverse()
        graph["edges"].reverse()
        self.assertEqual(plan(graph, "artifact:demo", "host:linux"), original)

    def test_planning_is_nonexecuting(self):
        with (patch.object(subprocess, "Popen", side_effect=AssertionError("execution attempted")),
              patch.object(subprocess, "run", side_effect=AssertionError("execution attempted")),
              patch.object(os, "system", side_effect=AssertionError("execution attempted"))):
            result = plan(self.graph, "artifact:demo", "host:linux")
        self.assertEqual(result["requirements"][0]["state"], "test_backed_candidate")

    def test_json_schema_agrees_on_fixture(self):
        try:
            import jsonschema
        except ImportError:
            self.skipTest("optional jsonschema dependency is not installed")
        schema = json.loads((ROOT / "schema-v0.json").read_text(encoding="utf-8"))
        jsonschema.Draft202012Validator.check_schema(schema)
        jsonschema.validate(self.graph, schema)

    def test_malformed_field_types_fail_cleanly(self):
        mutations = [
            lambda g: g["nodes"][0].update(kind=[]),
            lambda g: g["edges"][0].update(relationship=[]),
            lambda g: g["edges"][0].update(status=[]),
            lambda g: g["edges"][0].update(source=[]),
            lambda g: g["nodes"][-1]["scope"].update(relationship=[]),
        ]
        for i, mutate in enumerate(mutations):
            with self.subTest(case=i):
                graph = copy.deepcopy(self.graph)
                mutate(graph)
                with self.assertRaises(GraphError):
                    validate(graph)

    def test_nonstring_plan_identifiers_fail_cleanly(self):
        with self.assertRaises(GraphError):
            plan(self.graph, [], "host:linux")
        with self.assertRaises(GraphError):
            plan(self.graph, "artifact:demo", [])

    def test_malformed_identity_is_rejected(self):
        graph = copy.deepcopy(self.graph)
        graph["nodes"][0]["id"] = ""
        with self.assertRaises(GraphError):
            validate(graph)


if __name__ == "__main__":
    unittest.main()
