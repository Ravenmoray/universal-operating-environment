"""Data-only v0.5 proposal tests: no artifact execution or controller integration."""
import copy
import importlib.util
import json
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
EXPERIMENT = ROOT / "experiments" / "authorization-contract"
spec = importlib.util.spec_from_file_location("authorization_model", EXPERIMENT / "model.py")
model = importlib.util.module_from_spec(spec)
spec.loader.exec_module(model)


class AuthorizationContractTests(unittest.TestCase):
    def setUp(self):
        self.case = json.loads((EXPERIMENT / "example.json").read_text())

    def decision(self, case=None):
        c = self.case if case is None else case
        return model.evaluate(c["request"], c["approval"], c["context"], c["now"])

    def test_positive_control_is_only_eligibility_and_never_executes(self):
        self.assertEqual(self.decision(), {"decision": "eligible", "reason": "matched",
                                          "execution_attempted": False})

    def test_each_bound_request_field_requires_new_approval(self):
        changes = {"request_id": "request:other", "artifact_sha256": "f" * 64,
                   "adapter_sha256": "f" * 64, "image_sha256": "f" * 64,
                   "host_snapshot_sha256": "f" * 64, "policy_revision": "policy:other",
                   "argv": ["different", "argument"],
                   "limits": dict(self.case["request"]["limits"], pids=2)}
        for key, value in changes.items():
            with self.subTest(key=key):
                c = copy.deepcopy(self.case)
                c["request"][key] = value
                self.assertEqual(self.decision(c)["reason"], "subject_mismatch")

    def test_untrusted_extra_fields_cannot_grant_authority(self):
        for field in ("model_recommends", "confidence", "approved", "shell", "environment"):
            with self.subTest(field=field):
                c = copy.deepcopy(self.case)
                c["request"][field] = True
                self.assertEqual(self.decision(c)["reason"], "invalid_request")

    def test_every_field_is_required_and_unknown_fields_fail_closed(self):
        for section in ("request", "approval", "context"):
            for field in self.case[section]:
                with self.subTest(section=section, field=field):
                    c = copy.deepcopy(self.case)
                    del c[section][field]
                    self.assertEqual(self.decision(c)["decision"], "deny")
            c = copy.deepcopy(self.case)
            c[section]["extension"] = "unknown"
            self.assertEqual(self.decision(c)["decision"], "deny")

    def test_trusted_denials_override_a_matching_approval(self):
        for field, value, reason in (
            ("approval_authenticated", False, "unauthenticated_approval"),
            ("approval_revoked", True, "revoked_approval"),
            ("approval_consumed", True, "consumed_approval"),
            ("isolation_ready", False, "isolation_unavailable"),
            ("policy_revision", "policy:new", "policy_changed"),
            ("host_snapshot_sha256", "e" * 64, "host_changed"),
        ):
            with self.subTest(field=field):
                c = copy.deepcopy(self.case)
                c["context"][field] = value
                self.assertEqual(self.decision(c)["reason"], reason)

    def test_approval_window_boundaries_and_invalid_time_types(self):
        for now, decision in ((99, "deny"), (100, "eligible"), (199, "eligible"),
                              (200, "deny"), (201, "deny"), (True, "deny"),
                              (100.0, "deny"), (-1, "deny")):
            with self.subTest(now=now):
                c = copy.deepcopy(self.case)
                c["now"] = now
                self.assertEqual(self.decision(c)["decision"], decision)
        for field in ("issued_at", "expires_at"):
            for value in (True, 100.0, -1, 100):
                c = copy.deepcopy(self.case)
                c["approval"][field] = value
                if field == "issued_at" and value == 100 and type(value) is int:
                    continue
                self.assertEqual(self.decision(c)["decision"], "deny")

    def test_resource_limits_are_bounded_positive_integers(self):
        for key, cap in model.LIMITS.items():
            for value in (0, -1, True, 1.0, "1", cap + 1, None):
                with self.subTest(key=key, value=value):
                    c = copy.deepcopy(self.case)
                    c["request"]["limits"][key] = value
                    self.assertEqual(self.decision(c)["reason"], "invalid_request")
            for value in (1, cap):
                c = copy.deepcopy(self.case)
                c["request"]["limits"][key] = value
                c["approval"]["subject"] = copy.deepcopy(c["request"])
                self.assertEqual(self.decision(c)["decision"], "eligible")

    def test_dangerous_rights_are_unsupported_even_if_approved(self):
        for field, value in (("network", "internet"), ("host_mounts", ["/"]),
                             ("secrets", ["token"]), ("devices", ["gpu"]),
                             ("privileged", True), ("privileged", 0)):
            c = copy.deepcopy(self.case)
            c["request"]["rights"][field] = value
            c["approval"]["subject"] = copy.deepcopy(c["request"])
            self.assertEqual(self.decision(c)["reason"], "invalid_request")

    def test_malformed_json_values_fail_closed(self):
        for section in ("request", "approval", "context"):
            for value in (None, [], "yes", True, 1):
                c = copy.deepcopy(self.case)
                c[section] = value
                self.assertEqual(self.decision(c)["decision"], "deny")
        for key, value in (("schema_version", "future"), ("artifact_sha256", "A" * 64),
                           ("request_id", "x" * 129), ("argv", "shell command"),
                           ("argv", ["x"] * 33), ("argv", ["x" * 1025]),
                           ("argv", ["nul\x00byte"]), ("argv", [None]),
                           ("limits", []), ("rights", [])):
            c = copy.deepcopy(self.case)
            c["request"][key] = value
            self.assertEqual(self.decision(c)["reason"], "invalid_request")

    def test_context_flags_cannot_be_truthy_strings_or_numbers(self):
        for field in ("approval_authenticated", "approval_revoked", "approval_consumed",
                      "isolation_ready"):
            for value in (1, 0, "true", "false", None, []):
                with self.subTest(field=field, value=value):
                    c = copy.deepcopy(self.case)
                    c["context"][field] = value
                    self.assertEqual(self.decision(c)["reason"], "invalid_context")

    def test_invalid_approval_subject_and_nested_fields_deny(self):
        for field in ("limits", "rights"):
            for key in self.case["request"][field]:
                c = copy.deepcopy(self.case)
                del c["request"][field][key]
                self.assertEqual(self.decision(c)["reason"], "invalid_request")
            c = copy.deepcopy(self.case)
            c["request"][field]["unknown"] = False
            self.assertEqual(self.decision(c)["reason"], "invalid_request")
        for value in (None, {}, [], {"approved": True}):
            c = copy.deepcopy(self.case)
            c["approval"]["subject"] = value
            self.assertEqual(self.decision(c)["reason"], "invalid_approval")
        c = copy.deepcopy(self.case)
        c["approval"]["approval_id"] = ""
        self.assertEqual(self.decision(c)["reason"], "invalid_approval")

    def test_argument_order_is_bound_and_denial_precedence_is_stable(self):
        self.case["request"]["argv"] = ["one", "two"]
        self.case["approval"]["subject"] = copy.deepcopy(self.case["request"])
        self.assertEqual(self.decision()["decision"], "eligible")
        self.case["request"]["argv"].reverse()
        self.assertEqual(self.decision()["reason"], "subject_mismatch")
        self.case["context"]["approval_revoked"] = True
        self.case["context"]["approval_consumed"] = True
        self.assertEqual(self.decision()["reason"], "revoked_approval")
        self.case["context"]["approval_authenticated"] = False
        self.assertEqual(self.decision()["reason"], "unauthenticated_approval")

    def test_order_independence_repeatability_and_no_input_mutation(self):
        before = copy.deepcopy(self.case)
        def reverse(value):
            if isinstance(value, dict):
                return {k: reverse(v) for k, v in reversed(list(value.items()))}
            if isinstance(value, list):
                return [reverse(v) for v in value]
            return value
        self.assertEqual(self.decision(), self.decision(reverse(self.case)))
        self.assertEqual(self.decision(), self.decision())
        self.assertEqual(self.case, before)


if __name__ == "__main__":
    unittest.main()
