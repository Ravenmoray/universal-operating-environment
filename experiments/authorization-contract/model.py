"""Draft, data-only authorization predicate. Not an executor or security boundary.

Inputs are already decoded Python JSON values; trusted context is supplied by a
hypothetical controller, NEVER copied from a request or model response.
"""
import re

VERSION = "uoe.authorization-request.v0"
DIGEST = re.compile(r"[0-9a-f]{64}")
IDENTIFIER = re.compile(r"[A-Za-z0-9._:-]{1,128}")
LIMITS = {"cpu_ms": 60_000, "wall_ms": 60_000, "memory_bytes": 1_073_741_824,
          "disk_bytes": 1_073_741_824, "pids": 16}
RIGHTS = {"network": "none", "host_mounts": [], "secrets": [], "devices": [],
          "privileged": False}
REQUEST_KEYS = {"schema_version", "request_id", "artifact_sha256", "adapter_sha256",
                "image_sha256", "host_snapshot_sha256", "policy_revision", "argv",
                "limits", "rights"}
APPROVAL_KEYS = {"approval_id", "subject", "issued_at", "expires_at"}
CONTEXT_KEYS = {"approval_authenticated", "approval_revoked", "approval_consumed",
                "isolation_ready", "host_snapshot_sha256", "policy_revision"}


def exact_keys(value, keys):
    return type(value) is dict and value.keys() == set(keys)


def identifier(value):
    return type(value) is str and IDENTIFIER.fullmatch(value) is not None


def digest(value):
    return type(value) is str and DIGEST.fullmatch(value) is not None


def valid_request(value):
    if not exact_keys(value, REQUEST_KEYS) or value["schema_version"] != VERSION:
        return False
    if not all(identifier(value[k]) for k in ("request_id", "policy_revision")):
        return False
    if not all(digest(value[k]) for k in ("artifact_sha256", "adapter_sha256",
                                        "image_sha256", "host_snapshot_sha256")):
        return False
    argv = value["argv"]
    if type(argv) is not list or len(argv) > 32 or not all(
        type(arg) is str and len(arg) <= 1024 and "\x00" not in arg for arg in argv
    ):
        return False
    limits = value["limits"]
    if not exact_keys(limits, LIMITS) or not all(
        type(limits[k]) is int and 0 < limits[k] <= cap for k, cap in LIMITS.items()
    ):
        return False
    rights = value["rights"]
    return (exact_keys(rights, RIGHTS) and rights == RIGHTS
            and rights["privileged"] is False
            and all(type(rights[k]) is list for k in ("host_mounts", "secrets", "devices")))


def evaluate(request, approval, context, now):
    """Return a deterministic decision without reading clocks, files or services.

    The positive result is only eligibility for a future controller's atomic
    consume-and-start operation. It cannot be used as a reusable launch permit.
    """
    def result(reason):
        return {"decision": "eligible" if reason == "matched" else "deny",
                "reason": reason, "execution_attempted": False}

    if not valid_request(request):
        return result("invalid_request")
    if (not exact_keys(context, CONTEXT_KEYS) or type(now) is not int or now < 0
            or not digest(context["host_snapshot_sha256"])
            or not identifier(context["policy_revision"])
            or not all(type(context[k]) is bool for k in (
                "approval_authenticated", "approval_revoked", "approval_consumed", "isolation_ready"))):
        return result("invalid_context")
    if (not exact_keys(approval, APPROVAL_KEYS) or not identifier(approval["approval_id"])
            or not valid_request(approval["subject"])
            or any(type(approval[k]) is not int for k in ("issued_at", "expires_at"))
            or not 0 <= approval["issued_at"] < approval["expires_at"]):
        return result("invalid_approval")
    if not context["approval_authenticated"]:
        return result("unauthenticated_approval")
    if context["approval_revoked"]:
        return result("revoked_approval")
    if context["approval_consumed"]:
        return result("consumed_approval")
    if not approval["issued_at"] <= now < approval["expires_at"]:
        return result("outside_approval_window")
    if request != approval["subject"]:
        return result("subject_mismatch")
    if request["policy_revision"] != context["policy_revision"]:
        return result("policy_changed")
    if request["host_snapshot_sha256"] != context["host_snapshot_sha256"]:
        return result("host_changed")
    if not context["isolation_ready"]:
        return result("isolation_unavailable")
    return result("matched")
