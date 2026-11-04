"""Prototype identity binding for externally-run quality checks. NOT a deployed gate."""
import re
SHA = re.compile(r"[0-9a-f]{40}\Z")
REPO = re.compile(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+\Z")

class GateRejected(ValueError):
    pass

def validate_pr_identity(event, fetched, expected_repo):
    """Fail closed if incoming event and fresh GitHub PR disagree."""
    if not isinstance(expected_repo, str) or not REPO.fullmatch(expected_repo):
        raise GateRejected("unexpected configured repository")
    if not isinstance(event, dict) or not isinstance(fetched, dict):
        raise GateRejected("malformed PR data")
    try:
        request_repo = event["repository"]["full_name"]
        request_number = event["number"]
        request_sha = event["pull_request"]["head"]["sha"]
        actual_sha = fetched["head"]["sha"]
        actual_repo = fetched["head"]["repo"]["full_name"]
        base_repo = fetched["base"]["repo"]["full_name"]
        base_ref = fetched["base"]["ref"]
    except (KeyError, TypeError) as exc:
        raise GateRejected("missing PR identity") from exc
    if (request_repo != expected_repo or actual_repo != expected_repo
            or base_repo != expected_repo or base_ref != "main"):
        raise GateRejected("unexpected PR repository or base")
    if (type(request_number) is not int or request_number < 1
            or request_number != fetched.get("number")):
        raise GateRejected("PR number mismatch")
    if (not isinstance(request_sha, str) or not SHA.fullmatch(request_sha)
            or request_sha != actual_sha):
        raise GateRejected("PR head SHA mismatch")
    if fetched.get("state") != "open" or fetched.get("draft") is not False:
        raise GateRejected("PR is not open and ready")
    return {"repository": expected_repo, "pr": request_number, "head_sha": actual_sha}
