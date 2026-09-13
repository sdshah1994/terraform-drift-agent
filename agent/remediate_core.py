"""Test reference implementation of the deterministic core of agent/remediate.py.

Implements exactly what the article describes:
  1. Parse drift.json (terraform show -json) -> drifted resource_changes.
  2. Drift fingerprint = hash of the before/after attribute set.
  3. Idempotency: skip when an open PR already covers (address, fingerprint).
  4. Delete-drift -> needs-human, draft nothing.
Network calls (GitHub search, PR creation) are injected so tests run offline.
"""
import argparse
import hashlib
import json
import sys


def load_drifted_resources(plan_path):
    """Return resource_changes entries that actually drifted."""
    with open(plan_path) as fh:
        plan = json.load(fh)
    drifted = []
    for rc in plan.get("resource_changes", []):
        actions = rc.get("change", {}).get("actions", [])
        if actions == ["no-op"]:
            continue
        drifted.append(rc)
    return drifted


def drift_fingerprint(before, after):
    """Stable hash of the before/after attribute set from the plan JSON."""
    canonical = json.dumps(
        {"before": before, "after": after},
        sort_keys=True,
        separators=(",", ":"),
        default=str,  # after_unknown values etc. are JSON-safe already; be lenient
    )
    return hashlib.sha256(canonical.encode()).hexdigest()[:16]


def classify(rc):
    """Route a drifted resource: delete-drift is needs-human, never drafted."""
    actions = rc["change"]["actions"]
    if actions == ["delete"]:
        return "needs-human"
    return "candidate"


class FakeGitHub:
    """Stand-in for the GitHub API: tracks open drift PRs by (address, fingerprint)."""

    def __init__(self, open_prs=()):
        # open_prs: iterable of (address, fingerprint, pr_number)
        self.open_prs = list(open_prs)
        self.opened = []  # PRs this run "opened": (address, fingerprint)

    def find_open_pr(self, address, fingerprint):
        return next(
            (n for (a, f, n) in self.open_prs if a == address and f == fingerprint),
            None,
        )

    def open_pr(self, address, fingerprint, title, body):
        self.opened.append((address, fingerprint))
        return 900 + len(self.opened)


def triage(plan_path, github, deny_types=("aws_iam_policy", "aws_kms_key")):
    """Decide per drifted resource: draft / skip-duplicate / needs-human / denied."""
    decisions = []
    for rc in drifted_resources(plan_path):
        address = rc["address"]
        change = rc["change"]
        fp = drift_fingerprint(change.get("before"), change.get("after"))
        route = classify(rc)
        if route == "needs-human":
            decisions.append((address, "needs-human",
                              "delete drift: resource gone from reality; human must decide"))
            continue
        if rc["type"] in deny_types or "/security/" in address:
            decisions.append((address, "denied",
                              "sensitive type: detection-only, human opens the PR"))
            continue
        existing = github.find_open_pr(address, fp)
        if existing is not None:
            decisions.append((address, "skip-duplicate",
                              f"open PR #{existing} already covers fingerprint {fp}"))
            continue
        github.open_pr(address, fp, f"[drift] {address}", "drafted remediation")
        decisions.append((address, "drafted", f"opened PR for fingerprint {fp}"))
    return decisions


def drifted_resources(plan_path):
    return load_drifted_resources(plan_path)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--plan", required=True)
    args = ap.parse_args()
    gh = FakeGitHub()
    for address, decision, detail in triage(args.plan, gh):
        print(f"{decision:14} {address:45} {detail}")


if __name__ == "__main__":
    main()
