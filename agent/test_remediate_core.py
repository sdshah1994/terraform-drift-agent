"""Offline tests for the agent's deterministic core (no AWS, no API keys)."""
import json
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from remediate_core import (
    load_drifted_resources,
    drift_fingerprint,
    classify,
    triage,
    FakeGitHub,
)

PLAN = os.path.join(os.path.dirname(os.path.abspath(__file__)), "sample-drift.json")
passed = failed = 0


def check(name, cond, extra=""):
    global passed, failed
    if cond:
        passed += 1
        print(f"  PASS {name}")
    else:
        failed += 1
        print(f"  FAIL {name} {extra}")


print("== drift parsing ==")
rcs = load_drifted_resources(PLAN)
addrs = sorted(r["address"] for r in rcs)
check("finds 2 drifted resources (update + delete), skips no-op",
      addrs == ["aws_db_instance.legacy_reporting", "aws_security_group.app_alb"], addrs)

print("== fingerprint ==")
sg = next(r for r in rcs if r["address"] == "aws_security_group.app_alb")
fp1 = drift_fingerprint(sg["change"]["before"], sg["change"]["after"])
fp2 = drift_fingerprint(sg["change"]["before"], sg["change"]["after"])
check("fingerprint is deterministic", fp1 == fp2, (fp1, fp2))
mutated = json.loads(json.dumps(sg["change"]["after"]))
mutated["ingress"].append({"cidr_blocks": ["1.2.3.4/32"], "from_port": 22,
                           "protocol": "tcp", "to_port": 22})
fp3 = drift_fingerprint(sg["change"]["before"], mutated)
check("fingerprint changes when the diff changes", fp1 != fp3, (fp1, fp3))
check("fingerprint is a 16-hex string",
      len(fp1) == 16 and all(c in "0123456789abcdef" for c in fp1), fp1)

print("== delete-drift routing ==")
db = next(r for r in rcs if r["address"] == "aws_db_instance.legacy_reporting")
check("delete drift classifies as needs-human", classify(db) == "needs-human")
check("update drift classifies as candidate", classify(sg) == "candidate")

print("== triage: first run drafts, second run dedupes ==")
gh = FakeGitHub()
first = triage(PLAN, gh)
by_addr = {a: (d, det) for a, d, det in first}
check("SG drift drafted on first run", by_addr["aws_security_group.app_alb"][0] == "drafted",
      by_addr)
check("delete drift -> needs-human, nothing drafted",
      by_addr["aws_db_instance.legacy_reporting"][0] == "needs-human", by_addr)
check("exactly one PR opened", len(gh.opened) == 1, gh.opened)

# simulate the PR from run 1 still being open
sg_fp = drift_fingerprint(sg["change"]["before"], sg["change"]["after"])
gh2 = FakeGitHub(open_prs=[("aws_security_group.app_alb", sg_fp, 42)])
second = triage(PLAN, gh2)
by_addr2 = {a: (d, det) for a, d, det in second}
check("second run skips duplicate (idempotent PRs)",
      by_addr2["aws_security_group.app_alb"][0] == "skip-duplicate", by_addr2)
check("no new PR opened on second run", len(gh2.opened) == 0, gh2.opened)

print("== triage: deny-listed sensitive types ==")
plan2 = {"resource_changes": [{
    "address": "aws_iam_policy.admin", "type": "aws_iam_policy", "name": "admin",
    "mode": "managed", "provider_name": "registry.terraform.io/hashicorp/aws",
    "change": {"actions": ["update"], "before": {"policy": "a"}, "after": {"policy": "b"},
               "after_unknown": {}}}]}
p2path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "_tmp-deny.json")
with open(p2path, "w") as fh:
    json.dump(plan2, fh)
res = triage(p2path, FakeGitHub())
os.remove(p2path)
check("IAM policy drift is detection-only (denied)",
      res and res[0][1] == "denied", res)

print(f"\n{passed} passed, {failed} failed")
sys.exit(1 if failed else 0)
