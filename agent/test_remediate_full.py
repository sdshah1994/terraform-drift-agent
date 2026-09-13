"""Edge-case tests for remediate_full.py. Fully offline: no network, AWS, or keys."""
import json
import os
import sys
import tempfile
import threading

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from remediate_full import (
    NEEDS_HUMAN_LABEL,
    PlanLoadError,
    analyze_plan,
    drift_fingerprint,
    drifted_resources,
    execute_proposal,
    read_proposals,
    render_decision_record,
    run,
    write_proposals,
    FakeCloudTrail,
    FakeGitHub,
    FakeLLM,
)

HERE = os.path.dirname(os.path.abspath(__file__))
SAMPLE = os.path.join(HERE, "sample-drift.json")
passed = failed = 0


def check(name, cond, extra=""):
    global passed, failed
    if cond:
        passed += 1
        print(f"  PASS {name}")
    else:
        failed += 1
        print(f"  FAIL {name} {extra}")


def write_plan(obj):
    fd, path = tempfile.mkstemp(suffix=".json", dir=HERE)
    with os.fdopen(fd, "w") as fh:
        json.dump(obj, fh)
    return path


def write_raw(text):
    fd, path = tempfile.mkstemp(suffix=".json", dir=HERE)
    with os.fdopen(fd, "w") as fh:
        fh.write(text)
    return path


def rc(address, rtype="aws_security_group", actions=("update",), before=None, after=None):
    return {
        "address": address, "type": rtype, "name": address.split(".")[-1],
        "mode": "managed", "provider_name": "registry.terraform.io/hashicorp/aws",
        "change": {"actions": list(actions),
                   "before": before if before is not None else {"id": "x"},
                   "after": after,
                   "after_unknown": {}},
    }


def fresh():
    return FakeGitHub(), FakeCloudTrail(), FakeLLM()


# ---------- malformed inputs ----------
print("== malformed drift.json ==")
p = write_raw("{not json")
try:
    run(p, "s", *fresh())
    check("invalid JSON raises PlanLoadError", False)
except PlanLoadError:
    check("invalid JSON raises PlanLoadError", True)
os.remove(p)

p = write_raw("[1,2,3]")
try:
    run(p, "s", *fresh())
    check("non-object root raises PlanLoadError", False)
except PlanLoadError:
    check("non-object root raises PlanLoadError", True)
os.remove(p)

p = write_plan({"resource_changes": "nope"})
try:
    run(p, "s", *fresh())
    check("non-list resource_changes raises PlanLoadError", False)
except PlanLoadError:
    check("non-list resource_changes raises PlanLoadError", True)
os.remove(p)

p = write_plan({"terraform_version": "1.9.8"})  # missing key tolerated as empty
r = run(p, "s", *fresh())
check("missing resource_changes key -> ok, nothing to do",
      r["status"] == "ok" and r["decisions"] == [] and r["prs_opened"] == 0, r)
os.remove(p)

p = write_plan({"resource_changes": [{"type": "aws_instance"}]})  # no address/change
r = run(p, "s", *fresh())
d = r["decisions"][0]
check("entry missing address/change -> needs-human, run survives",
      d["decision"] == "needs-human" and d["fingerprint"] is None
      and r["prs_opened"] == 0, d)
os.remove(p)

p = write_plan({"resource_changes": [
    {"address": "aws_instance.a", "type": "aws_instance", "name": "a",
     "change": {"actions": ["update"]}},  # before/after absent entirely
]})
r = run(p, "s", *fresh())
check("entry missing before/after still triages",
      r["decisions"][0]["decision"] == "drafted", r["decisions"])
os.remove(p)

# ---------- real refresh-only plan shape (live test 2026-09-11) ----------
# A refresh-only `terraform show -json` reports drift under "resource_drift",
# NOT "resource_changes". The agent must read the right key or it sees nothing.
print("== live refresh-only plan shape ==")
LIVE = os.path.join(HERE, "live-drift.json")
if os.path.exists(LIVE):
    rcs = drifted_resources(LIVE)
    check("live drift.json parses to exactly 1 drifted resource",
          len(rcs) == 1, len(rcs))
    check("live drift address is the security group",
          rcs[0]["address"] == "aws_security_group.drift_test", rcs[0].get("address"))
    check("live drift change has before/after",
          isinstance(rcs[0]["change"].get("before"), dict)
          and isinstance(rcs[0]["change"].get("after"), dict), "")
    r = run(LIVE, "network/prod-use1", *fresh())
    check("live drift triages to a drafted decision",
          r["status"] == "ok" and len(r["decisions"]) == 1
          and r["decisions"][0]["decision"] == "drafted", r["decisions"])
    check("live drift produces a stable fingerprint",
          isinstance(r["decisions"][0]["fingerprint"], str)
          and len(r["decisions"][0]["fingerprint"]) == 16,
          r["decisions"][0].get("fingerprint"))
else:
    check("live-drift.json present (skipped: file not found)", False)
print()

# ---------- empty / no-op ----------
print("== empty and no-op plans ==")
p = write_plan({"resource_changes": []})
r = run(p, "s", *fresh())
check("empty resource_changes -> ok, no PRs, no page",
      r["status"] == "ok" and r["prs_opened"] == 0 and not r["paged_human"], r)
os.remove(p)

p = write_plan({"resource_changes": [rc("aws_instance.b", "aws_instance",
                                        actions=("no-op",))]})
r = run(p, "s", *fresh())
check("no-op-only plan -> nothing drifted",
      r["drifted_count"] == 0 and r["prs_opened"] == 0, r)
os.remove(p)

# ---------- fingerprint ----------
print("== fingerprint ==")
a = {"b": 1, "a": [1, 2, {"z": 0, "y": 9}]}
b = {"a": [1, 2, {"y": 9, "z": 0}], "b": 1}  # same content, different key order
check("fingerprint ignores key order",
      drift_fingerprint(a, None) == drift_fingerprint(b, None))
c = {"b": 1, "a": [1, 2, {"z": 0, "y": 10}]}  # one value changed
check("fingerprint sensitive to a single value change",
      drift_fingerprint(a, None) != drift_fingerprint(c, None))

big_before = {"rules": [{"cidr": f"10.{i // 256}.{i % 256}.0/24"} for i in range(20000)]}
big_after = {"rules": big_before["rules"] + [{"cidr": "192.168.0.0/24"}]}
fp = drift_fingerprint(big_before, big_after)
check("huge diff (20k-element list) -> still 16-hex fingerprint",
      len(fp) == 16 and all(ch in "0123456789abcdef" for ch in fp), fp)
p = write_plan({"resource_changes": [rc("aws_security_group.huge",
                                        before=big_before, after=big_after)]})
r = run(p, "s", *fresh())
check("huge diff triages to drafted", r["decisions"][0]["decision"] == "drafted",
      r["decisions"])
os.remove(p)

# ---------- routing: delete / deny-list ----------
print("== delete drift and deny-list ==")
gh, ct, llm = fresh()
r = run(SAMPLE, "network/prod-use1", gh, ct, llm)
by = {d["address"]: d for d in r["decisions"]}
check("delete drift -> needs-human",
      by["aws_db_instance.legacy_reporting"]["decision"] == "needs-human", by)
check("update drift -> drafted",
      by["aws_security_group.app_alb"]["decision"] == "drafted", by)
check("delete drift opened no PR", len(gh.opened) == 1, gh.opened)
check("delete drift filed a drift/needs-human issue instead of drafting",
      len(gh.issues) == 1 and gh.issues[0][2] == ("drift/needs-human",),
      gh.issues)
check("needs-human decision carries the issue number",
      by["aws_db_instance.legacy_reporting"].get("issue_number") == gh.issues[0][0],
      by["aws_db_instance.legacy_reporting"])

p = write_plan({"resource_changes": [rc("aws_iam_policy.admin", "aws_iam_policy")]})
gh, ct, llm = fresh()
r = run(p, "s", gh, ct, llm)
check("aws_iam_policy -> denied, no PR",
      r["decisions"][0]["decision"] == "denied" and r["prs_opened"] == 0,
      r["decisions"])
check("deny-listed type files a drift/needs-human issue for a human PR",
      len(gh.issues) == 1 and gh.issues[0][2] == ("drift/needs-human",)
      and len(gh.opened) == 0, (gh.issues, gh.opened))
os.remove(p)

p = write_plan({"resource_changes": [
    rc("module.security.aws_iam_policy.admin", "aws_iam_policy")]})
r = run(p, "s", *fresh())
check("module.security.* address form -> denied",
      r["decisions"][0]["decision"] == "denied", r["decisions"])
os.remove(p)

p = write_plan({"resource_changes": [
    rc("module.app/security/aws_security_group.web", "aws_security_group")]})
r = run(p, "s", *fresh())
check("'/security/' path form -> denied",
      r["decisions"][0]["decision"] == "denied", r["decisions"])
os.remove(p)

# ---------- threshold ----------
print("== sanity threshold ==")
many = [rc(f"aws_instance.w{i}", "aws_instance", before={"id": f"i-{i}"},
             after={"id": f"i-{i}", "tags": {"t": "drifted"}})
        for i in range(101)]
p = write_plan({"resource_changes": many})
gh, ct, llm = fresh()
r = run(p, "s", gh, ct, llm, drift_threshold=100)
check("101 drifted (>100) -> threshold-breached",
      r["status"] == "threshold-breached", r["status"])
check("breach pages human and drafts nothing",
      r["paged_human"] and r["prs_opened"] == 0 and r["decisions"] == [], r)
check("breach opens zero PRs on GitHub", len(gh.opened) == 0, gh.opened)
os.remove(p)

p = write_plan({"resource_changes": many[:100]})
gh, ct, llm = fresh()
r = run(p, "s", gh, ct, llm, drift_threshold=100)
check("exactly 100 (== threshold) still proceeds",
      r["status"] == "ok" and r["prs_opened"] == 100, r["prs_opened"])
os.remove(p)

# ---------- idempotency: sequential + concurrent ----------
print("== idempotency ==")
gh, ct, llm = fresh()
r1 = run(SAMPLE, "s", gh, ct, llm)
r2 = run(SAMPLE, "s", gh, ct, llm)
d2 = {d["address"]: d["decision"] for d in r2["decisions"]}
check("second sequential run -> skip-duplicate, no new PR",
      d2.get("aws_security_group.app_alb") == "skip-duplicate"
      and len(gh.opened) == 1, (d2, len(gh.opened)))

gh2, ct2, llm2 = fresh()
barrier = threading.Barrier(2)
results = []


def racer():
    barrier.wait()
    results.append(run(SAMPLE, "s", gh2, ct2, llm2))


t1, t2 = threading.Thread(target=racer), threading.Thread(target=racer)
t1.start(); t2.start(); t1.join(); t2.join()
decisions = sorted(d["decision"] for res in results for d in res["decisions"]
                   if d["address"] == "aws_security_group.app_alb")
check("two racing triage runs open exactly ONE PR total",
      len(gh2.opened) == 1, len(gh2.opened))
check("racing runs agree: one drafted, one skip-duplicate",
      decisions == ["drafted", "skip-duplicate"], decisions)

# ---------- one PR per resource ----------
print("== one PR per resource ==")
three = [rc(f"aws_security_group.sg{i}", before={"id": f"sg-{i}"},
            after={"id": f"sg-{i}", "extra": i}) for i in range(3)]
p = write_plan({"resource_changes": three})
gh, ct, llm = fresh()
r = run(p, "s", gh, ct, llm)
titles = [t for (_, _, _, t, _) in gh.opened]
check("3 drifted resources -> 3 separate PRs",
      r["prs_opened"] == 3 and len(titles) == 3 == len(set(titles)), titles)
os.remove(p)

# ---------- PR body: evidence trail ----------
print("== PR body rendering ==")
events = {"app_alb": [{
    "EventName": "AuthorizeSecurityGroupIngress",
    "EventTime": "2026-09-08T03:12:00Z",
    "Username": "IncidentResponder-oncall"}]}
gh, ct, llm = FakeGitHub(), FakeCloudTrail(events), FakeLLM()
r = run(SAMPLE, "network/prod-use1", gh, ct, llm)
body = next(d for d in r["decisions"]
            if d["address"] == "aws_security_group.app_alb")["pr_body"]
for needle in ["**Recommendation:** Codify (evidence: strong)",
               "**Drift:**", "**Evidence:**", "**Change:**",
               "**Post-merge plan:**", "**If you disagree:**",
               "AuthorizeSecurityGroupIngress", "IncidentResponder-oncall",
               "Drift fingerprint:", "never applies"]:
    check(f"PR body contains {needle[:28]!r}", needle in body)
check("CloudTrail was actually consulted for the resource",
      ct.lookups and ct.lookups[0][0] == "app_alb", ct.lookups)

# ---------- insufficient evidence -> uncertain, still drafts codify variant ----------
print("== uncertain direction ==")
gh, ct, llm = fresh()  # FakeCloudTrail has no events
r = run(SAMPLE, "s", gh, ct, llm)
d = next(x for x in r["decisions"]
         if x["address"] == "aws_security_group.app_alb")
check("no evidence -> still drafted (codify variant)",
      d["decision"] == "drafted", d)
check("body admits uncertainty",
      "Uncertain" in d["pr_body"] and "evidence: none" in d["pr_body"])
check("body still carries a Change section for review",
      "**Change:**" in d["pr_body"] and "codify variant" in d["pr_body"])

# ---------- revert recommendation -> no-op PR with decision ----------
print("== revert path ==")


def revert_responder(stack, resource_change, evidence):
    return {
        "recommendation": "revert", "evidence_strength": "strong",
        "drift_summary": f"`{resource_change['address']}` was changed wrongly.",
        "evidence": ["CloudTrail shows an accidental console edit."],
        "change_summary": "n/a",
        "hcl_diff": None,
        "plan_summary": "No changes. Your infrastructure matches the configuration.",
    }


gh, ct, llm = FakeGitHub(), FakeCloudTrail(), FakeLLM(revert_responder)
r = run(SAMPLE, "s", gh, ct, llm)
d = next(x for x in r["decisions"]
         if x["address"] == "aws_security_group.app_alb")
check("revert -> drafted-revert PR", d["decision"] == "drafted-revert", d)
check("revert PR changes nothing in HCL but carries the decision",
      "No HCL change" in d["pr_body"] and "restore the declared config" in d["pr_body"])
check("revert body has no diff block", "```hcl" not in d["pr_body"])
files = gh.pr_files[d["pr_number"]]
check("revert PR commits exactly one decision-record file", len(files) == 1, files)
path = next(iter(files))
check("decision-record lives under .drift-decisions/ and embeds the fingerprint",
      path.startswith(".drift-decisions/") and path.endswith(".md")
      and d["fingerprint"] in path, path)
check("decision-record states the revert decision and evidence",
      "# Drift decision: revert" in files[path]
      and "CloudTrail shows an accidental console edit." in files[path], files[path][:200])
check("decision-record explains the exit-2-by-design plan",
      "exits 2 by design" in files[path])
check("decision-record reports evidence strength, not model confidence",
      "Evidence strength" in files[path] and "Confidence:" not in files[path],
      files[path][:400])

# codify PRs must NOT carry a decision-record file
gh2, ct2, llm2 = fresh()
r2 = run(SAMPLE, "s", gh2, ct2, llm2)
d2 = next(x for x in r2["decisions"]
          if x["address"] == "aws_security_group.app_alb")
check("codify PR carries no extra files", gh2.pr_files[d2["pr_number"]] == {},
      gh2.pr_files)

# address sanitization: module/instance addresses become safe paths
from remediate_full import decision_record_path
check("decision-record path sanitizes brackets and quotes",
      decision_record_path('module.a.aws_sg.x["k"]', "abc123") ==
      ".drift-decisions/module.a.aws_sg.x--k---abc123.md")

# ---------- context cap ----------
print("== context cap ==")
gh, ct, llm = fresh()
run(SAMPLE, "s", gh, ct, llm)
call = llm.calls[0]
check("LLM sees exactly one resource_changes entry",
      set(call.keys()) == {"stack", "resource_change", "evidence"}
      and call["resource_change"]["address"] == "aws_security_group.app_alb", call.keys())
check("LLM never receives the whole plan",
      "resource_changes" not in call and "plan" not in {k.lower() for k in call})

# ---------- analyze/propose split: analyze writes nothing ----------
print("== analyze/propose split ==")
gh, ct, llm = fresh()
analysis = analyze_plan(SAMPLE, "network/prod-use1", ct, llm, region="us-east-1")
check("analyze_plan returns proposals without a GitHub client",
      analysis["status"] == "ok" and len(analysis["proposals"]) >= 1
      and analysis["region"] == "us-east-1", analysis["status"])
check("analyze performs zero GitHub writes",
      len(gh.opened) == 0 and len(gh.issues) == 0 and len(gh.closed) == 0)
check("delete-drift proposal is issue-kind with the needs-human label",
      any(p["kind"] == "issue" and p["decision"] == "needs-human"
          and p["labels"] == [NEEDS_HUMAN_LABEL]
          for p in analysis["proposals"]), [p["decision"] for p in analysis["proposals"]])

# proposals round-trip through the proposal/ dir, then propose executes them
import shutil
tmpd = tempfile.mkdtemp(dir=HERE)
paths = write_proposals(analysis["proposals"], os.path.join(tmpd, "proposal"))
check("write_proposals stages one JSON per proposal",
      len(paths) == len(analysis["proposals"])
      and all(p.endswith(".json") for p in paths), paths)
back = read_proposals(os.path.join(tmpd, "proposal"))
check("read_proposals restores every proposal deterministically",
      [p["fingerprint"] for p in back]
      == [p["fingerprint"] for p in analysis["proposals"]])
decisions = [execute_proposal("network/prod-use1", p, gh) for p in back]
check("propose opens the PR and files the issue",
      sum(1 for d in decisions if d["decision"] == "drafted") == 1
      and sum(1 for d in decisions if d["decision"] == "needs-human") == 1,
      [d["decision"] for d in decisions])
check("propose performed the writes on GitHub",
      len(gh.opened) == 1 and len(gh.issues) == 1, (len(gh.opened), len(gh.issues)))

# threshold breach in the analyze phase produces no proposals
many = [rc(f"aws_instance.q{i}", "aws_instance") for i in range(5)]
p = write_plan({"resource_changes": many})
analysis = analyze_plan(p, "s", *fresh(), drift_threshold=4)
check("analyze_plan: threshold breach -> no proposals, paged human",
      analysis["status"] == "threshold-breached"
      and analysis["proposals"] == [] and analysis["paged_human"], analysis["status"])
os.remove(p)
shutil.rmtree(tmpd)

# ---------- region flows into the CloudTrail lookup ----------
print("== region threading ==")
gh, ct, llm = fresh()
analyze_plan(SAMPLE, "s", ct, llm, region="us-east-2")
check("every CloudTrail lookup carries the stack's region",
      ct.lookups and all(lk[2] == "us-east-2" for lk in ct.lookups), ct.lookups)

# ---------- stale PRs are closed when drift changes ----------
print("== stale-PR close ==")
stale_fp = "deadbeef00000000"  # NOT the real fingerprint of the sample drift
gh = FakeGitHub(open_prs=[("aws_security_group.app_alb", stale_fp, 901)])
ct, llm = FakeCloudTrail(), FakeLLM()
r = run(SAMPLE, "s", gh, ct, llm)
d = next(x for x in r["decisions"]
         if x["address"] == "aws_security_group.app_alb")
check("re-drift with a new fingerprint opens a replacement PR",
      d["decision"] == "drafted" and d["pr_number"] != 901, d)
check("the stale PR is closed, not left open",
      gh.closed and gh.closed[0][0] == 901
      and f"#{d['pr_number']}" in gh.closed[0][1], gh.closed)
check("no duplicate open PRs for the address",
      len(gh.find_open_prs_for_address("aws_security_group.app_alb")) == 1)

# same fingerprint re-run still dedupes without closing anything
gh2 = FakeGitHub()
run(SAMPLE, "s", gh2, *fresh()[1:])
r2 = run(SAMPLE, "s", gh2, *fresh()[1:])
sg2 = next(x for x in r2["decisions"]
           if x["address"] == "aws_security_group.app_alb")
check("identical re-run -> skip-duplicate, nothing closed",
      sg2["decision"] == "skip-duplicate"
      and gh2.closed == [], (sg2["decision"], gh2.closed))

# ---------- CLI smoke test: remediate.py analyze / propose ----------
print("== remediate.py CLI (production wiring) ==")
import subprocess
# The production CLI must fail closed — never silently fall back to fakes.
# Strip any real credentials from the child's environment for the test.
env = {k: v for k, v in os.environ.items()
       if k not in ("ANTHROPIC_API_KEY", "ANTHROPIC_MODEL", "GITHUB_REPOSITORY",
                    "GH_TOKEN")}
tmpd = tempfile.mkdtemp(dir=HERE)
propdir = os.path.join(tmpd, "proposal")
cp = subprocess.run(
    [sys.executable, os.path.join(HERE, "remediate.py"), "analyze",
     "--stack", "network/prod-use1", "--region", "us-east-1",
     "--plan", SAMPLE, "--out", propdir],
    capture_output=True, text=True, env=env)
check("CLI analyze fails closed without model env",
      cp.returncode != 0 and "ANTHROPIC_API_KEY" in (cp.stdout + cp.stderr),
      (cp.stdout + cp.stderr)[-200:])
cp = subprocess.run(
    [sys.executable, os.path.join(HERE, "remediate.py"), "propose",
     "--stack", "network/prod-use1", "--proposal", propdir],
    capture_output=True, text=True, env=env)
check("CLI propose fails closed without GITHUB_REPOSITORY",
      cp.returncode != 0 and "GITHUB_REPOSITORY" in (cp.stdout + cp.stderr),
      (cp.stdout + cp.stderr)[-200:])
shutil.rmtree(tmpd)
# Offline end-to-end with fakes is covered through remediate_full.run()
# (see the dedup / threshold sections above).


print("== OpenAICompatibleLLM (stubbed HTTP) ==")
import io
import urllib.request
from real_clients import OpenAICompatibleLLM, validate_analysis

VALID_ANALYSIS = {
    "recommendation": "codify",
    "evidence_strength": "strong",
    "drift_summary": "tag added out-of-band",
    "evidence": "CloudTrail: bob SetBucketTagging",
    "change_summary": "tags.Environment dev->prod",
    "hcl_diff": "+ Environment = \"prod\"",
    "plan_summary": "1 to update",
}
RC = {"address": "aws_s3_bucket.demo", "name": "demo",
      "change": {"actions": ["update"],
                 "before": {"tags": {"Environment": "dev"}},
                 "after": {"tags": {"Environment": "prod"}}}}
EV = [{"EventName": "PutBucketTagging", "EventTime": "2026-09-12T10:00:00Z",
       "Username": "bob"}]


class FakeResp:
    def __init__(self, payload): self.payload = payload
    def read(self): return json.dumps(self.payload).encode()
    def __enter__(self): return self
    def __exit__(self, *a): return False


def chat_body(analysis):
    return {"choices": [{"message": {"content": json.dumps(analysis)}}]}


captured = {}
real_urlopen = urllib.request.urlopen


def stub_urlopen(req, timeout=None):
    captured["url"] = req.full_url
    captured["headers"] = dict(req.header_items())
    captured["payload"] = json.loads(req.data.decode())
    return FakeResp(chat_body(VALID_ANALYSIS))


urllib.request.urlopen = stub_urlopen
try:
    llm = OpenAICompatibleLLM(api_key="k", model="m",
                              base_url="https://example.com/v1/")
    out = llm.analyze(stack="s", resource_change=RC, evidence=EV)
    check("returns validated analysis", out["recommendation"] == "codify")
    check("posts to base_url + /chat/completions",
          captured["url"] == "https://example.com/v1/chat/completions",
          captured["url"])
    check("bearer auth header sent",
          captured["headers"].get("Authorization") == "Bearer k")
    check("json_object response_format requested",
          captured["payload"].get("response_format") == {"type": "json_object"})
    check("model + messages in payload",
          captured["payload"]["model"] == "m"
          and captured["payload"]["messages"][0]["role"] == "user"
          and "aws_s3_bucket.demo" in captured["payload"]["messages"][0]["content"])
    check("call recorded", len(llm.calls) == 1 and llm.calls[0]["stack"] == "s")
finally:
    urllib.request.urlopen = real_urlopen


def stub_bad_json(req, timeout=None):
    return FakeResp({"choices": [{"message": {"content": "not json"}}]})


urllib.request.urlopen = stub_bad_json
try:
    try:
        OpenAICompatibleLLM(api_key="k", model="m",
                            base_url="https://x/").analyze(
            stack="s", resource_change=RC, evidence=EV)
        check("non-JSON reply raises", False)
    except ValueError as e:
        check("non-JSON reply raises", "did not return JSON" in str(e))
finally:
    urllib.request.urlopen = real_urlopen


def stub_missing_keys(req, timeout=None):
    return FakeResp(chat_body({"recommendation": "codify"}))


urllib.request.urlopen = stub_missing_keys
try:
    try:
        OpenAICompatibleLLM(api_key="k", model="m",
                            base_url="https://x/").analyze(
            stack="s", resource_change=RC, evidence=EV)
        check("missing keys raise", False)
    except ValueError as e:
        check("missing keys raise", "missing keys" in str(e))
finally:
    urllib.request.urlopen = real_urlopen


def stub_http_error(req, timeout=None):
    raise urllib.request.URLError("boom")


urllib.request.urlopen = stub_http_error
try:
    try:
        OpenAICompatibleLLM(api_key="k", model="m",
                            base_url="https://x/").analyze(
            stack="s", resource_change=RC, evidence=EV)
        check("transport error fails closed", False)
    except RuntimeError as e:
        check("transport error fails closed", "model endpoint call failed" in str(e))
finally:
    urllib.request.urlopen = real_urlopen

# shared contract validator
try:
    validate_analysis(dict(VALID_ANALYSIS, recommendation="nuke"))
    check("bad recommendation rejected", False)
except ValueError:
    check("bad recommendation rejected", True)
try:
    validate_analysis("nope")
    check("non-dict rejected", False)
except ValueError:
    check("non-dict rejected", True)

print("== remediate.py provider selection ==")
import importlib.util
spec = importlib.util.spec_from_file_location(
    "remediate_prod", os.path.join(HERE, "remediate.py"))
remod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(remod)
keep = dict(os.environ)
try:
    os.environ.pop("ANTHROPIC_API_KEY", None)
    os.environ.pop("ANTHROPIC_MODEL", None)
    os.environ["DRIFT_MODEL_PROVIDER"] = "bogus"
    try:
        remod.build_llm()
        check("unknown provider fails closed", False)
    except SystemExit as e:
        check("unknown provider fails closed",
              "unknown DRIFT_MODEL_PROVIDER" in str(e))
    os.environ["DRIFT_MODEL_PROVIDER"] = "openai_compatible"
    try:
        remod.build_llm()
        check("openai_compatible missing env fails closed", False)
    except SystemExit as e:
        check("openai_compatible missing env fails closed",
              "DRIFT_MODEL_API_KEY" in str(e))
finally:
    os.environ.clear()
    os.environ.update(keep)

print(f"\n{passed} passed, {failed} failed")
sys.exit(1 if failed else 0)
