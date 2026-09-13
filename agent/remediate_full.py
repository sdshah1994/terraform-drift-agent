"""Fuller offline implementation of the drift-remediation agent from the article.

Faithful to the described behavior:
  - Stage 2 tool surface: read plan JSON, gather evidence (CloudTrail), open PR.
    The ONLY write is opening a PR (or a needs-human issue); there is no
    apply/merge anywhere here.
  - Two-phase execution (matches drift-remediate.yml): analyze_plan() does the
    read-only analysis and stages proposals under proposal/; the propose step
    performs the GitHub writes. The model key and the GitHub token never share
    a step. Region flows from the workflow input into the CloudTrail lookup.
  - Guardrails: one PR per resource; idempotent PRs via (address, fingerprint)
    dedupe; stale PRs (same address, new fingerprint) are closed with a pointer
    to the replacement; delete drift -> drift/needs-human issue, drafts
    nothing; deny-listed sensitive types are detection-only (issue, no PR);
    ">N drifted resources -> page a human" threshold; PR body carries the
    evidence trail (recommendation, evidence strength, evidence, plan summary).
  - System-prompt contract: codify vs revert vs uncertain; evidence strength
    is strong/partial/none; when evidence is insufficient the agent says so
    but still drafts the codify variant.

All external clients are injected fakes so this runs with no network, AWS,
or API keys.
"""
import argparse
import hashlib
import itertools
import json
import os
import threading

DEFAULT_DENY_TYPES = (
    "aws_iam_policy",
    "aws_iam_policy_attachment",
    "aws_iam_policy_document",  # data source rendered as managed in some plans
    "aws_kms_key",
    "aws_kms_key_policy",
)
# Terraform module-address forms for "anything in a security/ module".
DEFAULT_DENY_MODULE_MARKERS = ("module.security.", "/security/")


class PlanLoadError(ValueError):
    """drift.json is unreadable or structurally invalid; the run cannot proceed."""


def load_plan(plan_path):
    """Parse drift.json. Raises PlanLoadError on invalid JSON / bad root shape."""
    try:
        with open(plan_path) as fh:
            plan = json.load(fh)
    except (OSError, json.JSONDecodeError) as exc:
        raise PlanLoadError(f"cannot parse {plan_path}: {exc}") from exc
    if not isinstance(plan, dict):
        raise PlanLoadError(f"{plan_path}: root must be an object")
    # Refresh-only plans (what drift-detect uploads) report drift under
    # "resource_drift"; normal plans use "resource_changes". Prefer the former.
    changes = plan.get("resource_drift", plan.get("resource_changes", []))
    if not isinstance(changes, list):
        raise PlanLoadError(f"{plan_path}: resource_drift/resource_changes must be a list")
    return changes


def drifted_resources(plan_path):
    """Drift entries that actually changed (skip no-ops)."""
    return [
        rc for rc in load_plan(plan_path)
        if isinstance(rc, dict)
        and rc.get("change", {}).get("actions", []) != ["no-op"]
    ]


def drift_fingerprint(before, after):
    """Stable hash of the before/after attribute set from the plan JSON."""
    canonical = json.dumps(
        {"before": before, "after": after},
        sort_keys=True,
        separators=(",", ":"),
        default=str,
    )
    return hashlib.sha256(canonical.encode()).hexdigest()[:16]


def is_sensitive(rc, deny_types, deny_module_markers):
    address = rc.get("address", "")
    return rc.get("type") in deny_types or any(
        m in address for m in deny_module_markers
    )


def validate_entry(rc):
    """True when the entry has the minimum fields needed for triage."""
    return (
        isinstance(rc, dict)
        and isinstance(rc.get("address"), str)
        and isinstance(rc.get("change"), dict)
        and isinstance(rc["change"].get("actions"), list)
    )


class FakeGitHub:
    """Thread-safe stand-in for the GitHub API."""

    def __init__(self, open_prs=()):
        self._lock = threading.Lock()
        self._open = {(a, f): n for (a, f, n) in open_prs}
        self._numbers = itertools.count(900)
        self._issue_numbers = itertools.count(500)
        self.opened = []  # (address, fingerprint, number, title, body), in open order
        self.pr_files = {}  # pr_number -> {path: content} committed on the PR branch
        self.issues = []  # (number, title, labels), in open order
        self.closed = []  # (pr_number, comment), in close order

    def find_open_pr(self, address, fingerprint):
        with self._lock:
            return self._open.get((address, fingerprint))

    def find_open_prs_for_address(self, address):
        """All open PRs for an address (any fingerprint): (number, fingerprint)."""
        with self._lock:
            return [(n, f) for (a, f), n in self._open.items() if a == address]

    def close_pr(self, number, comment):
        """Close a PR as stale/superseded. Removes it from the open set."""
        with self._lock:
            found = False
            for key, n in list(self._open.items()):
                if n == number:
                    del self._open[key]
                    found = True
            if found:
                self.closed.append((number, comment))

    def open_issue(self, title, body, labels=()):
        """File a GitHub issue (used for drift/needs-human). Returns the number."""
        with self._lock:
            number = next(self._issue_numbers)
            self.issues.append((number, title, tuple(labels)))
            return number

    def open_pr_if_absent(self, address, fingerprint, title, body, files=None):
        """Atomically open a PR unless (address, fingerprint) is already covered.

        files: optional {path: content} committed on the PR branch. Used for
        revert decisions, where a branch identical to base cannot open a PR
        (GitHub returns 422 "No commits between") — the decision-record file
        gives the PR a real diff and preserves the decision in git history.

        Returns (pr_number, created: bool). The atomicity is what makes
        concurrent triage runs idempotent instead of opening duplicates.
        """
        with self._lock:
            if (address, fingerprint) in self._open:
                return self._open[(address, fingerprint)], False
            number = next(self._numbers)
            self._open[(address, fingerprint)] = number
            self.opened.append((address, fingerprint, number, title, body))
            self.pr_files[number] = dict(files or {})
            return number, True


class FakeCloudTrail:
    """Stand-in for CloudTrail LookupEvents, keyed by resource name."""

    def __init__(self, events_by_resource=None):
        # {resource_name: [event_dict, ...]}; event_dict e.g.
        # {"EventName": ..., "EventTime": ..., "Username": ...}
        self.events_by_resource = events_by_resource or {}
        self.lookups = []  # record of (resource_name, days, region) for assertions

    def lookup(self, resource_name, days=14, region=None):
        self.lookups.append((resource_name, days, region))
        return list(self.events_by_resource.get(resource_name, []))


class FakeLLM:
    """Deterministic stand-in for the analyst model.

    responder(stack, resource_change, evidence) -> analysis dict with keys:
      recommendation: "codify" | "revert" | "uncertain"
      evidence_strength: "strong" | "partial" | "none"   # calibrated wording:
          the article presents this as evidence strength, not model confidence
      drift_summary, evidence (list of bullets), change_summary,
      hcl_diff (None for revert), plan_summary
    """

    def __init__(self, responder=None):
        self.responder = responder or default_responder
        self.calls = []  # records of per-resource inputs (context-cap assertions)

    def analyze(self, stack, resource_change, evidence):
        # Context cap: the model sees ONE resource_changes entry, never the plan.
        self.calls.append(
            {"stack": stack, "resource_change": resource_change, "evidence": evidence}
        )
        return self.responder(
            stack=stack, resource_change=resource_change, evidence=evidence
        )


def default_responder(stack, resource_change, evidence):
    address = resource_change["address"]
    if evidence:
        first = evidence[0]
        return {
            "recommendation": "codify",
            "evidence_strength": "strong",
            "drift_summary": f"`{address}` drifted out-of-band.",
            "evidence": [
                f"CloudTrail `{first.get('EventName')}` at {first.get('EventTime')} "
                f"by `{first.get('Username')}`"
            ],
            "change_summary": f"updates the HCL declaring `{address}` to match reality.",
            "hcl_diff": f"# codify variant for {address}\n# (minimal diff)",
            "plan_summary": "No changes. Your infrastructure matches the configuration.",
        }
    return {
        "recommendation": "uncertain",
        "evidence_strength": "none",
        "drift_summary": f"`{address}` drifted out-of-band.",
        "evidence": ["Evidence was insufficient to choose a direction."],
        "change_summary": (
            f"draft codify variant for `{address}` anyway, so a reviewer can see "
            "what accepting the change would look like."
        ),
        "hcl_diff": f"# codify variant for {address} (uncertain direction)\n# (minimal diff)",
        "plan_summary": "No changes. Your infrastructure matches the configuration.",
    }


def render_decision_record(stack, address, fingerprint, analysis):
    """Markdown decision record committed on revert PRs.

    A revert PR changes nothing in HCL, and GitHub rejects PRs whose branch
    is identical to base — so the decision is committed as a file. The
    PR-time plan (exit 2, showing exactly the drifted change) proves that
    merge + apply will restore declared config.
    """
    evidence_lines = "\n".join(f"- {b}" for b in analysis["evidence"])
    return (
        f"# Drift decision: revert\n\n"
        f"- **Stack:** {stack}\n"
        f"- **Resource:** `{address}`\n"
        f"- **Drift fingerprint:** `{fingerprint}`\n"
        f"- **Evidence strength:** {analysis['evidence_strength']}\n\n"
        f"## Drift\n\n{analysis['drift_summary']}\n\n"
        f"## Evidence\n\n{evidence_lines}\n\n"
        f"## Decision\n\nRevert. No HCL change is proposed in this PR; merging it "
        f"and letting CI apply will restore the declared configuration. "
        f"The required PR-time plan on this branch exits 2 by design — the "
        f"gate interprets it (diff must equal the original drift), it doesn't "
        f"fail it.\n"
    )


def decision_record_path(address, fingerprint):
    """File path for a revert decision record; sanitized for use as a path."""
    safe = "".join(c if (c.isalnum() or c in "-_.") else "-" for c in address)
    return f".drift-decisions/{safe}-{fingerprint}.md"


def render_pr_body(stack, address, fingerprint, analysis):
    """PR body in the article's shape: recommendation, evidence trail, plan."""
    rec = analysis["recommendation"]
    rec_label = {
        "codify": "Codify",
        "revert": "Revert",
        "uncertain": "Uncertain — drafting codify variant for review",
    }[rec]
    if rec == "revert":
        change_block = (
            "No HCL change — recommend revert; merging this PR and letting CI "
            "apply will restore the declared config."
        )
    else:
        change_block = analysis["change_summary"]
        if analysis.get("hcl_diff"):
            change_block += f"\n\n```hcl\n{analysis['hcl_diff']}\n```"
    evidence_lines = "\n".join(f"- {b}" for b in analysis["evidence"])
    return (
        f"[drift] {stack}: {address} drifted out-of-band\n\n"
        f"**Recommendation:** {rec_label} (evidence: {analysis['evidence_strength']})\n\n"
        f"**Drift:** {analysis['drift_summary']}\n\n"
        f"**Evidence:**\n{evidence_lines}\n\n"
        f"**Change:** {change_block}\n\n"
        f"**Post-merge plan:** `{analysis['plan_summary']}`\n\n"
        f"**If you disagree:** close this PR; the next scheduled apply will "
        f"remove the change.\n\n"
        f"---\n"
        f"_Drift fingerprint: `{fingerprint}` · drafted by drift-remediation "
        f"agent (read-only; never applies)_"
    )


def render_issue_body(stack, address, fingerprint, reason, evidence):
    """Body for a drift/needs-human issue: evidence trail, no proposed change."""
    evidence_lines = "\n".join(f"- {b}" for b in evidence) or \
        "- No CloudTrail events found for this resource in the lookup window."
    return (
        f"[drift] {stack}: {address} needs a human decision\n\n"
        f"**Why a human:** {reason}\n\n"
        f"**Drift fingerprint:** `{fingerprint}`\n\n"
        f"**Evidence gathered:**\n{evidence_lines}\n\n"
        f"The agent drafted nothing for this resource. A human should open "
        f"the remediation PR.\n\n"
        f"---\n"
        f"_filed by drift-remediation agent (read-only; never applies)_"
    )


NEEDS_HUMAN_LABEL = "drift/needs-human"


def analyze_resource(stack, rc, cloudtrail, llm,
                     deny_types, deny_module_markers, region=None):
    """Analyze one drifted resource. Performs NO GitHub writes.

    Returns a proposal dict: {"address", "fingerprint", "kind",
    "decision", "reason", ...}. kind is "pr" (open a PR) or "issue"
    (file a drift/needs-human issue, draft nothing).
    """
    address = rc["address"]
    change = rc["change"]
    fingerprint = drift_fingerprint(change.get("before"), change.get("after"))

    if change.get("actions") == ["delete"]:
        reason = "delete drift: resource gone from reality; human must decide"
        evidence = cloudtrail.lookup(rc.get("name", address), region=region)
        return {
            "address": address, "fingerprint": fingerprint,
            "kind": "issue", "decision": "needs-human", "reason": reason,
            "issue_title": f"[drift] {stack}: {address} deleted out-of-band",
            "issue_body": render_issue_body(stack, address, fingerprint,
                                            reason, evidence),
            "labels": [NEEDS_HUMAN_LABEL],
        }
    if is_sensitive(rc, deny_types, deny_module_markers):
        reason = "sensitive type: detection-only; PR must be opened by a human"
        evidence = cloudtrail.lookup(rc.get("name", address), region=region)
        return {
            "address": address, "fingerprint": fingerprint,
            "kind": "issue", "decision": "denied", "reason": reason,
            "issue_title": f"[drift] {stack}: {address} needs a human",
            "issue_body": render_issue_body(stack, address, fingerprint,
                                            reason, evidence),
            "labels": [NEEDS_HUMAN_LABEL],
        }

    evidence = cloudtrail.lookup(rc.get("name", address), region=region)
    analysis = llm.analyze(stack=stack, resource_change=rc, evidence=evidence)
    title = f"[drift] {stack}: {address} drifted out-of-band"
    body = render_pr_body(stack, address, fingerprint, analysis)
    files = None
    if analysis["recommendation"] == "revert":
        # Decision-record file: a revert PR changes nothing in HCL, and a
        # branch identical to base cannot open a PR — so the decision ships
        # as a committed file, giving the PR a real diff.
        files = {decision_record_path(address, fingerprint):
                 render_decision_record(stack, address, fingerprint, analysis)}
    return {
        "address": address, "fingerprint": fingerprint,
        "kind": "pr",
        # Final decision (drafted / drafted-revert / skip-duplicate) is made
        # at propose time, when current GitHub state is known.
        "decision": "pending",
        "reason": f"{analysis['recommendation']} "
                  f"(evidence: {analysis['evidence_strength']})",
        "title": title, "body": body, "files": files,
        "analysis": analysis,
    }


def execute_proposal(stack, proposal, github):
    """Perform the GitHub writes for one proposal. Returns a decision dict."""
    address, fingerprint = proposal["address"], proposal["fingerprint"]
    if proposal["kind"] == "issue":
        number = github.open_issue(proposal["issue_title"],
                                   proposal["issue_body"],
                                   proposal["labels"])
        return {
            "address": address, "fingerprint": fingerprint,
            "decision": proposal["decision"], "reason": proposal["reason"],
            "issue_number": number,
        }
    pr_number, created = github.open_pr_if_absent(
        address, fingerprint, proposal["title"], proposal["body"],
        proposal["files"])
    if created:
        # Stale-PR close: the same address drifted again with a NEW
        # fingerprint. Close the old PR(s) pointing at the replacement so a
        # reviewer never approves a fix for drift that no longer exists.
        for stale_number, _stale_fp in github.find_open_prs_for_address(address):
            if stale_number != pr_number:
                github.close_pr(
                    stale_number,
                    f"Closed as stale: `{address}` drifted again since this PR "
                    f"was opened. Superseded by #{pr_number} "
                    f"(fingerprint `{fingerprint}`).")
        decision = ("drafted-revert"
                    if proposal["analysis"]["recommendation"] == "revert"
                    else "drafted")
        return {
            "address": address, "fingerprint": fingerprint,
            "decision": decision,
            "reason": f"opened PR #{pr_number} ({proposal['reason']})",
            "pr_number": pr_number,
            "pr_title": proposal["title"],
            "pr_body": proposal["body"],
        }
    return {
        "address": address, "fingerprint": fingerprint,
        "decision": "skip-duplicate",
        "reason": f"open PR #{pr_number} already covers fingerprint {fingerprint}",
        "pr_number": pr_number,
    }


def triage_resource(stack, rc, github, cloudtrail, llm,
                    deny_types, deny_module_markers, region=None):
    """Analyze one resource and immediately perform its GitHub writes.

    Thin wrapper over analyze_resource + execute_proposal; kept so the
    single-step path stays readable. The workflow uses the two-step path
    (analyze -> proposal/ -> propose) instead.
    """
    return execute_proposal(
        stack,
        analyze_resource(stack, rc, cloudtrail, llm,
                         deny_types, deny_module_markers, region),
        github)


def analyze_plan(plan_path, stack, cloudtrail, llm, region=None,
                 drift_threshold=100,
                 deny_types=DEFAULT_DENY_TYPES,
                 deny_module_markers=DEFAULT_DENY_MODULE_MARKERS):
    """Read-only analysis phase: no GitHub writes.

    Returns {"status", "stack", "region", "drifted_count", "proposals",
    "paged_human"}. Breaching the sanity threshold pages a human and
    produces no proposals.
    """
    drifted = drifted_resources(plan_path)
    if len(drifted) > drift_threshold:
        return {
            "status": "threshold-breached",
            "stack": stack, "region": region,
            "drifted_count": len(drifted),
            "paged_human": True,
            "proposals": [],
        }
    proposals = []
    unparseable = []
    for rc in drifted:
        if not validate_entry(rc):
            unparseable.append({
                "address": rc.get("address") if isinstance(rc, dict) else None,
                "fingerprint": None,
                "kind": "issue", "decision": "needs-human",
                "reason": "unparseable resource_change entry; human must inspect",
                "issue_title": f"[drift] {stack}: unparseable plan entry",
                "issue_body": "A resource_changes entry in drift.json could not "
                              "be parsed; a human must inspect the plan.",
                "labels": [NEEDS_HUMAN_LABEL],
            })
            continue
        proposals.append(analyze_resource(
            stack, rc, cloudtrail, llm, deny_types, deny_module_markers, region))
    # Deterministic order: sort by (address, fingerprint) so the proposal/
    # directory contents are stable across runs.
    proposals.sort(key=lambda p: (p["address"] or "", p["fingerprint"] or ""))
    return {
        "status": "ok",
        "stack": stack, "region": region,
        "drifted_count": len(drifted),
        "paged_human": False,
        "proposals": unparseable + proposals,
    }


def write_proposals(proposals, out_dir):
    """Stage proposals as JSON files for the propose step (the proposal/ dir)."""
    os.makedirs(out_dir, exist_ok=True)
    paths = []
    for p in proposals:
        safe = "".join(c if (c.isalnum() or c in "-_.") else "-"
                       for c in (p["address"] or "unknown"))
        path = os.path.join(out_dir, f"{safe}-{p['fingerprint'] or 'none'}.json")
        with open(path, "w") as fh:
            json.dump(p, fh, indent=2, default=str)
        paths.append(path)
    return sorted(paths)


def read_proposals(proposal_dir):
    """Read staged proposal JSONs back, sorted by (address, fingerprint).

    Sorting by content (not filename) keeps the order deterministic even
    when address sanitization changes the filename collation.
    """
    proposals = []
    for name in os.listdir(proposal_dir):
        if not name.endswith(".json"):
            continue
        with open(os.path.join(proposal_dir, name)) as fh:
            proposals.append(json.load(fh))
    proposals.sort(key=lambda p: (p.get("address") or "", p.get("fingerprint") or ""))
    return proposals


def run(plan_path, stack, github, cloudtrail, llm,
        drift_threshold=100,
        deny_types=DEFAULT_DENY_TYPES,
        deny_module_markers=DEFAULT_DENY_MODULE_MARKERS,
        region=None):
    """Run the remediation agent over drift.json: analyze, then propose.

    Returns a result dict with status "ok" or "threshold-breached".
    Breaching the sanity threshold pages a human and drafts nothing.
    """
    analysis = analyze_plan(plan_path, stack, cloudtrail, llm, region,
                            drift_threshold, deny_types, deny_module_markers)
    decisions = [execute_proposal(stack, p, github)
                 for p in analysis["proposals"]]
    return {
        "status": analysis["status"],
        "stack": stack,
        "region": region,
        "drifted_count": analysis["drifted_count"],
        "paged_human": analysis["paged_human"],
        "decisions": decisions,
        "prs_opened": sum(1 for d in decisions
                          if d["decision"] in ("drafted", "drafted-revert")),
        "issues_opened": sum(1 for d in decisions
                             if d["decision"] in ("needs-human", "denied")),
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--plan", required=True)
    ap.add_argument("--stack", required=True)
    ap.add_argument("--threshold", type=int, default=100)
    args = ap.parse_args()
    result = run(args.plan, args.stack, FakeGitHub(), FakeCloudTrail(), FakeLLM(),
                 drift_threshold=args.threshold)
    print(f"status={result['status']} drifted={result['drifted_count']} "
          f"prs={result['prs_opened']} paged_human={result['paged_human']}")
    for d in result["decisions"]:
        print(f"  {d['decision']:14} {d['address']} :: {d['reason']}")


if __name__ == "__main__":
    main()
