"""CLI entry point for the drift-remediation agent (production wiring).

Used by .github/workflows/drift-remediate.yml in two steps:

    python agent/remediate.py analyze --stack S --region R --plan drift.json --out proposal/
    python agent/remediate.py propose --stack S --proposal proposal/

The analyze step is read-only (plan JSON + AWS evidence) and stages one JSON
proposal per drifted resource under proposal/. The propose step performs the
GitHub writes (open PRs, file needs-human issues, close stale PRs).

Real clients, no mocks:
  - model step .... provider-pluggable (DRIFT_MODEL_PROVIDER):
                      anthropic (default) .. AnthropicLLM (Anthropic API)
                      openai_compatible .... OpenAICompatibleLLM (any
                        OpenAI-compatible chat-completions endpoint)
  - evidence ...... BotoCloudTrail (boto3 CloudTrail LookupEvents, regional)
  - GitHub writes . GhGitHub (gh CLI + git; GH_TOKEN holds the bot token)

The offline test doubles live in remediate_full.py (FakeCloudTrail, FakeLLM,
FakeGitHub) and are exercised by the suite in agent/test_remediate_*.py:

    python -m pytest agent/ -q        # or: python agent/test_remediate_full.py
"""
import argparse
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from remediate_full import (
    analyze_plan,
    execute_proposal,
    read_proposals,
    write_proposals,
)
from real_clients import (AnthropicLLM, BotoCloudTrail, GhGitHub,
                            OpenAICompatibleLLM)


def build_llm():
    """Pick the model client from DRIFT_MODEL_PROVIDER (default: anthropic).

    Fails closed on missing credentials or an unknown provider — never
    silently falls back to a test double."""
    provider = os.environ.get("DRIFT_MODEL_PROVIDER", "anthropic").lower()
    if provider == "anthropic":
        api_key = os.environ.get("ANTHROPIC_API_KEY")
        model = os.environ.get("ANTHROPIC_MODEL")
        if not api_key or not model:
            raise SystemExit(
                "analyze needs ANTHROPIC_API_KEY and ANTHROPIC_MODEL in the "
                "environment (the workflow sets them from secrets/vars).")
        return AnthropicLLM(api_key=api_key, model=model)
    if provider == "openai_compatible":
        api_key = os.environ.get("DRIFT_MODEL_API_KEY")
        model = os.environ.get("DRIFT_MODEL_NAME")
        base_url = os.environ.get("DRIFT_MODEL_BASE_URL")
        if not api_key or not model or not base_url:
            raise SystemExit(
                "openai_compatible provider needs DRIFT_MODEL_API_KEY, "
                "DRIFT_MODEL_NAME and DRIFT_MODEL_BASE_URL in the environment.")
        return OpenAICompatibleLLM(api_key=api_key, model=model,
                                   base_url=base_url)
    raise SystemExit(
        "unknown DRIFT_MODEL_PROVIDER %r (want 'anthropic' or "
        "'openai_compatible')" % provider)


def cmd_analyze(args):
    llm = build_llm()
    # Optional: {"terraform_name": "aws_id"} when the TF resource name is not
    # the CloudTrail ResourceName. JSON object in DRIFT_NAME_MAP_JSON.
    name_map = json.loads(os.environ.get("DRIFT_NAME_MAP_JSON", "{}"))
    cloudtrail = BotoCloudTrail(region=args.region, name_map=name_map)
    result = analyze_plan(args.plan, args.stack, cloudtrail, llm,
                          region=args.region)
    if result["status"] == "threshold-breached":
        print(f"threshold breached: {result['drifted_count']} drifted "
              f"resources in {args.stack}; paging a human, drafting nothing")
        return 0
    paths = write_proposals(result["proposals"], args.out)
    print(f"analyzed {result['drifted_count']} drifted resources in "
          f"{args.stack} (region {args.region}); "
          f"staged {len(paths)} proposals under {args.out}/")
    return 0


def cmd_propose(args):
    # This step runs in a checkout of the repo; the bot token (GitHub App or
    # fine-grained PAT — NOT GITHUB_TOKEN) is in GH_TOKEN.
    repo = os.environ.get("GITHUB_REPOSITORY")
    workdir = os.environ.get("GITHUB_WORKSPACE", os.getcwd())
    if not repo:
        raise SystemExit("propose needs GITHUB_REPOSITORY in the environment.")
    github = GhGitHub(repo=repo, workdir=workdir)
    proposals = read_proposals(args.proposal)
    decisions = [execute_proposal(args.stack, p, github) for p in proposals]
    prs = sum(1 for d in decisions
              if d["decision"] in ("drafted", "drafted-revert"))
    issues = sum(1 for d in decisions
                 if d["decision"] in ("needs-human", "denied"))
    for d in decisions:
        print(f"  {d['decision']:14} {d['address']} :: {d['reason']}")
    print(f"proposed: {prs} PRs, {issues} issues, "
          f"{len(github.closed)} stale PRs closed")
    return 0


def main(argv=None):
    ap = argparse.ArgumentParser(prog="remediate.py")
    sub = ap.add_subparsers(dest="cmd", required=True)

    a = sub.add_parser("analyze", help="read-only analysis; stage proposals")
    a.add_argument("--stack", required=True)
    a.add_argument("--region", required=True,
                   help="stack's AWS region (CloudTrail LookupEvents is regional)")
    a.add_argument("--plan", required=True, help="drift.json from the detect run")
    a.add_argument("--out", required=True, help="proposal staging directory")
    a.set_defaults(fn=cmd_analyze)

    p = sub.add_parser("propose", help="perform the GitHub writes")
    p.add_argument("--stack", required=True)
    p.add_argument("--proposal", required=True, help="proposal staging directory")
    p.set_defaults(fn=cmd_propose)

    args = ap.parse_args(argv)
    return args.fn(args)


if __name__ == "__main__":
    sys.exit(main())
