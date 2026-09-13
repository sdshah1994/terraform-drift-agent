"""Production clients for the drift-remediation agent.

These implement the EXACT interfaces the decision logic in remediate_full.py
expects (same method names and signatures as FakeGitHub, FakeCloudTrail and
FakeLLM), so analyze_plan() and execute_proposal() run UNCHANGED. Only the
I/O plugs differ:

- BotoCloudTrail -> boto3 CloudTrail LookupEvents (regional, like the article)
- MuseLLM        -> the assistant, in conversation, plays the model step.
                   complete()/analyze() renders the exact prompt the agent
                   built, writes it to a file, and pauses the pipeline. The
                   assistant answers it in chat (following the system prompt's
                   contract); the JSON is saved and fed back via --llm-json.
- GhGitHub       -> the gh CLI + git against a real repo (branch, commit,
                   push, open PR / issue, close stale PRs).

Honest scope notes (also recorded in the e2e test report):
- The model step does NOT validate the Anthropic SDK call; it validates
  prompt construction, evidence flow, the JSON contract, and everything
  downstream. The SDK call it stands in for is a thin, low-risk call.
- Workflow STEPS run on this machine (same commands, order, and per-step
  secrets separation as drift-remediate.yml). The PR GATE runs for real in
  GitHub Actions when the PR opens.
- open_pr_if_absent is check-then-act here, not atomic like the fake: a tiny
  race window exists if two triage runs overlap. The e2e runs serially, so
  this does not apply; production would use the atomic API variant.
"""

import json
import os
import re
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from remediate_full import NEEDS_HUMAN_LABEL  # noqa: F401  (re-exported)


class ModelStepPaused(Exception):
    """Raised by MuseLLM.analyze: the pipeline stops until the assistant
    answers the rendered prompt in chat and the JSON is fed back via
    drive.py analyze --llm-json <file>."""

    def __init__(self, address, prompt_path):
        super().__init__(
            f"model step paused for {address}: prompt written to {prompt_path}. "
            "Answer it in chat, save the JSON, re-run with --llm-json.")
        self.address = address
        self.prompt_path = prompt_path


# System prompt: quoted from the article ("The tool surface" section), with the
# tool-calling mechanics rendered as a plain JSON contract for this test.
MODEL_SYSTEM_PROMPT = """You are the drift analyst. Rules:
1. Read-only. You can inspect plan JSON and query evidence sources. You cannot
   modify infrastructure, approve PRs, or merge.
2. Decide codify vs revert per resource: codify when the out-of-band change
   looks deliberate and safe to keep (then emit the minimal HCL diff);
   revert when it looks accidental, temporary, or policy-violating (then emit
   only the decision record, no HCL change).
3. Never auto-remediate delete drift or deny-listed types — file the
   drift/needs-human issue and stop.
4. Rate the strength of the evidence as strong, partial, or none — never state
   confidence as a probability.
5. You see exactly one resource_changes entry per call, never the whole plan.
"""


def render_model_prompt(stack, resource_change, evidence, region):
    """Render the exact prompt the agent would send the model."""
    change = resource_change["change"]
    before = change.get("before")
    after = change.get("after")
    lines = [
        "Stack: %s (region %s)" % (stack, region),
        "Resource: %s (type %s)" % (resource_change["address"],
                                    resource_change.get("type", "?")),
        "Change actions: %s" % (change.get("actions"),),
        "",
        "Before (abridged):",
        json.dumps(before, indent=2, default=str)[:4000],
        "",
        "After (abridged):",
        json.dumps(after, indent=2, default=str)[:4000],
        "",
        "CloudTrail evidence (region %s, last 14 days):" % region,
    ]
    if evidence:
        for e in evidence:
            lines.append("- %s at %s by %s" % (
                e.get("EventName"), e.get("EventTime"), e.get("Username")))
    else:
        lines.append("- (no CloudTrail events found for this resource)")
    lines += [
        "",
        "Return ONLY a JSON object with exactly these keys:",
        '  recommendation: "codify" | "revert" | "uncertain"',
        '  evidence_strength: "strong" | "partial" | "none"',
        "  drift_summary: one-sentence description of the drift",
        "  evidence: list of short evidence bullets (strings)",
        "  change_summary: what the proposed change does, one sentence",
        "  hcl_diff: unified diff of the minimal HCL change (codify), or null (revert)",
        "  plan_summary: the plan line a reviewer should expect on the PR",
    ]
    return MODEL_SYSTEM_PROMPT + "\n" + "\n".join(lines)


class MuseLLM:
    """The assistant plays the model. analyze() renders the prompt, writes it
    to prompt_dir, records the call (like FakeLLM.calls), and raises
    ModelStepPaused. Re-run with CannedLLM (via --llm-json) once the answers
    exist."""

    def __init__(self, prompt_dir):
        self.prompt_dir = prompt_dir
        os.makedirs(prompt_dir, exist_ok=True)
        self.calls = []

    def analyze(self, stack, resource_change, evidence, region="us-east-1"):
        address = resource_change["address"]
        self.calls.append({"stack": stack, "resource_change": resource_change,
                           "evidence": evidence})
        prompt = render_model_prompt(stack, resource_change, evidence, region)
        slug = re.sub(r"[^a-zA-Z0-9_.-]", "-", address)
        path = os.path.join(self.prompt_dir, "model-prompt-%s.md" % slug)
        with open(path, "w") as fh:
            fh.write(prompt)
        raise ModelStepPaused(address, path)


class CannedLLM:
    """Replays in-conversation model answers: {address: analysis dict}."""

    def __init__(self, answers):
        self.answers = answers
        self.calls = []

    def analyze(self, stack, resource_change, evidence, region="us-east-1"):
        address = resource_change["address"]
        self.calls.append({"stack": stack, "resource_change": resource_change,
                           "evidence": evidence})
        if address not in self.answers:
            raise KeyError("no model answer for %s (run without --llm-json "
                           "first so the prompts get rendered)" % address)
        return self.answers[address]


# The JSON contract every model client must return. Provider-agnostic:
# render the same prompt, return these keys, recommendation in the set.
ANALYSIS_REQUIRED_KEYS = ("recommendation", "evidence_strength", "drift_summary",
                          "evidence", "change_summary", "hcl_diff", "plan_summary")
ANALYSIS_RECOMMENDATIONS = ("codify", "revert", "uncertain")


def validate_analysis(analysis):
    """Raise ValueError unless the model reply honors the analysis contract."""
    if not isinstance(analysis, dict):
        raise ValueError("model did not return a JSON object")
    missing = [k for k in ANALYSIS_REQUIRED_KEYS if k not in analysis]
    if missing:
        raise ValueError("model JSON missing keys: " + ", ".join(missing))
    if analysis["recommendation"] not in ANALYSIS_RECOMMENDATIONS:
        raise ValueError("bad recommendation: %r" % (analysis["recommendation"],))
    return analysis


class AnthropicLLM:
    """Production model client: the Anthropic API.

    Renders the same prompt the offline/human-in-the-loop path uses
    (render_model_prompt) and parses the reply as the analysis JSON the
    decision logic expects. Requires a funded ANTHROPIC_API_KEY.

    NOTE: this client has not been exercised against the live API in the
    offline suite (no network). It is a thin call: render prompt, send,
    parse JSON, validate keys.
    """

    def __init__(self, api_key, model, max_tokens=2000):
        import anthropic
        self.client = anthropic.Anthropic(api_key=api_key)
        self.model = model
        self.max_tokens = max_tokens
        self.calls = []  # records of per-resource inputs (context-cap assertions)

    def analyze(self, stack, resource_change, evidence, region="us-east-1"):
        prompt = render_model_prompt(stack, resource_change, evidence, region)
        self.calls.append({"stack": stack, "resource_change": resource_change,
                           "evidence": evidence})
        msg = self.client.messages.create(
            model=self.model,
            max_tokens=self.max_tokens,
            messages=[{"role": "user", "content": prompt}],
        )
        text = "".join(getattr(b, "text", "") for b in msg.content)
        try:
            analysis = json.loads(text)
        except ValueError:
            raise ValueError("model did not return JSON: %r" % text[:200])
        return validate_analysis(analysis)


class OpenAICompatibleLLM:
    """Model-agnostic client: any OpenAI-compatible chat-completions endpoint.

    Same prompt and same JSON contract as AnthropicLLM; only the transport
    differs. Works with OpenAI, Azure OpenAI, Bedrock via a compatible
    proxy, self-hosted OpenAI-compatible servers, etc. — set base_url to
    the endpoint root (the client appends /chat/completions).

    Uses only the stdlib (urllib), so no extra dependency. Sends
    response_format {"type": "json_object"} and validates the reply with
    validate_analysis, exactly like AnthropicLLM.

    NOTE: like AnthropicLLM, not exercised against a live endpoint in the
    offline suite (no network/keys). Request shape and validation are
    covered by the stubbed-HTTP tests in test_remediate_full.py.
    """

    def __init__(self, api_key, model, base_url, max_tokens=2000, timeout=120):
        self.api_key = api_key
        self.model = model
        self.base_url = base_url.rstrip("/")
        self.max_tokens = max_tokens
        self.timeout = timeout
        self.calls = []  # records of per-resource inputs (context-cap assertions)

    def _post(self, payload):
        import urllib.request
        req = urllib.request.Request(
            self.base_url + "/chat/completions",
            data=json.dumps(payload).encode("utf-8"),
            headers={"Content-Type": "application/json",
                     "Authorization": "Bearer " + self.api_key},
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                return json.loads(resp.read().decode("utf-8"))
        except Exception as e:  # HTTPError/URLError/timeout: fail closed
            raise RuntimeError("model endpoint call failed: %s" % e)

    def analyze(self, stack, resource_change, evidence, region="us-east-1"):
        prompt = render_model_prompt(stack, resource_change, evidence, region)
        self.calls.append({"stack": stack, "resource_change": resource_change,
                           "evidence": evidence})
        body = self._post({
            "model": self.model,
            "max_tokens": self.max_tokens,
            "response_format": {"type": "json_object"},
            "messages": [{"role": "user", "content": prompt}],
        })
        try:
            text = body["choices"][0]["message"]["content"]
        except (KeyError, IndexError, TypeError):
            raise ValueError("unexpected chat-completions shape: %r"
                             % (str(body)[:200],))
        try:
            analysis = json.loads(text)
        except ValueError:
            raise ValueError("model did not return JSON: %r" % text[:200])
        return validate_analysis(analysis)


class BotoCloudTrail:
    """Real CloudTrail LookupEvents. name_map translates terraform resource
    names (e.g. 'app') to AWS ids (e.g. 'sg-0abc...') for the ResourceName
    lookup attribute."""

    def __init__(self, region, name_map=None):
        import boto3
        self.client = boto3.client("cloudtrail", region_name=region)
        self.region = region
        self.name_map = name_map or {}
        self.lookups = []  # (resource_name, aws_id, days, region)

    def lookup(self, resource_name, days=14, region=None):
        aws_id = self.name_map.get(resource_name, resource_name)
        self.lookups.append((resource_name, aws_id, days, self.region))
        resp = self.client.lookup_events(
            LookupAttributes=[{"AttributeKey": "ResourceName",
                               "AttributeValue": aws_id}],
            MaxResults=50,  # article: CloudTrail pages at 50
        )
        events = []
        for e in resp.get("Events", []):
            events.append({
                "EventName": e.get("EventName"),
                # datetime -> str so the analysis JSON stays serializable
                "EventTime": str(e.get("EventTime")),
                "Username": e.get("Username"),
            })
        return events


class GhGitHub:
    """Real GitHub via the gh CLI + git. GH_TOKEN must hold the bot PAT
    (fine-grained: Contents write, Pull requests write) in the environment.
    workdir is a clone of the repo; the PR branch is created there."""

    def __init__(self, repo, workdir):
        self.repo = repo            # "owner/name"
        self.workdir = workdir
        self.opened = []            # (address, fingerprint, number, title, body)
        self.pr_files = {}          # pr_number -> {path: content}
        self.issues = []            # (number, title, labels)
        self.closed = []            # (pr_number, comment)

    # -- plumbing ------------------------------------------------------
    def _gh(self, *args, input_text=None):
        p = subprocess.run(["gh", *args, "-R", self.repo],
                           capture_output=True, text=True, input=input_text,
                           env=os.environ)
        if p.returncode != 0:
            raise RuntimeError("gh %s failed: %s" % (" ".join(args), p.stderr))
        return p.stdout.strip()

    def _git(self, *args):
        p = subprocess.run(["git", *args], capture_output=True, text=True,
                           cwd=self.workdir, env=os.environ)
        if p.returncode != 0:
            raise RuntimeError("git %s failed: %s" % (" ".join(args), p.stderr))
        return p.stdout.strip()

    # -- interface (mirrors FakeGitHub) --------------------------------
    def find_open_pr(self, address, fingerprint):
        out = self._gh("pr", "list", "--state", "open", "--json",
                       "number,body", "--search",
                       '"%s" in:body' % fingerprint)
        prs = json.loads(out or "[]")
        return prs[0]["number"] if prs else None

    def find_open_prs_for_address(self, address):
        out = self._gh("pr", "list", "--state", "open", "--json",
                       "number,body", "--search",
                       '"%s" in:body' % address)
        result = []
        for pr in json.loads(out or "[]"):
            m = re.search(r"Drift fingerprint:\s*`([0-9a-f]{16})`",
                          pr.get("body") or "")
            result.append((pr["number"], m.group(1) if m else None))
        return result

    def close_pr(self, number, comment):
        self._gh("pr", "close", str(number), "--comment", comment)
        self.closed.append((number, comment))

    def ensure_label(self, name, color="d876e3", description=""):
        # gh has no --force for label create; create-and-ignore-"already
        # exists" is the idempotent path. Found live: issue creation fails
        # when drift/needs-human doesn't exist yet.
        try:
            self._gh("label", "create", name, "--color", color,
                     "--description", description)
        except RuntimeError as e:
            if "already exists" not in str(e):
                raise

    def open_issue(self, title, body, labels=()):
        for lb in labels:
            desc = ("Drift the agent could not safely draft a fix for; "
                    "needs a human decision" if lb == NEEDS_HUMAN_LABEL else "")
            self.ensure_label(lb, description=desc)
        args = ["issue", "create", "--title", title, "--body", body]
        for lb in labels:
            args += ["--label", lb]
        url = self._gh(*args)
        number = int(url.rstrip("/").rsplit("/", 1)[-1])
        self.issues.append((number, title, tuple(labels)))
        return number

    def open_pr_if_absent(self, address, fingerprint, title, body, files=None):
        existing = self.find_open_pr(address, fingerprint)
        if existing:
            return existing, False
        slug = re.sub(r"[^a-zA-Z0-9_.-]", "-", address)
        branch = "drift/%s-%s" % (slug, fingerprint[:8])
        # files (e.g. the revert decision record) land in the working tree;
        # codify HCL edits are applied by the driver before this call.
        for path, content in (files or {}).items():
            full = os.path.join(self.workdir, path)
            os.makedirs(os.path.dirname(full), exist_ok=True)
            with open(full, "w") as fh:
                fh.write(content)
        # Cut each PR branch from the base ref, not from whatever branch
        # the previous proposal left checked out — otherwise PRs stack and
        # a later PR carries earlier PRs' commits.
        self._git("checkout", "-b", branch, "origin/main")
        self._git("add", "-A")
        self._git("-c", "user.name=drift-agent",
                  "-c", "user.email=drift-agent@users.noreply.github.com",
                  "commit", "-m", title)
        self._git("push", "-u", "origin", branch)
        url = self._gh("pr", "create", "--title", title, "--body", body,
                       "--base", "main", "--head", branch)
        number = int(url.rstrip("/").rsplit("/", 1)[-1])
        self.opened.append((address, fingerprint, number, title, body))
        self.pr_files[number] = dict(files or {})
        return number, True
