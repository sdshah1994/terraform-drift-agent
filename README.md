# Drift Agent — Terraform drift triage that drafts PRs but never applies them

Companion code for the article "Closing the Drift Loop". A scheduled
GitHub Actions workflow detects Terraform drift with a refresh-only plan;
an agent triages each drifted resource (codify / revert / needs-human)
using CloudTrail evidence and a model, then opens a PR per resource —
or files a `drift/needs-human` issue when no safe fix exists. A PR gate
re-plans on every agent PR and asserts **per-resource** convergence.
The agent is never in the apply path: worst case is a closed PR.

## Layout

```
.github/workflows/
  drift-detect.yml     refresh-only plan per stack → drift.json artifact
                       → dispatches drift-remediate (drift-storm guard: >20
                       resources pages a human instead)
  drift-remediate.yml  analyze (read-only) → propose (GitHub writes)
  pr-gate.yml          required check on agent PRs: re-plans every stack the
                       PR touches and asserts the PR's own resource converges
                       (codify: no planned diff; revert: the claimed drift
                       fingerprint still shows). OIDC auth, no static keys.
agent/
  remediate.py         production CLI: analyze / propose (real clients)
  remediate_full.py    decision logic + offline test doubles
  real_clients.py      BotoCloudTrail, AnthropicLLM, GhGitHub
  requirements.txt     boto3, anthropic
  test_*.py            offline suite (no network, no keys)
stacks/example/       layout reference — copy per stack
```

## Setup

1. **Stacks**: copy `stacks/example/` per stack; configure your backend.
   List them in the `drift-detect.yml` matrix with their regions.
2. **AWS**: GitHub OIDC identity provider + a read-only role
   (`vars.DRIFT_READONLY_ROLE`) with: state backend read, state-lock write
   (plan holds a lock), `cloudtrail:LookupEvents`, and `Describe*` for your
   resource types.
3. **Secrets / vars**:
   - Model provider (the agent is model-agnostic; the decision logic only
     needs the analysis JSON contract):
     - `vars.DRIFT_MODEL_PROVIDER=anthropic` (default): `secrets.ANTHROPIC_API_KEY`
       + `vars.ANTHROPIC_MODEL`
     - `vars.DRIFT_MODEL_PROVIDER=openai_compatible`: `secrets.DRIFT_MODEL_API_KEY`
       + `vars.DRIFT_MODEL_NAME` + `vars.DRIFT_MODEL_BASE_URL` (any
       OpenAI-compatible chat-completions endpoint)
   - `secrets.DRIFT_BOT_TOKEN` — GitHub App or fine-grained PAT
     (Contents write, Pull requests write). Must NOT be `GITHUB_TOKEN`:
     PRs opened with `GITHUB_TOKEN` trigger no workflows, so the gate
     would silently never run on the agent's own PRs.
   - `vars.DRIFT_READONLY_ROLE` — the OIDC role ARN
   - `vars.DRIFT_STACK_REGIONS_JSON` — e.g. `{"example":"us-east-1"}`; the
     PR gate plans each stack the PR touches in its own region and fails
     closed if a touched stack has no entry
   - optional `vars.DRIFT_NAME_MAP_JSON` — `{"tf_name": "aws_id"}` when the
     Terraform resource name isn't the CloudTrail ResourceName
4. **Branch protection** on `main`: require the `pr-gate` check + human
   review (CODEOWNERS on platform paths). The bot identity must not be
   able to approve its own PRs.

## Security notes

- **No static cloud credentials.** All three workflows authenticate to AWS
  via OIDC (`vars.DRIFT_READONLY_ROLE`). Never put access keys in repo
  secrets for this pattern — a leaked key is a standing credential, while
  an OIDC token is minted per run and scoped by the trust policy.
- **Scope the role's trust policy.** The PR gate runs on PR code, so on a
  public repo a fork PR could trigger it. GitHub withholds secrets from
  fork-PR runs, and the role is read-only in shape, but scope the trust
  policy's `sub` to this repo anyway (e.g.
  `repo:<owner>/terraform-drift-agent:*`), so the role can't be assumed
  from anywhere else.
- **PR metadata is untrusted input.** The gate passes the PR title/body to
  its checker via environment variables, never interpolated into shell —
  titles and bodies on a public repo are attacker-controlled. The checker
  also fails closed when the body doesn't match the agent's format.

## Design notes (validated live)

- **One PR per resource, per-resource gate.** Drifts arrive together; the
  gate judges only the PR's own resource so concurrent drift can't
  deadlock unrelated PRs.
- **Delete drift is never auto-remediated.** A resource gone from reality
  becomes a `drift/needs-human` issue, not a PR.
- **Deny-list for sensitive types.** IAM/KMS policies and `module.security.*`
  are evidence-only; a human opens any PR.
- **Idempotent PRs.** The agent skips drift that already has an open PR
  with the same address + fingerprint, and closes stale PRs when a
  resource drifts again with a new fingerprint.
- **Drift fingerprint** = sha256 of the plan's before/after attribute set
  (sorted keys), so attribute ordering doesn't create duplicates.

## Offline tests

```
cd agent && python -m pytest . -q
```

No AWS, no API keys. The suite covers the decision logic, fingerprinting,
deduplication, threshold guard, and the gate's per-resource assertions
against real plan JSON fixtures.

## License

MIT — see [LICENSE](LICENSE).
