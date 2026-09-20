# Task 2 — Cloud Security Check

```
vulnerable/   the template and Dockerfile exactly as supplied
hardened/     the rewritten versions 
prevention/   the controls that stop this class of change reaching an account
```

## Part A — CloudFormation template

### The findings

The brief asks for at least three. There are seven worth naming, ordered by how
much damage each one does.

**1. `Action: "*"` on `Resource: "*"` — critical.**
This is `AdministratorAccess` written by hand. The principal can read every
bucket, mint new users, disable CloudTrail, and delete the account's backups. It
also silently grants permissions to services adopted a year from now. Least
privilege is not a nicety here: this single statement makes every other control
in the account advisory.
*Fix:* name the actions and scope them to ARNs. In `hardened/template.yaml` the
role gets `s3:GetObject`/`PutObject` on one bucket prefix and `kms:Decrypt`
/`GenerateDataKey` on one key, with a `kms:ViaService` condition so the key
cannot be used outside S3.

**2. An IAM *user* rather than a role — critical.**
A user implies a long-lived access key. Keys get committed to Git, baked into
images, pasted into CI variables, and they do not expire. Combined with finding
1, one leaked string is full account compromise, and rotation is a manual chore
nobody schedules.
*Fix:* `AWS::IAM::Role` with an `AssumeRolePolicyDocument`. Credentials become
short-lived STS sessions, the trust policy names exactly who may assume it and
requires MFA. Workloads use instance profiles/IRSA, CI uses OIDC federation,
humans use IAM Identity Center. No key material exists to leak.

**3. `UserName: "UnrestrictedUser"` hardcoded — high (structural).**
A physical name makes the stack un-deployable twice (name collision), blocks
blue/green replacement, and forces `CAPABILITY_NAMED_IAM`. The name also
advertises the principal's value to anyone reading the template.
*Fix:* let CloudFormation generate the name, or derive it from a parameter as
the hardened template does.

**4. The S3 bucket has no `PublicAccessBlockConfiguration` — high.**
The bucket is private *today*, but nothing stops a future `PutBucketAcl` or a
policy change from making it world-readable — which is precisely how the
well-known S3 breaches happened. Note that findings 1 and 4 compose: the
wildcard user is allowed to run exactly that call.
*Fix:* all four block flags true, plus `ObjectOwnership: BucketOwnerEnforced`,
which disables ACLs outright.

**5. No encryption configuration — high.**
Objects land with whatever default applies. There is no customer-managed key, so
no independent revocation lever, no key rotation policy of our own, and no
`kms:` entries in CloudTrail tying data access to a key grant.
*Fix:* SSE-KMS with a CMK that has `EnableKeyRotation: true`, plus a bucket
policy that *denies* uploads not encrypted with that specific key — configuration
sets the default, the policy makes it mandatory.

**6. No versioning, no lifecycle, no access logging — medium.**
An overwrite or a delete is unrecoverable, incomplete multipart uploads
accumulate as invisible cost, and there is no record of who read what. After an
incident, "we cannot tell what was accessed" is the worst possible answer.
*Fix:* versioning on, server access logging to a separate bucket, lifecycle
rules for noncurrent versions and aborted uploads.

**7. No TLS enforcement, no `DeletionPolicy` — medium.**
Without an `aws:SecureTransport` deny, plain HTTP requests are accepted. Without
`DeletionPolicy: Retain`, `cloudformation delete-stack` — or a failed update
rollback — takes the data with it.
*Fix:* both are in the hardened template, the KMS key carries `Retain` too, since
deleting the key destroys the objects just as effectively.

### The improved template

`hardened/template.yaml`. Beyond fixing the above: a separate log bucket (so the
data path cannot erase its own audit trail), a `BucketKeyEnabled` setting that
cuts KMS request cost, an optional `aws:SourceVpce` condition to confine access
to a VPC endpoint, and a documented Checkov skip on the log bucket — a log
destination cannot log to itself, and the honest way to handle that is an
annotated exception rather than a silenced scanner.

### Finding this in a live account

Full runbook in `prevention/detect-and-remediate.md`. In short: the IAM
credential report and `get-account-authorization-details` enumerate wildcard
policies and key-bearing users, IAM Access Analyzer finds externally reachable
resources and can *generate* a least-privilege policy from CloudTrail history,
AWS Config rules (`iam-policy-no-statements-with-admin-access`,
`iam-user-no-policies-check`, `s3-bucket-public-read-prohibited`) turn that into
standing detection, Security Hub aggregates across accounts.

---

## Part B — Dockerfile

### The issues

**1. `FROM ubuntu:latest` — high.**
Tags are mutable, so the build is not reproducible and a rebuild can silently
change the OS. `latest` also drags in a general-purpose distro when the app needs
an interpreter: hundreds of extra packages, every one a CVE source.
*Fix:* a pinned slim base (`python:3.12.7-slim-bookworm`), ideally pinned by
digest. Distroless or Alpine goes further where the dependency set allows it.

**2. The container runs as root — high.**
No `USER` instruction means UID 0. A remote code execution in `app.py` is then
root inside the container.
*Fix:* create a fixed-UID account (10001) and `USER 10001:10001` before `CMD`.


**3. `COPY . /app` copies the entire build context — high.**
`.git` (full history, including secrets deleted in a later commit), `.env`,
`*.pem`, `~/.aws/credentials`, `node_modules`, `terraform.tfstate` — all of it
ships inside the image, readable by anyone who can pull it. Deleting a file in a
later layer does not remove it, it stays in the layer beneath.
*Fix:* an allow-list `.dockerignore` (`*` then `!app/`) and copying only what the
stage needs. `hardened/.dockerignore` does both.

**4. `apt-get install` with no version pins, no `--no-install-recommends`, and no cache cleanup — medium.**
Unpinned versions make the image non-reproducible, recommends pull in packages
nobody asked for, leaving `/var/lib/apt/lists` behind inflates the image with
metadata that is also a useful map for an attacker.
*Fix:* `--no-install-recommends`, `apt-get clean`,
`rm -rf /var/lib/apt/lists/*`, all in the same `RUN` so the cache never becomes a
layer. Pin versions where the base distro's package set is stable enough.

**5. Shell-form `CMD python3 app.py` — medium.**
The process runs under `/bin/sh -c`, so PID 1 is the shell. It does not forward
`SIGTERM`, so `docker stop` and Kubernetes pod termination hang for the full
grace period and then `SIGKILL` — no clean shutdown, no connection draining.
*Fix:* exec form, `CMD ["python3", "/app/app.py"]`.

**6. No `HEALTHCHECK` — medium.**
The orchestrator cannot tell "process alive" from "process serving". A wedged
app stays in rotation.
*Fix:* a `HEALTHCHECK` hitting `/healthz` (which the sample app implements).

**7. Single stage, build tooling in the runtime image — medium.**
`pip`, compilers and headers remain in the shipped image, handing an attacker a
build environment inside the container and enlarging the CVE surface.
*Fix:* multi-stage — dependencies are built into a venv in the builder stage and
only the venv is copied forward.

**8. No integrity verification of dependencies — medium.**
`pip install` without `--require-hashes` trusts whatever the index serves, which
is the supply-chain attack path (typosquatting, a compromised index, a yanked-
and-republished version).
*Fix:* `--require-hashes` against a `pip-compile --generate-hashes` manifest.

**9. Application files writable by the runtime user — low.**
Default ownership lets a compromised process rewrite its own code and persist.
*Fix:* `COPY --chown=root:root --chmod=0444`, so the app can read its code but
not modify it. Pair with `docker run --read-only`.

### Runtime, not just build time

The image is half the control. The other half is how it is run:
`--user 10001:10001 --read-only --cap-drop=ALL --security-opt=no-new-privileges`,
a tmpfs for scratch, and in Kubernetes a `securityContext` with
`allowPrivilegeEscalation: false`, `runAsNonRoot: true`,
`readOnlyRootFilesystem: true`, enforced by Pod Security Admission or Kyverno.

---

## Part C — Preventing this from being introduced

By applying the principle of defence in deph it is possible to apply security on every layer.

| # | Gate | Control | Catches |
|---|---|---|---|
| 1 | Developer machine | `prevention/.pre-commit-config.yaml` — checkov, cfn-lint, hadolint, gitleaks, terraform fmt/validate/tflint | Most of it, in seconds, before a commit exists |
| 2 | Pull request | `.github/workflows/security.yml` — the same scanners plus Trivy image/filesystem scanning, results uploaded as SARIF to code scanning. **Required status check**, so a red run blocks merge | Anything committed anyway, puts findings inline on the diff |
| 3 | Deploy pipeline | `cfn-guard validate` against `prevention/s3-iam.guard`, `terraform plan` reviewed by OPA, security approval for IAM changes | Org-specific rules a vendor scanner does not know |
| 4 | The account itself | `prevention/scp-guardrails.json` SCPs, CloudFormation Hooks running the same Guard rules server-side, org policies | Everything above, *including changes made in the console* this is the only gate a human cannot skip |
| 5 | Runtime | AWS Config rules + Security Hub + GuardDuty or a CSPM solution like Wiz, auto-remediation via EventBridge → SSM | Drift, manual edits, and anything created before the gates existed |

Two points worth making explicitly:

- **Gates 1–3 are advisory, gate 4 is authority.** CI can be skipped with
  `--no-verify`, a pipeline can be bypassed by an engineer with console access.
  An SCP removes the permission itself. Controls that only live in CI are
  suggestions.
- **Exceptions must be visible.** The documented `checkov:skip` on the log bucket
  is the pattern: an annotated, reviewable exception with a reason attached,
  rather than a check quietly removed from the config. If a suppression has no
  justification in the diff, it should fail review.

Supporting practices: `CODEOWNERS` routing IaC and IAM changes to the security
team, golden modules (Task 1's module is one) so teams inherit hardened defaults
instead of writing firewall rules by hand, a base-image registry with signed,
scanned images and a rebuild cadence, and drift detection that alerts when
deployed state diverges from the repository.
