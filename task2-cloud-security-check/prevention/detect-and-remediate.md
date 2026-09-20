# Finding misconfigurations like these in a live account

## 1. Find it

| Signal | Query / tool | What it tells you |
|---|---|---|
| IAM credential report | `aws iam generate-credential-report` then `get-credential-report` | Every user, whether it has access keys, key age, MFA status, last use. `UnrestrictedUser` shows up as a key-bearing user with no MFA |
| Wildcard policies | `aws accessanalyzer start-policy-generation` / `aws iam get-account-authorization-details` piped through `jq 'select(.Action=="*")'` | Every inline and attached policy that grants `*` on `*` |
| What it actually used | IAM Access Advisor (`aws iam get-service-last-accessed-details`) | Services the principal genuinely touched in the last 400 days. This is the evidence base for writing the replacement policy |
| External exposure | IAM Access Analyzer (account + org analyzers) | Buckets, roles and keys reachable from outside the trust zone |
| Continuous config drift | AWS Config managed rules: `iam-policy-no-statements-with-admin-access`, `iam-user-no-policies-check`, `s3-bucket-public-read-prohibited`, `s3-bucket-server-side-encryption-enabled`, `access-keys-rotated` | Standing detection with a compliance timeline, not a point-in-time scan |
| Aggregated posture | Security Hub with the AWS Foundational Security Best Practices and CIS standards enabled | Cross-account, deduplicated, severity-scored |
| Behavioural | GuardDuty findings, CloudTrail `ConsoleLogin` without MFA, `AssumeRole` from unusual ASNs | Tells you whether the exposure was merely present or actually exercised |
| Point-in-time audit | `prowler aws -c iam_policy_no_administrative_privileges` or ScoutSuite | Fast, scriptable, good for an engagement report |


## 2. Judge the blast radius before touching it

CloudTrail answers what the key actually did. Look up the last 90 days for the
principal, group by `eventSource`/`eventName`, and check whether anything
production depends on it. An admin key that has only ever called `s3:GetObject`
is a one-line fix, one that runs a deploy pipeline needs a migration window.

## 3. Fix it, in this order

1. **Contain.** Attach an inline deny or move the user into a group with a deny-all
   boundary, rather than deleting immediately. Deletion destroys evidence and can
   break a caller you have not identified yet.
2. **Deactivate, do not delete, the access key** (`aws iam update-access-key
   --status Inactive`). Reversible in one command if something breaks.
3. **Replace the identity.** A role assumed by the workload (instance profile,
   IRSA, or OIDC for CI) removes the long-lived key entirely. If a human needs
   access, that is IAM Identity Center with MFA.
4. **Right-size the policy** from the Access Advisor data, plus an Access
   Analyzer *policy generation* run over CloudTrail — it drafts a least-privilege
   policy from observed calls. Review the draft, it is a starting point, not an
   answer.
5. **Attach a permissions boundary** to the new role so a future edit cannot
   re-widen it beyond the boundary.
6. **Rotate anything the key could reach.** Assume compromise: an admin key that
   existed in a repo or a container image is compromised until proven otherwise.
7. **Delete the user** once telemetry shows zero use for a full billing cycle.
8. **Close the loop** — add the Config rule and the SCP so the same shape cannot
   return, then confirm the finding auto-closes in Security Hub.

## 4. Automate the remediation

AWS Config rule → EventBridge → SSM Automation document or Lambda. Useful
pairings:

| Detection | Automatic response |
|---|---|
| `s3-bucket-public-read-prohibited` non-compliant | SSM `AWS-DisableS3BucketPublicReadWrite` |
| `iam-policy-no-statements-with-admin-access` non-compliant | Lambda detaches the policy, opens a ticket, pages the owner |
| `access-keys-rotated` non-compliant | Lambda deactivates the key at 90 days, deletes at 120 |
| GuardDuty `UnauthorizedAccess:IAMUser/*` | Step Functions: quarantine policy, revoke sessions, snapshot evidence |

Auto-remediation that can itself cause an outage should start in
dry-run/notify-only mode and be promoted once the false-positive rate is known.
