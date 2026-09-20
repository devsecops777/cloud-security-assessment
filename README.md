# Cloud Security Engineer — Technical Assessment

Four scenario answers: a hardened GCP Terraform module, a CloudFormation and
Dockerfile security review, a multi-cloud open-firewall scanner in Go, and a
dependency audit with automated reporting.

Everything here was executed, not just written. Each task's README shows the
commands and their real output.

| Task | Deliverable | Verified by |
|---|---|---|
| [1 — Secure GCP infrastructure](task1-terraform-gcp/) | Terraform module: VPC with public/private subnets, private Compute Engine instance, global HTTPS load balancer, firewall policy, least-privilege IAM | `terraform validate` against the real `hashicorp/google` provider, `terraform fmt -recursive -check` clean, the anti-`0.0.0.0/0` SSH guard demonstrated rejecting both `0.0.0.0/0` and the `0.0.0.0/1` + `128.0.0.0/1` bypass |
| [2 — Cloud security check](task2-cloud-security-check/) | 7 CloudFormation findings + 9 Dockerfile findings, hardened rewrites of both, and the controls that keep them out | Checkov **13 → 0** on the template, **3 → 0** on the Dockerfile, hadolint 5 → 0, cfn-lint clean |
| [3 — `cloudscan`](task3-go-cloud-scanner/) | Go CLI scanning AWS, GCP and Azure for rules open to `0.0.0.0/0`, emitting the required JSON | `go build`, `go vet`, `go test` all clean, golden test asserts the output schema byte for byte, 78% coverage on the detection layer |
| [4 — Dependency audit](task4-dependency-audit/) | `npm audit` analysis, remediation, and a Python reporter that emits CSV/JSON and gates CI | **23 vulnerabilities → 0**, measured, every remediation tier run and counted |