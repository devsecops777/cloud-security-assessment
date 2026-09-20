# secure-web-stack

Terraform module for an internet-facing web stack on GCP.

Creates a VPC with a public and a private subnet, a Compute Engine instance in
the private subnet with no external IP, a global HTTPS load balancer in front of
it, Cloud NAT for outbound access, and a dedicated least-privilege service
account. TCP/443 is the only port reachable from the internet, SSH goes through
Identity-Aware Proxy.

## Requirements

| | |
|---|---|
| Terraform | >= 1.5 |
| `hashicorp/google` | >= 5.0, < 7.0 |
| APIs | `compute`, `iam`, and `iap` when `ssh_access_mode = "iap"` |
| Project | billing enabled |

## Usage

```hcl
module "web" {
  source = "./modules/secure-web-stack"

  project_id  = "my-project"
  name_prefix = "secure-web"

  ssl_domains     = ["app.example.com"]
  ssh_access_mode = "iap"
  iap_ssh_members = ["user:you@example.com"]
}
```

After `apply`, create a DNS **A record** for your domain pointing at the
`load_balancer_ip` output. GCP does not give the load balancer a hostname, and
the Google-managed certificate stays in `PROVISIONING` until that record
resolves — typically 15–60 minutes.

## TLS

Set exactly one of these, or the plan fails on a precondition:

- **`ssl_domains`** — Google issues and renews a managed certificate. Requires a
  domain you control plus the DNS record above.
- **`ssl_certificate_self_links`** — bring your own certificate. Use this when
  you have no domain, or when certificates are issued outside this module.

## SSH access

| `ssh_access_mode` | Behaviour |
|---|---|
| `"iap"` *(default)* | Tunnel through IAP. No public SSH surface. Needs `iap_ssh_members` |
| `"trusted_cidr"` | Classic allow-list. Needs `trusted_ssh_cidrs`. `0.0.0.0/0` is rejected at plan time |
| `"none"` | No SSH ingress rule at all |

```bash
gcloud compute ssh <name_prefix>-app --zone <zone> --tunnel-through-iap
```

## Inputs

| Name | Type | Default | Description |
|---|---|---|---|
| `project_id` | `string` | — | **Required.** Project to deploy into |
| `region` | `string` | `"us-central1"` | Region for subnets, NAT and the instance |
| `zone` | `string` | `"us-central1-a"` | Zone for the instance, must be inside `region` |
| `name_prefix` | `string` | `"secure-web"` | Prefix for all resource names |
| `public_subnet_cidr` | `string` | `"10.10.0.0/24"` | Public subnet range |
| `private_subnet_cidr` | `string` | `"10.10.1.0/24"` | Private subnet range, hosts the instance |
| `ssh_access_mode` | `string` | `"iap"` | `iap` \| `trusted_cidr` \| `none` |
| `iap_ssh_members` | `list(string)` | `[]` | Principals allowed to SSH, e.g. `["user:a@b.com"]` |
| `trusted_ssh_cidrs` | `list(string)` | `[]` | Allow-list for `trusted_cidr` mode |
| `ssl_domains` | `list(string)` | `[]` | Domains for a Google-managed certificate |
| `ssl_certificate_self_links` | `list(string)` | `[]` | Existing certificates to attach instead |
| `machine_type` | `string` | `"e2-micro"` | Instance size. Burstable — raise for real traffic |
| `boot_disk_type` | `string` | `"pd-standard"` | Use `pd-balanced` in production |
| `boot_disk_size_gb` | `number` | `30` | Minimum 10 |
| `boot_image` | `string` | `"debian-cloud/debian-12"` | Boot image |
| `enable_cloud_armor` | `bool` | `true` | Attach a baseline WAF policy (chargeable) |
| `enable_restrictive_egress` | `bool` | `true` | Egress allow-list plus a logged deny-all |
| `enable_http_to_https_redirect` | `bool` | `false` | Add a port-80 frontend that only redirects |
| `labels` | `map(string)` | `{}` | Labels applied where supported |

## Outputs

| Name | Description |
|---|---|
| `load_balancer_ip` | Anycast IP. Point your DNS A record here |
| `load_balancer_url` | Public URL once DNS and the certificate are ready |
| `ssh_command` | Ready-to-run command for the configured access mode |
| `instance_name` | Name of the Compute Engine instance |
| `instance_internal_ip` | Private address of the instance |
| `instance_service_account` | Service account the instance runs as |
| `network_id` | VPC self link |
| `public_subnet` / `private_subnet` | Name and CIDR of each subnet |
| `firewall_rules` | Names of the rules created, for review |

## Example

A working root configuration lives in [`examples/`](examples/).