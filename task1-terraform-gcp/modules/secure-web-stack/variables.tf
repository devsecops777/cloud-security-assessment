variable "project_id" {
  description = "GCP project ID the stack is deployed into."
  type        = string
}

variable "region" {
  type    = string
  default = "us-central1"
}

variable "zone" {
  description = "Zone for the Compute Engine instance. Must be inside var.region."
  type        = string
  default     = "us-central1-a"
}

variable "name_prefix" {
  description = "Prefix applied to every resource name."
  type        = string
  default     = "secure-web"
}

variable "public_subnet_cidr" {
  description = "Primary CIDR of the public subnet. Hosts internet-facing / egress infrastructure (Cloud NAT gateway path, optional bastion)."
  type        = string
  default     = "10.10.0.0/24"
}

variable "private_subnet_cidr" {
  description = "Primary CIDR of the private subnet that hosts the Compute Engine instance."
  type        = string
  default     = "10.10.1.0/24"
}

variable "trusted_ssh_cidrs" {
  description = <<-EOT
    Trusted source ranges allowed to reach TCP/22 on the instance. Used only when
    ssh_access_mode = "trusted_cidr". Internet-wide ranges are rejected.
  EOT
  type        = list(string)
  default     = []

  validation {
    # Two conditions, both necessary: a valid IPv4 CIDR, and a prefix of /16 or
    # narrower. The prefix check is what actually matters -- rejecting the
    # literal string "0.0.0.0/0" is trivially worked around with 0.0.0.0/1,
    # which together with 128.0.0.0/1 is still the whole internet.
    condition = alltrue([
      for cidr in var.trusted_ssh_cidrs :
      can(cidrnetmask(cidr)) && can(regex("/(1[6-9]|2[0-9]|3[0-2])$", cidr))
    ])
    error_message = "trusted_ssh_cidrs entries must be valid IPv4 CIDRs of /16 or narrower. 0.0.0.0/0 and other internet-wide ranges are not permitted for SSH."
  }
}

variable "ssh_access_mode" {
  description = <<-EOT
    How administrative SSH reaches the private instance:
      - "iap"          : Identity-Aware Proxy TCP forwarding only (35.235.240.0/20). Recommended, no public SSH surface at all.
      - "trusted_cidr" : classic allow-list, requires a non-empty trusted_ssh_cidrs.
      - "none"         : no SSH ingress rule is created at all.
  EOT
  type        = string
  default     = "iap"
}

variable "machine_type" {
  type    = string
  default = "e2-micro"
}

variable "boot_disk_type" {
  type    = string
  default = "pd-standard"
}

variable "boot_disk_size_gb" {
  type    = number
  default = 30
}

variable "boot_image" {
  description = "Boot image for the instance."
  type        = string
  default     = "debian-cloud/debian-12"
}

variable "ssl_domains" {
  description = <<-EOT
    Domains for the Google-managed SSL certificate fronting the load balancer.
    Leave empty and set ssl_certificate_self_links instead if you manage certificates yourself.
  EOT
  type        = list(string)
  default     = []
}

variable "ssl_certificate_self_links" {
  description = "Self links of pre-existing SSL certificates to attach to the HTTPS proxy. Takes precedence over ssl_domains."
  type        = list(string)
  default     = []
}

variable "iap_ssh_members" {
  description = "IAM members (user:, group:, serviceAccount:) granted IAP tunnel access to the instance when ssh_access_mode = \"iap\"."
  type        = list(string)
  default     = []
}

variable "enable_cloud_armor" {
  description = "Attach a baseline Cloud Armor policy (pre-configured OWASP rules + default deny for unlisted abuse) to the backend service."
  type        = bool
  default     = true
}

variable "labels" {
  description = "Labels applied to every resource that supports them."
  type        = map(string)
  default     = {}
}

variable "enable_restrictive_egress" {
  type    = bool
  default = true
}
