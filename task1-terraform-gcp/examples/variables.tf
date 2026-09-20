variable "project_id" {
  description = "GCP project ID to deploy into."
  type        = string
}

variable "region" {
  description = "Deployment region."
  type        = string
  default     = "us-central1"
}

variable "zone" {
  description = "Deployment zone, inside var.region."
  type        = string
  default     = "us-central1-a"
}

variable "ssl_domains" {
  description = "Domains for the Google-managed certificate. DNS must point at the load balancer IP before the certificate can become ACTIVE."
  type        = list(string)
  default     = ["app.example.com"]
}

variable "iap_ssh_members" {
  description = "Principals allowed to SSH through IAP, e.g. [\"user:alice@example.com\"]."
  type        = list(string)
  default     = []
}
