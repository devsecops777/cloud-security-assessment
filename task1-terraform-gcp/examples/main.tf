terraform {
  required_version = ">= 1.5.0"

  required_providers {
    google = {
      source  = "hashicorp/google"
      version = ">= 5.0.0, < 7.0.0"
    }
  }

  # Remote state holds resource metadata and should be treated as sensitive:
  # a versioned, encrypted, non-public bucket with uniform bucket-level access.
  #
  # backend "gcs" {
  #   bucket = "my-tfstate-bucket"
  #   prefix = "secure-web-stack"
  # }
}

provider "google" {
  project = var.project_id
  region  = var.region
}

module "secure_web_stack" {
  source = "../modules/secure-web-stack"

  project_id  = var.project_id
  region      = var.region
  zone        = var.zone
  name_prefix = "secure-web"

  public_subnet_cidr  = "10.10.0.0/24"
  private_subnet_cidr = "10.10.1.0/24"

  # Administrative access via Identity-Aware Proxy: no public SSH surface, and
  # authorisation is an IAM decision rather than a key on disk.
  ssh_access_mode = "iap"
  iap_ssh_members = var.iap_ssh_members

  # To use a classic allow-list instead, swap the two lines above for:
  #   ssh_access_mode   = "trusted_cidr"
  #   trusted_ssh_cidrs = ["203.0.113.0/24"]   # 0.0.0.0/0 is rejected at plan time

  ssl_domains        = var.ssl_domains
  enable_cloud_armor = true

  labels = {
    environment = "assessment"
    owner       = "cloud-security"
  }
}
