locals {
  # Google Front End ranges that originate both load balancer traffic and
  # health checks for global external HTTP(S) load balancers. These are the
  # only sources that may reach the instance on port 80.
  gfe_ranges = ["130.211.0.0/22", "35.191.0.0/16"]

  # Fixed range used by Identity-Aware Proxy TCP forwarding.
  iap_range = ["35.235.240.0/20"]

  web_tag = "${var.name_prefix}-web"
}

resource "google_compute_firewall" "allow_lb_to_instance_http" {
  project     = var.project_id
  name        = "${var.name_prefix}-allow-http-from-lb"
  network     = google_compute_network.this.name
  description = "Allow HTTP/80 from Google Front Ends (load balancer + health checks) to tagged web instances."
  direction   = "INGRESS"
  priority    = 1000

  source_ranges = local.gfe_ranges
  target_tags   = [local.web_tag]

  allow {
    protocol = "tcp"
    ports    = ["80"]
  }

  log_config {
    metadata = "INCLUDE_ALL_METADATA"
  }
}

resource "google_compute_firewall" "allow_ssh_iap" {
  count = var.ssh_access_mode == "iap" ? 1 : 0

  project     = var.project_id
  name        = "${var.name_prefix}-allow-ssh-iap"
  network     = google_compute_network.this.name
  description = "Allow SSH/22 from the Identity-Aware Proxy TCP forwarding range only."
  direction   = "INGRESS"
  priority    = 1000

  source_ranges = local.iap_range
  target_tags   = [local.web_tag]

  allow {
    protocol = "tcp"
    ports    = ["22"]
  }

  log_config {
    metadata = "INCLUDE_ALL_METADATA"
  }
}

resource "google_compute_firewall" "allow_ssh_trusted" {
  count = var.ssh_access_mode == "trusted_cidr" ? 1 : 0

  project     = var.project_id
  name        = "${var.name_prefix}-allow-ssh-trusted"
  network     = google_compute_network.this.name
  description = "Allow SSH/22 from the allow-list only."
  direction   = "INGRESS"
  priority    = 1000

  source_ranges = var.trusted_ssh_cidrs
  target_tags   = [local.web_tag]

  allow {
    protocol = "tcp"
    ports    = ["22"]
  }

  log_config {
    metadata = "INCLUDE_ALL_METADATA"
  }
}

resource "google_compute_firewall" "deny_all_ingress" {
  project     = var.project_id
  name        = "${var.name_prefix}-deny-all-ingress"
  network     = google_compute_network.this.name
  description = "Explicit, logged catch-all deny for ingress that no allow rule matched."
  direction   = "INGRESS"
  priority    = 65000

  source_ranges = ["0.0.0.0/0"]

  deny {
    protocol = "all"
  }

  log_config {
    metadata = "INCLUDE_ALL_METADATA"
  }
}

resource "google_compute_firewall" "allow_egress_web" {
  count = var.enable_restrictive_egress ? 1 : 0

  project     = var.project_id
  name        = "${var.name_prefix}-allow-egress-web"
  network     = google_compute_network.this.name
  description = "Allow outbound TCP/80 and TCP/443 (OS patching, Google APIs) from tagged web instances."
  direction   = "EGRESS"
  priority    = 1000

  destination_ranges = ["0.0.0.0/0"]
  target_tags        = [local.web_tag]

  allow {
    protocol = "tcp"
    ports    = ["80", "443"]
  }

  log_config {
    metadata = "INCLUDE_ALL_METADATA"
  }
}

resource "google_compute_firewall" "deny_all_egress" {
  count = var.enable_restrictive_egress ? 1 : 0

  project     = var.project_id
  name        = "${var.name_prefix}-deny-all-egress"
  network     = google_compute_network.this.name
  description = "Deny every outbound flow that the allow-list did not permit."
  direction   = "EGRESS"
  priority    = 65000

  destination_ranges = ["0.0.0.0/0"]

  deny {
    protocol = "all"
  }

  log_config {
    metadata = "INCLUDE_ALL_METADATA"
  }
}
