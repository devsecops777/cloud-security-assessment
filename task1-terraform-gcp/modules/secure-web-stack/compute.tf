resource "google_compute_instance" "web" {
  project      = var.project_id
  name         = "${var.name_prefix}-app"
  machine_type = var.machine_type
  zone         = var.zone
  tags         = [local.web_tag]
  labels       = var.labels

  boot_disk {
    auto_delete = true

    initialize_params {
      image  = var.boot_image
      type   = var.boot_disk_type
      size   = var.boot_disk_size_gb
      labels = var.labels
    }
  }

  network_interface {
    subnetwork = google_compute_subnetwork.private.id
  }

  shielded_instance_config {
    enable_secure_boot          = true
    enable_vtpm                 = true
    enable_integrity_monitoring = true
  }

  # confidential_instance_config {
  #   enable_confidential_compute = true
  # }

  service_account {
    email  = google_service_account.instance.email
    scopes = ["https://www.googleapis.com/auth/cloud-platform"]
  }

  metadata = {
    enable-oslogin         = "TRUE"
    block-project-ssh-keys = "TRUE"
    serial-port-enable     = "FALSE"
  }

  metadata_startup_script = <<-EOT
    #!/bin/bash
    set -euo pipefail
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -y
    apt-get install -y nginx curl gnupg
    cat >/var/www/html/index.html <<'HTML'
    <!doctype html><title>secure-web-stack</title>
    <h1>Backend healthy</h1>
    HTML
    systemctl enable --now nginx

    install -m 0755 -d /usr/share/keyrings
    curl -fsSL https://packages.cloud.google.com/apt/doc/apt-key.gpg | gpg --dearmor -o /usr/share/keyrings/cloud.google.gpg
    CODENAME=$(. /etc/os-release && echo "$VERSION_CODENAME")
    echo "deb [signed-by=/usr/share/keyrings/cloud.google.gpg] https://packages.cloud.google.com/apt google-cloud-ops-agent-$CODENAME-all main" > /etc/apt/sources.list.d/google-cloud-ops-agent.list
    apt-get update -y
    apt-get install -y google-cloud-ops-agent
    systemctl enable --now google-cloud-ops-agent
  EOT

  # allow_stopping_for_update = true
}

resource "google_compute_instance_group" "web" {
  project   = var.project_id
  name      = "${var.name_prefix}-ig"
  zone      = var.zone
  network   = google_compute_network.this.id
  instances = [google_compute_instance.web.self_link]

  named_port {
    name = "http"
    port = 80
  }
}
