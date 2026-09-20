resource "google_service_account" "instance" {
  project      = var.project_id
  account_id   = "${var.name_prefix}-vm"
  display_name = "${var.name_prefix} web instance"
  description  = "Runtime identity for the ${var.name_prefix} Compute Engine instance. Telemetry write access only."
}

locals {
  instance_roles = [
    "roles/logging.logWriter",                  # append log entries, cannot read them back
    "roles/monitoring.metricWriter",            # write time series, cannot read or delete
    "roles/stackdriver.resourceMetadata.writer" # lets the Ops Agent describe the VM
  ]
}

resource "google_project_iam_member" "instance" {
  for_each = toset(local.instance_roles)

  project = var.project_id
  role    = each.value
  member  = "serviceAccount:${google_service_account.instance.email}"
}

resource "google_compute_instance_iam_member" "os_login" {
  for_each = var.ssh_access_mode == "none" ? toset([]) : toset(var.iap_ssh_members)

  project       = var.project_id
  zone          = var.zone
  instance_name = google_compute_instance.web.name
  role          = "roles/compute.osLogin" # unprivileged shell, not osAdminLogin (no sudo)
  member        = each.value
}

resource "google_iap_tunnel_instance_iam_member" "ssh" {
  for_each = var.ssh_access_mode == "iap" ? toset(var.iap_ssh_members) : toset([])

  project  = var.project_id
  zone     = var.zone
  instance = google_compute_instance.web.name
  role     = "roles/iap.tunnelResourceAccessor"
  member   = each.value
}
