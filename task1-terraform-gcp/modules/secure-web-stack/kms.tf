data "google_project" "this" {
  project_id = var.project_id
}

resource "google_kms_key_ring" "this" {
  project  = var.project_id
  name     = "${var.name_prefix}-keyring"
  location = var.region
}

resource "google_kms_crypto_key" "boot_disk" {
  name     = "${var.name_prefix}-boot-disk"
  key_ring = google_kms_key_ring.this.id
  purpose  = "ENCRYPT_DECRYPT"

  # 90 days. Rotation re-encrypts new data only; existing disks keep the key
  # version they were created with, which is why rotation is a containment
  # measure rather than a cure.
  rotation_period = "7776000s"

  lifecycle {
    prevent_destroy = true
  }
}

resource "google_kms_crypto_key_iam_member" "compute" {
  crypto_key_id = google_kms_crypto_key.boot_disk.id
  role          = "roles/cloudkms.cryptoKeyEncrypterDecrypter"
  member        = "serviceAccount:service-${data.google_project.this.number}@compute-system.iam.gserviceaccount.com"
}
