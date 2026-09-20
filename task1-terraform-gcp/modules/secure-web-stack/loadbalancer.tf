resource "google_compute_health_check" "web" {
  project             = var.project_id
  name                = "${var.name_prefix}-hc"
  check_interval_sec  = 10
  timeout_sec         = 5
  healthy_threshold   = 2
  unhealthy_threshold = 3

  http_health_check {
    port_name    = "http"
    request_path = "/"
  }

  log_config {
    enable = true
  }
}

resource "google_compute_security_policy" "web" {
  count = var.enable_cloud_armor ? 1 : 0

  project     = var.project_id
  name        = "${var.name_prefix}-armor"
  description = "Baseline WAF: OWASP pre-configured SQLi/XSS/LFI rules plus adaptive L7 DDoS protection."

  rule {
    action   = "deny(403)"
    priority = 1000

    match {
      expr {
        expression = "evaluatePreconfiguredExpr('sqli-v33-stable')"
      }
    }

    description = "Block SQL injection signatures."
  }

  rule {
    action   = "deny(403)"
    priority = 1001

    match {
      expr {
        expression = "evaluatePreconfiguredExpr('xss-v33-stable')"
      }
    }

    description = "Block cross-site scripting signatures."
  }

  rule {
    action   = "deny(403)"
    priority = 1002

    match {
      expr {
        expression = "evaluatePreconfiguredExpr('lfi-v33-stable')"
      }
    }

    description = "Block local file inclusion signatures."
  }

  rule {
    action   = "allow"
    priority = 2147483647

    match {
      versioned_expr = "SRC_IPS_V1"

      config {
        src_ip_ranges = ["*"]
      }
    }

    description = "Default rule: allow traffic that matched no deny rule."
  }

  adaptive_protection_config {
    layer_7_ddos_defense_config {
      enable = true
    }
  }
}

resource "google_compute_backend_service" "web" {
  project     = var.project_id
  name        = "${var.name_prefix}-backend"
  protocol    = "HTTP"
  port_name   = "http"
  timeout_sec = 30

  load_balancing_scheme = "EXTERNAL_MANAGED"
  health_checks         = [google_compute_health_check.web.id]
  security_policy       = var.enable_cloud_armor ? google_compute_security_policy.web[0].id : null

  backend {
    group           = google_compute_instance_group.web.id
    balancing_mode  = "UTILIZATION"
    capacity_scaler = 1.0
  }

  log_config {
    enable      = true
    sample_rate = 1.0
  }
}

resource "google_compute_url_map" "web" {
  project         = var.project_id
  name            = "${var.name_prefix}-urlmap"
  default_service = google_compute_backend_service.web.id
}

resource "google_compute_managed_ssl_certificate" "web" {
  count = length(var.ssl_certificate_self_links) == 0 ? 1 : 0

  project = var.project_id
  name    = "${var.name_prefix}-cert"

  managed {
    domains = var.ssl_domains
  }

  lifecycle {
    precondition {
      condition     = length(var.ssl_domains) > 0
      error_message = "Set ssl_domains (for a Google-managed certificate) or ssl_certificate_self_links (to bring your own)."
    }
  }
}

# Refuse obsolete protocol versions and cipher suites at the edge.
resource "google_compute_ssl_policy" "web" {
  project         = var.project_id
  name            = "${var.name_prefix}-ssl-policy"
  profile         = "RESTRICTED"
  min_tls_version = "TLS_1_2"
}

resource "google_compute_target_https_proxy" "web" {
  project = var.project_id
  name    = "${var.name_prefix}-https-proxy"
  url_map = google_compute_url_map.web.id

  ssl_certificates = length(var.ssl_certificate_self_links) > 0 ? var.ssl_certificate_self_links : [google_compute_managed_ssl_certificate.web[0].id]
  ssl_policy       = google_compute_ssl_policy.web.id
}

resource "google_compute_global_address" "web" {
  project      = var.project_id
  name         = "${var.name_prefix}-ip"
  ip_version   = "IPV4"
  address_type = "EXTERNAL"
}

resource "google_compute_global_forwarding_rule" "https" {
  project    = var.project_id
  name       = "${var.name_prefix}-https-fr"
  target     = google_compute_target_https_proxy.web.id
  ip_address = google_compute_global_address.web.id
  port_range = "443"
  labels     = var.labels

  load_balancing_scheme = "EXTERNAL_MANAGED"
}
