output "network_id" {
  description = "Self link of the VPC network."
  value       = google_compute_network.this.id
}

output "public_subnet" {
  description = "Name and CIDR of the public subnet."
  value = {
    name = google_compute_subnetwork.public.name
    cidr = google_compute_subnetwork.public.ip_cidr_range
  }
}

output "private_subnet" {
  description = "Name and CIDR of the private subnet hosting the workload."
  value = {
    name = google_compute_subnetwork.private.name
    cidr = google_compute_subnetwork.private.ip_cidr_range
  }
}

output "instance_name" {
  description = "Name of the Compute Engine instance."
  value       = google_compute_instance.web.name
}

output "instance_internal_ip" {
  description = "Private address of the instance. There is no external address by design."
  value       = google_compute_instance.web.network_interface[0].network_ip
}

output "instance_service_account" {
  description = "Least-privilege service account the instance runs as."
  value       = google_service_account.instance.email
}

output "load_balancer_ip" {
  description = "Global anycast IP of the load balancer. Point your DNS A record here."
  value       = google_compute_global_address.web.address
}

output "load_balancer_url" {
  description = "Public URL once DNS resolves and the managed certificate is ACTIVE."
  value       = length(var.ssl_domains) > 0 ? "https://${var.ssl_domains[0]}" : "https://${google_compute_global_address.web.address}"
}

output "ssh_command" {
  description = "How to reach the instance for administration."
  value = var.ssh_access_mode == "iap" ? "gcloud compute ssh ${google_compute_instance.web.name} --zone ${var.zone} --project ${var.project_id} --tunnel-through-iap" : (
    var.ssh_access_mode == "trusted_cidr" ? "ssh from ${join(", ", var.trusted_ssh_cidrs)} to ${google_compute_instance.web.network_interface[0].network_ip}" : "SSH ingress is disabled (ssh_access_mode = \"none\")."
  )
}

output "firewall_rules" {
  description = "Names of the firewall rules created by the module, for review and drift checks."
  value = compact([
    google_compute_firewall.allow_lb_to_instance_http.name,
    try(google_compute_firewall.allow_ssh_iap[0].name, ""),
    try(google_compute_firewall.allow_ssh_trusted[0].name, ""),
    google_compute_firewall.deny_all_ingress.name,
    try(google_compute_firewall.allow_egress_web[0].name, ""),
    try(google_compute_firewall.deny_all_egress[0].name, ""),
  ])
}
