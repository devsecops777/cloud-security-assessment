output "load_balancer_ip" {
  description = "Create an A record for your domain pointing at this address."
  value       = module.secure_web_stack.load_balancer_ip
}

output "load_balancer_url" {
  value = module.secure_web_stack.load_balancer_url
}

output "instance_internal_ip" {
  value = module.secure_web_stack.instance_internal_ip
}

output "instance_service_account" {
  value = module.secure_web_stack.instance_service_account
}

output "firewall_rules" {
  value = module.secure_web_stack.firewall_rules
}

output "ssh_command" {
  value = module.secure_web_stack.ssh_command
}
