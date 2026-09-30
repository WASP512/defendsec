output "user_data" {
  description = "First-boot script for the chosen platform. Contains the enroll secret."
  value       = var.platform == "windows" ? local.windows : local.linux
  sensitive   = true
}
