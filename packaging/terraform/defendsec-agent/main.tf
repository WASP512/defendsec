# DefendSec agent enrollment as instance user data (roadmap 5.6).
#
# This module renders the script a new instance runs at first boot to install
# and enroll the agent. It creates no cloud resources, so it works with any
# provider that takes user data: pass `user_data` to aws_instance,
# azurerm_linux_virtual_machine (custom_data, base64-encoded),
# google_compute_instance (metadata startup-script), and so on.

locals {
  download_base = var.download_base != "" ? trimsuffix(var.download_base, "/") : "https://${var.server}:47261/downloads"

  linux = templatefile("${path.module}/templates/linux.sh.tftpl", {
    server        = var.server
    enroll_secret = var.enroll_secret
    download_base = local.download_base
    console_ca    = var.console_ca_pem
    http_port     = var.http_port
    grpc_port     = var.grpc_port
  })

  windows = templatefile("${path.module}/templates/windows.ps1.tftpl", {
    server        = var.server
    enroll_secret = var.enroll_secret
    download_base = local.download_base
    console_ca    = var.console_ca_pem
    http_port     = var.http_port
    grpc_port     = var.grpc_port
  })
}
