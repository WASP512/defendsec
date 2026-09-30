variable "server" {
  description = "Hostname or IP of the DefendSec server. Must match its certificate."
  type        = string
  validation {
    condition     = can(regex("^[A-Za-z0-9.:-]+$", var.server))
    error_message = "server must be a hostname or IP address."
  }
}

variable "enroll_secret" {
  description = "The enroll secret from the console's Enroll page."
  type        = string
  sensitive   = true
  validation {
    condition     = can(regex("^[A-Za-z0-9._~-]{8,256}$", var.enroll_secret))
    error_message = "enroll_secret must be 8-256 URL-safe characters."
  }
}

variable "platform" {
  description = "linux or windows: which user-data script to render."
  type        = string
  default     = "linux"
  validation {
    condition     = contains(["linux", "windows"], var.platform)
    error_message = "platform must be linux or windows."
  }
}

variable "console_ca_pem" {
  description = "PEM of the console certificate (/var/lib/defendsec/tls/console.crt) when it is self-signed. Downloads are verified against it; there is no option to skip verification."
  type        = string
  default     = ""
}

variable "download_base" {
  description = "Where installers are downloaded from. Defaults to the server's console."
  type        = string
  default     = ""
}

variable "http_port" {
  type    = number
  default = 47262
}

variable "grpc_port" {
  type    = number
  default = 47263
}
