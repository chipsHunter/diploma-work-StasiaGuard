variable "do_token" {
  description = "DigitalOcean API token"
  type        = string
  sensitive   = true
}

variable "ssh_key_fingerprint" {
  description = "Fingerprint of SSH key registered in DigitalOcean"
  type        = string
}

variable "region" {
  description = "DigitalOcean region for the VPN server"
  type        = string
  default     = "fra1"
}

variable "droplet_size" {
  description = "Droplet size slug"
  type        = string
  default     = "s-1vcpu-1gb"
}
