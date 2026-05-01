output "server_ip" {
  description = "VPN server public IP address"
  value       = digitalocean_droplet.vpn_server.ipv4_address
}

output "deploy_command" {
  description = "Run this to deploy VPN to the new server"
  value       = "../deploy.sh server ${digitalocean_droplet.vpn_server.ipv4_address}"
}
