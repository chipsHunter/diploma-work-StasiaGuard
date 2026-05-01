resource "digitalocean_droplet" "vpn_server" {
  name     = "stasiguard-server"
  region   = var.region
  size     = var.droplet_size
  image    = "ubuntu-24-04-x64"
  ssh_keys = [var.ssh_key_fingerprint]

  tags = ["vpn", "stasiguard"]
}

resource "digitalocean_firewall" "vpn" {
  name        = "stasiguard-firewall"
  droplet_ids = [digitalocean_droplet.vpn_server.id]

  # VPN tunnel traffic
  inbound_rule {
    protocol         = "udp"
    port_range       = "51820"
    source_addresses = ["0.0.0.0/0", "::/0"]
  }

  # SSH access
  inbound_rule {
    protocol         = "tcp"
    port_range       = "22"
    source_addresses = ["0.0.0.0/0", "::/0"]
  }

  # All outbound
  outbound_rule {
    protocol              = "tcp"
    port_range            = "1-65535"
    destination_addresses = ["0.0.0.0/0", "::/0"]
  }

  outbound_rule {
    protocol              = "udp"
    port_range            = "1-65535"
    destination_addresses = ["0.0.0.0/0", "::/0"]
  }

  outbound_rule {
    protocol              = "icmp"
    destination_addresses = ["0.0.0.0/0", "::/0"]
  }
}
