#!/usr/bin/env bash
#
# StasiaGuard VPN deployment script.
#
# Deploys VPN server or client to a remote host via SSH.
# Builds from source, generates keys, creates configs.
#
# Usage:
#   ./deploy.sh server <host>
#   ./deploy.sh client <host> <server_ip> <server_pubkey> <vpn_ip>
#   ./deploy.sh add-peer <server_host> <client_pubkey> <client_vpn_ip>
#   ./deploy.sh start <host>
#   ./deploy.sh stop <host>
#   ./deploy.sh status <host>
#   ./deploy.sh logs <host>
#
set -euo pipefail

REMOTE_DIR="/opt/stasiguard"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
CODE_DIR="$(dirname "$SCRIPT_DIR")"

usage() {
    cat <<EOF
StasiaGuard VPN deploy tool

Commands:
  server <host>                                          Deploy VPN server
  client <host> <server_ip> <server_pubkey> <vpn_ip>     Deploy VPN client
  add-peer <server_host> <client_pubkey> <client_vpn_ip> Add peer to server config
  start <host>                                           Start VPN daemon
  stop <host>                                            Stop VPN daemon
  status <host>                                          Check if daemon is running
  logs <host>                                            Show last 50 log lines

Examples:
  $0 server 104.248.141.250
  $0 client 104.131.99.157 104.248.141.250 "bR5s...=" 10.0.0.2
  $0 add-peer 104.248.141.250 "Kx9a...=" 10.0.0.2
  $0 start 104.248.141.250
EOF
    exit 1
}

# --- helpers ---

remote() {
    ssh -o StrictHostKeyChecking=accept-new -o ConnectTimeout=10 "root@$1" "${@:2}"
}

install_deps() {
    local host=$1
    echo "[*] Installing build dependencies on $host..."
    remote "$host" "export DEBIAN_FRONTEND=noninteractive && \
        apt-get update -qq && \
        apt-get install -y -qq build-essential cmake pkg-config \
            libsodium-dev libyaml-cpp-dev > /dev/null 2>&1"
    echo "    done"
}

sync_source() {
    local host=$1
    echo "[*] Syncing source code to $host:$REMOTE_DIR/code/..."
    remote "$host" "mkdir -p $REMOTE_DIR"
    rsync -az --delete \
        --exclude=build \
        --exclude=.git \
        --exclude='*.key' \
        --exclude='config.yaml' \
        --exclude='vpn.log' \
        "$CODE_DIR/" "root@$host:$REMOTE_DIR/code/"
    echo "    done"
}

build_remote() {
    local host=$1
    echo "[*] Building on $host..."
    remote "$host" "cd $REMOTE_DIR/code && \
        cmake -B build -DCMAKE_BUILD_TYPE=Release > /dev/null 2>&1 && \
        cmake --build build -j\$(nproc) 2>&1 | tail -3"
    echo "    done"
}

ensure_keys() {
    local host=$1
    local pubkey
    remote "$host" "cd $REMOTE_DIR && \
        if [ ! -f vpn.key ]; then \
            ./code/build/vpn genkey > vpn.key && \
            chmod 600 vpn.key && \
            echo 'NEW' >&2; \
        else \
            echo 'EXISTS' >&2; \
        fi" 2>/dev/null
    pubkey=$(remote "$host" "$REMOTE_DIR/code/build/vpn pubkey < $REMOTE_DIR/vpn.key")
    echo "$pubkey"
}

# --- commands ---

cmd_deploy_server() {
    local host=$1

    install_deps "$host"
    sync_source "$host"
    build_remote "$host"

    echo "[*] Generating keys on $host..."
    local pubkey
    pubkey=$(ensure_keys "$host")

    echo "[*] Writing server config..."
    remote "$host" "cat > $REMOTE_DIR/config.yaml << 'ENDCFG'
role: server
listen_port: 51820
tun_ip: 10.0.0.1
tun_mask: 24
private_key_path: $REMOTE_DIR/vpn.key
traffic_profile: tls
peers: []
ENDCFG"

    echo ""
    echo "=== Server deployed ==="
    echo "Host:       $host"
    echo "Public key: $pubkey"
    echo ""
    echo "Next: deploy a client, then add-peer, then start."
}

cmd_deploy_client() {
    local host=$1
    local server_ip=$2
    local server_pubkey=$3
    local vpn_ip=$4

    install_deps "$host"
    sync_source "$host"
    build_remote "$host"

    echo "[*] Generating keys on $host..."
    local pubkey
    pubkey=$(ensure_keys "$host")

    echo "[*] Writing client config (VPN IP: $vpn_ip)..."
    remote "$host" "cat > $REMOTE_DIR/config.yaml << ENDCFG
role: client
listen_port: 51820
tun_ip: $vpn_ip
tun_mask: 24
private_key_path: $REMOTE_DIR/vpn.key
traffic_profile: tls
peers:
  - public_key: \"$server_pubkey\"
    endpoint: \"$server_ip:51820\"
    allowed_ip: \"10.0.0.1\"
ENDCFG"

    echo ""
    echo "=== Client deployed ==="
    echo "Host:       $host"
    echo "VPN IP:     $vpn_ip"
    echo "Public key: $pubkey"
    echo ""
    echo "Now add this client to the server:"
    echo "  $0 add-peer <server_host> \"$pubkey\" \"$vpn_ip\""
}

cmd_add_peer() {
    local host=$1
    local peer_pubkey=$2
    local peer_vpn_ip=$3

    echo "[*] Adding peer $peer_vpn_ip to server $host..."
    remote "$host" "cd $REMOTE_DIR && \
        sed -i 's/^peers: \[\]/peers:/' config.yaml && \
        printf '  - public_key: \"%s\"\n    allowed_ip: \"%s\"\n' \
            '$peer_pubkey' '$peer_vpn_ip' >> config.yaml"

    echo "    done"
    echo ""
    echo "Peer added. Restart the server if it is running:"
    echo "  $0 stop $host && $0 start $host"
}

cmd_start() {
    local host=$1

    echo "[*] Starting VPN on $host..."
    remote "$host" "killall vpn 2>/dev/null || true"
    sleep 1
    ssh -o StrictHostKeyChecking=accept-new -o ConnectTimeout=10 \
        "root@$host" \
        "cd $REMOTE_DIR && (./code/build/vpn --config config.yaml < /dev/null > vpn.log 2>&1 &)"
    sleep 2
    remote "$host" "if pgrep -x vpn > /dev/null 2>&1; then \
            echo \"VPN started (PID \$(pgrep -x vpn))\"; \
        else \
            echo 'ERROR: VPN failed to start'; \
            tail -10 $REMOTE_DIR/vpn.log 2>/dev/null; \
        fi"
}

cmd_stop() {
    local host=$1

    echo "[*] Stopping VPN on $host..."
    remote "$host" "if killall vpn 2>/dev/null; then \
            echo 'VPN stopped'; \
        else \
            echo 'VPN was not running'; \
        fi"
}

cmd_status() {
    local host=$1

    remote "$host" "if pgrep -x vpn > /dev/null 2>&1; then \
            echo \"VPN is running (PID \$(pgrep -x vpn))\"; \
        else \
            echo 'VPN is not running'; \
        fi"
}

cmd_logs() {
    local host=$1

    remote "$host" "tail -50 $REMOTE_DIR/vpn.log 2>/dev/null || echo 'No logs found'"
}

# --- main ---

[ $# -lt 2 ] && usage

case "$1" in
    server)
        [ $# -ne 2 ] && { echo "Usage: $0 server <host>"; exit 1; }
        cmd_deploy_server "$2"
        ;;
    client)
        [ $# -ne 5 ] && { echo "Usage: $0 client <host> <server_ip> <server_pubkey> <vpn_ip>"; exit 1; }
        cmd_deploy_client "$2" "$3" "$4" "$5"
        ;;
    add-peer)
        [ $# -ne 4 ] && { echo "Usage: $0 add-peer <server_host> <client_pubkey> <client_vpn_ip>"; exit 1; }
        cmd_add_peer "$2" "$3" "$4"
        ;;
    start)
        cmd_start "$2"
        ;;
    stop)
        cmd_stop "$2"
        ;;
    status)
        cmd_status "$2"
        ;;
    logs)
        cmd_logs "$2"
        ;;
    *)
        usage
        ;;
esac
