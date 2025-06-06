#!/bin/bash
set -e
# WireGuard configuration
WG_INTERFACE="wg0"
WG_PORT="123"
# WG_HOST will get DNS name for WAN interface, or you can set it to your own IP/Hostname
# alternatively to get public IP only: $(curl -s ifconfig.me)
WG_HOST="$(host $(curl -s ifconfig.me) | awk '/domain name pointer/ {gsub(/\.$/, "", $5); print $5}')"
SERVER_IP="10.40.41.1/24"
SERVER_PRIV_KEY="/etc/wireguard/$WG_INTERFACE.key"
WG_CONF="/etc/wireguard/$WG_INTERFACE.conf"
WG_ALLOWED_IPS_CLIENT="10.40.41.0/24, 10.97.195.0/24"  # this is for client what will route via wg
WG_SCRIPT="/etc/wireguard/script-wireguard.sh"

# Client1 generation:
CLIENT_NAME="client1"
CLIENT_IP="10.40.41.2/32"
CLIENT_FOLDER="/etc/wireguard/clients"
CLIENT_KEY="$CLIENT_FOLDER/$CLIENT_NAME.key"
CLIENT_PUB="$CLIENT_FOLDER/$CLIENT_NAME.pub"
CLIENT_CONF="$CLIENT_FOLDER/$CLIENT_NAME.conf"
CLIENT_PRESHAREDKEY="$CLIENT_FOLDER/$CLIENT_NAME.psk"

# ------------------------- setup: ------------------------------------------
apt update
apt install -y wireguard

echo "net.ipv4.ip_forward=1" > /etc/sysctl.d/99-wireguard-forward.conf
sysctl --system

mkdir -p $CLIENT_FOLDER

# ----------- Generate or reuse SERVER private key -----------
if [[ -f "$WG_PRIV_KEY_FILE" ]]; then
    read -p "Server private key exists. Overwrite? [y/N]: " OW
    if [[ "$OW" =~ ^[Yy]$ ]]; then
        wg genkey > "$WG_PRIV_KEY_FILE"
    fi
else
    wg genkey > "$WG_PRIV_KEY_FILE"
fi
chmod 600 "$WG_PRIV_KEY_FILE"
SERVER_PRIV_KEY=$(cat "$WG_PRIV_KEY_FILE")
SERVER_PUB_KEY=$(echo "$SERVER_PRIV_KEY" | wg pubkey)

# ----------- Generate or reuse CLIENT keys -----------
if [[ -f "$CLIENT_KEY" ]]; then
    read -p "Client private key exists. Overwrite? [y/N]: " OW
    if [[ "$OW" =~ ^[Yy]$ ]]; then
        wg genkey | tee "$CLIENT_KEY" | wg pubkey > "$CLIENT_PUB"
    fi
else
    wg genkey | tee "$CLIENT_KEY" | wg pubkey > "$CLIENT_PUB"
fi
chmod 600 "$CLIENT_KEY" "$CLIENT_PUB"

# ----------- Generate or reuse preshared key -----------
if [[ -f "$CLIENT_PRESHAREDKEY" ]]; then
    read -p "Client preshared key exists. Overwrite? [y/N]: " OW
    if [[ "$OW" =~ ^[Yy]$ ]]; then
        wg genpsk > "$CLIENT_PRESHAREDKEY"
    fi
else
    wg genpsk > "$CLIENT_PRESHAREDKEY"
fi
chmod 600 "$CLIENT_PRESHAREDKEY"

# ----------- Create WireGuard server config -----------
if [[ -f "$WG_CONF" ]]; then
    read -p "$WG_CONF exists. Overwrite server config? [y/N]: " OW
    if [[ "$OW" =~ ^[Yy]$ ]]; then
        CREATE_CONF=true
    else
        CREATE_CONF=false
    fi
else
    CREATE_CONF=true
fi

if $CREATE_CONF; then
cat > "$WG_CONF" <<EOF
[Interface]
Address = $SERVER_IP
ListenPort = $WG_PORT
PostUp = wg set %i private-key /etc/wireguard/%i.key
PostUp = /etc/wireguard/script-wireguard.sh up
PostDown = /etc/wireguard/script-wireguard.sh down
# PostUp = iptables -A FORWARD -i %i -j ACCEPT; iptables -A FORWARD -o %i -j ACCEPT; iptables -t nat -A POSTROUTING -o \$(ip route list default | awk '/default/ {print \$5}') -j MASQUERADE
# PostDown = iptables -D FORWARD -i %i -j ACCEPT; iptables -D FORWARD -o %i -j ACCEPT; iptables -t nat -D POSTROUTING -o \$(ip route list default | awk '/default/ {print \$5}') -j MASQUERADE

[Peer]
# Client 1
PublicKey = $(cat "$CLIENT_PUB")
PresharedKey = $(cat "$CLIENT_PRESHAREDKEY")
AllowedIPs = $CLIENT_IP
EOF
chmod 600 "$WG_CONF"
fi

cat > "$WG_SCRIPT" <<EOF
#!/bin/bash
# Check if an argument is provided - up for PostUp, down for PostDown
if [ $# -ne 1 ]; then
    echo "Usage: $0 {up|down}"
    exit 1
fi

# Define network and client IP variables
WG_NETWORK="10.40.41.0/24"
CLIENT_IP="10.40.41.2"

# Get public IP from file
PUB_IP=$(cat /etc/wireguard/wan_port)

# Interface variable for WireGuard
INTERFACE="%i"

case "$1" in
    up)
        # Add WireGuard interface to trusted zone
        firewall-cmd --zone=trusted --add-interface="$INTERFACE"
        # Add direct rule for NAT masquerading
        firewall-cmd --direct --add-rule ipv4 nat POSTROUTING 0 -o "$INTERFACE" -j MASQUERADE
        # OPTIONAL: Port forwarding via the tunnell:
            # Enable masquerading in trusted zone
        firewall-cmd --zone=trusted --add-masquerade
            # Add port forwarding rules for public zone
        firewall-cmd --zone=public --add-forward-port=port=80:proto=tcp:toport=5000:toaddr="$CLIENT_IP"
            # Add rich rules for trusted zone so we can access it while on wg or from server itself
        firewall-cmd --zone=trusted --add-rich-rule="rule family=ipv4 source address=\"$WG_NETWORK\" destination address=\"$PUB_IP\" forward-port port=80 protocol=tcp to-port=5000 to-addr=\"$CLIENT_IP\""

        echo "WireGuard PostUp rules applied"
        ;;
    down)
        # Remove WireGuard interface from trusted zone
        firewall-cmd --zone=trusted --remove-interface="$INTERFACE"
        # Remove direct rule for NAT masquerading
        firewall-cmd --direct --remove-rule ipv4 nat POSTROUTING 0 -o "$INTERFACE" -j MASQUERADE
        # OPTIONAL: Port forwarding via the tunnell:
            # Remove masquerading from trusted zone
        firewall-cmd --zone=trusted --remove-masquerade
            # Remove port forwarding rules from public zone
        firewall-cmd --zone=public --remove-forward-port=port=80:proto=tcp:toport=5000:toaddr="$CLIENT_IP"
            # Remove rich rules from trusted zone
        firewall-cmd --zone=trusted --remove-rich-rule="rule family=ipv4 source address=\"$WG_NETWORK\" destination address=\"$PUB_IP\" forward-port port=80 protocol=tcp to-port=5000 to-addr=\"$CLIENT_IP\""

        echo "WireGuard PostDown rules applied"
        ;;
    *)
        echo "Invalid argument: $1"
        echo "Usage: $0 {up|down}"
        exit 1
        ;;
esac
EOF
chmod 700 "$WG_SCRIPT"

systemctl enable wg-quick@$WG_INTERFACE
systemctl restart wg-quick@$WG_INTERFACE

# ----------- Generate client1 config -----------
if [[ -f "$CLIENT_CONF" ]]; then
    read -p "$CLIENT_CONF exists. Overwrite client config? [y/N]: " OW
    if [[ "$OW" =~ ^[Yy]$ ]]; then
        CREATE_CLIENT=true
    else
        CREATE_CLIENT=false
    fi
else
    CREATE_CLIENT=true
fi

if $CREATE_CLIENT; then
cat > "$CLIENT_CONF" <<EOF
[Interface]
PrivateKey = $(cat "$CLIENT_KEY")
Address = $CLIENT_IP
DNS = 1.1.1.1

[Peer]
PublicKey = $SERVER_PUB_KEY
PresharedKey = $(cat "$CLIENT_PRESHAREDKEY")
Endpoint = $WG_HOST:$WG_PORT
AllowedIPs = $WG_ALLOWED_IPS_CLIENT
PersistentKeepalive = 25
EOF
chmod 600 "$CLIENT_CONF"
fi

# Output client config
echo ""
echo "=== WireGuard Server and Client1 Setup Complete ==="
echo ""
echo "Client1 config:"
echo "----------------------"
cat "$CLIENT_CONF"
echo "----------------------"
echo "Saved to: $CLIENT_CONF"
