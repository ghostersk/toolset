#!/bin/bash
# === 🛠️ DEFAULT CONFIGURATION ===
DEFAULT_COUNTRIES=("gb") # "gb" "us"
DEFAULT_MANUAL_IPS=() # "203.0.113.10" "198.51.100.0/24"
DEFAULT_TCP_PORTS=() # Empty means all TCP ports by default
DEFAULT_UDP_PORTS=() # Empty means all UDP ports by default
IPSET_SAVE_PATH="/etc/ipset.conf"

# === 🌐 Constants ===
GEOIP_DIR="/usr/share/xt_geoip"
IPSET_NAME="geo-allowed"
CRON_JOB_PATH="/etc/cron.weekly/update-xt-geoip"
SYSTEMD_IPSET_SERVICE="/etc/systemd/system/ipset-restore.service"
SCRIPT_NAME="$(basename "$0")"

# === Runtime Config ===
COUNTRIES=("${DEFAULT_COUNTRIES[@]}")
MANUAL_IPS=("${DEFAULT_MANUAL_IPS[@]}")
TCP_PORTS=("${DEFAULT_TCP_PORTS[@]}")
UDP_PORTS=("${DEFAULT_UDP_PORTS[@]}")
REMOVE=false

# === Help ===
usage() {
    echo "Usage: $0 [OPTIONS]"
    echo ""
    echo "Options:"
    echo "  --countries gb,us        Comma-separated list of country codes to allow"
    echo "  --manual-ips ip1,ip2     Comma-separated list of manual IPs/ranges to allow"
    echo "  --tcp-ports 25,587       Restrict GeoIP filtering to specific TCP ports (default: all)"
    echo "  --udp-ports 53,123       Restrict GeoIP filtering to specific UDP ports (default: all)"
    echo "  --remove                 Remove all rules and ipset"
    echo "  -h, --help               Show this help message"
    exit 1
}

# === Parse CLI Arguments ===
while [[ "$#" -gt 0 ]]; do
    case "$1" in
        --countries) IFS=',' read -r -a COUNTRIES <<< "$2"; shift ;;
        --manual-ips) IFS=',' read -r -a MANUAL_IPS <<< "$2"; shift ;;
        --tcp-ports) IFS=',' read -r -a TCP_PORTS <<< "$2"; shift ;;
        --udp-ports) IFS=',' read -r -a UDP_PORTS <<< "$2"; shift ;;
        --remove) REMOVE=true ;;
        -h|--help) usage ;;
        *) echo "Unknown option: $1"; usage ;;
    esac
    shift
done

# === Error Handling ===
check_command() {
    command -v "$1" >/dev/null 2>&1 || { echo "Error: $1 is required but not installed."; exit 1; }
}

# === Cleanup Function ===
remove_firewall_rules() {
    echo "🔧 Removing firewalld rules..."
    
    # TCP
    if [ ${#TCP_PORTS[@]} -eq 0 ]; then
        firewall-cmd --permanent --direct --remove-rule ipv4 filter INPUT 0 \
            -p tcp -m set ! --match-set "$IPSET_NAME" src -j DROP 2>/dev/null || true
    else
        for port in "${TCP_PORTS[@]}"; do
            firewall-cmd --permanent --direct --remove-rule ipv4 filter INPUT 0 \
                -p tcp --dport "$port" -m set ! --match-set "$IPSET_NAME" src -j DROP 2>/dev/null || true
        done
    fi

    # UDP
    if [ ${#UDP_PORTS[@]} -eq 0 ]; then
        firewall-cmd --permanent --direct --remove-rule ipv4 filter INPUT 0 \
            -p udp -m set ! --match-set "$IPSET_NAME" src -j DROP 2>/dev/null || true
    else
        for port in "${UDP_PORTS[@]}"; do
            firewall-cmd --permanent --direct --remove-rule ipv4 filter INPUT 0 \
                -p udp --dport "$port" -m set ! --match-set "$IPSET_NAME" src -j DROP 2>/dev/null || true
        done
    fi

    echo "🧼 Flushing and destroying ipset..."
    ipset flush "$IPSET_NAME" 2>/dev/null || true
    ipset destroy "$IPSET_NAME" 2>/dev/null || true

    echo "🗑️ Removing cron job at $CRON_JOB_PATH"
    rm -f "$CRON_JOB_PATH"

    echo "🗑️ Removing ipset persistence configuration"
    rm -f "$IPSET_SAVE_PATH"
    systemctl disable ipset-restore.service 2>/dev/null || true
    rm -f "$SYSTEMD_IPSET_SERVICE"

    echo "♻️ Reloading firewalld..."
    firewall-cmd --reload || { echo "Error: Failed to reload firewalld."; exit 1; }

    echo "✅ Firewall rules and GeoIP ipset removed."
}

if [ "$REMOVE" = true ]; then
    remove_firewall_rules
    exit 0
fi

# === Detect Package Manager ===
if command -v apt >/dev/null 2>&1; then
    PKG_MANAGER="apt"
elif command -v yum >/dev/null 2>&1; then
    PKG_MANAGER="yum"
elif command -v dnf >/dev/null 2>&1; then
    PKG_MANAGER="dnf"
else
    echo "Error: No supported package manager (apt/yum/dnf) found."
    exit 1
fi

# === Install Dependencies ===
echo "📦 Installing dependencies..."
if [ "$PKG_MANAGER" = "apt" ]; then
    apt update && apt install -y ipset xtables-addons-common libtext-csv-xs-perl wget || { echo "Error: Failed to install dependencies."; exit 1; }
elif [ "$PKG_MANAGER" = "yum" ] || [ "$PKG_MANAGER" = "dnf" ]; then
    $PKG_MANAGER install -y ipset xtables-addons perl-Text-CSV_XS wget || { echo "Error: Failed to install dependencies."; exit 1; }
fi

# === Check Required Commands ===
check_command ipset
check_command firewall-cmd
check_command wget

# === Verify iptables-legacy Backend ===
if firewall-cmd --get-ipset-types | grep -q "hash:net"; then
    echo "✅ ipset hash:net supported by firewalld."
else
    echo "Error: ipset hash:net not supported. Ensure xt_geoip module is loaded."
    exit 1
fi

# === Locate xtables-addons Binaries ===
XTABLES_DIR=""
for dir in /usr/libexec/xtables-addons /usr/lib/xtables-addons /usr/sbin /usr/bin; do
    if [ -f "$dir/xt_geoip_dl" ] && [ -f "$dir/xt_geoip_build" ]; then
        XTABLES_DIR="$dir"
        break
    fi
done
if [ -z "$XTABLES_DIR" ]; then
    echo "Error: Could not find xt_geoip_dl and xt_geoip_build. Ensure xtables-addons is installed correctly."
    exit 1
fi

# === Download and Build GeoIP DB ===
echo "🔧 Building GeoIP database..."
mkdir -p "$GEOIP_DIR" || { echo "Error: Failed to create $GEOIP_DIR."; exit 1; }
cd "$XTABLES_DIR" || { echo "Error: Failed to change to $XTABLES_DIR."; exit 1; }
./xt_geoip_dl || { echo "Error: Failed to download GeoIP data."; exit 1; }
./xt_geoip_build -D "$GEOIP_DIR" GeoIPCountryWhois.csv || { echo "Error: Failed to build GeoIP database."; exit 1; }

# === Create and Populate ipset ===
echo "🧰 Creating ipset: $IPSET_NAME"
ipset destroy "$IPSET_NAME" 2>/dev/null || true
ipset create "$IPSET_NAME" hash:net || { echo "Error: Failed to create ipset $IPSET_NAME."; exit 1; }

echo "🌍 Adding country IPs..."
for cc in "${COUNTRIES[@]}"; do
    echo "  -> $cc"
    wget -q -O "/tmp/${cc}.zone" "https://www.ipdeny.com/ipblocks/data/countries/${cc}.zone" || { echo "Error: Failed to download IP list for $cc."; exit 1; }
    while IFS= read -r ip; do
        [[ -z "$ip" ]] && continue
        ipset add "$IPSET_NAME" "$ip" || { echo "Error: Failed to add $ip to ipset."; exit 1; }
    done < "/tmp/${cc}.zone"
    rm -f "/tmp/${cc}.zone"
done

echo "➕ Adding manual IPs..."
for ip in "${MANUAL_IPS[@]}"; do
    ipset add "$IPSET_NAME" "$ip" || { echo "Error: Failed to add manual IP $ip to ipset."; exit 1; }
done

# === Save ipset for Persistence ===
echo "💾 Saving ipset to $IPSET_SAVE_PATH for persistence..."
ipset save "$IPSET_NAME" > "$IPSET_SAVE_PATH" || { echo "Error: Failed to save ipset."; exit 1; }

# === Create systemd Service for ipset Restore ===
echo "🛠️ Creating systemd service for ipset persistence..."
cat <<EOF > "$SYSTEMD_IPSET_SERVICE"
[Unit]
Description=Restore ipset on boot
After=network.target firewalld.service

[Service]
Type=oneshot
ExecStart=/usr/sbin/ipset restore -f $IPSET_SAVE_PATH
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
EOF
systemctl enable ipset-restore.service || { echo "Error: Failed to enable ipset-restore service."; exit 1; }

# === Add firewalld rules ===
echo "🔥 Adding firewalld rules..."

# TCP
if [ ${#TCP_PORTS[@]} -eq 0 ]; then
    echo "  -> All TCP ports"
    firewall-cmd --permanent --direct --add-rule ipv4 filter INPUT 0 \
        -p tcp -m set ! --match-set "$IPSET_NAME" src -j DROP || { echo "Error: Failed to add TCP rule."; exit 1; }
else
    for port in "${TCP_PORTS[@]}"; do
        echo "  -> TCP $port"
        firewall-cmd --permanent --direct --add-rule ipv4 filter INPUT 0 \
            -p tcp --dport "$port" -m set ! --match-set "$IPSET_NAME" src -j DROP || { echo "Error: Failed to add TCP rule for port $port."; exit 1; }
    done
fi

# UDP
if [ ${#UDP_PORTS[@]} -eq 0 ]; then
    echo "  -> All UDP ports"
    firewall-cmd --permanent --direct --add-rule ipv4 filter INPUT 0 \
        -p udp -m set ! --match-set "$IPSET_NAME" src -j DROP || { echo "Error: Failed to add UDP rule."; exit 1; }
else
    for port in "${UDP_PORTS[@]}"; do
        echo "  -> UDP $port"
        firewall-cmd --permanent --direct --add-rule ipv4 filter INPUT 0 \
            -p udp --dport "$port" -m set ! --match-set "$IPSET_NAME" src -j DROP || { echo "Error: Failed to add UDP rule for port $port."; exit 1; }
    done
fi

# === Cron Job for Weekly GeoIP Update ===
echo "🕒 Installing weekly cron job at $CRON_JOB_PATH"
cat <<EOF > "$CRON_JOB_PATH"
#!/bin/bash
cd "$XTABLES_DIR" || exit 1
./xt_geoip_dl || exit 1
./xt_geoip_build -D "$GEOIP_DIR" GeoIPCountryWhois.csv || exit 1
ipset flush "$IPSET_NAME"
for cc in ${COUNTRIES[*]}; do
    wget -q -O "/tmp/\${cc}.zone" "https://www.ipdeny.com/ipblocks/data/countries/\${cc}.zone" || exit 1
    while IFS= read -r ip; do
        [[ -z "\$ip" ]] && continue
        ipset add "$IPSET_NAME" "\$ip" || exit 1
    done < "/tmp/\${cc}.zone"
    rm -f "/tmp/\${cc}.zone"
done
for ip in ${MANUAL_IPS[*]}; do
    ipset add "$IPSET_NAME" "\$ip" || exit 1
done
ipset save "$IPSET_NAME" > "$IPSET_SAVE_PATH" || exit 1
EOF
chmod +x "$CRON_JOB_PATH" || { echo "Error: Failed to create cron job."; exit 1; }

# === Reload firewalld ===
echo "🔄 Reloading firewalld..."
firewall-cmd --reload || { echo "Error: Failed to reload firewalld."; exit 1; }

echo "✅ GeoIP firewall filtering is now active."
