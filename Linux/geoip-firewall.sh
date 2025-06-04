#!/bin/bash
# === 🛠️ DEFAULT CONFIGURATION ===
DEFAULT_COUNTRIES=("gb") # Default: UK
DEFAULT_MANUAL_IPS=() # e.g., "203.0.113.10" "198.51.100.0/24"
DEFAULT_TCP_PORTS=() # Empty means all TCP ports
DEFAULT_UDP_PORTS=() # Empty means all UDP ports
IPSET_SAVE_PATH="/etc/ipset.conf"
GEOIP_DIR="/usr/share/xt_geoip"
IPSET_NAME="geo-allowed"
CRON_JOB_PATH="/etc/cron.daily/update-xt-geoip"
SYSTEMD_IPSET_SERVICE="/etc/systemd/system/ipset-restore.service"
BLOCKED_IP_LOG="/var/log/geo-blocked-ips.log"
SCRIPT_NAME="$(basename "$0")"
IP_SOURCE="ripe" # Default: RIPE (options: ripe, both)
MAXMIND_YOUR_ACCOUNT_ID="" # Replace with your MaxMind Account ID if using MaxMind
MAXMIND_LICENSE_KEY="" # MaxMind license key for GeoLite2
[ -n "$MAXMIND_LICENSE_KEY" ] && [ -n "$MAXMIND_YOUR_ACCOUNT_ID" ] && IP_SOURCE="both" # if Maxmind details provided - using Ripe and Max
GEOIPUPDATE_AVAILABLE=false
command -v geoipupdate >/dev/null 2>&1 && GEOIPUPDATE_AVAILABLE=true

# === Runtime Config ===
COUNTRIES=("${DEFAULT_COUNTRIES[@]}")
MANUAL_IPS=("${DEFAULT_MANUAL_IPS[@]}")
TCP_PORTS=("${DEFAULT_TCP_PORTS[@]}")
UDP_PORTS=("${DEFAULT_UDP_PORTS[@]}")
REMOVE=false
STATUS=false
IPV6=false

# === Help ===
usage() {
    echo "Usage: $0 [OPTIONS]"
    echo ""
    echo "Options:"
    echo "  --countries gb,us        Comma-separated list of country codes to allow"
    echo "  --manual-ips ip1,ip2     Comma-separated list of manual IPs/ranges to allow"
    echo "  --tcp-ports 25,587       Restrict GeoIP filtering to specific TCP ports (default: all)"
    echo "  --udp-ports 53,123       Restrict GeoIP filtering to specific UDP ports (default: all)"
    echo "  --ip-source ripe|both    IP list source (default: ripe)"
    echo "  --maxmind-key KEY        MaxMind license key for GeoLite2"
    echo "  --ipv6                   Enable IPv6 GeoIP filtering"
    echo "  --status                 Check GeoIP configuration status"
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
                --ip-source) IP_SOURCE="$2"; shift ;;
        --maxmind-id) MAXMIND_YOUR_ACCOUNT_ID="$2"; [ -n "$MAXMIND_LICENSE_KEY" ] && [ -n "$MAXMIND_YOUR_ACCOUNT_ID" ] && IP_SOURCE="both"; shift ;;
        --maxmind-key) MAXMIND_LICENSE_KEY="$2"; [ -n "$MAXMIND_LICENSE_KEY" ] && [ -n "$MAXMIND_YOUR_ACCOUNT_ID" ] && IP_SOURCE="both"; shift ;;
        --ipv6) IPV6=true ;;
        --status) STATUS=true ;;
        --remove) REMOVE=true ;;
        -h|--help) usage ;;
        *) echo "ERROR: Unknown option: $1"; usage ;;
    esac
    shift
done

# === Error Handling ===
check_command() {
    command -v "$1" >/dev/null 2>&1 || { echo "ERROR: $1 is required but not installed."; exit 1; }
}

# === Convert IP Range to CIDR ===
convert_range_to_cidr() {
    local range="$1"
    local start_ip end_ip
    IFS='-' read -r start_ip end_ip <<< "$range"
    if command -v ipcalc >/dev/null 2>&1; then
        ipcalc -r "$start_ip" "$end_ip" | grep -oE '[0-9.]+/[0-9]+' || { echo "WARNING: Failed to convert range $range to CIDR. Skipping."; return 1; }
    else
        echo "WARNING: ipcalc not installed. Cannot convert range $range to CIDR. Skipping."
        return 1
    fi
}

# === Validate Inputs ===
validate_country_code() {
    local cc="$1"
    if [[ ! "$cc" =~ ^[a-zA-Z]{2}$ ]]; then
        echo "ERROR: Invalid country code: $cc. Must be a 2-letter ISO code."
        exit 1
    fi
}

validate_ip() {
    local ip="$1"
    if [[ "$ip" =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}(/[0-9]{1,2})?$ ]]; then
        return 0
    elif [[ "$IPV6" = true && "$ip" =~ ^[0-9a-fA-F:]+(/[0-9]{1,3})?$ ]]; then
        return 0
    else
        echo "ERROR: Invalid IP or CIDR: $ip"
        exit 1
    fi
}

# === Detect LAN Subnets ===
detect_lan_subnets() {
    echo "INFO: Detecting LAN subnets..."
    LAN_SUBNETS=()
    for iface in $(ip link show | grep -E '^[0-9]+:.*state UP' | cut -d: -f2 | awk '{print $1}'); do
        subnets=$(ip addr show "$iface" | grep -oE 'inet [0-9.]+/[0-9]+' | awk '{print $2}')
        for subnet in $subnets; do
            LAN_SUBNETS+=("$subnet")
            echo "INFO: Detected LAN subnet: $subnet"
        done
        if [ "$IPV6" = true ]; then
            ipv6_subnets=$(ip addr show "$iface" | grep -oE 'inet6 [0-9a-fA-F:]+/[0-9]+' | awk '{print $2}')
            for subnet in $ipv6_subnets; do
                LAN_SUBNETS+=("$subnet")
                echo "INFO: Detected LAN IPv6 subnet: $subnet"
            done
        fi
    done
}

# === Cleanup Function ===
remove_firewall_rules() {
    echo "INFO: Removing firewalld rules..."

    # Remove custom chain for blocked IPs
    iptables -F GEO_BLOCK 2>/dev/null || true
    iptables -X GEO_BLOCK 2>/dev/null || true
    ip6tables -F GEO_BLOCK 2>/dev/null || true
    ip6tables -X GEO_BLOCK 2>/dev/null || true

    # TCP
    if [ ${#TCP_PORTS[@]} -eq 0 ]; then
        firewall-cmd --permanent --direct --remove-rule ipv4 filter INPUT 0 \
            -p tcp -m set ! --match-set "$IPSET_NAME" src -j GEO_BLOCK 2>/dev/null || true
        firewall-cmd --permanent --direct --remove-rule ipv4 filter INPUT 0 \
            -p tcp -m set ! --match-set "$IPSET_NAME" src -j DROP 2>/dev/null || true
    else
        for port in "${TCP_PORTS[@]}"; do
            firewall-cmd --permanent --direct --remove-rule ipv4 filter INPUT 0 \
                -p tcp --dport "$port" -m set ! --match-set "$IPSET_NAME" src -j GEO_BLOCK 2>/dev/null || true
            firewall-cmd --permanent --direct --remove-rule ipv4 filter INPUT 0 \
                -p tcp --dport "$port" -m set ! --match-set "$IPSET_NAME" src -j DROP 2>/dev/null || true
        done
    fi

    # UDP
    if [ ${#UDP_PORTS[@]} -eq 0 ]; then
        firewall-cmd --permanent --direct --remove-rule ipv4 filter INPUT 0 \
            -p udp -m set ! --match-set "$IPSET_NAME" src -j GEO_BLOCK 2>/dev/null || true
        firewall-cmd --permanent --direct --remove-rule ipv4 filter INPUT 0 \
            -p udp -m set ! --match-set "$IPSET_NAME" src -j DROP 2>/dev/null || true
    else
        for port in "${UDP_PORTS[@]}"; do
            firewall-cmd --permanent --direct --remove-rule ipv4 filter INPUT 0 \
                -p udp --dport "$port" -m set ! --match-set "$IPSET_NAME" src -j GEO_BLOCK 2>/dev/null || true
            firewall-cmd --permanent --direct --remove-rule ipv4 filter INPUT 0 \
                -p udp --dport "$port" -m set ! --match-set "$IPSET_NAME" src -j DROP 2>/dev/null || true
        done
    fi

    # IPv6
    if [ "$IPV6" = true ]; then
        IPSET_NAME_V6="geo-allowed-v6"
        if [ ${#TCP_PORTS[@]} -eq 0 ]; then
            firewall-cmd --permanent --direct --remove-rule ipv6 filter INPUT 0 \
                -p tcp -m set ! --match-set "$IPSET_NAME_V6" src -j GEO_BLOCK 2>/dev/null || true
            firewall-cmd --permanent --direct --remove-rule ipv6 filter INPUT 0 \
                -p tcp -m set ! --match-set "$IPSET_NAME_V6" src -j DROP 2>/dev/null || true
        else
            for port in "${TCP_PORTS[@]}"; do
                firewall-cmd --permanent --direct --remove-rule ipv6 filter INPUT 0 \
                    -p tcp --dport "$port" -m set ! --match-set "$IPSET_NAME_V6" src -j GEO_BLOCK 2>/dev/null || true
                firewall-cmd --permanent --direct --remove-rule ipv6 filter INPUT 0 \
                    -p tcp --dport "$port" -m set ! --match-set "$IPSET_NAME_V6" src -j DROP 2>/dev/null || true
            done
        fi
        if [ ${#UDP_PORTS[@]} -eq 0 ]; then
            firewall-cmd --permanent --direct --remove-rule ipv6 filter INPUT 0 \
                -p udp -m set ! --match-set "$IPSET_NAME_V6" src -j GEO_BLOCK 2>/dev/null || true
            firewall-cmd --permanent --direct --remove-rule ipv6 filter INPUT 0 \
                -p udp -m set ! --match-set "$IPSET_NAME_V6" src -j DROP 2>/dev/null || true
        else
            for port in "${UDP_PORTS[@]}"; do
                firewall-cmd --permanent --direct --remove-rule ipv6 filter INPUT 0 \
                    -p udp --dport "$port" -m set ! --match-set "$IPSET_NAME_V6" src -j GEO_BLOCK 2>/dev/null || true
                firewall-cmd --permanent --direct --remove-rule ipv6 filter INPUT 0 \
                    -p udp --dport "$port" -m set ! --match-set "$IPSET_NAME_V6" src -j DROP 2>/dev/null || true
            done
        fi
        ipset flush "$IPSET_NAME_V6" 2>/dev/null || true
        ipset destroy "$IPSET_NAME_V6" 2>/dev/null || true
    fi

    echo "INFO: Flushing and destroying ipset..."
    ipset flush "$IPSET_NAME" 2>/dev/null || true
    ipset destroy "$IPSET_NAME" 2>/dev/null || true

    echo "INFO: Removing cron job at $CRON_JOB_PATH"
    rm -f "$CRON_JOB_PATH"

    echo "INFO: Removing ipset persistence configuration"
    rm -f "$IPSET_SAVE_PATH"
    systemctl disable ipset-restore.service 2>/dev/null || true
    rm -f "$SYSTEMD_IPSET_SERVICE"

    echo "INFO: Removing blocked IP log"
    rm -f "$BLOCKED_IP_LOG"

    echo "INFO: Reloading firewalld..."
    firewall-cmd --reload || { echo "ERROR: Failed to reload firewalld."; exit 1; }

    echo "INFO: Firewall rules and GeoIP ipset removed."
}

# === Status Check ===
check_status() {
    echo "=== GeoIP Firewall Status ==="
    echo "IP Source: $IP_SOURCE"
    echo "MaxMind geoipupdate Available: $GEOIPUPDATE_AVAILABLE"
    echo "Countries Allowed: ${COUNTRIES[*]}"
    echo "Manual IPs: ${MANUAL_IPS[*]:-None}"
    echo "TCP Ports: ${TCP_PORTS[*]:-All}"
    echo "UDP Ports: ${UDP_PORTS[*]:-All}"
    echo "IPv6 Enabled: $IPV6"
    echo "ipset Contents:"
    ipset list "$IPSET_NAME" 2>/dev/null || echo "  ipset $IPSET_NAME not found"
    if [ "$IPV6" = true ]; then
        ipset list "$IPSET_NAME_V6" 2>/dev/null || echo "  ipset $IPSET_NAME_V6 not found"
    fi
    echo "Firewall Rules:"
    firewall-cmd --direct --get-all-rules
    echo "Blocked IPs (see $BLOCKED_IP_LOG):"
    if [ -f "$BLOCKED_IP_LOG" ]; then
        cat "$BLOCKED_IP_LOG"
    else
        echo "  No blocked IPs logged yet."
    fi
    exit 0
}

if [ "$STATUS" = true ]; then
    check_status
fi

if [ "$REMOVE" = true ]; then
    remove_firewall_rules
    exit 0
fi

# === Validate Inputs ===
for cc in "${COUNTRIES[@]}"; do
    validate_country_code "$cc"
done
for ip in "${MANUAL_IPS[@]}"; do
    validate_ip "$ip"
done

# === Detect Package Manager ===
if command -v apt >/dev/null 2>&1; then
    PKG_MANAGER="apt"
elif command -v yum >/dev/null 2>&1; then
    PKG_MANAGER="yum"
elif command -v dnf >/dev/null 2>&1; then
    PKG_MANAGER="dnf"
else
    echo "ERROR: No supported package manager (apt/yum/dnf) found."
    exit 1
fi

# === Install Dependencies ===
echo "INFO: Installing dependencies..."
if [ "$PKG_MANAGER" = "apt" ]; then
    apt update && apt install -y ipset xtables-addons-common libtext-csv-xs-perl wget curl jq ipcalc || { echo "ERROR: Failed to install dependencies."; exit 1; }
    if [ "$IP_SOURCE" = "both" ] && [ -n "$MAXMIND_LICENSE_KEY" ]; then
        apt install -y geoipupdate || echo "WARNING: geoipupdate not found in repositories. MaxMind support disabled."
        command -v geoipupdate >/dev/null 2>&1 && GEOIPUPDATE_AVAILABLE=true || GEOIPUPDATE_AVAILABLE=false
    fi
elif [ "$PKG_MANAGER" = "yum" ] || [ "$PKG_MANAGER" = "dnf" ]; then
    $PKG_MANAGER install -y ipset xtables-addons perl-Text-CSV_XS wget curl jq ipcalc || { echo "ERROR: Failed to install dependencies."; exit 1; }
    if [ "$IP_SOURCE" = "both" ] && [ -n "$MAXMIND_LICENSE_KEY" ]; then
        $PKG_MANAGER install -y geoipupdate || echo "WARNING: geoipupdate not found in repositories. MaxMind support disabled."
        command -v geoipupdate >/dev/null 2>&1 && GEOIPUPDATE_AVAILABLE=true || GEOIPUPDATE_AVAILABLE=false
    fi
fi

# === Check Required Commands ===
check_command ipset
check_command firewall-cmd
check_command wget
check_command curl
check_command jq
check_command ipcalc

# === Verify iptables-legacy Backend ===
if firewall-cmd --get-ipset-types | grep -q "hash:net"; then
    echo "INFO: ipset hash:net supported by firewalld."
else
    echo "ERROR: ipset hash:net not supported. Ensure xt_geoip module is loaded."
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
    echo "ERROR: Could not find xt_geoip_dl and xt_geoip_build. Ensure xtables-addons is installed correctly."
    exit 1
fi

# === Validate IP List ===
validate_ip_list() {
    local file="$1"
    if [ ! -s "$file" ]; then
        echo "ERROR: IP list file $file is empty or does not exist."
        exit 1
    fi
    while IFS= read -r ip; do
        [[ -z "$ip" ]] && continue
        validate_ip "$ip"
    done < "$file"
}

# === Download GeoIP Data ===
download_geoip_data() {
    local cc="$1"
    local tmp_file="/tmp/${cc}.zone"
    local ip_list_file="/tmp/${cc}_ips.txt"
    local temp_range_file="/tmp/${cc}_ranges.txt"
    > "$ip_list_file" # Clear temporary IP list file
    > "$temp_range_file"

    # RIPE
    echo "INFO: Downloading RIPE IP list for $cc..."
    wget -q -O "$tmp_file" "https://stat.ripe.net/data/country-resource-list/data.json?resource=$cc&v=4" || { echo "ERROR: Failed to download RIPE IP list for $cc."; exit 1; }
    if [ -s "$tmp_file" ]; then
        jq -r '.data.resources.ipv4[]' "$tmp_file" > "$temp_range_file" 2>/dev/null
        while IFS= read -r range; do
            [[ -z "$range" ]] && continue
            if [[ "$range" =~ - ]]; then
                convert_range_to_cidr "$range" >> "$ip_list_file" || continue
            else
                echo "$range" >> "$ip_list_file"
            fi
        done < "$temp_range_file"
        validate_ip_list "$ip_list_file"
        if [ "$IPV6" = true ]; then
            jq -r '.data.resources.ipv6[]' "$tmp_file" > "${tmp_file}.v6" 2>/dev/null
            if [ -s "${tmp_file}.v6" ]; then
                validate_ip_list "${tmp_file}.v6"
            fi
        fi
    fi
    rm -f "$tmp_file" "$temp_range_file"

    # MaxMind (if license key provided, geoipupdate available, and --ip-source both)
    if [ "$GEOIPUPDATE_AVAILABLE" = true ] && [ -n "$MAXMIND_LICENSE_KEY" ] && [ -n "$MAXMIND_YOUR_ACCOUNT_ID" ] && [ "$IP_SOURCE" = "both" ]; then
        echo "INFO: Downloading MaxMind GeoLite2-Country CSV for $cc..."
        # Download GeoLite2-Country-CSV directly
        csv_zip="/tmp/GeoLite2-Country-CSV.zip"
        wget -q -O "$csv_zip" "https://download.maxmind.com/geoip/databases/GeoLite2-Country-CSV/download?suffix=zip" \
            --user="$MAXMIND_YOUR_ACCOUNT_ID" --password="$MAXMIND_LICENSE_KEY" || { echo "ERROR: Failed to download MaxMind GeoLite2-CSV."; exit 1; }
        unzip -q -o "$csv_zip" -d /tmp || { echo "ERROR: Failed to unzip MaxMind GeoLite2-CSV."; exit 1; }
        csv_file=$(find /tmp -name "GeoLite2-Country-Blocks-IPv4.csv" | head -n 1)
        if [ -z "$csv_file" ]; then
            echo "WARNING: GeoLite2-Country-Blocks-IPv4.csv not found. Falling back to RIPE."
            mv "$ip_list_file" "$tmp_file"
            rm -f "$csv_zip"
            return
        fi
        # Extract IPs for the country
        grep ",$cc," "$csv_file" | cut -d',' -f1 >> "$ip_list_file" || { echo "WARNING: Failed to extract IPs for $cc from MaxMind CSV. Falling back to RIPE."; mv "$ip_list_file" "$tmp_file"; rm -f "$csv_zip" /tmp/GeoLite2-Country_*/GeoLite2-Country-*.csv; return; }
        validate_ip_list "$ip_list_file"
        mv "$ip_list_file" "$tmp_file"
        rm -f "$csv_zip" /tmp/GeoLite2-Country_*/GeoLite2-Country-*.csv
    else
        if [ -n "$MAXMIND_LICENSE_KEY" ] && [ "$IP_SOURCE" = "both" ]; then
            echo "WARNING: geoipupdate or account ID missing. Falling back to RIPE. Install geoipupdate and set MAXMIND_YOUR_ACCOUNT_ID for MaxMind support."
        fi
        mv "$ip_list_file" "$tmp_file"
    fi
}

# === Build GeoIP Database ===
build_geoip_db() {
    echo "INFO: Building GeoIP database..."
    mkdir -p "$GEOIP_DIR" || { echo "ERROR: Failed to create $GEOIP_DIR."; exit 1; }
    cd "$XTABLES_DIR" || { echo "ERROR: Failed to change to $XTABLES_DIR."; exit 1; }
    for cc in "${COUNTRIES[@]}"; do
        ./xt_geoip_build -D "$GEOIP_DIR" "/tmp/${cc}.zone" || { echo "ERROR: Failed to build GeoIP database for $cc."; exit 1; }
    done
}

# === Create and Populate ipset ===
create_ipset() {
    echo "INFO: Creating ipset: $IPSET_NAME"
    ipset destroy "$IPSET_NAME" 2>/dev/null || true
    ipset create "$IPSET_NAME" hash:net family inet || { echo "ERROR: Failed to create ipset $IPSET_NAME."; exit 1; }
    if [ "$IPV6" = true ]; then
        IPSET_NAME_V6="geo-allowed-v6"
        ipset destroy "$IPSET_NAME_V6" 2>/dev/null || true
        ipset create "$IPSET_NAME_V6" hash:net family inet6 || { echo "ERROR: Failed to create ipset $IPSET_NAME_V6."; exit 1; }
    fi
}

populate_ipset() {
    echo "INFO: Adding country IPs..."
    for cc in "${COUNTRIES[@]}"; do
        echo "INFO:  -> $cc"
        download_geoip_data "$cc"
        while IFS= read -r ip; do
            [[ -z "$ip" ]] && continue
            ipset add "$IPSET_NAME" "$ip" || { echo "ERROR: Failed to add $ip to ipset."; exit 1; }
        done < "/tmp/${cc}.zone"
        if [ "$IPV6" = true ] && [ -f "/tmp/${cc}.zone.v6" ]; then
            while IFS= read -r ip; do
                [[ -z "$ip" ]] && continue
                ipset add "$IPSET_NAME_V6" "$ip" || { echo "ERROR: Failed to add IPv6 $ip to ipset."; exit 1; }
            done < "/tmp/${cc}.zone.v6"
        fi
        rm -f "/tmp/${cc}.zone" "/tmp/${cc}.zone.v6"
    done

    echo "INFO: Adding manual IPs..."
    for ip in "${MANUAL_IPS[@]}"; do
        if [[ "$ip" =~ : ]]; then
            ipset add "$IPSET_NAME_V6" "$ip" || { echo "ERROR: Failed to add manual IPv6 $ip to ipset."; exit 1; }
        else
            ipset add "$IPSET_NAME" "$ip" || { echo "ERROR: Failed to add manual IP $ip to ipset."; exit 1; }
        fi
    done

    echo "INFO: Adding LAN subnets..."
    detect_lan_subnets
    for subnet in "${LAN_SUBNETS[@]}"; do
        if [[ "$subnet" =~ : ]]; then
            ipset add "$IPSET_NAME_V6" "$subnet" || { echo "ERROR: Failed to add LAN IPv6 subnet $subnet to ipset."; exit 1; }
        else
            ipset add "$IPSET_NAME" "$subnet" || { echo "ERROR: Failed to add LAN subnet $subnet to ipset."; exit 1; }
        fi
    done
}

# === Save ipset for Persistence ===
save_ipset() {
    echo "INFO: Saving ipset to $IPSET_SAVE_PATH for persistence..."
    ipset save "$IPSET_NAME" > "$IPSET_SAVE_PATH" || { echo "ERROR: Failed to save ipset."; exit 1; }
    if [ "$IPV6" = true ]; then
        ipset save "$IPSET_NAME_V6" >> "$IPSET_SAVE_PATH" || { echo "ERROR: Failed to save IPv6 ipset."; exit 1; }
    fi
}

# === Create systemd Service for ipset Restore ===
create_systemd_service() {
    echo "INFO: Creating systemd service for ipset persistence..."
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
    systemctl enable ipset-restore.service || { echo "ERROR: Failed to enable ipset-restore service."; exit 1; }
}

# === Setup Blocked IP Logging ===
setup_blocked_ip_logging() {
    echo "INFO: Setting up blocked IP logging..."
    # Check firewalld state
    if ! firewall-cmd --state >/dev/null 2>&1; then
        echo "INFO: Firewalld is not running or in failed state. Using firewall-offline-cmd..."
        # Stop firewalld if running
        systemctl stop firewalld 2>/dev/null || true
        # Remove any existing GEO_BLOCK chain
        firewall-offline-cmd --direct --remove-chain ipv4 filter GEO_BLOCK 2>/dev/null || true
        firewall-offline-cmd --direct --remove-rules ipv4 filter GEO_BLOCK 2>/dev/null || true
        # Create GEO_BLOCK chain
        firewall-offline-cmd --direct --add-chain ipv4 filter GEO_BLOCK || { echo "ERROR: Failed to create GEO_BLOCK chain offline."; exit 1; }
        # Add logging and drop rules
        firewall-offline-cmd --direct --add-rule ipv4 filter GEO_BLOCK 0 -m limit --limit 1/minute -j LOG --log-prefix "GEO_BLOCK: " --log-level 4 || { echo "ERROR: Failed to add logging rule offline."; exit 1; }
        firewall-offline-cmd --direct --add-rule ipv4 filter GEO_BLOCK 1 -j DROP || { echo "ERROR: Failed to add drop rule offline."; exit 1; }
        if [ "$IPV6" = true ]; then
            # Remove any existing GEO_BLOCK chain for IPv6
            firewall-offline-cmd --direct --remove-chain ipv6 filter GEO_BLOCK 2>/dev/null || true
            firewall-offline-cmd --direct --remove-rules ipv6 filter GEO_BLOCK 2>/dev/null || true
            # Create GEO_BLOCK chain for IPv6
            firewall-offline-cmd --direct --add-chain ipv6 filter GEO_BLOCK || { echo "ERROR: Failed to create GEO_BLOCK chain for IPv6 offline."; exit 1; }
            # Add logging and drop rules for IPv6
            firewall-offline-cmd --direct --add-rule ipv6 filter GEO_BLOCK 0 -m limit --limit 1/minute -j LOG --log-prefix "GEO_BLOCK_V6: " --log-level 4 || { echo "ERROR: Failed to add IPv6 logging rule offline."; exit 1; }
            firewall-offline-cmd --direct --add-rule ipv6 filter GEO_BLOCK 1 -j DROP || { echo "ERROR: Failed to add IPv6 drop rule offline."; exit 1; }
        fi
        # Restart firewalld
        systemctl start firewalld || { echo "ERROR: Failed to restart firewalld."; exit 1; }
    else
        # Remove any existing GEO_BLOCK chain
        firewall-cmd --permanent --direct --remove-chain ipv4 filter GEO_BLOCK 2>/dev/null || true
        firewall-cmd --permanent --direct --remove-rules ipv4 filter GEO_BLOCK 2>/dev/null || true
        # Create GEO_BLOCK chain
        firewall-cmd --permanent --direct --add-chain ipv4 filter GEO_BLOCK || { echo "ERROR: Failed to create GEO_BLOCK chain."; exit 1; }
        # Add logging and drop rules
        firewall-cmd --permanent --direct --add-rule ipv4 filter GEO_BLOCK 0 -m limit --limit 1/minute -j LOG --log-prefix "GEO_BLOCK: " --log-level 4 || { echo "ERROR: Failed to add logging rule."; exit 1; }
        firewall-cmd --permanent --direct --add-rule ipv4 filter GEO_BLOCK 1 -j DROP || { echo "ERROR: Failed to add drop rule."; exit 1; }
        if [ "$IPV6" = true ]; then
            # Remove any existing GEO_BLOCK chain for IPv6
            firewall-cmd --permanent --direct --remove-chain ipv6 filter GEO_BLOCK 2>/dev/null || true
            firewall-cmd --permanent --direct --remove-rules ipv6 filter GEO_BLOCK 2>/dev/null || true
            # Create GEO_BLOCK chain for IPv6
            firewall-cmd --permanent --direct --add-chain ipv6 filter GEO_BLOCK || { echo "ERROR: Failed to create GEO_BLOCK chain for IPv6."; exit 1; }
            # Add logging and drop rules for IPv6
            firewall-cmd --permanent --direct --add-rule ipv6 filter GEO_BLOCK 0 -m limit --limit 1/minute -j LOG --log-prefix "GEO_BLOCK_V6: " --log-level 4 || { echo "ERROR: Failed to add IPv6 logging rule."; exit 1; }
            firewall-cmd --permanent --direct --add-rule ipv6 filter GEO_BLOCK 1 -j DROP || { echo "ERROR: Failed to add IPv6 drop rule."; exit 1; }
        fi
    fi
    # Ensure log file exists
    touch "$BLOCKED_IP_LOG"
    chmod 600 "$BLOCKED_IP_LOG"
}

# === Add firewalld rules ===
add_firewall_rules() {
    echo "INFO: Adding firewalld rules..."
    setup_blocked_ip_logging

    # Allow established and related sessions
    echo "INFO: Allowing established and related sessions"
    firewall-cmd --permanent --direct --add-rule ipv4 filter INPUT 0 \
        -m state --state ESTABLISHED,RELATED -j ACCEPT || { echo "ERROR: Failed to add ESTABLISHED/RELATED rule."; exit 1; }
    if [ "$IPV6" = true ]; then
        firewall-cmd --permanent --direct --add-rule ipv6 filter INPUT 0 \
            -m state --state ESTABLISHED,RELATED -j ACCEPT || { echo "ERROR: Failed to add IPv6 ESTABLISHED/RELATED rule."; exit 1; }
    fi

    # TCP
    if [ ${#TCP_PORTS[@]} -eq 0 ]; then
        echo "INFO:  -> All TCP ports"
        firewall-cmd --permanent --direct --add-rule ipv4 filter INPUT 1 \
            -p tcp -m state --state NEW -m set ! --match-set "$IPSET_NAME" src -j GEO_BLOCK || { echo "ERROR: Failed to add TCP rule."; exit 1; }
    else
        for port in "${TCP_PORTS[@]}"; do
            echo "INFO:  -> TCP $port"
            firewall-cmd --permanent --direct --add-rule ipv4 filter INPUT 1 \
                -p tcp --dport "$port" -m state --state NEW -m set ! --match-set "$IPSET_NAME" src -j GEO_BLOCK || { echo "ERROR: Failed to add TCP rule for port $port."; exit 1; }
        done
    fi

    # UDP
    if [ ${#UDP_PORTS[@]} -eq 0 ]; then
        echo "INFO:  -> All UDP ports"
        firewall-cmd --permanent --direct --add-rule ipv4 filter INPUT 1 \
            -p udp -m state --state NEW -m set ! --match-set "$IPSET_NAME" src -j GEO_BLOCK || { echo "ERROR: Failed to add UDP rule."; exit 1; }
    else
        for port in "${UDP_PORTS[@]}"; do
            echo "INFO:  -> UDP port $port"
            firewall-cmd --permanent --direct --add-rule ipv4 filter INPUT 1 \
                -p udp --dport "$port" -m state --state NEW -m set ! --match-set "$IPSET_NAME" src -j GEO_BLOCK || { echo "ERROR: Failed to add UDP rule for port $port". exit 1; }
        done
    fi

    # IPv6
    if [ "$IPV6" = true ]; then
        IPSET_NAME_V6="geo-allowed-v6-v6"
        if [ ${#TCP_PORTS[@]} -eq 0 ]; then
            echo "INFO:  -> All TCP IPv6 ports"
            firewall-cmd --permanent --direct --add-rule ipv6 filter INPUT 1 \
                -p tcp -m state --state NEW -m set ! --match-set "$IPSET_NAME_V6" src -j GEO_BLOCK || { echo "ERROR: Failed to add TCP IPv6 rule."; exit 1; }
        else
            for port in "${TCP_PORTS[@]}"; do
                echo "INFO:  -> TCP IPv6 $port"
                firewall-cmd --permanent --direct --add-rule ipv6 filter INPUT 1 \
                    -p tcp --dport "$port" -m state --state NEW -m set ! --match-set "$IPSET_NAME_V6" src -j GEO_BLOCK || { echo "ERROR: Failed to add TCP IPv6 rule for port $port."; exit 1; }
            done
        fi
        if [ ${#UDP_PORTS[@]} -eq 0 ]; then
            echo "INFO:  -> All UDP IPv6 ports"
            firewall-cmd --permanent --direct --add-rule ipv6 filter INPUT 1 \
                -p udp -m state --state NEW -m set ! --match-set "$IPSET_NAME_V6" src -j GEO_BLOCK || { echo "ERROR: Failed to add UDP IPv6 rule."; exit 1; }
        else
            for port in "${UDP_PORTS[@]}"; do
                echo "INFO:  -> UDP IPv6 $port"
                firewall-cmd --permanent --direct --add-rule ipv6 filter INPUT 1 \
                    -p udp --dport "$port" -m state --state NEW -m set ! --match-set "$IPSET_NAME_V6" src -j GEO_BLOCK || { echo "ERROR: Failed to add UDP IPv6 rule for port $port."; exit 1; }
            done
        fi
    fi
}

# === Cron Job for Daily GeoIP Update ===
create_cron_job() {
    echo "INFO: Installing daily cron job at $CRON_JOB_PATH"
    cat <<EOF > "$CRON_JOB_PATH"
#!/bin/bash
cd "$XTABLES_DIR" || { echo "ERROR: Failed to change to $XTABLES_DIR."; exit 1; }
ipset flush "$IPSET_NAME"
if [ "$IPV6" = true ]; then
    ipset flush "$IPSET_NAME_V6"
fi
for cc in ${COUNTRIES[*]}; do
    ip_list_file="/tmp/\${cc}_ips.txt"
    temp_range_file="/tmp/\${cc}_ranges.txt"
    > "\$ip_list_file"
    > "\$temp_range_file"
    wget -q -O "/tmp/\${cc}.zone" "https://stat.ripe.net/data/country-resource-list/data.json?resource=\${cc}&v=4" || { echo "ERROR: Failed to download RIPE IP list for \${cc}."; exit 1; }
    if [ -s "/tmp/\${cc}.zone" ]; then
        jq -r '.data.resources.ipv4[]' "/tmp/\${cc}.zone" > "\$temp_range_file" 2>/dev/null
        while IFS= read -r range; do
            [[ -z "\$range" ]] && continue
            if [[ "\$range" =~ - ]]; then
                ipcalc -r "\${range//-/ }" | grep -oE '[0-9.]+/[0-9]+' >> "\$ip_list_file" || continue
            else
                echo "\$range" >> "\$ip_list_file"
            fi
        done < "\$temp_range_file"
        if [ "$IPV6" = true ]; then
            jq -r '.data.resources.ipv6[]' "/tmp/\${cc}.zone" > "/tmp/\${cc}.zone.v6" 2>/dev/null
        fi
    fi
    if [ "$GEOIPUPDATE_AVAILABLE" = true ] && [ -n "$MAXMIND_LICENSE_KEY" ] && [ -n "$MAXMIND_YOUR_ACCOUNT_ID" ] && [ "$IP_SOURCE" = "both" ]; then
        csv_zip="/tmp/GeoLite2-Country-CSV.zip"
        wget -q -O "$csv_zip" "https://download.maxmind.com/geoip/databases/GeoLite2-Country-CSV/download?suffix=zip" \
            --user="$MAXMIND_YOUR_ACCOUNT_ID" --password="$MAXMIND_LICENSE_KEY" || { echo "WARNING: Failed to download MaxMind GeoLite2-CSV. Falling back to RIPE."; }
        unzip -q -o "$csv_zip" -d /tmp || { echo "WARNING: Failed to unzip MaxMind GeoLite2-CSV. Falling back to RIPE."; }
        csv_file=$(find /tmp -name "GeoLite2-Country-Blocks-IPv4.csv" | head -n 1)
        if [ -n "$csv_file" ]; then
            grep ",${cc}," "$csv_file" | cut -d',' -f1 >> "$ip_list_file" || { echo "WARNING: Failed to extract IPs for $cc from MaxMind CSV. Falling back to RIPE."; }
        fi
        rm -f "$csv_zip" /tmp/GeoLite2-Country_*/GeoLite2-Country-*.csv
    fi
    mv "\$ip_list_file" "/tmp/\${cc}.zone"
    ./xt_geoip_build -D "$GEOIP_DIR" "/tmp/\${cc}.zone" || { echo "ERROR: Failed to build GeoIP database for \${cc}."; exit 1; }
    while IFS= read -r ip; do
        [[ -z "\$ip" ]] && continue
        ipset add "$IPSET_NAME" "\$ip" || { echo "ERROR: Failed to add \$ip to ipset."; exit 1; }
    done < "/tmp/\${cc}.zone"
    if [ "$IPV6" = true ] && [ -f "/tmp/\${cc}.zone.v6" ]; then
        while IFS= read -r ip; do
            [[ -z "\$ip" ]] && continue
            ipset add "$IPSET_NAME_V6" "\$ip" || { echo "ERROR: Failed to add IPv6 \$ip to ipset."; exit 1; }
        done < "/tmp/\${cc}.zone.v6"
    fi
    rm -f "/tmp/\${cc}.zone" "/tmp/\${cc}.zone.v6" "\$temp_range_file"
done
for ip in ${MANUAL_IPS[*]}; do
    if [[ "\$ip" =~ : ]]; then
        ipset add "$IPSET_NAME_V6" "\$ip" || { echo "ERROR: Failed to add manual IPv6 \$ip to ipset."; exit 1; }
    else
        ipset add "$IPSET_NAME" "\$ip" || { echo "ERROR: Failed to add manual IP \$ip to ipset."; exit 1; }
    fi
done
LAN_SUBNETS=()
for iface in \$(ip link show | grep -E '^[0-9]+:.*state UP' | cut -d: -f2 | awk '{print \$1}'); do
    subnets=\$(ip addr show "\$iface" | grep -oE 'inet [0-9.]+/[0-9]+' | awk '{print \$2}')
    for subnet in \$subnets; do
        LAN_SUBNETS+=("\$subnet")
        ipset add "$IPSET_NAME" "\$subnet" || { echo "ERROR: Failed to add LAN subnet \$subnet to ipset."; exit 1; }
    done
    if [ "$IPV6" = true ]; then
        ipv6_subnets=\$(ip addr show "\$iface" | grep -oE 'inet6 [0-9a-fA-F:]+/[0-9]+' | awk '{print \$2}')
        for subnet in \$ipv6_subnets; do
            LAN_SUBNETS+=("\$subnet")
            ipset add "$IPSET_NAME_V6" "\$subnet" || { echo "ERROR: Failed to add LAN IPv6 subnet \$subnet to ipset."; exit 1; }
        done
    fi
done
ipset save "$IPSET_NAME" > "$IPSET_SAVE_PATH" || { echo "ERROR: Failed to save ipset."; exit 1; }
if [ "$IPV6" = true ]; then
    ipset save "$IPSET_NAME_V6" >> "$IPSET_SAVE_PATH" || { echo "ERROR: Failed to save IPv6 ipset."; exit 1; }
fi
echo "INFO: GeoIP update completed successfully."
EOF
    chmod +x "$CRON_JOB_PATH" || { echo "ERROR: Failed to create cron job."; exit 1; }
}

# === Main Execution ===
create_ipset
populate_ipset
save_ipset
create_systemd_service
add_firewall_rules
create_cron_job

echo "INFO: Reloading firewalld..."
firewall-cmd --reload || { echo "ERROR: Failed to reload firewalld."; exit 1; }

echo "INFO: GeoIP firewall filtering is now active."
