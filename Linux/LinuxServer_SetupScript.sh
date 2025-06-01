#!/bin/bash
set -e

INTERFACE_NAME="internal0"
PRIVATE_IP="10.94.195.1/24"
NETDEV_FILE="/etc/systemd/network/${INTERFACE_NAME}.netdev"
NETWORK_FILE="/etc/systemd/network/${INTERFACE_NAME}.network"
DOCKER_DAEMON_FILE="/etc/docker/daemon.json"
FIREWALLD_ZONE="trusted"
USER_NEW="username"
LOCALE_FILE="/etc/default/locale"

echo Adding new user with sudo privileges: $USER_NEW
sudo useradd -m $USER_NEW
sudo usermod -aG sudo $USER_NEW
sudo chsh -s /bin/sh $USER_NEW

sudo apt update && sudo apt install -y firewalld jq git net-tools

sudo tee $LOCALE_FILE > /dev/null <<EOF
LANG=en_US.UTF-8
LANGUAGE=en_US.UTF-8
LC_ALL=en_US.UTF-8
EOF
sudo locale-gen en_US.UTF-8
sudo update-locale LANG=en_US.UTF-8 LANGUAGE=en_US.UTF-8 LC_ALL=en_US.UTF-8


echo "Setting up firewall rules..."
sudo firewall-cmd --zone=public --add-port=80/tcp --permanent > /dev/null
sudo firewall-cmd --zone=public --add-port=443/tcp --permanent > /dev/null
sudo firewall-cmd --zone=public --add-port=25/tcp --permanent > /dev/null
sudo firewall-cmd --zone=public --add-port=465/tcp --permanent > /dev/null
sudo firewall-cmd --zone=public --add-port=587/tcp --permanent > /dev/null
sudo firewall-cmd --zone=public --add-port=8000/tcp --permanent > /dev/null
sudo firewall-cmd --zone=public --add-port=5000/tcp --permanent > /dev/null

sudo firewall-cmd --zone=public --add-port=500/udp --permanent > /dev/null
sudo firewall-cmd --zone=public --add-port=4500/udp --permanent > /dev/null

sudo firewall-cmd --zone=public --change-interface=ens6 --permanent
sudo firewall-cmd --permanent --zone=public --add-masquerade  > /dev/null
sudo firewall-cmd --set-default-zone=trusted

sudo firewall-cmd --reload
sudo firewall-cmd --get-default-zone

echo "Creating dummy interface: $INTERFACE_NAME"

# Create .netdev file
cat <<EOF | sudo tee "$NETDEV_FILE"
[NetDev]
Name=$INTERFACE_NAME
Kind=dummy
EOF

# Create .network file
cat <<EOF | sudo tee "$NETWORK_FILE"
[Match]
Name=$INTERFACE_NAME

[Network]
Address=$PRIVATE_IP
EOF

echo "Reloading systemd-networkd configuration..."

sudo systemctl restart systemd-networkd

# Wait for interface to be created
sleep 2

# Add interface to firewalld trusted zone
echo "Assigning interface to firewalld trusted zone..."
sudo firewall-cmd --zone=trusted --add-interface=$INTERFACE_NAME --permanent
sudo firewall-cmd --reload

echo "Done. Verifying..."

ip a show "$INTERFACE_NAME"
sudo firewall-cmd --get-active-zones

sudo update-alternatives --set iptables /usr/sbin/iptables-legacy
sudo update-alternatives --set ip6tables /usr/sbin/ip6tables-legacy
sudo update-alternatives --set arptables /usr/sbin/arptables-legacy
sudo update-alternatives --set ebtables /usr/sbin/ebtables-legacy
sudo systemctl restart firewalld

echo "Installing Docker..."

sudo apt-get install ca-certificates curl
sudo install -m 0755 -d /etc/apt/keyrings
sudo curl -fsSL https://download.docker.com/linux/debian/gpg -o /etc/apt/keyrings/docker.asc
sudo chmod a+r /etc/apt/keyrings/docker.asc
echo \
  "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/debian \
  $(. /etc/os-release && echo "$VERSION_CODENAME") stable" | \
  sudo tee /etc/apt/sources.list.d/docker.list > /dev/null
sudo apt-get update
sudo apt-get install -y docker-ce docker-ce-cli containerd.io \
    docker-buildx-plugin docker-compose-plugin docker-compose

sudo usermod -aG docker $USER_NEW

sudo mkdir -p /etc/docker
if [[ -f "$DOCKER_DAEMON_FILE" ]]; then
    if grep -q '"iptables": false' "$DOCKER_DAEMON_FILE"; then
        echo "Docker already configured to not use iptables."
    else
        echo "Adding iptables=false to existing daemon.json..."
        sudo jq '. + {iptables: false}' "$DOCKER_DAEMON_FILE" | sudo tee "$DOCKER_DAEMON_FILE" > /dev/null
    fi
else
    echo '{ "iptables": false }' | sudo tee "$DOCKER_DAEMON_FILE" > /dev/null
fi

docker network create \
  --driver=bridge \
  --subnet=172.32.97.0/24 \
  --gateway=172.32.97.1 \
  --attachable=true \
  --opt com.docker.network.bridge.name=backend \
  backend

sudo systemctl restart docker

echo "Creating symlink for python... if necessary"
command -v python >/dev/null 2>&1 || (PY3=$(command -v python3) && sudo ln -s "$PY3" /usr/bin/python && echo "Linked python -> $PY3") || echo "python3 not found"

sudo firewall-cmd --get-active-zones


