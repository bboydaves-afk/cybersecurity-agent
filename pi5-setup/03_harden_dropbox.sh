#!/bin/bash
# =============================================================================
# Raspberry Pi 5 - Security Hardening & Drop Box Configuration
# Run as root: sudo bash 03_harden_dropbox.sh
# =============================================================================

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

log()  { echo -e "${GREEN}[+]${NC} $1"; }
warn() { echo -e "${YELLOW}[!]${NC} $1"; }
err()  { echo -e "${RED}[-]${NC} $1"; }
info() { echo -e "${CYAN}[*]${NC} $1"; }

if [ "$EUID" -ne 0 ]; then
    err "Run as root: sudo bash $0"
    exit 1
fi

ACTUAL_USER="${SUDO_USER:-kali}"
HOME_DIR="/home/$ACTUAL_USER"

echo ""
echo "============================================================"
echo "  Security Hardening & Drop Box Configuration"
echo "============================================================"
echo ""

# ---------------------------------------------------------
# 1. SSH Hardening
# ---------------------------------------------------------
log "Phase 1: Hardening SSH..."

# Backup original config
cp /etc/ssh/sshd_config /etc/ssh/sshd_config.bak

# Change SSH port
SSH_PORT=2222
info "Changing SSH port to $SSH_PORT"

cat > /etc/ssh/sshd_config.d/hardened.conf << SSHCONFIG
# Cybersec Pi hardened SSH config
Port $SSH_PORT
PermitRootLogin no
PasswordAuthentication no
PubkeyAuthentication yes
MaxAuthTries 3
MaxSessions 3
X11Forwarding no
AllowTcpForwarding yes
GatewayPorts no
PermitTunnel yes
ClientAliveInterval 300
ClientAliveCountMax 2
LoginGraceTime 30
Banner none
SSHCONFIG

# Generate SSH key for the user if not exists
if [ ! -f "$HOME_DIR/.ssh/id_ed25519" ]; then
    sudo -u "$ACTUAL_USER" ssh-keygen -t ed25519 -f "$HOME_DIR/.ssh/id_ed25519" -N "" -C "cybersec-pi"
    info "Generated ED25519 SSH key"
fi

# Ensure authorized_keys exists
sudo -u "$ACTUAL_USER" mkdir -p "$HOME_DIR/.ssh"
sudo -u "$ACTUAL_USER" touch "$HOME_DIR/.ssh/authorized_keys"
chmod 700 "$HOME_DIR/.ssh"
chmod 600 "$HOME_DIR/.ssh/authorized_keys"

warn "ADD YOUR PUBLIC KEY to $HOME_DIR/.ssh/authorized_keys before restarting SSH!"
warn "Password auth will be DISABLED after restart."
warn "SSH port changed to $SSH_PORT"

# Don't restart SSH yet - user needs to add their key first

# ---------------------------------------------------------
# 2. Firewall (UFW)
# ---------------------------------------------------------
log "Phase 2: Configuring firewall..."

ufw --force reset
ufw default deny incoming
ufw default allow outgoing

# SSH (new port)
ufw allow "$SSH_PORT/tcp" comment "SSH"

# Agent dashboards (restrict to local network)
ufw allow from 192.168.0.0/16 to any port 8080 comment "SysAdmin Agent"
ufw allow from 192.168.0.0/16 to any port 8081 comment "Network Agent"
ufw allow from 192.168.0.0/16 to any port 8084 comment "Hacking Agent"
ufw allow from 10.0.0.0/8 to any port 8080 comment "SysAdmin Agent (10.x)"
ufw allow from 10.0.0.0/8 to any port 8081 comment "Network Agent (10.x)"
ufw allow from 10.0.0.0/8 to any port 8084 comment "Hacking Agent (10.x)"

# Metasploit RPC (localhost only - already bound to 127.0.0.1)
# No rule needed, it's localhost only

ufw --force enable
log "Firewall enabled with agent ports open to local networks"

# ---------------------------------------------------------
# 3. Fail2Ban
# ---------------------------------------------------------
log "Phase 3: Configuring Fail2Ban..."

cat > /etc/fail2ban/jail.d/cybersec-pi.conf << FAIL2BAN
[sshd]
enabled = true
port = $SSH_PORT
filter = sshd
logpath = /var/log/auth.log
maxretry = 3
bantime = 3600
findtime = 600

[agent-dashboards]
enabled = true
port = 8080,8081,8084
filter = agent-auth
logpath = /var/log/cybersec-agents/*.log
maxretry = 5
bantime = 1800
findtime = 300
FAIL2BAN

# Create filter for agent auth failures
cat > /etc/fail2ban/filter.d/agent-auth.conf << 'FILTER'
[Definition]
failregex = ^.*LOGIN_FAILED.*from <HOST>.*$
            ^.*401.*<HOST>.*$
            ^.*Unauthorized.*<HOST>.*$
ignoreregex =
FILTER

systemctl enable fail2ban
systemctl restart fail2ban
log "Fail2Ban configured"

# ---------------------------------------------------------
# 4. Automatic Updates (security only)
# ---------------------------------------------------------
log "Phase 4: Configuring automatic security updates..."

apt install -y unattended-upgrades apt-listchanges
cat > /etc/apt/apt.conf.d/50unattended-upgrades << 'AUTOUPDATE'
Unattended-Upgrade::Allowed-Origins {
    "${distro_id}:${distro_codename}-security";
};
Unattended-Upgrade::AutoFixInterruptedDpkg "true";
Unattended-Upgrade::Remove-Unused-Dependencies "true";
Unattended-Upgrade::Automatic-Reboot "false";
AUTOUPDATE

cat > /etc/apt/apt.conf.d/20auto-upgrades << 'AUTOPERIODIC'
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
APT::Periodic::AutocleanInterval "7";
AUTOPERIODIC

log "Automatic security updates enabled"

# ---------------------------------------------------------
# 5. Log Rotation for Agents
# ---------------------------------------------------------
log "Phase 5: Configuring log rotation..."

cat > /etc/logrotate.d/cybersec-agents << 'LOGROTATE'
/var/log/cybersec-agents/*.log {
    daily
    rotate 14
    compress
    delaycompress
    missingok
    notifempty
    create 0640 kali kali
    sharedscripts
    postrotate
        systemctl reload hacking-agent sysadmin-agent network-agent 2>/dev/null || true
    endscript
}
LOGROTATE

log "Log rotation configured (14 days retention)"

# ---------------------------------------------------------
# 6. Encrypted Storage for Loot
# ---------------------------------------------------------
log "Phase 6: Setting up encrypted storage for loot/evidence..."

apt install -y cryptsetup

LOOT_IMG="$HOME_DIR/.loot_vault.img"
LOOT_MOUNT="$HOME_DIR/loot"

if [ ! -f "$LOOT_IMG" ]; then
    info "Creating 1GB encrypted vault for loot storage..."
    dd if=/dev/zero of="$LOOT_IMG" bs=1M count=1024 status=progress
    chown "$ACTUAL_USER:$ACTUAL_USER" "$LOOT_IMG"

    # Create mount/unmount scripts
    cat > "$HOME_DIR/agents/vault-open.sh" << 'VAULTOPEN'
#!/bin/bash
# Open the encrypted loot vault
LOOT_IMG="$HOME/.loot_vault.img"
LOOT_MOUNT="$HOME/loot"

echo "Opening encrypted vault..."
sudo cryptsetup luksOpen "$LOOT_IMG" loot_vault
sudo mount /dev/mapper/loot_vault "$LOOT_MOUNT"
echo "[+] Vault mounted at $LOOT_MOUNT"
VAULTOPEN

    cat > "$HOME_DIR/agents/vault-close.sh" << 'VAULTCLOSE'
#!/bin/bash
# Close and lock the encrypted loot vault
LOOT_MOUNT="$HOME/loot"

echo "Closing encrypted vault..."
sudo umount "$LOOT_MOUNT" 2>/dev/null
sudo cryptsetup luksClose loot_vault
echo "[+] Vault locked"
VAULTCLOSE

    chmod +x "$HOME_DIR/agents/vault-open.sh"
    chmod +x "$HOME_DIR/agents/vault-close.sh"

    warn "Encrypted vault image created at $LOOT_IMG"
    warn "You need to format it on first use:"
    warn "  sudo cryptsetup luksFormat $LOOT_IMG"
    warn "  sudo cryptsetup luksOpen $LOOT_IMG loot_vault"
    warn "  sudo mkfs.ext4 /dev/mapper/loot_vault"
    warn "  sudo cryptsetup luksClose loot_vault"
    warn "Then use: ~/agents/vault-open.sh and ~/agents/vault-close.sh"
else
    info "Vault image already exists"
fi

# ---------------------------------------------------------
# 7. Drop Box Stealth Features
# ---------------------------------------------------------
log "Phase 7: Drop box stealth configuration..."

# Create stealth mode toggle
cat > "$HOME_DIR/agents/stealth.sh" << 'STEALTH'
#!/bin/bash
# Toggle stealth mode for drop box deployment

case "$1" in
    on)
        echo "[*] Enabling stealth mode..."

        # Disable LEDs
        echo none | sudo tee /sys/class/leds/ACT/trigger > /dev/null 2>&1
        echo 0 | sudo tee /sys/class/leds/ACT/brightness > /dev/null 2>&1
        echo none | sudo tee /sys/class/leds/PWR/trigger > /dev/null 2>&1
        echo 0 | sudo tee /sys/class/leds/PWR/brightness > /dev/null 2>&1

        # Disable HDMI output
        tvservice -o 2>/dev/null || true

        # Reduce network noise - disable mDNS/Avahi
        sudo systemctl stop avahi-daemon 2>/dev/null || true
        sudo systemctl stop cups 2>/dev/null || true
        sudo systemctl stop bluetooth 2>/dev/null || true

        # Set hostname to something inconspicuous
        sudo hostnamectl set-hostname "localhost"

        echo "[+] Stealth mode ON - LEDs off, services minimized"
        ;;
    off)
        echo "[*] Disabling stealth mode..."

        # Re-enable LEDs
        echo default-on | sudo tee /sys/class/leds/ACT/trigger > /dev/null 2>&1
        echo default-on | sudo tee /sys/class/leds/PWR/trigger > /dev/null 2>&1

        # Re-enable HDMI
        tvservice -p 2>/dev/null || true

        # Re-enable services
        sudo systemctl start avahi-daemon 2>/dev/null || true

        # Reset hostname
        sudo hostnamectl set-hostname "cybersec-pi"

        echo "[+] Stealth mode OFF"
        ;;
    *)
        echo "Usage: ./stealth.sh [on|off]"
        ;;
esac
STEALTH

chmod +x "$HOME_DIR/agents/stealth.sh"

# ---------------------------------------------------------
# 8. Panic / Wipe Script
# ---------------------------------------------------------
log "Phase 8: Creating emergency wipe script..."

cat > "$HOME_DIR/agents/panic.sh" << 'PANIC'
#!/bin/bash
# EMERGENCY: Securely wipe sensitive data
# USE WITH EXTREME CAUTION - THIS IS IRREVERSIBLE

RED='\033[0;31m'; NC='\033[0m'

echo -e "${RED}"
echo "============================================"
echo "  EMERGENCY WIPE - ALL DATA WILL BE LOST"
echo "============================================"
echo -e "${NC}"

read -p "Type 'WIPE' to confirm: " CONFIRM
if [ "$CONFIRM" != "WIPE" ]; then
    echo "Aborted."
    exit 1
fi

echo "[!] Stopping all agents..."
sudo systemctl stop hacking-agent sysadmin-agent network-agent 2>/dev/null

echo "[!] Closing encrypted vault..."
sudo umount ~/loot 2>/dev/null
sudo cryptsetup luksClose loot_vault 2>/dev/null

echo "[!] Wiping databases..."
find ~/agents -name "*.db" -exec shred -vfz -n 3 {} \;

echo "[!] Wiping environment file..."
shred -vfz -n 3 ~/agents/.env 2>/dev/null

echo "[!] Wiping loot vault..."
shred -vfz -n 1 ~/.loot_vault.img 2>/dev/null

echo "[!] Wiping engagement data..."
find ~/engagements -type f -exec shred -vfz -n 1 {} \;
find ~/reports -type f -exec shred -vfz -n 1 {} \;

echo "[!] Clearing logs..."
journalctl --rotate
journalctl --vacuum-time=1s
find /var/log -type f -exec truncate -s 0 {} \; 2>/dev/null

echo "[!] Clearing bash history..."
history -c
shred -vfz -n 3 ~/.bash_history 2>/dev/null
shred -vfz -n 3 ~/.python_history 2>/dev/null

echo "[+] Emergency wipe complete"
echo "[*] Consider running: sudo shutdown -h now"
PANIC

chmod +x "$HOME_DIR/agents/panic.sh"
warn "Emergency wipe script created at ~/agents/panic.sh"

# ---------------------------------------------------------
# 9. Network Bridge Mode (dual NIC inline tap)
# ---------------------------------------------------------
log "Phase 9: Creating network bridge configuration..."

cat > "$HOME_DIR/agents/bridge-mode.sh" << 'BRIDGE'
#!/bin/bash
# Set up transparent network bridge for inline packet capture
# Requires: eth0 (built-in) + eth1 (USB ethernet adapter)

case "$1" in
    on)
        echo "[*] Setting up transparent bridge (eth0 <-> eth1)..."

        # Install bridge utils if needed
        sudo apt install -y bridge-utils

        # Create bridge
        sudo ip link add name br0 type bridge
        sudo ip link set eth0 master br0
        sudo ip link set eth1 master br0
        sudo ip link set br0 up
        sudo ip link set eth0 up
        sudo ip link set eth1 up

        # Enable STP
        sudo brctl stp br0 off

        # Get DHCP on bridge
        sudo dhclient br0

        echo "[+] Bridge mode ON - traffic flows through Pi transparently"
        echo "[*] Capture with: sudo tcpdump -i br0 -w capture.pcap"
        ;;
    off)
        echo "[*] Tearing down bridge..."
        sudo ip link set eth0 nomaster
        sudo ip link set eth1 nomaster
        sudo ip link delete br0
        sudo dhclient eth0
        echo "[+] Bridge mode OFF"
        ;;
    *)
        echo "Usage: ./bridge-mode.sh [on|off]"
        echo "Requires USB Ethernet adapter as eth1"
        ;;
esac
BRIDGE

chmod +x "$HOME_DIR/agents/bridge-mode.sh"

# ---------------------------------------------------------
# 10. Set ownership
# ---------------------------------------------------------
log "Phase 10: Setting file ownership..."
chown -R "$ACTUAL_USER:$ACTUAL_USER" "$HOME_DIR/agents"
chown -R "$ACTUAL_USER:$ACTUAL_USER" "$HOME_DIR/.ssh"

# ---------------------------------------------------------
# Done
# ---------------------------------------------------------
echo ""
echo "============================================================"
log "Hardening & drop box configuration complete!"
echo "============================================================"
echo ""
info "SSH port:            $SSH_PORT (add your pubkey before restarting!)"
info "Firewall:            UFW enabled, agents on local network only"
info "Fail2Ban:            Active on SSH + agent dashboards"
info "Encrypted vault:     $LOOT_IMG (format on first use)"
info "Stealth mode:        ~/agents/stealth.sh [on|off]"
info "Bridge mode:         ~/agents/bridge-mode.sh [on|off]"
info "Emergency wipe:      ~/agents/panic.sh"
echo ""
warn "CRITICAL: Before restarting SSH, add your public key:"
warn "  echo 'your-public-key' >> $HOME_DIR/.ssh/authorized_keys"
warn "  sudo systemctl restart sshd"
echo ""
warn "NEXT: Run 04_field_operations.sh for reverse SSH & auto-callback"
echo ""
