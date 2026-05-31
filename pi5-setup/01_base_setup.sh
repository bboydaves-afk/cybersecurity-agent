#!/bin/bash
# =============================================================================
# Raspberry Pi 5 - Cybersecurity Platform Base Setup
# Run as root: sudo bash 01_base_setup.sh
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
echo "  Raspberry Pi 5 — Cybersecurity AI Agent Platform Setup"
echo "============================================================"
echo ""

# ---------------------------------------------------------
# 1. System Update
# ---------------------------------------------------------
log "Phase 1: System update and upgrade..."
apt update && apt full-upgrade -y
apt autoremove -y

# ---------------------------------------------------------
# 2. Essential System Packages
# ---------------------------------------------------------
log "Phase 2: Installing essential system packages..."
apt install -y \
    build-essential \
    git \
    curl \
    wget \
    vim \
    tmux \
    htop \
    tree \
    jq \
    unzip \
    p7zip-full \
    net-tools \
    dnsutils \
    whois \
    traceroute \
    mtr \
    iptables \
    ufw \
    fail2ban \
    sqlite3 \
    libsqlite3-dev \
    libffi-dev \
    libssl-dev \
    libxml2-dev \
    libxslt1-dev \
    zlib1g-dev \
    libbz2-dev \
    libreadline-dev \
    llvm \
    libncurses5-dev \
    libncursesw5-dev \
    xz-utils \
    tk-dev \
    libsnmp-dev \
    snmp \
    snmpd \
    openssh-server \
    sshpass \
    nfs-common \
    smbclient

# ---------------------------------------------------------
# 3. Python 3.11+ Setup
# ---------------------------------------------------------
log "Phase 3: Setting up Python environment..."

# Kali should have Python 3.11+ already, verify
PYTHON_VERSION=$(python3 --version 2>&1 | awk '{print $2}')
info "System Python: $PYTHON_VERSION"

# Install pip and venv
apt install -y python3-pip python3-venv python3-dev

# Allow pip install without venv warning (for system tools)
mkdir -p /etc/pip
cat > /etc/pip/pip.conf << 'PIPCONF'
[global]
break-system-packages = true
PIPCONF

# ---------------------------------------------------------
# 4. Kali Pentest Tool Groups
# ---------------------------------------------------------
log "Phase 4: Installing Kali pentest tool groups..."
info "This will take a while on first install..."

# Core pentest tools (smaller than kali-linux-large)
apt install -y \
    kali-tools-information-gathering \
    kali-tools-vulnerability \
    kali-tools-web \
    kali-tools-passwords \
    kali-tools-sniffing-spoofing \
    kali-tools-exploitation \
    2>/dev/null || warn "Some kali metapackages not available, installing individually..."

# Individual tools (in case metapackages fail)
apt install -y \
    nmap \
    masscan \
    nikto \
    dirb \
    gobuster \
    sqlmap \
    wfuzz \
    hydra \
    john \
    hashcat \
    medusa \
    aircrack-ng \
    wireshark-common \
    tshark \
    tcpdump \
    ettercap-text-only \
    arpwatch \
    netcat-openbsd \
    socat \
    proxychains4 \
    tor \
    enum4linux \
    smbmap \
    impacket-scripts \
    crackmapexec \
    responder \
    wordlists \
    seclists \
    metasploit-framework \
    exploitdb \
    searchsploit \
    wpscan \
    burpsuite \
    zaproxy \
    recon-ng \
    maltego \
    theharvester \
    fierce \
    dnsrecon \
    sublist3r \
    amass \
    whatweb \
    wafw00f \
    2>/dev/null || warn "Some tools not available in repo, continuing..."

# ---------------------------------------------------------
# 5. Additional Security Tools (pip)
# ---------------------------------------------------------
log "Phase 5: Installing Python security tools..."
pip3 install --break-system-packages \
    impacket \
    pwntools \
    volatility3 \
    mitm6 \
    bloodhound \
    certipy-ad \
    pypykatz \
    ldapdomaindump \
    droopescan \
    cme \
    2>/dev/null || warn "Some pip tools failed, continuing..."

# ---------------------------------------------------------
# 6. Metasploit Configuration
# ---------------------------------------------------------
log "Phase 6: Configuring Metasploit Framework..."
if command -v msfconsole &>/dev/null; then
    # Initialize MSF database
    systemctl enable postgresql
    systemctl start postgresql
    msfdb init 2>/dev/null || warn "MSF DB already initialized"
    info "Metasploit database initialized"

    # Enable MSF RPC for agent integration
    cat > /etc/systemd/system/msfrpcd.service << 'MSFRPC'
[Unit]
Description=Metasploit RPC Daemon
After=postgresql.service network.target

[Service]
Type=simple
User=root
ExecStart=/usr/bin/msfrpcd -U msf -P msfrpc123 -S -p 55553 -a 127.0.0.1
Restart=on-failure
RestartSec=10

[Install]
WantedBy=multi-user.target
MSFRPC
    systemctl daemon-reload
    systemctl enable msfrpcd
    warn "MSF RPC password set to 'msfrpc123' — CHANGE THIS in production!"
else
    warn "Metasploit not found, skipping RPC setup"
fi

# ---------------------------------------------------------
# 7. Directory Structure
# ---------------------------------------------------------
log "Phase 7: Creating agent directory structure..."
mkdir -p "$HOME_DIR/agents"
mkdir -p "$HOME_DIR/engagements"
mkdir -p "$HOME_DIR/loot"
mkdir -p "$HOME_DIR/wordlists"
mkdir -p "$HOME_DIR/reports"
mkdir -p "$HOME_DIR/scripts"
mkdir -p /var/log/cybersec-agents

# Copy wordlists to accessible location
if [ -d /usr/share/wordlists ]; then
    ln -sf /usr/share/wordlists "$HOME_DIR/wordlists/system"
    info "Linked system wordlists to ~/wordlists/system"
fi
if [ -d /usr/share/seclists ]; then
    ln -sf /usr/share/seclists "$HOME_DIR/wordlists/seclists"
    info "Linked SecLists to ~/wordlists/seclists"
fi

chown -R "$ACTUAL_USER:$ACTUAL_USER" "$HOME_DIR/agents"
chown -R "$ACTUAL_USER:$ACTUAL_USER" "$HOME_DIR/engagements"
chown -R "$ACTUAL_USER:$ACTUAL_USER" "$HOME_DIR/loot"
chown -R "$ACTUAL_USER:$ACTUAL_USER" "$HOME_DIR/wordlists"
chown -R "$ACTUAL_USER:$ACTUAL_USER" "$HOME_DIR/reports"
chown -R "$ACTUAL_USER:$ACTUAL_USER" "$HOME_DIR/scripts"

# ---------------------------------------------------------
# 8. Performance Tuning for Pi 5
# ---------------------------------------------------------
log "Phase 8: Performance tuning for Raspberry Pi 5..."

# Increase swap for ML/AI workloads
if [ -f /etc/dphys-swapfile ]; then
    sed -i 's/CONF_SWAPSIZE=.*/CONF_SWAPSIZE=2048/' /etc/dphys-swapfile
    systemctl restart dphys-swapfile
    info "Swap increased to 2GB"
elif ! swapon --show | grep -q "swapfile"; then
    fallocate -l 2G /swapfile
    chmod 600 /swapfile
    mkswap /swapfile
    swapon /swapfile
    echo '/swapfile none swap sw 0 0' >> /etc/fstab
    info "Created 2GB swap file"
fi

# GPU memory split — minimize GPU, maximize CPU RAM for headless
if [ -f /boot/firmware/config.txt ]; then
    if ! grep -q "gpu_mem=" /boot/firmware/config.txt; then
        echo "gpu_mem=16" >> /boot/firmware/config.txt
        info "GPU memory reduced to 16MB (headless optimization)"
    fi
fi

# Kernel parameters for network performance
cat > /etc/sysctl.d/99-cybersec-pi.conf << 'SYSCTL'
# Network performance for scanning/monitoring
net.core.rmem_max = 16777216
net.core.wmem_max = 16777216
net.ipv4.tcp_rmem = 4096 87380 16777216
net.ipv4.tcp_wmem = 4096 65536 16777216
net.core.netdev_max_backlog = 5000

# Allow IP forwarding (for MITM / routing)
net.ipv4.ip_forward = 1

# Ignore ICMP redirects (security)
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0

# Don't send ICMP redirects
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0

# Increase file descriptors for scanning
fs.file-max = 65535
SYSCTL
sysctl -p /etc/sysctl.d/99-cybersec-pi.conf

# Increase open file limits
cat >> /etc/security/limits.conf << 'LIMITS'
# Cybersec agent limits
*    soft    nofile    65535
*    hard    nofile    65535
kali soft    nofile    65535
kali hard    nofile    65535
LIMITS

# ---------------------------------------------------------
# 9. WiFi Monitor Mode Setup (if applicable)
# ---------------------------------------------------------
log "Phase 9: WiFi adapter configuration..."
if lsusb 2>/dev/null | grep -qi "realtek\|ralink\|atheros\|alfa"; then
    info "External WiFi adapter detected"
    apt install -y realtek-rtl88xxau-dkms 2>/dev/null || true
    info "Installed RTL88xx drivers for monitor mode"
else
    info "No external WiFi adapter detected — plug one in for wireless pentesting"
fi

# ---------------------------------------------------------
# Done
# ---------------------------------------------------------
echo ""
echo "============================================================"
log "Base setup complete!"
echo "============================================================"
echo ""
info "System packages:     Installed"
info "Python 3:            $PYTHON_VERSION"
info "Kali tools:          Installed"
info "Metasploit:          $(command -v msfconsole &>/dev/null && echo 'Ready' || echo 'Not found')"
info "Swap:                2GB"
info "GPU memory:          16MB (headless)"
info "Directory structure: ~/agents, ~/engagements, ~/loot, ~/reports"
echo ""
warn "NEXT: Run 02_deploy_agents.sh to deploy the AI agents"
warn "REMEMBER: Change the MSF RPC password before production use!"
echo ""
