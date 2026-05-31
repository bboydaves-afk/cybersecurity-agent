#!/bin/bash
# =============================================================================
# Raspberry Pi 5 - Deploy AI Agents
# Run as regular user: bash 02_deploy_agents.sh
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

AGENTS_DIR="$HOME/agents"
ENV_FILE="$AGENTS_DIR/.env"

echo ""
echo "============================================================"
echo "  Deploying Cybersecurity AI Agents"
echo "============================================================"
echo ""

# ---------------------------------------------------------
# 1. Verify agent directories exist
# ---------------------------------------------------------
log "Phase 1: Verifying agent directories..."

AGENTS=("hacking_agent" "sysadmin_agent" "network_agent")
for agent in "${AGENTS[@]}"; do
    if [ ! -d "$AGENTS_DIR/$agent" ]; then
        err "$agent not found at $AGENTS_DIR/$agent"
        err "Copy it from your desktop first:"
        err "  scp -r ${agent}/ kali@cybersec-pi.local:~/agents/${agent}/"
        exit 1
    fi
    info "Found $agent"
done

# ---------------------------------------------------------
# 2. Create shared .env file
# ---------------------------------------------------------
log "Phase 2: Creating shared environment file..."

if [ ! -f "$ENV_FILE" ]; then
    cat > "$ENV_FILE" << 'ENVFILE'
# =============================================================================
# Shared Environment Variables for All Agents
# EDIT THESE with your actual API keys before starting agents
# =============================================================================

# --- Claude AI (REQUIRED for all agents) ---
ANTHROPIC_API_KEY=sk-ant-xxxxx-your-key-here

# --- Hacking Agent Secrets ---
HACKING_ENCRYPTION_KEY=
HACKING_SECRET_KEY=
SHODAN_API_KEY=
VIRUSTOTAL_API_KEY=
HIBP_API_KEY=
NVD_API_KEY=
MSF_RPC_PASSWORD=msfrpc123
BURP_API_KEY=
GITHUB_TOKEN=

# --- SysAdmin Agent Secrets ---
SYSADMIN_ENCRYPTION_KEY=
SYSADMIN_SECRET_KEY=

# --- Network Agent Secrets ---
NETAGENT_ENCRYPTION_KEY=
NETAGENT_SECRET_KEY=

# --- Cloud Credentials (optional) ---
AWS_PROFILE=
AZURE_SUBSCRIPTION_ID=
AZURE_TENANT_ID=
GCP_PROJECT_ID=
GOOGLE_APPLICATION_CREDENTIALS=

# --- Notifications (optional) ---
SLACK_WEBHOOK_URL=
TEAMS_WEBHOOK_URL=
SMTP_HOST=
SMTP_PORT=587
SMTP_USER=
SMTP_PASSWORD=
ENVFILE

    # Generate encryption keys
    HACK_KEY=$(python3 -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())")
    HACK_SECRET=$(python3 -c "import secrets; print(secrets.token_hex(32))")
    SYS_KEY=$(python3 -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())")
    SYS_SECRET=$(python3 -c "import secrets; print(secrets.token_hex(32))")
    NET_KEY=$(python3 -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())")
    NET_SECRET=$(python3 -c "import secrets; print(secrets.token_hex(32))")

    sed -i "s|^HACKING_ENCRYPTION_KEY=.*|HACKING_ENCRYPTION_KEY=$HACK_KEY|" "$ENV_FILE"
    sed -i "s|^HACKING_SECRET_KEY=.*|HACKING_SECRET_KEY=$HACK_SECRET|" "$ENV_FILE"
    sed -i "s|^SYSADMIN_ENCRYPTION_KEY=.*|SYSADMIN_ENCRYPTION_KEY=$SYS_KEY|" "$ENV_FILE"
    sed -i "s|^SYSADMIN_SECRET_KEY=.*|SYSADMIN_SECRET_KEY=$SYS_SECRET|" "$ENV_FILE"
    sed -i "s|^NETAGENT_ENCRYPTION_KEY=.*|NETAGENT_ENCRYPTION_KEY=$NET_KEY|" "$ENV_FILE"
    sed -i "s|^NETAGENT_SECRET_KEY=.*|NETAGENT_SECRET_KEY=$NET_SECRET|" "$ENV_FILE"

    info "Generated encryption keys automatically"
    warn "EDIT $ENV_FILE with your ANTHROPIC_API_KEY and other API keys!"
else
    info "Environment file already exists at $ENV_FILE"
fi

chmod 600 "$ENV_FILE"

# ---------------------------------------------------------
# 3. Create Python virtual environments
# ---------------------------------------------------------
log "Phase 3: Creating Python virtual environments..."

for agent in "${AGENTS[@]}"; do
    AGENT_DIR="$AGENTS_DIR/$agent"
    VENV_DIR="$AGENT_DIR/.venv"

    if [ -d "$VENV_DIR" ]; then
        info "$agent venv already exists, skipping creation"
    else
        info "Creating venv for $agent..."
        python3 -m venv "$VENV_DIR"
    fi

    info "Installing dependencies for $agent..."
    source "$VENV_DIR/bin/activate"
    pip install --upgrade pip wheel setuptools 2>&1 | tail -1
    pip install -r "$AGENT_DIR/requirements.txt" 2>&1 | tail -5
    deactivate
    log "$agent dependencies installed"
done

# ---------------------------------------------------------
# 4. Initialize databases
# ---------------------------------------------------------
log "Phase 4: Initializing agent databases..."

for agent in "${AGENTS[@]}"; do
    AGENT_DIR="$AGENTS_DIR/$agent"
    VENV_DIR="$AGENT_DIR/.venv"

    info "Initializing $agent database..."
    source "$VENV_DIR/bin/activate"
    set -a; source "$ENV_FILE"; set +a
    cd "$AGENT_DIR"
    python run.py init 2>&1 || warn "$agent init had warnings"
    cd "$AGENTS_DIR"
    deactivate
    log "$agent database initialized"
done

# ---------------------------------------------------------
# 5. Create systemd service files
# ---------------------------------------------------------
log "Phase 5: Creating systemd service files..."

# Hacking Agent Service
sudo tee /etc/systemd/system/hacking-agent.service > /dev/null << HACKSERVICE
[Unit]
Description=CyberSecurity AI Agent - Hacking
After=network.target postgresql.service
Wants=msfrpcd.service

[Service]
Type=simple
User=$USER
Group=$USER
WorkingDirectory=$AGENTS_DIR/hacking_agent
EnvironmentFile=$ENV_FILE
ExecStart=$AGENTS_DIR/hacking_agent/.venv/bin/python run.py web
Restart=on-failure
RestartSec=10
StandardOutput=journal
StandardError=journal
SyslogIdentifier=hacking-agent

# Security hardening
NoNewPrivileges=false
ProtectHome=false
ProtectSystem=false

[Install]
WantedBy=multi-user.target
HACKSERVICE

# SysAdmin Agent Service
sudo tee /etc/systemd/system/sysadmin-agent.service > /dev/null << SYSSERVICE
[Unit]
Description=SysAdmin AI Agent
After=network.target

[Service]
Type=simple
User=$USER
Group=$USER
WorkingDirectory=$AGENTS_DIR/sysadmin_agent
EnvironmentFile=$ENV_FILE
ExecStart=$AGENTS_DIR/sysadmin_agent/.venv/bin/python run.py web
Restart=on-failure
RestartSec=10
StandardOutput=journal
StandardError=journal
SyslogIdentifier=sysadmin-agent

[Install]
WantedBy=multi-user.target
SYSSERVICE

# Network Agent Service
sudo tee /etc/systemd/system/network-agent.service > /dev/null << NETSERVICE
[Unit]
Description=Network AI Agent
After=network.target

[Service]
Type=simple
User=$USER
Group=$USER
WorkingDirectory=$AGENTS_DIR/network_agent
EnvironmentFile=$ENV_FILE
ExecStart=$AGENTS_DIR/network_agent/.venv/bin/python run.py web
Restart=on-failure
RestartSec=10
StandardOutput=journal
StandardError=journal
SyslogIdentifier=network-agent

[Install]
WantedBy=multi-user.target
NETSERVICE

# Combined target for all agents
sudo tee /etc/systemd/system/cybersec-agents.target > /dev/null << 'TARGET'
[Unit]
Description=All Cybersecurity AI Agents
Wants=hacking-agent.service sysadmin-agent.service network-agent.service
After=network.target

[Install]
WantedBy=multi-user.target
TARGET

sudo systemctl daemon-reload
log "Systemd services created"

# ---------------------------------------------------------
# 6. Create management script
# ---------------------------------------------------------
log "Phase 6: Creating management scripts..."

cat > "$AGENTS_DIR/agents.sh" << 'MGMT'
#!/bin/bash
# Quick management script for cybersec agents

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'

case "$1" in
    start)
        echo -e "${GREEN}[+]${NC} Starting all agents..."
        sudo systemctl start cybersec-agents.target
        sleep 2
        sudo systemctl status hacking-agent sysadmin-agent network-agent --no-pager -l
        ;;
    stop)
        echo -e "${YELLOW}[!]${NC} Stopping all agents..."
        sudo systemctl stop hacking-agent sysadmin-agent network-agent
        ;;
    restart)
        echo -e "${CYAN}[*]${NC} Restarting all agents..."
        sudo systemctl restart hacking-agent sysadmin-agent network-agent
        ;;
    status)
        echo ""
        echo "========== Agent Status =========="
        for svc in hacking-agent sysadmin-agent network-agent; do
            STATUS=$(systemctl is-active "$svc" 2>/dev/null)
            if [ "$STATUS" = "active" ]; then
                echo -e "${GREEN}[RUNNING]${NC} $svc"
            else
                echo -e "${RED}[STOPPED]${NC} $svc"
            fi
        done
        echo ""
        echo "========== Port Status =========="
        echo -e "Hacking Agent (8084):  $(ss -tlnp | grep -q ':8084' && echo -e "${GREEN}LISTENING${NC}" || echo -e "${RED}DOWN${NC}")"
        echo -e "SysAdmin Agent (8080): $(ss -tlnp | grep -q ':8080' && echo -e "${GREEN}LISTENING${NC}" || echo -e "${RED}DOWN${NC}")"
        echo -e "Network Agent (8081):  $(ss -tlnp | grep -q ':8081' && echo -e "${GREEN}LISTENING${NC}" || echo -e "${RED}DOWN${NC}")"
        echo ""
        echo "========== Resource Usage =========="
        echo "Memory: $(free -h | awk '/Mem:/ {printf "%s / %s (%.0f%%)", $3, $2, $3/$2*100}')"
        echo "Disk:   $(df -h / | awk 'NR==2 {printf "%s / %s (%s)", $3, $2, $5}')"
        echo "Temp:   $(cat /sys/class/thermal/thermal_zone0/temp 2>/dev/null | awk '{printf "%.1f°C", $1/1000}' || echo 'N/A')"
        echo "Uptime: $(uptime -p)"
        echo ""
        ;;
    logs)
        AGENT="${2:-hacking-agent}"
        journalctl -u "$AGENT" -f --no-pager
        ;;
    enable)
        echo -e "${GREEN}[+]${NC} Enabling auto-start on boot..."
        sudo systemctl enable cybersec-agents.target
        sudo systemctl enable hacking-agent sysadmin-agent network-agent
        ;;
    disable)
        echo -e "${YELLOW}[!]${NC} Disabling auto-start..."
        sudo systemctl disable cybersec-agents.target
        sudo systemctl disable hacking-agent sysadmin-agent network-agent
        ;;
    chat)
        AGENT="${2:-hacking}"
        AGENT_DIR="$HOME/agents/${AGENT}_agent"
        if [ -d "$AGENT_DIR" ]; then
            source "$AGENT_DIR/.venv/bin/activate"
            set -a; source "$HOME/agents/.env"; set +a
            cd "$AGENT_DIR"
            python run.py chat
        else
            echo -e "${RED}[-]${NC} Agent not found: $AGENT"
            echo "Available: hacking, sysadmin, network"
        fi
        ;;
    cli)
        AGENT="${2:-hacking}"
        AGENT_DIR="$HOME/agents/${AGENT}_agent"
        if [ -d "$AGENT_DIR" ]; then
            source "$AGENT_DIR/.venv/bin/activate"
            set -a; source "$HOME/agents/.env"; set +a
            cd "$AGENT_DIR"
            python run.py cli "${@:3}"
        else
            echo -e "${RED}[-]${NC} Agent not found: $AGENT"
        fi
        ;;
    *)
        echo "Cybersec Agent Manager"
        echo ""
        echo "Usage: ./agents.sh <command> [args]"
        echo ""
        echo "Commands:"
        echo "  start           Start all agents (web dashboards)"
        echo "  stop            Stop all agents"
        echo "  restart         Restart all agents"
        echo "  status          Show agent status, ports, resources"
        echo "  logs [agent]    Follow logs (default: hacking-agent)"
        echo "  enable          Enable auto-start on boot"
        echo "  disable         Disable auto-start"
        echo "  chat [agent]    Launch AI chat (hacking|sysadmin|network)"
        echo "  cli [agent]     Launch CLI (hacking|sysadmin|network)"
        echo ""
        ;;
esac
MGMT

chmod +x "$AGENTS_DIR/agents.sh"

# Add alias to bashrc
if ! grep -q "alias agents=" "$HOME/.bashrc" 2>/dev/null; then
    echo "" >> "$HOME/.bashrc"
    echo "# Cybersec Agent Manager" >> "$HOME/.bashrc"
    echo "alias agents='$AGENTS_DIR/agents.sh'" >> "$HOME/.bashrc"
    echo "alias hack='$AGENTS_DIR/agents.sh cli hacking'" >> "$HOME/.bashrc"
    echo "alias sysop='$AGENTS_DIR/agents.sh cli sysadmin'" >> "$HOME/.bashrc"
    echo "alias netop='$AGENTS_DIR/agents.sh cli network'" >> "$HOME/.bashrc"
    info "Added shell aliases: agents, hack, sysop, netop"
fi

# ---------------------------------------------------------
# 7. Create tmux layout for multi-agent monitoring
# ---------------------------------------------------------
log "Phase 7: Creating tmux monitoring layout..."

cat > "$AGENTS_DIR/monitor.sh" << 'TMUXMON'
#!/bin/bash
# Launch a tmux session with all agent logs side by side

SESSION="cybersec"

tmux has-session -t $SESSION 2>/dev/null
if [ $? -eq 0 ]; then
    echo "Session '$SESSION' already exists. Attaching..."
    tmux attach -t $SESSION
    exit 0
fi

tmux new-session -d -s $SESSION -n "agents"

# Top-left: Hacking Agent logs
tmux send-keys "journalctl -u hacking-agent -f --no-pager" C-m

# Top-right: SysAdmin Agent logs
tmux split-window -h
tmux send-keys "journalctl -u sysadmin-agent -f --no-pager" C-m

# Bottom-left: Network Agent logs
tmux select-pane -t 0
tmux split-window -v
tmux send-keys "journalctl -u network-agent -f --no-pager" C-m

# Bottom-right: System stats
tmux select-pane -t 2
tmux split-window -v
tmux send-keys "htop" C-m

# Create a second window for interactive work
tmux new-window -t $SESSION -n "work"
tmux send-keys "source ~/agents/.env && cd ~/agents" C-m

# Create a third window for Metasploit
tmux new-window -t $SESSION -n "msf"
tmux send-keys "# Run: msfconsole" C-m

tmux select-window -t $SESSION:0
tmux attach -t $SESSION
TMUXMON

chmod +x "$AGENTS_DIR/monitor.sh"

# ---------------------------------------------------------
# Done
# ---------------------------------------------------------
echo ""
echo "============================================================"
log "Agent deployment complete!"
echo "============================================================"
echo ""
info "Agents installed at:  $AGENTS_DIR/"
info "Environment file:     $ENV_FILE"
info "Management script:    $AGENTS_DIR/agents.sh"
info "Monitoring:           $AGENTS_DIR/monitor.sh"
echo ""
echo "Services created:"
info "  hacking-agent.service   → port 8084"
info "  sysadmin-agent.service  → port 8080"
info "  network-agent.service   → port 8081"
echo ""
warn "BEFORE STARTING:"
warn "  1. Edit $ENV_FILE with your ANTHROPIC_API_KEY"
warn "  2. Add any other API keys you need"
warn ""
info "Quick start:"
info "  agents start        # Start all agent dashboards"
info "  agents status       # Check status"
info "  agents chat hacking # Launch AI chat"
info "  agents cli network  # Launch Network CLI"
echo ""
warn "NEXT: Run 03_harden_dropbox.sh for security hardening"
echo ""
