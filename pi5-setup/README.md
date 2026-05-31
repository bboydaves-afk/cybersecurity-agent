# Raspberry Pi 5 - Cybersecurity AI Agent Platform

## Complete setup guide: bare Pi to fully operational pentest drop box

### What You're Building
- **Kali Linux ARM64** on Raspberry Pi 5
- **3 AI Agents**: Hacking (8084), SysAdmin (8080), Network (8081)
- **600+ pentest tools** pre-installed via Kali
- **Portable drop box** with reverse SSH callback
- **Network monitor** with continuous alerting
- **Home lab** for CTF/training

---

## Phase 1: Hardware & Flashing

### Required Hardware
- Raspberry Pi 5 (8GB RAM recommended, 4GB minimum)
- microSD card (64GB+ recommended, Class 10 / A2)
- USB-C power supply (27W / 5.1V 5A official Pi 5 PSU)
- Ethernet cable (for initial setup + network pentesting)
- USB WiFi adapter with monitor mode (e.g., Alfa AWUS036ACH) — optional but recommended for wireless pentesting

### Optional Hardware
- Pi 5 active cooler or case with fan (AI workloads generate heat)
- USB-to-Ethernet adapter (second NIC for drop box inline mode)
- Small OLED display (SSD1306 — for headless status display)
- Portable battery pack (PD 27W+ for field deployments)
- USB rubber ducky / BadUSB for physical engagements

### Flash Kali Linux ARM64

1. Download **Kali Linux ARM64** for Raspberry Pi 5:
   - https://www.kali.org/get-kali/#kali-arm
   - Select "Raspberry Pi 5" image (64-bit)

2. Flash with **Raspberry Pi Imager** or **balenaEtcher**:
   - In Pi Imager: Choose OS → Other → Use custom → select the .img.xz
   - Click gear icon to pre-configure:
     - Set hostname: `cybersec-pi`
     - Enable SSH (password auth)
     - Set username: `kali` / your password
     - Configure WiFi (optional, for initial access)
     - Set timezone

3. Insert microSD into Pi 5, connect Ethernet, power on

4. Find Pi on network:
   ```bash
   # From your desktop (run on same network)
   nmap -sn 192.168.1.0/24 | grep -B2 "Raspberry"
   # or check your router's DHCP lease table
   ```

5. SSH in:
   ```bash
   ssh kali@cybersec-pi.local
   # or ssh kali@<ip-address>
   ```

---

## Phase 2: Base System Setup

Run the setup script (copy to Pi first, or run commands manually):

```bash
# Copy setup script to Pi from your Windows machine:
scp pi5-setup/01_base_setup.sh kali@cybersec-pi.local:~/
ssh kali@cybersec-pi.local
chmod +x ~/01_base_setup.sh
sudo bash ~/01_base_setup.sh
```

---

## Phase 3: Agent Deployment

```bash
# From your Windows machine, copy all agents to Pi:
scp -r hacking_agent/ kali@cybersec-pi.local:~/agents/hacking_agent/
scp -r sysadmin_agent/ kali@cybersec-pi.local:~/agents/sysadmin_agent/
scp -r network_agent/ kali@cybersec-pi.local:~/agents/network_agent/

# Then SSH in and run the deployment script:
scp pi5-setup/02_deploy_agents.sh kali@cybersec-pi.local:~/
ssh kali@cybersec-pi.local
chmod +x ~/02_deploy_agents.sh
bash ~/02_deploy_agents.sh
```

---

## Phase 4: Hardening & Drop Box Config

```bash
scp pi5-setup/03_harden_dropbox.sh kali@cybersec-pi.local:~/
ssh kali@cybersec-pi.local
chmod +x ~/03_harden_dropbox.sh
sudo bash ~/03_harden_dropbox.sh
```

---

## Phase 5: Field Deployment

See `04_field_operations.sh` for:
- Reverse SSH tunnel setup (call-home to your C2 server)
- Auto-start on boot
- Stealth mode (disable LEDs, quiet network)
- USB Ethernet gadget mode

---

## Port Map

| Service          | Port  | Description                          |
|------------------|-------|--------------------------------------|
| Hacking Agent    | 8084  | Pentest AI agent web dashboard       |
| SysAdmin Agent   | 8080  | Infrastructure management dashboard  |
| Network Agent    | 8081  | Network monitoring dashboard         |
| SSH              | 22    | Remote access (change in hardening)  |
| Metasploit RPC   | 55553 | MSF console integration              |

---

## Quick Start After Setup

```bash
# Start all agents
sudo systemctl start cybersec-agents

# Or individually
sudo systemctl start hacking-agent
sudo systemctl start sysadmin-agent
sudo systemctl start network-agent

# Check status
sudo systemctl status cybersec-agents

# View logs
journalctl -u hacking-agent -f
journalctl -u network-agent -f

# Access dashboards (from any device on network)
# http://cybersec-pi.local:8084  (Hacking Agent)
# http://cybersec-pi.local:8080  (SysAdmin Agent)
# http://cybersec-pi.local:8081  (Network Agent)
```
