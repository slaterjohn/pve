#!/usr/bin/env bash
# ============================================================================
#  harden-server.sh — Interactive SSH hardening + Tailscale for a fresh server
#
#  Usage:
#    curl -fsSL <RAW_GIST_URL> -o harden.sh && bash harden.sh
#
#  What it does (step by step, with confirmation):
#    1. Connects to the remote server via SSH (username + password)
#    2. Enables root SSH access (if not already enabled)
#    3. Asks you to paste one or more SSH public keys
#    4. Installs keys into ~/.ssh/authorized_keys for root
#    5. Disables password authentication
#    6. Hardens sshd_config with modern best practices
#    7. Configures UFW firewall (SSH + Tailscale)
#    8. Applies automatic security updates (unattended-upgrades)
#    9. Installs Tailscale and provides the login link
#   10. Restarts SSH and verifies connectivity with the new key
# ============================================================================

set -euo pipefail

# ── Colours & helpers ────────────────────────────────────────────────────────

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
DIM='\033[2m'
RESET='\033[0m'

info()    { printf "${CYAN}▸${RESET} %s\n" "$*"; }
success() { printf "${GREEN}✔${RESET} %s\n" "$*"; }
warn()    { printf "${YELLOW}⚠${RESET} %s\n" "$*"; }
error()   { printf "${RED}✖${RESET} %s\n" "$*" >&2; }
header()  { printf "\n${BOLD}${CYAN}── %s ──${RESET}\n\n" "$*"; }

confirm() {
  local prompt="${1:-Continue?}"
  printf "${YELLOW}? ${RESET}${BOLD}%s${RESET} [Y/n] " "$prompt"
  read -r ans
  case "${ans,,}" in
    n|no) return 1 ;;
    *)    return 0 ;;
  esac
}

# ── Dependency check ─────────────────────────────────────────────────────────

check_deps() {
  local missing=()
  for cmd in ssh sshpass; do
    command -v "$cmd" &>/dev/null || missing+=("$cmd")
  done

  if [[ ${#missing[@]} -gt 0 ]]; then
    error "Missing required tools: ${missing[*]}"
    echo ""
    info "Install them with:"
    echo "  macOS:   brew install hudochenkov/sshpass/sshpass openssh"
    echo "  Ubuntu:  sudo apt install sshpass openssh-client"
    echo "  Fedora:  sudo dnf install sshpass openssh-clients"
    exit 1
  fi
}

# ── Collect connection info ──────────────────────────────────────────────────

collect_connection() {
  header "Server Connection"

  read -rp "$(printf "${BOLD}Host${RESET} (IP or hostname): ")" REMOTE_HOST
  read -rp "$(printf "${BOLD}SSH port${RESET} [22]: ")" REMOTE_PORT
  REMOTE_PORT="${REMOTE_PORT:-22}"
  read -rp "$(printf "${BOLD}Username${RESET} [root]: ")" REMOTE_USER
  REMOTE_USER="${REMOTE_USER:-root}"
  read -rsp "$(printf "${BOLD}Password${RESET}: ")" REMOTE_PASS
  echo ""

  if [[ -z "$REMOTE_HOST" || -z "$REMOTE_PASS" ]]; then
    error "Host and password are required."
    exit 1
  fi
}

# ── SSH helpers ──────────────────────────────────────────────────────────────

remote_exec() {
  sshpass -p "$REMOTE_PASS" ssh \
    -o StrictHostKeyChecking=accept-new \
    -o ConnectTimeout=10 \
    -p "$REMOTE_PORT" \
    "${REMOTE_USER}@${REMOTE_HOST}" \
    "$@"
}

remote_exec_root() {
  if [[ "$REMOTE_USER" == "root" ]]; then
    remote_exec "$@"
  else
    remote_exec "echo '${REMOTE_PASS}' | sudo -S bash -c '${*}'"
  fi
}

test_connection() {
  info "Testing SSH connection to ${REMOTE_USER}@${REMOTE_HOST}:${REMOTE_PORT} …"
  if remote_exec "echo ok" &>/dev/null; then
    success "Connection successful."
  else
    error "Could not connect. Check host, port, username, and password."
    exit 1
  fi
}

# ── Collect SSH keys ─────────────────────────────────────────────────────────

collect_ssh_keys() {
  header "SSH Public Keys"

  SSH_KEYS=()

  info "Paste your SSH public key (the content of ~/.ssh/id_*.pub)."
  info "Press Enter on a blank line when done pasting each key."
  echo ""

  local key_num=1
  while true; do
    printf "${BOLD}Key #%d${RESET} (paste, then press Enter on blank line):\n" "$key_num"
    local key=""
    while IFS= read -r line; do
      [[ -z "$line" ]] && break
      key+="$line"
    done

    if [[ -z "$key" ]]; then
      if [[ ${#SSH_KEYS[@]} -eq 0 ]]; then
        error "At least one SSH key is required."
        continue
      else
        break
      fi
    fi

    if [[ "$key" =~ ^ssh-(rsa|ed25519|ecdsa)|^ecdsa-sha2 ]]; then
      SSH_KEYS+=("$key")
      local key_type key_hash
      key_type="$(echo "$key" | awk '{print $1}')"
      key_hash="$(echo "$key" | awk '{print substr($2, length($2)-7)}')"
      success "Key #${key_num} accepted  ${DIM}${key_type} …${key_hash}${RESET}"
      ((key_num++))
    else
      warn "That doesn't look like a valid SSH public key. Try again."
      continue
    fi

    echo ""
    if ! confirm "Add another SSH key (e.g. from another machine / CI provider)?"; then
      break
    fi
    echo ""
  done

  echo ""
  success "Collected ${#SSH_KEYS[@]} SSH key(s)."
}

# ── Choose hardening options ─────────────────────────────────────────────────

choose_options() {
  header "Hardening Options"

  ENABLE_ROOT_SSH=false
  DISABLE_PASSWORD=true
  SETUP_UFW=true
  SETUP_UNATTENDED=true
  CHANGE_SSH_PORT=false
  NEW_SSH_PORT="$REMOTE_PORT"
  INSTALL_TAILSCALE=true
  TAILSCALE_SSH=false

  if [[ "$REMOTE_USER" != "root" ]]; then
    confirm "Enable root SSH login (key-only)?" && ENABLE_ROOT_SSH=true
  fi

  confirm "Disable SSH password authentication (key-only)?" && DISABLE_PASSWORD=true || {
    DISABLE_PASSWORD=false
    warn "Password auth will remain enabled — less secure."
  }

  confirm "Set up UFW firewall (allow SSH + Tailscale)?" && SETUP_UFW=true || SETUP_UFW=false

  confirm "Enable automatic security updates (unattended-upgrades)?" && SETUP_UNATTENDED=true || SETUP_UNATTENDED=false

  confirm "Install Tailscale?" && INSTALL_TAILSCALE=true || INSTALL_TAILSCALE=false

  if [[ "$INSTALL_TAILSCALE" == true ]]; then
    confirm "Enable Tailscale SSH (access server over Tailscale without SSH keys)?" && TAILSCALE_SSH=true || TAILSCALE_SSH=false
  fi

  if confirm "Change SSH port from ${REMOTE_PORT}?"; then
    CHANGE_SSH_PORT=true
    read -rp "$(printf "${BOLD}New SSH port${RESET}: ")" NEW_SSH_PORT
    if ! [[ "$NEW_SSH_PORT" =~ ^[0-9]+$ ]] || (( NEW_SSH_PORT < 1024 || NEW_SSH_PORT > 65535 )); then
      warn "Invalid port. Keeping ${REMOTE_PORT}."
      CHANGE_SSH_PORT=false
      NEW_SSH_PORT="$REMOTE_PORT"
    fi
  fi
}

# ── Summary ──────────────────────────────────────────────────────────────────

show_summary() {
  header "Summary — Review Before Applying"

  printf "  %-24s %s\n" "Server:"              "${REMOTE_HOST}:${REMOTE_PORT}"
  printf "  %-24s %s\n" "User:"                "${REMOTE_USER}"
  printf "  %-24s %s\n" "SSH keys to install:"  "${#SSH_KEYS[@]}"
  printf "  %-24s %s\n" "Disable password auth:" "${DISABLE_PASSWORD}"
  printf "  %-24s %s\n" "Enable root SSH:"       "${ENABLE_ROOT_SSH}"
  printf "  %-24s %s\n" "UFW firewall:"          "${SETUP_UFW}"
  printf "  %-24s %s\n" "Auto-updates:"          "${SETUP_UNATTENDED}"
  printf "  %-24s %s\n" "Install Tailscale:"     "${INSTALL_TAILSCALE}"
  if [[ "$INSTALL_TAILSCALE" == true ]]; then
    printf "  %-24s %s\n" "Tailscale SSH:"       "${TAILSCALE_SSH}"
  fi
  if [[ "$CHANGE_SSH_PORT" == true ]]; then
    printf "  %-24s %s\n" "New SSH port:"        "${NEW_SSH_PORT}"
  fi
  echo ""

  if ! confirm "Apply these changes now?"; then
    warn "Aborted by user."
    exit 0
  fi
}

# ── Apply: install SSH keys ──────────────────────────────────────────────────

install_ssh_keys() {
  header "Installing SSH Keys"

  local keys_block=""
  for k in "${SSH_KEYS[@]}"; do
    keys_block+="${k}"$'\n'
  done

  remote_exec_root "
    mkdir -p /root/.ssh
    chmod 700 /root/.ssh
    cat >> /root/.ssh/authorized_keys <<'KEYEOF'
${keys_block}KEYEOF
    sort -u -o /root/.ssh/authorized_keys /root/.ssh/authorized_keys
    chmod 600 /root/.ssh/authorized_keys
  "
  success "SSH keys installed into /root/.ssh/authorized_keys"

  # If non-root user, also install keys for that user
  if [[ "$REMOTE_USER" != "root" ]]; then
    remote_exec "
      mkdir -p ~/.ssh
      chmod 700 ~/.ssh
      cat >> ~/.ssh/authorized_keys <<'KEYEOF'
${keys_block}KEYEOF
      sort -u -o ~/.ssh/authorized_keys ~/.ssh/authorized_keys
      chmod 600 ~/.ssh/authorized_keys
    "
    success "SSH keys also installed for user ${REMOTE_USER}"
  fi
}

# ── Apply: harden sshd_config ───────────────────────────────────────────────

harden_sshd() {
  header "Hardening SSH Configuration"

  local sshd_port="$NEW_SSH_PORT"

  remote_exec_root "
    cp /etc/ssh/sshd_config /etc/ssh/sshd_config.bak.\$(date +%s)

    cat > /etc/ssh/sshd_config.d/99-hardened.conf <<'SSHEOF'
# ── Hardened SSH config (applied by harden-server.sh) ──

Port ${sshd_port}

# ── Authentication ──
PermitRootLogin prohibit-password
MaxAuthTries 3
MaxSessions 5
PubkeyAuthentication yes
AuthorizedKeysFile .ssh/authorized_keys
PasswordAuthentication $([ "$DISABLE_PASSWORD" = true ] && echo no || echo yes)
PermitEmptyPasswords no
ChallengeResponseAuthentication no
UsePAM yes
KbdInteractiveAuthentication no

# ── Security ──
X11Forwarding no
AllowTcpForwarding no
AllowAgentForwarding no
PermitTunnel no
GatewayPorts no
PrintMotd no
TCPKeepAlive yes
ClientAliveInterval 300
ClientAliveCountMax 2
LoginGraceTime 30
StrictModes yes

# ── Crypto hardening ──
KexAlgorithms sntrup761x25519-sha512@openssh.com,curve25519-sha256@libssh.org,curve25519-sha256
Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com
MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com
HostKeyAlgorithms ssh-ed25519,rsa-sha2-512,rsa-sha2-256
SSHEOF

    # Validate config before restarting
    sshd -t 2>/dev/null && echo 'SSHD_CONFIG_OK' || echo 'SSHD_CONFIG_ERR'
  " | tail -1 | grep -q 'SSHD_CONFIG_OK'

  if [[ $? -eq 0 ]]; then
    success "sshd_config hardened and validated."
  else
    error "sshd_config validation failed — rolling back."
    remote_exec_root "rm -f /etc/ssh/sshd_config.d/99-hardened.conf"
    exit 1
  fi
}

# ── Apply: UFW firewall ─────────────────────────────────────────────────────

setup_firewall() {
  [[ "$SETUP_UFW" != true ]] && return
  header "Configuring UFW Firewall"

  remote_exec_root "
    apt-get update -qq
    apt-get install -y -qq ufw > /dev/null 2>&1

    ufw default deny incoming
    ufw default allow outgoing

    # SSH
    ufw allow ${NEW_SSH_PORT}/tcp comment 'SSH'

    # Tailscale — allow its UDP port and the interface
    ufw allow 41641/udp comment 'Tailscale'

    # Allow all traffic on the Tailscale interface
    ufw allow in on tailscale0 comment 'Tailscale interface'

    echo 'y' | ufw enable
    ufw status verbose
  "
  success "UFW firewall configured."
}

# ── Apply: unattended upgrades ───────────────────────────────────────────────

setup_auto_updates() {
  [[ "$SETUP_UNATTENDED" != true ]] && return
  header "Enabling Automatic Security Updates"

  remote_exec_root "
    apt-get install -y -qq unattended-upgrades apt-listchanges > /dev/null 2>&1

    cat > /etc/apt/apt.conf.d/20auto-upgrades <<'UEOF'
APT::Periodic::Update-Package-Lists \"1\";
APT::Periodic::Unattended-Upgrade \"1\";
APT::Periodic::AutocleanInterval \"7\";
UEOF

    systemctl enable --now unattended-upgrades
  "
  success "Unattended security upgrades enabled."
}

# ── Apply: install Tailscale ─────────────────────────────────────────────────

install_tailscale() {
  [[ "$INSTALL_TAILSCALE" != true ]] && return
  header "Installing Tailscale"

  info "Installing Tailscale on remote server…"

  remote_exec_root "
    curl -fsSL https://tailscale.com/install.sh | sh
  "
  success "Tailscale installed."

  echo ""
  info "Starting Tailscale — a login URL will appear below."
  info "Open it in your browser to authenticate the node."
  echo ""

  local ts_flags=""
  if [[ "$TAILSCALE_SSH" == true ]]; then
    ts_flags="--ssh"
    info "Tailscale SSH is enabled — you'll be able to SSH via Tailscale identity."
  fi

  # Run tailscale up and capture the login URL.
  # tailscale up prints the URL to stderr, so we redirect.
  local ts_output
  ts_output="$(remote_exec_root "tailscale up ${ts_flags} 2>&1" || true)"

  # Print the full output so the user can see the URL
  echo ""
  printf "${BOLD}${CYAN}╭──────────────────────────────────────────────────────╮${RESET}\n"
  printf "${BOLD}${CYAN}│  TAILSCALE LOGIN                                     │${RESET}\n"
  printf "${BOLD}${CYAN}╰──────────────────────────────────────────────────────╯${RESET}\n"
  echo ""
  echo "$ts_output" | grep -iE "https://login\.tailscale\.com" | while read -r line; do
    printf "  ${BOLD}${GREEN}→ %s${RESET}\n" "$line"
  done
  # If no URL found, just dump everything
  if ! echo "$ts_output" | grep -qiE "https://login\.tailscale\.com"; then
    echo "$ts_output"
  fi
  echo ""

  printf "${YELLOW}? ${RESET}${BOLD}Open the URL above, authenticate, then press Enter to continue…${RESET}"
  read -r

  # Verify Tailscale is connected
  local ts_status
  ts_status="$(remote_exec_root "tailscale status --json 2>/dev/null | head -5" || true)"
  if echo "$ts_status" | grep -q '"BackendState"'; then
    local ts_ip
    ts_ip="$(remote_exec_root "tailscale ip -4 2>/dev/null" || echo "unknown")"
    success "Tailscale is connected.  IP: ${ts_ip}"
  else
    warn "Could not verify Tailscale status. Check manually with: tailscale status"
  fi
}

# ── Apply: restart SSH ───────────────────────────────────────────────────────

restart_ssh() {
  header "Restarting SSH"

  remote_exec_root "systemctl restart sshd || systemctl restart ssh"
  success "SSH daemon restarted."
}

# ── Verify key-based login ───────────────────────────────────────────────────

verify_key_login() {
  header "Verification"

  if [[ "$DISABLE_PASSWORD" == true ]]; then
    warn "Password authentication is now DISABLED."
    warn "Make sure you can log in with your key before closing this terminal!"
    echo ""
    echo "  Test with:"
    echo "    ssh -i ~/.ssh/your_key -p ${NEW_SSH_PORT} root@${REMOTE_HOST}"
    echo ""
    if [[ "$INSTALL_TAILSCALE" == true ]]; then
      echo "  Or via Tailscale:"
      echo "    ssh -i ~/.ssh/your_key root@<tailscale-hostname>"
      if [[ "$TAILSCALE_SSH" == true ]]; then
        echo "    ssh <tailscale-hostname>   ${DIM}(Tailscale SSH — no key needed)${RESET}"
      fi
      echo ""
    fi
  fi
}

# ── Final report ─────────────────────────────────────────────────────────────

final_report() {
  header "Done! Server Hardening Complete"

  printf "${GREEN}"
  cat << 'BANNER'
  ╔══════════════════════════════════════════════════╗
  ║              SERVER HARDENED ✔                   ║
  ╚══════════════════════════════════════════════════╝
BANNER
  printf "${RESET}"
  echo ""
  echo "  Applied:"
  echo "    ✔ SSH keys installed (${#SSH_KEYS[@]} key(s))"
  [[ "$DISABLE_PASSWORD" == true ]] && echo "    ✔ Password authentication disabled"
  echo "    ✔ SSH hardened (crypto, timeouts, access)"
  [[ "$CHANGE_SSH_PORT" == true ]]  && echo "    ✔ SSH port changed to ${NEW_SSH_PORT}"
  [[ "$SETUP_UFW" == true ]]        && echo "    ✔ UFW firewall active"
  [[ "$SETUP_UNATTENDED" == true ]] && echo "    ✔ Automatic security updates enabled"
  [[ "$INSTALL_TAILSCALE" == true ]] && echo "    ✔ Tailscale installed & connected"
  [[ "$TAILSCALE_SSH" == true ]]     && echo "    ✔ Tailscale SSH enabled"
  echo ""
  echo "  Connection:"
  echo "    Public:    ssh -p ${NEW_SSH_PORT} root@${REMOTE_HOST}"
  if [[ "$INSTALL_TAILSCALE" == true ]]; then
    echo "    Tailscale: ssh root@<tailscale-hostname>"
  fi
  echo ""
  warn "IMPORTANT: Test key-based login in a NEW terminal before closing this one!"
}

# ── Main ─────────────────────────────────────────────────────────────────────

main() {
  clear
  printf "${BOLD}${CYAN}"
  cat << 'LOGO'

   ┬ ┬┌─┐┬─┐┌┬┐┌─┐┌┐┌   ┌─┐┌─┐┬─┐┬  ┬┌─┐┬─┐
   ├─┤├─┤├┬┘ ││├┤ │││───└─┐├┤ ├┬┘└┐┌┘├┤ ├┬┘
   ┴ ┴┴ ┴┴└──┴┘└─┘┘└┘   └─┘└─┘┴└─ └┘ └─┘┴└─
   Interactive SSH Hardening + Tailscale Setup

LOGO
  printf "${RESET}"

  check_deps
  collect_connection
  test_connection
  collect_ssh_keys
  choose_options
  show_summary

  install_ssh_keys
  harden_sshd
  setup_firewall
  setup_auto_updates
  install_tailscale
  restart_ssh
  verify_key_login
  final_report
}

main "$@"