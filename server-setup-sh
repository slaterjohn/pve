#!/usr/bin/env bash
# ============================================================================
#  server-setup.sh — Interactive server hardening + Tailscale setup
#
#  Run this directly on a fresh Ubuntu server (e.g. via remote desktop
#  terminal). No SSH keys required — Tailscale is the sole SSH transport.
#
#  Usage:
#    sudo bash server-setup.sh
#
#  What it does:
#    1.  Detects users and collects your auth preferences
#    2.  Configures SSH root access and per-user password rules
#    3.  Hardens sshd_config (crypto, timeouts, access controls)
#    4.  Configures UFW firewall (SSH port + Tailscale)
#    5.  Enables automatic security updates
#    6.  Installs Tailscale + optionally enables Tailscale SSH
#    7.  Restarts SSH and prints a final report
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
  case "$(printf '%s' "$ans" | tr '[:upper:]' '[:lower:]')" in
    n|no) return 1 ;;
    *)    return 0 ;;
  esac
}

# ── Root check / sudo re-exec ────────────────────────────────────────────────
#
#  On a fresh Ubuntu server the default user is not root, but has sudo access.
#  Rather than requiring the user to re-run manually, the script re-executes
#  itself under sudo automatically if needed.

check_root() {
  if [[ "$EUID" -ne 0 ]]; then
    info "This script needs root privileges — re-launching with sudo…"
    echo ""
    exec sudo bash "$0" "$@"
    # exec replaces this process; the lines below only run if exec fails
    error "sudo failed. Please run:  sudo bash $0"
    exit 1
  fi
}

# ── Dependency check ─────────────────────────────────────────────────────────

check_deps() {
  local missing=()
  for cmd in curl awk systemctl; do
    command -v "$cmd" &>/dev/null || missing+=("$cmd")
  done

  if [[ ${#missing[@]} -gt 0 ]]; then
    error "Missing required tools: ${missing[*]}"
    echo ""
    info "Install them with:  apt-get install -y ${missing[*]}"
    exit 1
  fi
}

# ── Collect user & auth preferences ─────────────────────────────────────────

collect_user_config() {
  header "User & Authentication Setup"

  info "Detecting users on this server…"
  local users_raw
  users_raw="$(awk -F: '$3 >= 1000 && $3 < 65534 {print $1}' /etc/passwd || true)"

  echo ""
  info "Non-root users found:"
  if [[ -n "$users_raw" ]]; then
    echo "$users_raw" | while read -r u; do
      [[ -n "$u" ]] && printf "    ${DIM}%s${RESET}\n" "$u"
    done
  else
    printf "    ${DIM}(none)${RESET}\n"
  fi
  printf "    ${DIM}root${RESET}\n"
  echo ""

  # ── Root SSH access ──
  ENABLE_ROOT_SSH=false

  if confirm "Enable root SSH login (key-only, no password)?"; then
    ENABLE_ROOT_SSH=true
    success "Root will be permitted via publickey only."
  fi

  # ── Service users with password auth preserved ──
  PASSWORD_USERS=()

  if confirm "Keep password SSH login for a service user (e.g. dokploy)?"; then
    local first_user
    printf "${YELLOW}? ${RESET}${BOLD}Username to keep password auth for${RESET}: "
    read -r first_user
    [[ -n "$first_user" ]] && PASSWORD_USERS+=("$first_user")

    while confirm "Add another user with password auth preserved?"; do
      local extra_user
      printf "${YELLOW}? ${RESET}${BOLD}Username${RESET}: "
      read -r extra_user
      [[ -n "$extra_user" ]] && PASSWORD_USERS+=("$extra_user")
    done
  fi

  echo ""
  if [[ ${#PASSWORD_USERS[@]} -gt 0 ]]; then
    success "Password auth will be preserved for: ${PASSWORD_USERS[*]}"
  fi
}

# ── Hardening & install options ──────────────────────────────────────────────

choose_options() {
  header "Hardening Options"

  SETUP_UFW=true
  SETUP_UNATTENDED=true
  CHANGE_SSH_PORT=false
  CURRENT_SSH_PORT=22
  NEW_SSH_PORT=22
  INSTALL_TAILSCALE=true
  TAILSCALE_SSH=false
  TAILSCALE_TAGS=()

  # Detect current SSH port from sshd_config
  local detected_port
  detected_port="$(sshd -T 2>/dev/null | awk '/^port / {print $2; exit}' || echo 22)"
  CURRENT_SSH_PORT="${detected_port:-22}"
  NEW_SSH_PORT="$CURRENT_SSH_PORT"

  confirm "Set up UFW firewall (allow SSH + Tailscale)?"   && SETUP_UFW=true        || SETUP_UFW=false
  confirm "Enable automatic security updates?"              && SETUP_UNATTENDED=true  || SETUP_UNATTENDED=false
  confirm "Install Tailscale?"                              && INSTALL_TAILSCALE=true || INSTALL_TAILSCALE=false

  if [[ "$INSTALL_TAILSCALE" == true ]]; then
    confirm "Enable Tailscale SSH (SSH via Tailscale identity — strongly recommended)?" \
      && TAILSCALE_SSH=true || TAILSCALE_SSH=false

    # ── Tailscale tags ──
    header "Tailscale Tags"

    info "Tags are used in your Tailscale ACL policy to control access."
    info "The tag ${BOLD}tag:allow-ssh-in${RESET} will be added automatically."
    echo ""

    TAILSCALE_TAGS=("tag:allow-ssh-in")
    success "Auto-added: tag:allow-ssh-in"

    while confirm "Add another Tailscale tag?"; do
      local tag_input
      printf "${YELLOW}? ${RESET}${BOLD}Tag name${RESET} (e.g. dokploy, webserver, staging): "
      read -r tag_input
      tag_input="$(echo "$tag_input" | tr -d '[:space:]')"

      if [[ -z "$tag_input" ]]; then
        warn "Empty tag — skipped."
        continue
      fi

      tag_input="${tag_input#tag:}"
      TAILSCALE_TAGS+=("tag:${tag_input}")
      success "Added: tag:${tag_input}"
    done

    echo ""
    info "Tags to apply: ${TAILSCALE_TAGS[*]}"
    echo ""
    warn "These tags must exist in your Tailscale ACL policy."
    warn "Edit at: https://login.tailscale.com/admin/acls/file"
    echo ""
    info "Example ACL snippet for SSH access:"
    echo ""
    printf "${DIM}"
    echo '  "tagOwners": {'
    for t in "${TAILSCALE_TAGS[@]}"; do
      echo "    \"${t}\": [\"autogroup:admin\"],"
    done
    echo '  },'
    echo ''
    echo '  "ssh": ['
    echo '    {'
    echo '      "action": "accept",'
    echo '      "src":    ["autogroup:admin"],'
    echo '      "dst":    ["tag:allow-ssh-in"],'
    echo '      "users":  ["root", "autogroup:nonroot"]'
    echo '    }'
    echo '  ]'
    printf "${RESET}"
    echo ""
  fi

  # ── SSH port change ──
  if confirm "Change SSH port from ${CURRENT_SSH_PORT}?"; then
    CHANGE_SSH_PORT=true
    printf "${YELLOW}? ${RESET}${BOLD}New SSH port${RESET}: "
    read -r NEW_SSH_PORT
    if ! [[ "$NEW_SSH_PORT" =~ ^[0-9]+$ ]] || (( NEW_SSH_PORT < 1024 || NEW_SSH_PORT > 65535 )); then
      warn "Invalid port — keeping ${CURRENT_SSH_PORT}."
      CHANGE_SSH_PORT=false
      NEW_SSH_PORT="$CURRENT_SSH_PORT"
    fi
  fi
}

# ── Summary ──────────────────────────────────────────────────────────────────

show_summary() {
  header "Summary — Review Before Applying"

  local hostname_val
  hostname_val="$(hostname -f 2>/dev/null || hostname)"

  printf "  %-30s %s\n" "Hostname:"               "${hostname_val}"
  printf "  %-30s %s\n" "Running as:"             "root (local)"
  echo ""
  printf "  ${BOLD}Auth model:${RESET}\n"
  if [[ "$ENABLE_ROOT_SSH" == true ]]; then
    printf "    %-26s %s\n" "root:"  "key-only SSH (no password)"
  else
    printf "    %-26s %s\n" "root:"  "SSH login disabled"
  fi
  for pu in "${PASSWORD_USERS[@]}"; do
    printf "    %-26s %s\n" "${pu}:" "password SSH preserved"
  done
  echo ""
  printf "  %-30s %s\n" "UFW firewall:"           "${SETUP_UFW}"
  printf "  %-30s %s\n" "Auto-updates:"           "${SETUP_UNATTENDED}"
  printf "  %-30s %s\n" "Tailscale:"              "${INSTALL_TAILSCALE}"
  if [[ "$INSTALL_TAILSCALE" == true ]]; then
    printf "  %-30s %s\n" "Tailscale SSH:"        "${TAILSCALE_SSH}"
    if [[ ${#TAILSCALE_TAGS[@]} -gt 0 ]]; then
      printf "  %-30s %s\n" "Tailscale tags:"     "${TAILSCALE_TAGS[*]}"
    fi
  fi
  if [[ "$CHANGE_SSH_PORT" == true ]]; then
    printf "  %-30s %s\n" "New SSH port:"         "${NEW_SSH_PORT}"
  else
    printf "  %-30s %s\n" "SSH port:"             "${CURRENT_SSH_PORT} (unchanged)"
  fi
  echo ""

  if ! confirm "Apply these changes now?"; then
    warn "Aborted by user."
    exit 0
  fi
}

# ── Apply: enable root SSH login ─────────────────────────────────────────────

enable_root_ssh() {
  [[ "$ENABLE_ROOT_SSH" != true ]] && return
  header "Enabling Root SSH Login"

  # Unlock root account if locked (Ubuntu locks root by default)
  if grep -q '^root:!' /etc/shadow 2>/dev/null; then
    info "Root account is locked — unlocking for key-only SSH…"
    usermod -U root 2>/dev/null || true
  fi

  # Ensure root's .ssh directory exists with correct permissions
  mkdir -p /root/.ssh
  chmod 700 /root/.ssh
  touch /root/.ssh/authorized_keys
  chmod 600 /root/.ssh/authorized_keys

  success "Root SSH access enabled."
  info "Remember to add your public key to /root/.ssh/authorized_keys."
}

# ── Apply: harden sshd_config ────────────────────────────────────────────────

harden_sshd() {
  header "Hardening SSH Configuration"

  # Build per-user Match blocks for service accounts that need password auth
  local match_blocks=""
  for pu in "${PASSWORD_USERS[@]}"; do
    match_blocks+="
# Allow password auth for ${pu} (e.g. Dokploy deployments)
Match User ${pu}
    PasswordAuthentication yes
    PubkeyAuthentication yes
"
  done

  # Back up the current sshd_config
  cp /etc/ssh/sshd_config "/etc/ssh/sshd_config.bak.$(date +%s)"
  info "Backed up existing sshd_config."

  # Write the drop-in hardening file
  cat > /etc/ssh/sshd_config.d/99-hardened.conf <<SSHEOF
# ── Hardened SSH config (applied by server-setup.sh) ──

Port ${NEW_SSH_PORT}

# ── Global defaults ──
PermitRootLogin $([ "$ENABLE_ROOT_SSH" = true ] && echo prohibit-password || echo no)
MaxAuthTries 3
MaxSessions 5
PubkeyAuthentication yes
AuthorizedKeysFile .ssh/authorized_keys

# Global: disable password auth (overridden per-user below if needed)
PasswordAuthentication no
PermitEmptyPasswords no
ChallengeResponseAuthentication no
KbdInteractiveAuthentication no
UsePAM yes

# ── Security ──
X11Forwarding no
AllowTcpForwarding yes
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

# ── Per-user overrides ──
${match_blocks}
SSHEOF

  # Validate the new config before committing
  if sshd -t 2>/dev/null; then
    success "sshd_config hardened and validated."
  else
    error "sshd_config validation failed — rolling back."
    rm -f /etc/ssh/sshd_config.d/99-hardened.conf
    exit 1
  fi
}

# ── Apply: UFW firewall ──────────────────────────────────────────────────────

setup_firewall() {
  [[ "$SETUP_UFW" != true ]] && return
  header "Configuring UFW Firewall"

  apt-get update -qq
  apt-get install -y -qq ufw > /dev/null 2>&1

  ufw default deny incoming
  ufw default allow outgoing

  # SSH on the configured port
  ufw allow "${NEW_SSH_PORT}/tcp" comment 'SSH'

  # Tailscale WireGuard UDP port
  ufw allow 41641/udp comment 'Tailscale WireGuard'

  # Allow all traffic on the Tailscale network interface
  ufw allow in on tailscale0 comment 'Tailscale interface'

  echo 'y' | ufw enable
  ufw status verbose

  success "UFW firewall configured."
}

# ── Apply: unattended upgrades ───────────────────────────────────────────────

setup_auto_updates() {
  [[ "$SETUP_UNATTENDED" != true ]] && return
  header "Enabling Automatic Security Updates"

  apt-get install -y -qq unattended-upgrades apt-listchanges > /dev/null 2>&1

  cat > /etc/apt/apt.conf.d/20auto-upgrades <<'UEOF'
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
APT::Periodic::AutocleanInterval "7";
UEOF

  systemctl enable --now unattended-upgrades
  success "Unattended security upgrades enabled."
}

# ── Apply: install Tailscale ─────────────────────────────────────────────────

install_tailscale() {
  [[ "$INSTALL_TAILSCALE" != true ]] && return
  header "Installing Tailscale"

  info "Downloading and running the Tailscale installer…"
  curl -fsSL https://tailscale.com/install.sh | sh
  success "Tailscale installed."

  echo ""
  info "Starting Tailscale — an authentication URL will appear below."
  info "Open it in a browser on another device to authenticate this node."
  echo ""

  # Build tailscale up flags
  local ts_flags=""
  if [[ "$TAILSCALE_SSH" == true ]]; then
    ts_flags="--ssh"
    info "Tailscale SSH enabled — you will be able to SSH via Tailscale identity."
  fi

  # Build --advertise-tags flag
  if [[ ${#TAILSCALE_TAGS[@]} -gt 0 ]]; then
    local tags_csv=""
    for t in "${TAILSCALE_TAGS[@]}"; do
      if [[ -n "$tags_csv" ]]; then
        tags_csv+=",${t}"
      else
        tags_csv="${t}"
      fi
    done
    ts_flags="${ts_flags} --advertise-tags=${tags_csv}"
    info "Advertising tags: ${tags_csv}"
  fi

  echo ""
  printf "${BOLD}${CYAN}╭──────────────────────────────────────────────────────╮${RESET}\n"
  printf "${BOLD}${CYAN}│  TAILSCALE LOGIN                                     │${RESET}\n"
  printf "${BOLD}${CYAN}╰──────────────────────────────────────────────────────╯${RESET}\n"
  echo ""

  # Run tailscale up — TTY is available since we're on the local terminal
  # shellcheck disable=SC2086
  tailscale up ${ts_flags} || true

  echo ""
  success "Tailscale authentication complete."

  TAILSCALE_IP="$(tailscale ip -4 2>/dev/null || echo "")"
  TAILSCALE_IP="$(echo "$TAILSCALE_IP" | tr -d '[:space:]')"

  TAILSCALE_HOSTNAME="$(tailscale status --self --json 2>/dev/null \
    | grep -o '"DNSName":"[^"]*"' | head -1 \
    | sed 's/"DNSName":"//;s/"//' || echo "")"
  TAILSCALE_HOSTNAME="$(echo "$TAILSCALE_HOSTNAME" | sed 's/\.$//' | tr -d '[:space:]')"

  if [[ -n "$TAILSCALE_IP" ]]; then
    success "Tailscale connected.  IP: ${TAILSCALE_IP}"
    [[ -n "$TAILSCALE_HOSTNAME" ]] && success "Tailscale hostname: ${TAILSCALE_HOSTNAME}"
    if [[ ${#TAILSCALE_TAGS[@]} -gt 0 ]]; then
      success "Tags applied: ${TAILSCALE_TAGS[*]}"
    fi
  else
    warn "Could not verify Tailscale IP. Check manually: tailscale status"
  fi
}

# ── Apply: restart SSH ───────────────────────────────────────────────────────

restart_ssh() {
  header "Restarting SSH"

  # Warn the user before we restart — they're on a local terminal so this
  # won't drop their session, but it's good to be explicit.
  warn "Restarting SSH daemon now. This will not affect your current terminal session."
  systemctl restart sshd || systemctl restart ssh
  success "SSH daemon restarted."
}

# ── Final report ─────────────────────────────────────────────────────────────

final_report() {
  header "Done! Server Setup Complete"

  printf "${GREEN}"
  cat << 'BANNER'
  ╔══════════════════════════════════════════════════╗
  ║              SERVER HARDENED ✔                   ║
  ╚══════════════════════════════════════════════════╝
BANNER
  printf "${RESET}"
  echo ""
  echo "  Applied:"

  if [[ "$ENABLE_ROOT_SSH" == true ]]; then
    echo "    ✔ Root SSH enabled (publickey only)"
    echo "      → Add your public key to /root/.ssh/authorized_keys"
  else
    echo "    ✔ Root SSH login disabled"
  fi

  if [[ ${#PASSWORD_USERS[@]} -gt 0 ]]; then
    echo "    ✔ Password auth preserved for: ${PASSWORD_USERS[*]}"
  fi

  echo "    ✔ Password auth disabled globally"
  echo "    ✔ SSH hardened (crypto, timeouts, access controls)"

  [[ "$CHANGE_SSH_PORT" == true ]]   && echo "    ✔ SSH port changed to ${NEW_SSH_PORT}"
  [[ "$SETUP_UFW" == true ]]         && echo "    ✔ UFW firewall active"
  [[ "$SETUP_UNATTENDED" == true ]]  && echo "    ✔ Automatic security updates enabled"
  [[ "$INSTALL_TAILSCALE" == true ]] && echo "    ✔ Tailscale installed & connected"
  [[ "$TAILSCALE_SSH" == true ]]     && echo "    ✔ Tailscale SSH enabled"

  if [[ ${#TAILSCALE_TAGS[@]} -gt 0 ]]; then
    echo "    ✔ Tailscale tags: ${TAILSCALE_TAGS[*]}"
  fi

  echo ""
  echo "  Connect from another machine via Tailscale:"
  echo ""

  if [[ -n "${TAILSCALE_HOSTNAME:-}" ]]; then
    if [[ "$TAILSCALE_SSH" == true ]]; then
      printf "    ${BOLD}${GREEN}ssh root@${TAILSCALE_HOSTNAME}${RESET}   ${DIM}(Tailscale SSH — no key needed)${RESET}\n"
    else
      printf "    ${BOLD}${GREEN}ssh -i <key> root@${TAILSCALE_HOSTNAME}${RESET}\n"
    fi
    if [[ ${#PASSWORD_USERS[@]} -gt 0 ]]; then
      echo ""
      echo "  Password login (e.g. for Dokploy):"
      for pu in "${PASSWORD_USERS[@]}"; do
        echo "    ssh -p ${NEW_SSH_PORT} ${pu}@${TAILSCALE_HOSTNAME}"
      done
    fi
  elif [[ -n "${TAILSCALE_IP:-}" ]]; then
    if [[ "$TAILSCALE_SSH" == true ]]; then
      printf "    ${BOLD}${GREEN}ssh root@${TAILSCALE_IP}${RESET}   ${DIM}(Tailscale SSH — no key needed)${RESET}\n"
    else
      printf "    ${BOLD}${GREEN}ssh -i <key> root@${TAILSCALE_IP}${RESET}\n"
    fi
    if [[ ${#PASSWORD_USERS[@]} -gt 0 ]]; then
      echo ""
      echo "  Password login (e.g. for Dokploy):"
      for pu in "${PASSWORD_USERS[@]}"; do
        echo "    ssh -p ${NEW_SSH_PORT} ${pu}@${TAILSCALE_IP}"
      done
    fi
  else
    warn "Tailscale IP not detected — run 'tailscale status' to find your address."
  fi

  echo ""
  echo "  Useful commands on this server:"
  echo "    tailscale status          — check Tailscale connection"
  echo "    tailscale ip -4           — show Tailscale IP"
  echo "    ufw status verbose        — review firewall rules"
  echo "    systemctl status sshd     — check SSH daemon"
  echo ""
}

# ── Main ─────────────────────────────────────────────────────────────────────

main() {
  clear
  printf "${BOLD}${CYAN}"
  cat << 'LOGO'

   ┌─┐┌─┐┬─┐┬  ┬┌─┐┬─┐   ┌─┐┌─┐┌┬┐┬ ┬┌─┐
   └─┐├┤ ├┬┘└┐┌┘├┤ ├┬┘───└─┐├┤  │ │ │├─┘
   └─┘└─┘┴└─ └┘ └─┘┴└─   └─┘└─┘ ┴ └─┘┴
   Interactive Server Hardening + Tailscale
   Runs locally — no SSH keys required

LOGO
  printf "${RESET}"

  TAILSCALE_IP=""
  TAILSCALE_HOSTNAME=""

  check_root "$@"
  check_deps
  collect_user_config
  choose_options
  show_summary

  enable_root_ssh
  harden_sshd
  setup_firewall
  setup_auto_updates
  install_tailscale
  restart_ssh
  final_report
}

main "$@"
