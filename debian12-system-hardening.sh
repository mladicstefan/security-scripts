#!/usr/bin/env bash

cat << 'BANNER'
              {}
             {{}}
             {{}}
              {}
            .-''-.
           /  __  \
          /.-'  '-.\
          \::.  .::/
           \'    '/
      __ ___)    (___ __
    .'   \\        //   `.
   /     | '-.__.-' |     \
   |     |  '::::'  |     |
   |    /    '::'    \    |
   |_.-;\     __     /;-._|
   \.'^`\\    \/    //`^'./
   /   _.-._ _||_ _.-._   \
  `\___\    '-..-'    /___/`
       /'---.  `\.---'\
      ||    |`\\\|    ||
      ||    | || |    ||
      |;.__.' || '.__.;|
      |       ||       |
      {{{{{{{{||}}}}}}}}
       |      ||      |
       |.-==-.||.-==-.|
       <.    .||.    .>
        \'=='/||\'=='/
        |   / || \   |
        |   | || |   |
        |   | || |   |
        /^^\| || |/^^\
       /   .' || '.   \
jgs   /   /   ||   \   \
     (__.'    \/    '.__)

Art by Joan G. Stark
BANNER

echo ""
echo "Debian 13 Security Hardening Script"
echo "Aligned with MITRE ATT&CK defense techniques"
echo ""

set -euo pipefail

if [[ $EUID -ne 0 ]]; then
   echo "Error: This script must be run as root (use sudo)"
   exit 1
fi

if [ $# -eq 0 ]; then
    echo "Usage: $0 <username>"
    echo "Example: $0 john"
    exit 1
fi

USERNAME=$1

if ! id "$USERNAME" &>/dev/null; then
    echo "Error: User $USERNAME does not exist"
    exit 1
fi

echo "Hardening Debian 13 for user: $USERNAME"

apt update && apt upgrade -y

apt install -y ufw fail2ban unattended-upgrades apparmor apparmor-profiles apparmor-utils auditd audispd-plugins aide mailutils

# === UFW Firewall ===
ufw default deny incoming

echo ""
echo "OUTBOUND TRAFFIC: Currently allows all outgoing connections"
echo "For high-security environments, consider whitelisting only required ports:"
echo "  ufw default deny outgoing"
echo "  ufw allow out 53/udp    # DNS (vulnerable to DNS spoofing - consider DNSSEC)"
echo "  ufw allow out 80/tcp    # HTTP"
echo "  ufw allow out 443/tcp   # HTTPS"
echo "  ufw allow out 123/udp   # NTP"
echo ""
# OUTBOUND TRAFFIC: Currently allows all outgoing connections
# For high-security environments, consider whitelisting only required ports:
#   ufw default deny outgoing
#   ufw allow out 53/udp    # DNS (vulnerable to DNS spoofing - consider DNSSEC)
#   ufw allow out 80/tcp    # HTTP
#   ufw allow out 443/tcp   # HTTPS
#   ufw allow out 123/udp   # NTP
ufw default allow outgoing

ufw allow 22/tcp
ufw --force enable

# === SSH Hardening ===
cp /etc/ssh/sshd_config /etc/ssh/sshd_config.backup

cat > /etc/ssh/sshd_config.d/hardening.conf << EOF
PermitRootLogin no
PasswordAuthentication yes
PermitEmptyPasswords no
X11Forwarding no
MaxAuthTries 3
ClientAliveInterval 300
ClientAliveCountMax 2
Protocol 2
HostbasedAuthentication no
IgnoreRhosts yes
AllowUsers $USERNAME
EOF

if sshd -t; then
    systemctl restart sshd
    echo "SSH configuration applied successfully"
else
    echo "ERROR: SSH config test failed - NOT restarting sshd"
    echo "Review /etc/ssh/sshd_config.d/hardening.conf"
    exit 1
fi

passwd -l root

# === AppArmor Enable ===
mkdir -p /etc/default/grub.d
echo 'GRUB_CMDLINE_LINUX_DEFAULT="$GRUB_CMDLINE_LINUX_DEFAULT apparmor=1 security=apparmor"' | tee /etc/default/grub.d/apparmor.cfg
update-grub

if [ -f /etc/apparmor.d/sbin.dhclient ]; then
    aa-enforce /etc/apparmor.d/sbin.dhclient
fi
if [ -f /etc/apparmor.d/usr.sbin.tcpdump ]; then
    aa-enforce /etc/apparmor.d/usr.sbin.tcpdump
fi

# === AppArmor Nginx Profile ===
if command -v nginx &>/dev/null; then
    if [ ! -f /etc/apparmor.d/usr.sbin.nginx ]; then
        cat > /etc/apparmor.d/usr.sbin.nginx << 'APPARMOR_EOF'
#include <tunables/global>

/usr/sbin/nginx {
  #include <abstractions/base>
  #include <abstractions/nameservice>
  #include <abstractions/openssl>

  capability dac_override,
  capability setuid,
  capability setgid,
  capability net_bind_service,
  capability sys_resource,

  /usr/sbin/nginx mr,
  /etc/nginx/** r,
  /etc/ssl/openssl.cnf r,
  /etc/ssl/certs/** r,
  /etc/ssl/private/** r,
  
  /var/log/nginx/** w,
  /var/lib/nginx/** rw,
  /var/cache/nginx/** rw,
  
  /run/nginx.pid rw,
  /run/nginx/*.sock rw,
  
  # Web content directories (adjust paths as needed)
  /var/www/** r,
  /usr/share/nginx/** r,
  
  # Deny writes to web content by default
  deny /var/www/** w,
  
  # Allow network operations
  network inet stream,
  network inet6 stream,
  
  # Unix sockets for FastCGI/PHP-FPM
  unix (send, receive) type=stream peer=(label=unconfined),
}
APPARMOR_EOF
        apparmor_parser -r /etc/apparmor.d/usr.sbin.nginx
        aa-enforce /etc/apparmor.d/usr.sbin.nginx
        echo "Nginx AppArmor profile created and enforced"
    else
        aa-enforce /etc/apparmor.d/usr.sbin.nginx
        echo "Nginx AppArmor profile enforced"
    fi
else
    echo "Nginx not installed - skipping AppArmor profile"
fi

# === Kernel Hardening via sysctl ===
echo ""
echo "NOTE: SYN flood protections can be bypassed by tools like nmap's SYN scan"
echo "which can still fill the connection table. For production environments under"
echo "active attack, implement connection rate limiting with iptables/nftables."
echo ""
cat > /etc/sysctl.d/99-security-hardening.conf << 'EOF'
# Prevents this system from routing packets between interfaces (not a router)
net.ipv4.ip_forward = 0
net.ipv6.conf.all.forwarding = 0

# Enable SYN cookies to protect against SYN flood DoS attacks
# NOTE: SYN cookies can still be exploited by nmap SYN scans to fill connection tables.
# These settings mitigate but don't eliminate the attack vector. For production systems
# under active attack, implement connection rate limiting via iptables/nftables.
net.ipv4.tcp_syncookies = 1

# Reduce SYN/SYNACK retry attempts to mitigate SYN flood impact
net.ipv4.tcp_syn_retries = 2
net.ipv4.tcp_synack_retries = 2

# Increase max SYN backlog queue size for better handling of connection floods
# Larger backlog helps absorb SYN floods but attackers can still exhaust this with
# sufficient volume (nmap -sS -Pn --scan-delay 0 can generate thousands per second)
net.ipv4.tcp_max_syn_backlog = 4096

# Reject source-routed packets (attacker could specify routing path)
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv6.conf.all.accept_source_route = 0
net.ipv6.conf.default.accept_source_route = 0

# Reject ICMP redirects (prevents MITM attacks via route manipulation)
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.secure_redirects = 0
net.ipv4.conf.default.secure_redirects = 0
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0

# Do not send ICMP redirects (we are not a router)
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0

# Enable reverse path filtering to prevent IP spoofing attacks
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1

# Log packets with impossible addresses (martian packets) for security monitoring
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.default.log_martians = 1

# Ignore ICMP broadcast echo requests to prevent smurf attacks
net.ipv4.icmp_echo_ignore_broadcasts = 1

# Ignore bogus ICMP error responses
net.ipv4.icmp_ignore_bogus_error_responses = 1

# Restrict dmesg access to root only (prevents info leakage to unprivileged users)
kernel.dmesg_restrict = 1

# Hide kernel pointers in /proc to prevent kernel address leaks
kernel.kptr_restrict = 2

# Disable unprivileged BPF to prevent JIT spraying and other BPF exploits
kernel.unprivileged_bpf_disabled = 1

# Prevent loading new kernels via kexec (stops kernel-level persistence)
kernel.kexec_load_disabled = 1

# Prevent following symlinks in world-writable sticky directories (like /tmp)
fs.protected_symlinks = 1

# Prevent creating hardlinks to files you don't own in world-writable directories
fs.protected_hardlinks = 1

# Restrict opening FIFOs in world-writable sticky directories
fs.protected_fifos = 2

# Restrict opening regular files in world-writable sticky directories
fs.protected_regular = 2

# Disable core dumps for setuid programs (prevents privilege escalation info leaks)
fs.suid_dumpable = 0

# Increase ASLR entropy for memory randomization on 64-bit systems
vm.mmap_rnd_bits = 32

# Increase ASLR entropy for 32-bit compatibility mode
vm.mmap_rnd_compat_bits = 16

# Append PID to core dump filenames for better debugging organization
kernel.core_uses_pid = 1
EOF

sysctl -p /etc/sysctl.d/99-security-hardening.conf

# === Auditd Configuration ===
cat > /etc/audit/rules.d/hardening.rules << 'EOF'
-D
-b 8192

# Set failure mode: 1 = print failure message but continue
# After rules are tested in production, consider -f 2 (kernel panic on audit failure)
-f 1

# Track access to audit logs themselves
-w /var/log/audit/ -k auditlog

# Monitor changes to audit configuration
-w /etc/audit/ -p wa -k auditconfig
-w /etc/libaudit.conf -p wa -k auditconfig
-w /etc/audisp/ -p wa -k audispconfig

# Monitor execution of audit management tools
-w /sbin/auditctl -p x -k audittools
-w /sbin/auditd -p x -k audittools

# Track modifications to user and group databases
-w /etc/group -p wa -k identity
-w /etc/passwd -p wa -k identity
-w /etc/gshadow -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/security/opasswd -p wa -k identity

# Monitor system hostname and domain changes
-a always,exit -F arch=b64 -S sethostname -S setdomainname -k network_modifications
-a always,exit -F arch=b32 -S sethostname -S setdomainname -k network_modifications

# Track changes to network configuration files
-w /etc/hosts -p wa -k network_modifications
-w /etc/network/ -p wa -k network_modifications

# Monitor login/logout events
-w /var/log/faillog -p wa -k logins
-w /var/log/lastlog -p wa -k logins
-w /var/log/tallylog -p wa -k logins

# Track changes to sudo configuration
-w /etc/sudoers -p wa -k sudoers
-w /etc/sudoers.d/ -p wa -k sudoers

# Monitor systemd service modifications (persistence - T1543.002)
-w /etc/systemd/system/ -p wa -k systemd_units
-w /usr/lib/systemd/system/ -p wa -k systemd_units

# Monitor cron job modifications (scheduled tasks - T1053.003)
-w /etc/cron.d/ -p wa -k cron
-w /etc/cron.daily/ -p wa -k cron
-w /etc/cron.hourly/ -p wa -k cron
-w /etc/cron.monthly/ -p wa -k cron
-w /etc/cron.weekly/ -p wa -k cron
-w /var/spool/cron/ -p wa -k cron

# Log all commands executed as root
-a exit,always -F arch=b64 -F euid=0 -S execve -k rootcmd
-a exit,always -F arch=b32 -F euid=0 -S execve -k rootcmd

# Monitor execution of privileged commands
-a always,exit -F path=/usr/bin/passwd -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged
-a always,exit -F path=/usr/bin/sudo -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged
-a always,exit -F path=/usr/bin/su -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged

# Track file deletion operations
-a always,exit -F arch=b64 -S unlink -S unlinkat -S rename -S renameat -k delete
-a always,exit -F arch=b32 -S unlink -S unlinkat -S rename -S renameat -k delete

# Make audit configuration immutable (requires reboot to modify)
# This prevents even root from disabling auditing or modifying rules at runtime
# Provides defense against anti-forensics techniques (T1070)
-e 2
EOF

systemctl restart auditd

# === Log Rotation to Prevent Disk Exhaustion ===
# Auditd logs can grow rapidly on busy systems. Ensure rotation is configured.
# Modify main auditd.conf directly as auditd.conf.d may not exist
cp /etc/audit/auditd.conf /etc/audit/auditd.conf.backup

# Update auditd.conf with disk management settings
sed -i 's/^max_log_file =.*/max_log_file = 100/' /etc/audit/auditd.conf
sed -i 's/^num_logs =.*/num_logs = 10/' /etc/audit/auditd.conf
sed -i 's/^space_left_action =.*/space_left_action = SYSLOG/' /etc/audit/auditd.conf
sed -i 's/^disk_full_action =.*/disk_full_action = SUSPEND/' /etc/audit/auditd.conf
sed -i 's/^admin_space_left =.*/admin_space_left = 50/' /etc/audit/auditd.conf

# Configure logrotate for other security logs
cat > /etc/logrotate.d/security-logs << 'EOF'
/var/log/auth.log
/var/log/syslog
/var/log/fail2ban.log
{
    rotate 7
    daily
    missingok
    notifempty
    compress
    delaycompress
    sharedscripts
    postrotate
        systemctl reload rsyslog > /dev/null 2>&1 || true
        systemctl reload fail2ban > /dev/null 2>&1 || true
    endscript
}
EOF

echo "Log rotation configured to prevent disk exhaustion"

# === Fail2ban Configuration ===
cat > /etc/fail2ban/jail.local << 'EOF'
[DEFAULT]
bantime = 3600
findtime = 600
maxretry = 5
destemail = root@localhost
sendername = Fail2Ban

[sshd]
enabled = true
port = 22
logpath = /var/log/auth.log
backend = systemd
EOF

systemctl enable fail2ban
systemctl restart fail2ban

dpkg-reconfigure -plow unattended-upgrades

# === AIDE (Advanced Intrusion Detection Environment) ===
# AIDE creates cryptographic checksums of system files to detect unauthorized modifications.
# It monitors critical system binaries, libraries, and configuration files for tampering.
# This provides defense against MITRE T1565.001 (Stored Data Manipulation) and 
# T1556 (Modify Authentication Process) by detecting file integrity violations.

# Create aide.conf.d directory if it doesn't exist
mkdir -p /etc/aide/aide.conf.d

cat > /etc/aide/aide.conf.d/99-custom-rules << 'EOF'
# Monitor web server content for unauthorized modifications
!/var/www$ VarDir
/var/www R+a+sha256

# Monitor systemd service files for persistence mechanisms
/etc/systemd/system R+a+sha256
/usr/lib/systemd/system R+a+sha256

# Monitor cron for scheduled task persistence (T1053)
/etc/cron.d R+a+sha256
/etc/cron.daily R+a+sha256
/etc/cron.hourly R+a+sha256
/etc/cron.monthly R+a+sha256
/etc/cron.weekly R+a+sha256
/var/spool/cron R+a+sha256
EOF

echo "Initializing AIDE database (this may take several minutes)..."
aideinit
mv /var/lib/aide/aide.db.new /var/lib/aide/aide.db

# Schedule daily AIDE integrity checks
cat > /etc/cron.daily/aide-check << 'EOF'
#!/bin/bash
# Run AIDE check and email root if changes detected
/usr/bin/aide --check | /usr/bin/mail -s "AIDE Integrity Report - $(hostname)" root
EOF
chmod +x /etc/cron.daily/aide-check

echo "AIDE configured with daily integrity checks"

# === Disable unused filesystems ===
cat > /etc/modprobe.d/disable-filesystems.conf << 'EOF'
# Compressed ROM filesystem (rarely used, reduces attack surface)
install cramfs /bin/true

# Veritas filesystem (legacy, rarely needed)
install freevxfs /bin/true

# Journaling Flash File System v2 (embedded systems only)
install jffs2 /bin/true

# Apple HFS filesystem (not needed on Linux servers)
install hfs /bin/true

# Apple HFS+ filesystem (not needed on Linux servers)
install hfsplus /bin/true

# Universal Disk Format (optical media, rarely needed on servers)
install udf /bin/true
EOF

# === Disable unused network protocols ===
cat > /etc/modprobe.d/disable-protocols.conf << 'EOF'
# Datagram Congestion Control Protocol (rarely used, has had vulnerabilities)
install dccp /bin/true

# Stream Control Transmission Protocol (specialized use cases only)
install sctp /bin/true

# Reliable Datagram Sockets (specialized use cases only)
install rds /bin/true

# Transparent Inter-Process Communication (cluster environments only)
install tipc /bin/true
EOF

echo ""
echo "================================================"
echo "Hardening complete for user: $USERNAME"
echo "================================================"
echo "REBOOT REQUIRED for all changes to take effect"
echo ""
echo "Status:"
echo "  - SSH: Password auth enabled for $USERNAME"
echo "  - Root login: Disabled (locked)"
echo "  - UFW: Enabled (port 22 allowed)"
echo "  - Fail2ban: Active"
echo "  - AppArmor: Enabled (reboot required)"
echo "  - Auditd: Running with immutable rules (-e 2)"
echo "  - AIDE: Initialized with daily checks"
echo "  - Log rotation: Configured"
echo "  - Unattended-upgrades: Configured"
echo ""
echo "AppArmor profiles in complain mode by default."
echo "Nginx profile enforced if nginx is installed."
echo "Test your applications, then enforce with:"
echo "  sudo aa-enforce /etc/apparmor.d/PROFILE"
echo ""
echo "For web servers, add UFW rules:"
echo "  sudo ufw allow 80/tcp"
echo "  sudo ufw allow 443/tcp"
echo ""
echo "For Samba file sharing, add UFW rules:"
echo "  sudo ufw allow 137,138/udp"
echo "  sudo ufw allow 139,445/tcp"
echo ""
echo "IMPORTANT: Audit rules are now IMMUTABLE (-e 2)"
echo "To modify audit rules after reboot, you must:"
echo "  1. Reboot into single-user mode, OR"
echo "  2. Remove -e 2 from /etc/audit/rules.d/hardening.rules"
echo "  3. Reboot again"
echo ""
echo "SECURITY NOTES:"
echo "  - SYN flood protections configured but can be bypassed"
echo "  - DNS traffic (port 53) vulnerable to spoofing attacks"
echo "    Consider implementing DNSSEC for critical systems"
echo ""
echo "Test SSH before rebooting!"
echo "================================================"
