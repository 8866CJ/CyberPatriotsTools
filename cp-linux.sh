#!/usr/bin/env bash
# CyberPatriot Linux Toolkit
# Linux Mint 21 / Ubuntu 22.04+ (apt-based). Plain bash + tools that ship with the OS.
#
# Run:  sudo bash cp-linux.sh
# READ THE README FIRST. Answer forensics questions BEFORE deleting users or files.
# Anything destructive asks first. Every change goes to the log next to this script,
# and every config file is backed up once as <file>.cp-bak before the first edit.

[[ $EUID -ne 0 ]] && exec sudo bash "$0" "$@"

ME=${SUDO_USER:-root}
HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
LOG="$HERE/cp-log-$(date +%Y%m%d-%H%M%S).txt"
touch "$LOG" 2>/dev/null || LOG="/root/cp-log-$(date +%Y%m%d-%H%M%S).txt"
OSNAME=$(. /etc/os-release 2>/dev/null; echo "${PRETTY_NAME:-Linux}")

# --- output helpers -------------------------------------------------------------
G=$'\e[32m'; Y=$'\e[33m'; C=$'\e[36m'; M=$'\e[35m'; D=$'\e[90m'; W=$'\e[97m'; N=$'\e[0m'
ok()    { echo "  ${G}[+]${N} $*"; echo "[+] $*" >> "$LOG"; }
warn()  { echo "  ${Y}[!]${N} $*"; echo "[!] $*" >> "$LOG"; }
info()  { echo "  ${C}[*]${N} $*"; }
good()  { echo "  ${D}[=] $*${N}"; }
head_() { echo; echo "  ${M}--- $* ---${N}"; }
ask()   { local a; read -rp "  $* [y/N] " a; [[ $a =~ ^[Yy] ]]; }
in_list() { local x=$1 i; shift; for i in "$@"; do [[ $i == "$x" ]] && return 0; done; return 1; }

# read_list ARRAYNAME "prompt"  -> fills the array from a comma/space separated answer
read_list() { local -n _out=$1; local a; read -rp "  $2 (comma/space separated): " a; read -ra _out <<< "${a//,/ }"; }

# Numbered picker: pick "item" "item"...  -> PIDX=(chosen indexes). Accepts 1,3,5-8 / all / Enter.
pick() {
    PIDX=()
    local -a items=("$@") parts; local s part a b i
    if ((${#items[@]} == 0)); then good '(none found)'; return 1; fi
    for i in "${!items[@]}"; do printf '  %3d) %s\n' $((i + 1)) "${items[i]}"; done
    read -rp "  Select (e.g. 1,3,5-8 / all / Enter = none): " s
    [[ $s == all ]] && s="1-${#items[@]}"
    local -A seen=()
    read -ra parts <<< "${s//,/ }"
    for part in "${parts[@]}"; do
        [[ $part =~ ^([0-9]+)(-([0-9]+))?$ ]] || continue
        a=${BASH_REMATCH[1]}; b=${BASH_REMATCH[3]:-$a}
        for ((i = a; i <= b; i++)); do
            ((i >= 1 && i <= ${#items[@]})) && [[ -z ${seen[$i]:-} ]] && { seen[$i]=1; PIDX+=($((i - 1))); }
        done
    done
    ((${#PIDX[@]}))
}

apt_get() { DEBIAN_FRONTEND=noninteractive apt-get -o DPkg::Lock::Timeout=120 "$@"; }
backup()  { local f; for f; do [[ -f $f && ! -f $f.cp-bak ]] && cp -p "$f" "$f.cp-bak"; done; }
restore() { local f; for f; do [[ -f $f.cp-bak ]] && cp -p "$f.cp-bak" "$f"; done; }

# set_kv FILE KEY VALUE [SEP]
# Replaces the first line setting KEY (even if commented out) and comments out any later duplicates.
# If KEY is not there, adds it as the first line (safe for sshd_config: before any Match block).
set_kv() {
    local f=$1 k=$2 v=$3 sep=${4:- }
    [[ -f $f ]] || { mkdir -p "$(dirname "$f")"; touch "$f"; }
    backup "$f"
    local re="^[[:space:]#]*${k//./\\.}([[:space:]]*=|[[:space:]]+)"
    if grep -qE "$re" "$f"; then
        RE="$re" LINE="$k$sep$v" awk '
            $0 ~ ENVIRON["RE"] {
                if (!done) { print ENVIRON["LINE"]; done = 1; next }
                if ($0 !~ /^[[:space:]]*#/) { print "#" $0; next }
            }
            { print }' "$f" > "$f.cp-tmp" && cat "$f.cp-tmp" > "$f"
        rm -f "$f.cp-tmp"
    elif [[ -s $f ]]; then
        sed -i "1i $k$sep$v" "$f"
    else
        echo "$k$sep$v" > "$f"
    fi
}

# ini_set FILE SECTION KEY VALUE [SEP]  - sets KEY inside [SECTION] (lightdm, smb.conf)
ini_set() {
    local f=$1 sec=$2 k=$3 v=$4 sep=${5:- = }
    [[ -f $f ]] || { mkdir -p "$(dirname "$f")"; touch "$f"; }
    backup "$f"
    local esc; esc=$(printf '%s' "$sec" | sed 's/[]\[*.^$/]/\\&/g')
    grep -q "^\[$esc\]" "$f" || printf '\n[%s]\n' "$sec" >> "$f"
    sed -i -E "/^[#;[:space:]]*${k//./\\.}[[:space:]]*=/d" "$f"
    sed -i "/^\[$esc\]/a $k$sep$v" "$f"
}

human_users() { awk -F: '$3 >= 1000 && $3 < 60000 { print $1 }' /etc/passwd; }

# Prints the paths (args) that no installed package owns - planted files show up here.
unowned() {
    local norm='s#^/usr/lib/#/lib/#; s#^/usr/bin/#/bin/#; s#^/usr/sbin/#/sbin/#'
    printf '%s\n' "$@" | sed "$norm" | grep -vxF -f <(cat /var/lib/dpkg/info/*.list 2>/dev/null | sed "$norm" | sort -u)
}

# sync_group GROUP wanted-members...  (asks before every change)
sync_group() {
    local g=$1; shift
    local -a want=("$@") have; local m
    getent group "$g" > /dev/null || return
    IFS=, read -ra have <<< "$(getent group "$g" | cut -d: -f4)"
    for m in "${have[@]}"; do
        [[ -z $m ]] && continue
        in_list "$m" "${want[@]}" && continue
        ask "'$m' should NOT be in '$g' - remove?" && gpasswd -d "$m" "$g" > /dev/null && ok "Removed $m from $g"
    done
    for m in "${want[@]}"; do
        in_list "$m" "${have[@]}" && continue
        id "$m" &> /dev/null || continue
        ask "'$m' is missing from '$g' - add?" && gpasswd -a "$m" "$g" > /dev/null && ok "Added $m to $g"
    done
}

get_pw() {
    [[ -n ${PW:-} ]] && return
    local p2
    while :; do
        read -rsp '  Secure password to set (12+ chars, upper/lower/digit/symbol): ' PW; echo
        read -rsp '  Confirm: ' p2; echo
        [[ $PW == "$p2" && ${#PW} -ge 12 ]] && return
        warn 'Passwords differ or shorter than 12 characters - try again'
    done
}

# ==================================================================================
# 1. Users
# ==================================================================================
users_audit() {
    local -a pw_lines admins users all
    local l n uid gid shell a u
    head_ 'Human users (UID >= 1000)'
    mapfile -t pw_lines < /etc/passwd
    for l in "${pw_lines[@]}"; do
        IFS=: read -r n _ uid _ _ _ shell <<< "$l"
        ((uid >= 1000 && uid < 60000)) && printf '  %-16s uid=%-6s %-18s %s\n' "$n" "$uid" "$shell" "$(id -nG "$n" | tr ' ' ',')"
    done
    info "sudo: $(getent group sudo | cut -d: -f4)    adm: $(getent group adm | cut -d: -f4)"
    info "You are '$ME' - you are always kept."
    read_list admins 'Authorized ADMINISTRATORS from README'
    read_list users 'Authorized standard USERS from README'
    all=("${admins[@]}" "${users[@]}" "$ME")

    head_ 'Unauthorized users'
    for u in $(human_users); do
        in_list "$u" "${all[@]}" && continue
        read -rp "  Unauthorized user '$u' - [d]elete / [l]ock / Enter = skip: " a
        case $a in
            [Dd]*) pkill -KILL -u "$u" 2> /dev/null; userdel -r "$u" &> /dev/null
                   if id "$u" &> /dev/null; then warn "Could not delete $u"; else ok "Removed unauthorized user $u"; fi ;;
            [Ll]*) usermod -L -e 1 "$u" && ok "Locked unauthorized user $u" ;;
        esac
    done

    head_ 'Hidden and root-equivalent accounts'
    local sudo_gid; sudo_gid=$(getent group sudo | cut -d: -f3)
    mapfile -t pw_lines < /etc/passwd
    for l in "${pw_lines[@]}"; do
        IFS=: read -r n _ uid gid _ _ shell <<< "$l"
        if [[ $uid == 0 && $n != root ]]; then
            warn "$n has UID 0 (root equivalent)"
            ask "Delete account '$n'? (its home is kept)" && userdel -f "$n" && ok "Removed UID-0 account $n"
        elif ((uid > 0 && uid < 1000)) && [[ $shell =~ /(ba|da|z|k|c|tc|fi)?sh$ ]]; then
            local hash; hash=$(getent shadow "$n" | cut -d: -f2)
            [[ $hash == [\!*]* ]] && continue
            warn "System account '$n' (uid $uid) has a login shell AND a password"
            ask "Set its shell to nologin and lock it?" && usermod -s /usr/sbin/nologin -L "$n" && ok "Disabled login for system account $n"
        fi
        if [[ -n $sudo_gid && $gid == "$sudo_gid" ]] && ! in_list "$n" "${admins[@]}"; then
            warn "$n has 'sudo' as its PRIMARY group (hidden admin)"
            ask "Give $n its own primary group?" && { groupadd -f "$n"; usermod -g "$n" "$n" && ok "$n no longer has sudo as primary group"; }
        fi
    done
    local dup; dup=$(cut -d: -f3 /etc/passwd | sort | uniq -d | tr '\n' ' ')
    [[ -n $dup ]] && warn "Duplicate UIDs: $dup - check /etc/passwd"
    for u in $(awk -F: '$2 == "" { print $1 }' /etc/shadow); do warn "$u has NO password"; done

    head_ 'Missing users'
    local -a created=()
    for u in "${all[@]}"; do
        id "$u" &> /dev/null && continue
        ask "User '$u' is in the README but missing - create?" || continue
        get_pw
        useradd -m -s /bin/bash "$u" && printf '%s:%s\n' "$u" "$PW" | chpasswd && ok "Created user account $u" && created+=("$u")
    done

    head_ 'Administrator groups (sudo, adm, admin, wheel)'
    sync_group sudo "${admins[@]}" "$ME"
    sync_group adm "${admins[@]}" "$ME" syslog
    sync_group admin "${admins[@]}" "$ME"
    sync_group wheel "${admins[@]}" "$ME"
    info 'Direct grants in /etc/sudoers are checked in option 11.'

    head_ 'Passwords'
    if ask 'Set a secure password on all authorized users except you (fixes weak README passwords)?'; then
        get_pw
        for u in "${all[@]}"; do
            [[ $u == "$ME" ]] && continue
            id "$u" &> /dev/null || continue
            if printf '%s:%s\n' "$u" "$PW" | chpasswd; then ok "Changed password for $u"; else warn "Password change failed for $u"; fi
        done
    fi
    if ((${#created[@]})) && ask "Force new users (${created[*]}) to change password at next login?"; then
        for u in "${created[@]}"; do passwd -e "$u" > /dev/null && ok "User $u must change password at next login"; done
    fi
    if ask 'Force ALL authorized users except you to change password at next login?'; then
        for u in "${all[@]}"; do [[ $u != "$ME" ]] && id "$u" &> /dev/null && passwd -e "$u" > /dev/null && ok "User $u must change password at next login"; done
    fi
    for u in "${all[@]}"; do
        if [[ $(passwd -S "$u" 2> /dev/null | awk '{print $2}') == L ]] && ask "Authorized user '$u' is locked - unlock?"; then
            usermod -U -e '' "$u" && ok "Unlocked $u"
        fi
    done
}

# ==================================================================================
# 2. Groups
# ==================================================================================
groups_edit() {
    head_ 'Groups that have members'
    getent group | awk -F: '$4 != "" { printf "  %-22s %s\n", $1, $4 }'
    local g; local -a want
    while read -rp $'\n  Group to edit (Enter = back): ' g && [[ -n $g ]]; do
        if ! getent group "$g" > /dev/null; then
            ask "Group '$g' does not exist - create?" && groupadd "$g" && ok "Created group $g" || continue
        fi
        info "Now: $(getent group "$g" | cut -d: -f4)"
        if ask "Delete group '$g' entirely?"; then groupdel "$g" && ok "Deleted group $g"; continue; fi
        read_list want "Exact members the README wants in '$g'"
        sync_group "$g" "${want[@]}"
    done
}

# ==================================================================================
# 3. Password policy / PAM
# ==================================================================================
password_policy() {
    set_kv /etc/login.defs PASS_MAX_DAYS 90
    set_kv /etc/login.defs PASS_MIN_DAYS 7
    set_kv /etc/login.defs PASS_WARN_AGE 14
    ok 'login.defs: PASS_MAX_DAYS 90, PASS_MIN_DAYS 7, PASS_WARN_AGE 14'
    local u; for u in $(human_users); do chage -M 90 -m 7 -W 14 "$u"; done
    ok 'Password aging applied to existing users'

    dpkg -s libpam-pwquality &> /dev/null || { info 'Installing libpam-pwquality...'; apt_get install -y libpam-pwquality > /dev/null; }

    # pam-auth-update rewrites common-*, so it must run BEFORE the manual edits below.
    if ask 'Enable account lockout (faillock: 5 bad tries = 30 min lock)?'; then
        cat > /usr/share/pam-configs/faillock << 'EOF'
Name: Enforce failed login attempt counter
Default: no
Priority: 0
Auth-Type: Primary
Auth:
	[default=die] pam_faillock.so authfail
	sufficient pam_faillock.so authsucc
EOF
        cat > /usr/share/pam-configs/faillock_notify << 'EOF'
Name: Notify on failed login attempts
Default: no
Priority: 1024
Auth-Type: Primary
Auth:
	requisite pam_faillock.so preauth
EOF
        set_kv /etc/security/faillock.conf deny 5 ' = '
        set_kv /etc/security/faillock.conf unlock_time 1800 ' = '
        set_kv /etc/security/faillock.conf fail_interval 900 ' = '
        backup /etc/pam.d/common-auth /etc/pam.d/common-password /etc/pam.d/common-account
        DEBIAN_FRONTEND=noninteractive pam-auth-update --enable faillock faillock_notify < /dev/null > /dev/null 2>&1
        if ! grep -q pam_faillock /etc/pam.d/common-auth && ask 'PAM files were edited locally, so pam-auth-update skipped them. Regenerate them (--force)?'; then
            DEBIAN_FRONTEND=noninteractive pam-auth-update --force --enable faillock faillock_notify < /dev/null > /dev/null 2>&1
        fi
        if grep -q pam_faillock /etc/pam.d/common-auth; then ok 'Account lockout policy (pam_faillock) enabled'; else warn 'faillock not enabled - run: sudo pam-auth-update'; fi
    fi

    set_kv /etc/security/pwquality.conf minlen 12 ' = '
    local k; for k in dcredit ucredit lcredit ocredit; do set_kv /etc/security/pwquality.conf $k -1 ' = '; done
    set_kv /etc/security/pwquality.conf maxrepeat 3 ' = '
    set_kv /etc/security/pwquality.conf usercheck 1 ' = '
    set_kv /etc/security/pwquality.conf dictcheck 1 ' = '
    set_kv /etc/security/pwquality.conf retry 3 ' = '
    grep -qE '^[[:space:]]*enforce_for_root' /etc/security/pwquality.conf || echo 'enforce_for_root' >> /etc/security/pwquality.conf
    ok 'pwquality: min length 12, needs upper/lower/digit/symbol'

    local cp=/etc/pam.d/common-password ca=/etc/pam.d/common-auth
    backup "$cp" "$ca"
    sed -i -E '/pam_pwquality\.so/ { s/[[:space:]](minlen|ucredit|lcredit|dcredit|ocredit|retry)=[^[:space:]]*//g; s/$/ retry=3 minlen=12 ucredit=-1 lcredit=-1 dcredit=-1 ocredit=-1/ }' "$cp"
    sed -i -E '/pam_unix\.so/ { s/[[:space:]]remember=[0-9]+//g; s/[[:space:]]nullok(_secure)?//g; s/$/ remember=5/ }' "$cp"
    touch /etc/security/opasswd && chmod 600 /etc/security/opasswd
    ok 'common-password: pam_pwquality minlen=12 + credits, pam_unix remember=5'
    sed -i -E 's/[[:space:]]nullok(_secure)?//g' "$ca"
    ok 'common-auth: removed nullok (null passwords cannot log in)'
    grep -rlE '^[^#]*pam_exec|^[^#]*(sufficient|success=)[^#]*pam_permit\.so' /etc/pam.d/ 2> /dev/null | while read -r f; do warn "Check $f - contains pam_exec / permissive pam_permit"; done
    warn 'TEST NOW: open a NEW terminal and run  sudo -k; sudo true   (restore: cp /etc/pam.d/common-auth.cp-bak /etc/pam.d/common-auth)'
}

# ==================================================================================
# 4. Kernel / network hardening
# ==================================================================================
SYSCTL=(
    net.ipv4.tcp_syncookies=1 net.ipv4.ip_forward=0
    net.ipv4.conf.all.accept_redirects=0 net.ipv4.conf.default.accept_redirects=0
    net.ipv4.conf.all.secure_redirects=0 net.ipv4.conf.default.secure_redirects=0
    net.ipv4.conf.all.send_redirects=0 net.ipv4.conf.default.send_redirects=0
    net.ipv4.conf.all.rp_filter=1 net.ipv4.conf.default.rp_filter=1
    net.ipv4.conf.all.accept_source_route=0 net.ipv4.conf.default.accept_source_route=0
    net.ipv4.conf.all.log_martians=1 net.ipv4.conf.default.log_martians=1
    net.ipv4.icmp_echo_ignore_broadcasts=1 net.ipv4.icmp_ignore_bogus_error_responses=1
    net.ipv4.tcp_max_syn_backlog=2048 net.ipv4.tcp_synack_retries=2 net.ipv4.tcp_syn_retries=5
    net.ipv6.conf.all.accept_redirects=0 net.ipv6.conf.default.accept_redirects=0
    net.ipv6.conf.all.accept_ra=0 net.ipv6.conf.default.accept_ra=0
    kernel.randomize_va_space=2 kernel.dmesg_restrict=1 kernel.kptr_restrict=2 kernel.sysrq=0
    kernel.yama.ptrace_scope=1 fs.suid_dumpable=0 fs.protected_hardlinks=1 fs.protected_symlinks=1
)

sysctl_harden() {
    local -a want=("${SYSCTL[@]}"); local kv
    ask 'Disable IPv6 (only if the README does not need it)?' &&
        want+=(net.ipv6.conf.all.disable_ipv6=1 net.ipv6.conf.default.disable_ipv6=1 net.ipv6.conf.lo.disable_ipv6=1)
    for kv in "${want[@]}"; do set_kv /etc/sysctl.conf "${kv%%=*}" "${kv#*=}" ' = '; done
    sysctl --system > /dev/null 2>&1
    local bad=0
    for kv in "${want[@]}"; do
        [[ $(sysctl -n "${kv%%=*}" 2> /dev/null) == "${kv#*=}" ]] || { warn "${kv%%=*} is '$(sysctl -n "${kv%%=*}" 2> /dev/null)' (wanted ${kv#*=})"; bad=1; }
    done
    ((bad)) || ok "sysctl: ${#want[@]} settings applied (SYN cookies, no forwarding/redirects/source routing, ASLR...)"
    systemctl mask ctrl-alt-del.target > /dev/null 2>&1 && ok 'Ctrl+Alt+Del reboot disabled'
    grep -qE '^\*[[:space:]]+hard[[:space:]]+core[[:space:]]+0' /etc/security/limits.conf ||
        { backup /etc/security/limits.conf; echo '* hard core 0' >> /etc/security/limits.conf; ok 'Core dumps disabled'; }
}

# ==================================================================================
# 5. Firewall, AppArmor, antivirus
# ==================================================================================
protection() {
    command -v ufw > /dev/null || { info 'Installing UFW...'; apt_get install -y ufw > /dev/null; }
    ufw default deny incoming > /dev/null; ufw default allow outgoing > /dev/null; ufw logging on > /dev/null
    info 'Allow ONLY what the README needs, e.g.:  ssh  http  https  21/tcp  samba   (Enter = none)'
    local -a allow; local p
    read_list allow 'Services/ports to allow'
    for p in "${allow[@]}"; do ufw allow "$p" > /dev/null && ok "UFW allows $p" || warn "ufw allow $p failed"; done
    ufw --force enable > /dev/null && ok 'Uncomplicated Firewall (UFW) protection has been enabled'
    ufw status verbose | sed 's/^/  /'

    systemctl enable --now apparmor > /dev/null 2>&1 && ok 'AppArmor enabled'
    if ask 'Install + enable auditd (audit logging)?'; then
        apt_get install -y auditd > /dev/null && systemctl enable --now auditd > /dev/null 2>&1 && ok 'auditd installed and running'
    fi
    if ask 'Install ClamAV and scan /home, /root, /tmp (takes a few minutes)?'; then
        apt_get install -y clamav > /dev/null
        systemctl stop clamav-freshclam 2> /dev/null; freshclam > /dev/null 2>&1; systemctl start clamav-freshclam 2> /dev/null
        info 'Scanning...'
        local -a hits
        mapfile -t hits < <(clamscan -r -i --no-summary /home /root /tmp 2> /dev/null | sed -E 's/: .* FOUND$//')
        pick "${hits[@]}"
        local i; for i in "${PIDX[@]}"; do rm -f -- "${hits[i]}" && ok "Deleted infected file ${hits[i]}"; done
    fi
}

# ==================================================================================
# 6. Login screen and root
# ==================================================================================
login_harden() {
    local c
    if [[ -d /etc/lightdm ]]; then
        for c in /etc/lightdm/lightdm.conf.d/*.conf /usr/share/lightdm/lightdm.conf.d/*.conf; do
            [[ -f $c ]] || continue
            if grep -qE '^[[:space:]]*(autologin-user|allow-guest[[:space:]]*=[[:space:]]*true)' "$c"; then
                backup "$c"
                sed -i -E 's/^([[:space:]]*autologin-user.*)/#\1/; s/^([[:space:]]*allow-guest[[:space:]]*=[[:space:]]*)true/\1false/' "$c"
                ok "Removed guest/autologin settings from $c"
            fi
        done
        local f=/etc/lightdm/lightdm.conf
        ini_set "$f" 'Seat:*' allow-guest false '='
        ini_set "$f" 'Seat:*' greeter-hide-users true '='
        ini_set "$f" 'Seat:*' greeter-show-manual-login true '='
        ini_set "$f" 'Seat:*' autologin-guest false '='
        sed -i -E 's/^([[:space:]]*autologin-user[[:space:]]*=.*)/#\1/' "$f"
        ok 'LightDM: guest disabled, user list hidden, manual login shown, no autologin (applies after reboot)'
    fi
    if [[ -f /etc/gdm3/custom.conf ]]; then
        set_kv /etc/gdm3/custom.conf AutomaticLoginEnable false =
        set_kv /etc/gdm3/custom.conf TimedLoginEnable false =
        ok 'GDM: automatic login disabled'
    fi
    if [[ $(passwd -S root | awk '{print $2}') != L ]]; then
        ask 'Lock the root account (passwd -l root)?' && passwd -l root > /dev/null && ok 'Root account locked'
    else good 'root already locked'; fi
}

# ==================================================================================
# 7. SSH
# ==================================================================================
ssh_harden() {
    if ! dpkg -s openssh-server &> /dev/null; then good 'openssh-server is not installed'; return; fi
    local a; read -rp '  Is SSH a CRITICAL service in the README? (y/n/Enter = skip): ' a
    case $a in
        [Nn]*) ask 'Stop and purge openssh-server?' && systemctl disable --now ssh > /dev/null 2>&1 &&
                   apt_get purge -y openssh-server > /dev/null && ok 'SSH server removed'
               return ;;
        [Yy]*) ;;
        *) return ;;
    esac
    local f=/etc/ssh/sshd_config k
    local -A S=(
        [PermitRootLogin]=no [PermitEmptyPasswords]=no [PasswordAuthentication]=yes [UsePAM]=yes
        [X11Forwarding]=no [LoginGraceTime]=60 [MaxAuthTries]=4 [HostbasedAuthentication]=no
        [IgnoreRhosts]=yes [PermitUserEnvironment]=no [ClientAliveInterval]=300 [ClientAliveCountMax]=3
        [AllowAgentForwarding]=no [AllowTcpForwarding]=no [LogLevel]=VERBOSE
    )
    backup "$f" /etc/ssh/sshd_config.d/*.conf
    for k in "${!S[@]}"; do
        set_kv "$f" "$k" "${S[$k]}"
        # Files in sshd_config.d are read first and WIN, so drop the same keys there.
        sed -i -E "/^[[:space:]]*$k[[:space:]]/Id" /etc/ssh/sshd_config.d/*.conf 2> /dev/null
    done
    mkdir -p /run/sshd   # sshd -t fails without it when ssh is stopped
    if sshd -t 2> /dev/null; then
        systemctl enable ssh > /dev/null 2>&1; systemctl restart ssh
        ok 'SSH hardened: root login off, empty passwords off, X11 off, MaxAuthTries 4, LoginGraceTime 60'
        command -v ufw > /dev/null && ufw allow ssh > /dev/null && ok 'UFW allows ssh'
    else
        restore "$f" /etc/ssh/sshd_config.d/*.conf
        warn 'sshd -t rejected the config - restored the original. Edit /etc/ssh/sshd_config by hand.'
    fi

    head_ 'authorized_keys files (backdoor keys let people in without a password)'
    local -a keys; mapfile -t keys < <(ls /root/.ssh/authorized_keys /home/*/.ssh/authorized_keys 2> /dev/null)
    local -a labels=(); for k in "${keys[@]}"; do labels+=("$k  ($(grep -c . "$k") keys: $(awk '{print $NF}' "$k" | tr '\n' ' '))"); done
    pick "${labels[@]}"
    local i; for i in "${PIDX[@]}"; do backup "${keys[i]}"; : > "${keys[i]}" && ok "Emptied ${keys[i]}"; done
}

# ==================================================================================
# 8. Services
# ==================================================================================
BAD_SVC=(
    vsftpd:FTP proftpd:FTP pure-ftpd:FTP tftpd-hpa:TFTP apache2:'Apache web server' nginx:'nginx web server'
    lighttpd:'lighttpd web server' smbd:Samba nmbd:'Samba NetBIOS' named:'BIND DNS' bind9:'BIND DNS'
    openbsd-inetd:'inetd (telnet etc.)' inetd:inetd xinetd:xinetd snmpd:SNMP nfs-server:NFS
    nfs-kernel-server:NFS rpcbind:rpcbind avahi-daemon:'Avahi/mDNS' cups:'CUPS printing'
    cups-browsed:'CUPS browsing' postfix:'Postfix mail' sendmail:Sendmail exim4:Exim dovecot:Dovecot
    x11vnc:'VNC server' vncserver:'VNC server' isc-dhcp-server:'DHCP server' slapd:'LDAP server'
    squid:'Squid proxy' rsync:'rsync daemon' mysql:MySQL mariadb:MariaDB postgresql:PostgreSQL
    ypserv:NIS inspircd:'IRC server' ngircd:'IRC server' minissdpd:UPnP
)

services_audit() {
    info "Keep anything the README lists as a critical service! (SSH is option 7)"
    local e u label a frag pkg
    for e in "${BAD_SVC[@]}"; do
        u=${e%%:*}; label=${e#*:}
        systemctl cat "$u.service" &> /dev/null || continue
        local state; state="$(systemctl is-active "$u" 2> /dev/null)/$(systemctl is-enabled "$u" 2> /dev/null)"
        [[ $state == inactive/disabled || $state == inactive/masked ]] && { good "$label ($u) already stopped/disabled"; continue; }
        read -rp "  $label ($u) is $state - [s]top+disable / [p]urge package / Enter = keep: " a
        case $a in
            [Ss]*) systemctl disable --now "$u" > /dev/null 2>&1 && ok "$label service has been stopped and disabled" ;;
            [Pp]*) frag=$(systemctl show -p FragmentPath --value "$u")
                   pkg=$(dpkg -S "$frag" 2> /dev/null | head -1 | cut -d: -f1)
                   systemctl disable --now "$u" > /dev/null 2>&1
                   if [[ -n $pkg ]] && apt_get purge -y "$pkg" > /dev/null; then ok "$label removed (purged $pkg)"; else warn "Could not find/purge package for $u - stopped it instead"; fi ;;
        esac
    done
    head_ 'All running services (look for anything unexpected)'
    systemctl list-units --type=service --state=running --no-legend --plain | awk '{print "  " $1}' | column -c 160
}

# ==================================================================================
# 9. Software
# ==================================================================================
BAD_PKG='^(john|john-data|hydra|hydra-gtk|nmap|zenmap|ncat|ndiff|wireshark.*|tshark|termshark|ophcrack.*|aircrack-ng|'
BAD_PKG+='nikto|sqlmap|hashcat|medusa|ncrack|kismet.*|ettercap.*|dsniff|netcat|netcat-traditional|netcat-openbsd|socat|'
BAD_PKG+='metasploit.*|burpsuite|wifite|reaver|pixiewps|fcrackzip|rarcrack|pdfcrack|sucrack|chntpw|macchanger|yersinia|'
BAD_PKG+='bettercap|responder|crunch|cewl|masscan|zmap|hping3|driftnet|tcpdump|deluge.*|transmission.*|qbittorrent|'
BAD_PKG+='frostwire|vuze|amule.*|ktorrent|x11vnc|tightvncserver|tigervnc.*|vnc4server|telnetd|inetutils-telnetd|telnet|'
BAD_PKG+='rsh-server|rsh-client|rsh-redone.*|talk|talkd|nis|yp-tools|tftpd.*|atftpd|tftp|snmpd|vsftpd|pure-ftpd.*|'
BAD_PKG+='proftpd.*|xinetd|openbsd-inetd|irssi|hexchat|pidgin)$'

software_audit() {
    local -a rows names labels; local l p v s i
    mapfile -t rows < <(dpkg-query -W -f='${db:Status-Abbrev}|${Package}|${Version}|${Section}\n' 2> /dev/null | awk -F'|' '$1 ~ /^ii/')
    for l in "${rows[@]}"; do
        IFS='|' read -r _ p v s <<< "$l"
        [[ $p =~ $BAD_PKG || $s == games || $s == */games ]] || continue
        names+=("$p"); labels+=("$(printf '%-30s %-28s %s' "$p" "${v:0:27}" "$s")")
    done
    head_ 'Flagged packages (hacking tools, P2P, remote access, insecure servers, games)'
    info 'Do NOT remove anything the README requires.'
    if pick "${labels[@]}"; then
        local -a sel=(); for i in "${PIDX[@]}"; do sel+=("${names[i]}"); done
        apt_get purge -y "${sel[@]}" > /dev/null && ok "Removed prohibited software: ${sel[*]}" || warn "apt purge failed for: ${sel[*]}"
    fi

    if ask 'Review every manually-installed package?'; then
        local -a man; mapfile -t man < <(apt-mark showmanual)
        if pick "${man[@]}"; then
            local -a sel=(); for i in "${PIDX[@]}"; do sel+=("${man[i]}"); done
            apt_get purge -y "${sel[@]}" > /dev/null && ok "Removed: ${sel[*]}"
        fi
    fi
    if command -v flatpak > /dev/null; then
        head_ 'Flatpak apps'
        local -a fp; mapfile -t fp < <(flatpak list --app --columns=application 2> /dev/null)
        pick "${fp[@]}" && for i in "${PIDX[@]}"; do flatpak uninstall -y --noninteractive "${fp[i]}" > /dev/null && ok "Removed flatpak ${fp[i]}"; done
    fi
    if command -v snap > /dev/null; then
        head_ 'Snap packages'
        local -a sp; mapfile -t sp < <(snap list 2> /dev/null | awk 'NR > 1 && $1 !~ /^(core[0-9]*|snapd|bare|gtk-common-themes|gnome-[0-9-]+)$/ {print $1}')
        pick "${sp[@]}" && for i in "${PIDX[@]}"; do snap remove "${sp[i]}" > /dev/null && ok "Removed snap ${sp[i]}"; done
    fi

    head_ 'Programs not installed by apt (/opt, /usr/local, stray binaries in bin dirs)'
    local -a cand stray; local f
    for f in /opt/* /usr/local/bin/* /usr/local/sbin/* /usr/bin/* /usr/sbin/*; do [[ -e $f && ! -L $f ]] && cand+=("$f"); done
    mapfile -t stray < <(unowned "${cand[@]}")
    pick "${stray[@]}" && for i in "${PIDX[@]}"; do rm -rf -- "${stray[i]}" && ok "Deleted ${stray[i]}"; done
    ask 'Run apt autoremove (clean leftover dependencies)?' && apt_get autoremove -y > /dev/null && ok 'Removed unused dependencies'
}

# ==================================================================================
# 10. Prohibited files
# ==================================================================================
MEDIA='mp3|mp4|m4a|m4v|wav|wma|wmv|flac|aac|ogg|oga|opus|avi|mkv|mov|flv|webm|mpg|mpeg|mp2|3gp|aiff'
IMAGES='jpg|jpeg|png|gif|bmp|tif|tiff|webp'
SUSPECT_EXT='sh|py|pl|rb|elf|bin|exe|zip|tar|gz|tgz|7z|rar|deb|appimage|iso|torrent|pcap|pcapng|kdbx'
SUSPECT_NAME='pass(word|wd)?s?|cred|secret|hack|crack|keygen|backdoor|payload|exploit|rootkit|netcat|shell'

files_audit() {
    local roots; read -rp '  Folders to scan [/home /root /srv /opt /tmp /var/www]: ' roots
    roots=${roots:-/home /root /srv /opt /tmp /var/www}
    local img=0; ask 'Include images (jpg/png/gif...)?' && img=1
    info 'Scanning...'
    local -a paths labels; local f name ext why
    while IFS= read -r -d '' f; do
        name=${f##*/}; ext=${name##*.}; ext=${ext,,}
        why=''
        if [[ $name == *.* && $ext =~ ^($MEDIA)$ ]]; then why=media
        elif ((img)) && [[ $name == *.* && $ext =~ ^($IMAGES)$ ]]; then why=image
        elif [[ ${name,,} =~ $SUSPECT_NAME ]]; then why=name
        elif [[ $name == *.* && $ext =~ ^($SUSPECT_EXT)$ ]]; then why=type
        fi
        [[ -n $why ]] && { paths+=("$f"); labels+=("[$(printf '%-5s' $why)] $f ($(du -h -- "$f" | cut -f1))"); }
    done < <(find $roots -xdev -type f \
        -not -path '*/.cache/*' -not -path '*/.mozilla/*' -not -path '*/.config/google-chrome/*' \
        -not -path '*/.config/chromium/*' -not -path '*/.local/share/icons/*' -not -path '*/.icons/*' \
        -not -path '*/.themes/*' -not -path '*/.local/lib/*' -print0 2> /dev/null)
    info 'Answer forensics questions BEFORE deleting anything they might ask about.'
    pick "${labels[@]}"
    local i; for i in "${PIDX[@]}"; do rm -f -- "${paths[i]}" && ok "Deleted ${paths[i]}"; done
}

# ==================================================================================
# 11. Hunt: processes, ports, cron, units, sudoers, permissions, SUID, hosts
# ==================================================================================
hunt() {
    local -a labels list; local i f n line

    head_ 'Suspicious processes (hacking tools, running from /tmp /home /dev/shm, deleted binaries)'
    local re='(^|/)(nc|ncat|netcat|socat|john|hydra|nmap|tcpdump|tshark|xmrig|minerd)( |$)|http\.server'
    local -a pids=(); local pid user args exe
    while read -r pid user args; do
        exe=$(readlink "/proc/$pid/exe" 2> /dev/null)
        if [[ $args =~ $re || $exe =~ ^/(tmp|var/tmp|dev/shm|home)/ || $exe == *'(deleted)' ]]; then
            pids+=("$pid"); labels+=("pid $pid  $user  ${exe:-?}  ::  ${args:0:90}")
        fi
    done < <(ps -eo pid=,user=,args=)
    pick "${labels[@]}" && for i in "${PIDX[@]}"; do kill -9 "${pids[i]}" 2> /dev/null && ok "Killed ${labels[i]}"; done

    head_ 'Listening ports (anything odd? check the process, then remove it)'
    ss -tulpn | sed 's/^/  /'

    head_ 'Cron jobs (selected lines get commented out)'
    local -a cfile=() cline=(); labels=()
    for f in /etc/crontab /etc/cron.d/* /var/spool/cron/crontabs/*; do
        [[ -f $f ]] || continue
        n=0
        while IFS= read -r line; do
            ((n++))
            [[ $line =~ ^[[:space:]]*(#|$) || $line =~ ^[[:space:]]*[A-Za-z_]+= ]] && continue
            [[ $line =~ run-parts\ --report\ /etc/cron\.|test\ -x\ /usr/sbin/anacron ]] && continue
            cfile+=("$f"); cline+=("$n"); labels+=("$f:$n  $line")
        done < "$f"
    done
    pick "${labels[@]}" && for i in "${PIDX[@]}"; do
        backup "${cfile[i]}"; sed -i "${cline[i]}s/^/#CP-REMOVED /" "${cfile[i]}" && ok "Disabled cron job ${labels[i]}"
    done

    head_ 'Cron / init.d scripts not installed by any package'
    local -a cand=(); for f in /etc/cron.{hourly,daily,weekly,monthly}/* /etc/init.d/*; do [[ -f $f ]] && cand+=("$f"); done
    mapfile -t list < <(unowned "${cand[@]}")
    labels=(); for f in "${list[@]}"; do labels+=("$f  ::  $(grep -vE '^[[:space:]]*(#|$)' "$f" | head -1 | cut -c1-80)"); done
    pick "${labels[@]}" && for i in "${PIDX[@]}"; do
        f=${list[i]}; [[ $f == /etc/init.d/* ]] && update-rc.d -f "${f##*/}" remove > /dev/null 2>&1
        backup "$f"; rm -f "$f" && ok "Removed unpackaged script $f (backup $f.cp-bak)"
    done

    head_ 'systemd services not installed by any package'
    cand=(); for f in /etc/systemd/system/*.service /lib/systemd/system/*.service; do [[ -f $f && ! -L $f ]] && cand+=("$f"); done
    mapfile -t list < <(unowned "${cand[@]}")
    labels=(); for f in "${list[@]}"; do labels+=("$f  ::  $(grep -m1 '^ExecStart' "$f" | cut -c1-90)"); done
    pick "${labels[@]}" && for i in "${PIDX[@]}"; do
        f=${list[i]}; systemctl disable --now "${f##*/}" > /dev/null 2>&1
        backup "$f"; rm -f "$f" && ok "Removed service ${f##*/}"
    done
    systemctl daemon-reload

    head_ 'sudoers (NOPASSWD gets stripped, other picked lines get commented out)'
    local -a sfile=() sline=(); labels=()
    for f in /etc/sudoers /etc/sudoers.d/*; do
        [[ -f $f ]] || continue
        n=0
        while IFS= read -r line; do
            ((n++))
            [[ $line =~ ^[[:space:]]*(#|$) || $line =~ ^[[:space:]]*@include ]] && continue
            [[ $line =~ ^[[:space:]]*Defaults && ! $line =~ \!authenticate ]] && continue
            [[ $line =~ ^[[:space:]]*(root|%sudo|%admin)[[:space:]]+ALL=\(ALL(:ALL)?\)[[:space:]]+ALL[[:space:]]*$ ]] && continue
            sfile+=("$f"); sline+=("$n"); labels+=("$f:$n  $line")
        done < "$f"
    done
    if pick "${labels[@]}"; then
        for i in "${PIDX[@]}"; do
            backup "${sfile[i]}"
            if [[ ${labels[i]} =~ NOPASSWD && ! ${labels[i]} =~ :[0-9]+\ +Defaults ]]; then
                sed -i "${sline[i]}s/NOPASSWD:[[:space:]]*//g" "${sfile[i]}"
            else
                sed -i "${sline[i]}s/^/#CP-REMOVED /" "${sfile[i]}"
            fi
        done
        if visudo -c > /dev/null 2>&1; then ok 'sudoers fixed (sudo now always asks for a password)'
        else restore "${sfile[@]}"; warn 'visudo rejected the change - restored the original sudoers files'; fi
    fi

    head_ 'Critical file permissions'
    local -a P=('/etc/passwd 644 root:root' '/etc/group 644 root:root' '/etc/shadow 640 root:shadow'
                '/etc/gshadow 640 root:shadow' '/etc/sudoers 440 root:root' '/etc/ssh/sshd_config 600 root:root'
                '/etc/crontab 600 root:root' '/boot/grub/grub.cfg 600 root:root')
    local -a fix=(); local p mode own
    for p in "${P[@]}"; do
        read -r f mode own <<< "$p"
        [[ -e $f ]] || continue
        [[ $(stat -c '%a %U:%G' "$f") == "$mode $own" ]] && continue
        warn "$f is $(stat -c '%a %U:%G' "$f") (should be $mode $own)"; fix+=("$p")
    done
    for f in /home/*; do [[ -d $f && $(stat -c '%a' "$f") =~ [1-7]$ ]] && { warn "$f is readable by everyone"; fix+=("$f 750 -"); }; done
    if ((${#fix[@]})) && ask 'Fix all of these permissions?'; then
        for p in "${fix[@]}"; do
            read -r f mode own <<< "$p"
            chmod "$mode" "$f"; [[ $own != - ]] && chown "$own" "$f"
            ok "Secured permissions on $f ($mode)"
        done
    fi
    ((${#fix[@]})) || good 'all good'

    head_ 'SUID/SGID files that are not from a package or are known escalation risks'
    mapfile -t cand < <(find / -xdev \( -perm -4000 -o -perm -2000 \) -type f 2> /dev/null)
    mapfile -t list < <(
        unowned "${cand[@]}"
        printf '%s\n' "${cand[@]}" | grep -E '/(find|vim?|vim\.[a-z]+|nano|bash|sh|dash|zsh|python[0-9.]*|perl|ruby|php[0-9.]*|awk|gawk|mawk|less|more|cp|mv|tar|zip|env|nmap|tee|nc|socat)$'
    )
    pick "${list[@]}" && for i in "${PIDX[@]}"; do chmod u-s,g-s "${list[i]}" && ok "Removed SUID/SGID from ${list[i]}"; done

    head_ 'World-writable files in system folders'
    mapfile -t list < <(find /etc /usr /bin /sbin /opt /var/www -xdev -type f -perm -0002 2> /dev/null)
    pick "${list[@]}" && for i in "${PIDX[@]}"; do chmod o-w "${list[i]}" && ok "Removed world-write on ${list[i]}"; done

    head_ 'Startup files with backdoor patterns (review)'
    grep -nE '/dev/tcp|(^|[ ;|])(nc|ncat|netcat|socat) |bash -i|(curl|wget) .*\| *(ba)?sh|alias (sudo|ls|cd|passwd|su)=' \
        /etc/rc.local /etc/profile /etc/bash.bashrc /etc/profile.d/* /root/.bashrc /root/.profile \
        /home/*/.bashrc /home/*/.profile /home/*/.bash_aliases 2> /dev/null | while IFS= read -r line; do warn "$line"; done
    [[ -f /etc/rc.local ]] && grep -vqE '^[[:space:]]*(#|$|exit 0)' /etc/rc.local && warn '/etc/rc.local has commands - review it'

    head_ '/etc/hosts'
    local h; h=$(grep -vE '^[[:space:]]*(#|$)|^[[:space:]]*(127\.0\.[01]\.1|::1|fe00::0|ff0[0-2]::[0-3])[[:space:]]' /etc/hosts)
    if [[ -z $h ]]; then good 'hosts file clean'
    else
        echo "$h" | while IFS= read -r line; do warn "hosts: $line"; done
        if ask 'Reset /etc/hosts to default?'; then
            backup /etc/hosts
            printf '127.0.0.1\tlocalhost\n127.0.1.1\t%s\n\n::1     ip6-localhost ip6-loopback\nfe00::0 ip6-localnet\nff00::0 ip6-mcastprefix\nff02::1 ip6-allnodes\nff02::2 ip6-allrouters\n' "$(hostname)" > /etc/hosts
            ok 'hosts file reset'
        fi
    fi
}

# ==================================================================================
# 12-14. Updates
# ==================================================================================
os_update() {
    head_ 'APT sources (look for unofficial repositories)'
    grep -rhE '^[[:space:]]*(deb|URIs:)' /etc/apt/sources.list /etc/apt/sources.list.d/ 2> /dev/null | sed 's/^/  /'
    grep -rhiE 'AllowUnauthenticated|AllowInsecureRepositories|trusted=yes' /etc/apt/ 2> /dev/null | while IFS= read -r l; do warn "Insecure apt setting: $l"; done
    ask 'Run a full system upgrade now (keeps your existing config files)?' || return
    apt_get update && apt_get -y -o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold full-upgrade &&
        ok 'Installed all updates (reboot for kernel/systemd)' || warn 'Upgrade failed - read the output above'
}

pkg_update() {
    info 'Refreshing package lists...'
    apt_get update -qq
    local -a lines; mapfile -t lines < <(apt list --upgradable 2> /dev/null | tail -n +2)
    info 'Do NOT update programs you are about to remove.'
    if pick "${lines[@]}"; then
        local -a sel=(); local i; for i in "${PIDX[@]}"; do sel+=("${lines[i]%%/*}"); done
        apt_get install -y --only-upgrade -o Dpkg::Options::=--force-confold "${sel[@]}" && ok "Updated: ${sel[*]}"
    fi
    local -a inst; read_list inst 'Packages the README requires that are missing (Enter = none)'
    ((${#inst[@]})) && apt_get install -y "${inst[@]}" && ok "Installed: ${inst[*]}"
}

auto_updates() {
    dpkg -s unattended-upgrades &> /dev/null || apt_get install -y unattended-upgrades > /dev/null
    backup /etc/apt/apt.conf.d/20auto-upgrades
    cat > /etc/apt/apt.conf.d/20auto-upgrades << 'EOF'
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Download-Upgradeable-Packages "1";
APT::Periodic::AutocleanInterval "7";
APT::Periodic::Unattended-Upgrade "1";
EOF
    # Other apt.conf.d files are read too - make sure none of them switch it back off.
    local f; for f in /etc/apt/apt.conf.d/*; do
        [[ $f == */20auto-upgrades ]] && continue
        grep -qE 'APT::Periodic::(Update-Package-Lists|Unattended-Upgrade)[[:space:]]+"0"' "$f" 2> /dev/null &&
            { backup "$f"; sed -i -E 's/(APT::Periodic::(Update-Package-Lists|Unattended-Upgrade)[[:space:]]+)"0"/\1"1"/' "$f"; ok "Fixed disabled auto-update in $f"; }
    done
    systemctl enable --now apt-daily.timer apt-daily-upgrade.timer unattended-upgrades > /dev/null 2>&1
    ok 'The system refreshes the list of updates automatically (daily) and installs security updates'
    command -v mintupdate-automation > /dev/null && mintupdate-automation upgrade enable > /dev/null 2>&1 && ok 'Mint Update Manager: apply updates automatically'
}

# ==================================================================================
# 15. Critical services
# ==================================================================================
critical_harden() {
    local f k
    if [[ -d /etc/apache2 ]] && ask 'Apache is installed - harden it (README needs a web server)?'; then
        f=/etc/apache2/conf-available/security.conf
        set_kv "$f" ServerTokens Prod; set_kv "$f" ServerSignature Off; set_kv "$f" TraceEnable Off
        a2enconf security > /dev/null 2>&1
        set_kv /etc/apache2/apache2.conf Timeout 45
        sed -i -E 's/^([[:space:]]*)Options[[:space:]]+Indexes[[:space:]]+FollowSymLinks[[:space:]]*$/\1Options -Indexes -FollowSymLinks -ExecCGI/' /etc/apache2/apache2.conf
        grep -qE 'APACHE_RUN_USER=root' /etc/apache2/envvars && warn 'Apache runs as root! Set APACHE_RUN_USER=www-data in /etc/apache2/envvars'
        if ask 'Install mod_security (web application firewall)?'; then
            apt_get install -y libapache2-mod-security2 > /dev/null && a2enmod security2 > /dev/null 2>&1
            [[ -f /etc/modsecurity/modsecurity.conf-recommended && ! -f /etc/modsecurity/modsecurity.conf ]] &&
                cp /etc/modsecurity/modsecurity.conf-recommended /etc/modsecurity/modsecurity.conf
            [[ -f /etc/modsecurity/modsecurity.conf ]] && set_kv /etc/modsecurity/modsecurity.conf SecRuleEngine On
        fi
        if apache2ctl configtest > /dev/null 2>&1 && systemctl restart apache2; then
            ok 'Apache: version hidden, TRACE off, no directory listing/symlinks/CGI, Timeout 45'
        else restore "$f" /etc/apache2/apache2.conf; systemctl restart apache2; warn 'Apache config test failed - restored originals'; fi
    fi

    local php; for php in /etc/php/*/apache2/php.ini /etc/php/*/fpm/php.ini; do
        [[ -f $php ]] || continue
        ask "Harden $php?" || continue
        for k in 'expose_php Off' 'allow_url_fopen Off' 'allow_url_include Off' 'display_errors Off' \
                 'upload_max_filesize 2M' 'max_execution_time 30' 'max_input_time 60' \
                 'disable_functions exec,shell_exec,passthru,system,popen,curl_exec,curl_multi_exec,parse_ini_file,show_source,proc_open,pcntl_exec'; do
            set_kv "$php" "${k%% *}" "${k#* }" ' = '
        done
        ok "PHP hardened: $php"
        systemctl restart apache2 2> /dev/null; systemctl restart "php*-fpm" 2> /dev/null
    done

    if [[ -d /etc/mysql ]] && ask 'MySQL/MariaDB is installed - harden it?'; then
        local d=/etc/mysql/mysql.conf.d; [[ -d /etc/mysql/mariadb.conf.d ]] && d=/etc/mysql/mariadb.conf.d
        mkdir -p "$d"
        printf '[mysqld]\nlocal-infile = 0\n' > "$d/zz-cp-hardening.cnf"
        if ! ask 'Does the README need REMOTE database access?'; then
            echo 'bind-address = 127.0.0.1' >> "$d/zz-cp-hardening.cnf"
            grep -rlE '^[[:space:]]*bind-address' /etc/mysql 2> /dev/null | while read -r f; do
                [[ $f == */zz-cp-hardening.cnf ]] || { backup "$f"; sed -i -E 's/^([[:space:]]*bind-address[[:space:]]*=).*/\1 127.0.0.1/' "$f"; }
            done
        fi
        local svc=mysql; systemctl cat mariadb &> /dev/null && svc=mariadb
        if systemctl restart "$svc"; then ok 'MySQL: LOCAL INFILE off, bound to localhost'
        else rm -f "$d/zz-cp-hardening.cnf"; systemctl restart "$svc"; warn 'MySQL failed to restart - removed the hardening file'; fi
        ask 'Run mysql_secure_installation now (interactive: answer y to everything)?' && mysql_secure_installation
    fi

    if [[ -f /etc/vsftpd.conf ]] && ask 'vsftpd is installed - harden it (README needs FTP)?'; then
        f=/etc/vsftpd.conf
        for k in anonymous_enable=NO local_enable=YES chroot_local_user=YES allow_writeable_chroot=YES \
                 anon_upload_enable=NO anon_mkdir_write_enable=NO xferlog_enable=YES ls_recurse_enable=NO hide_ids=YES; do
            set_kv "$f" "${k%%=*}" "${k#*=}" =
        done
        if ask 'Do FTP users need to upload files (write_enable)?'; then set_kv "$f" write_enable YES =; else set_kv "$f" write_enable NO =; fi
        if ask 'Require FTPS (TLS) using the system certificate?'; then
            for k in ssl_enable=YES force_local_logins_ssl=YES force_local_data_ssl=YES \
                     rsa_cert_file=/etc/ssl/certs/ssl-cert-snakeoil.pem rsa_private_key_file=/etc/ssl/private/ssl-cert-snakeoil.key; do
                set_kv "$f" "${k%%=*}" "${k#*=}" =
            done
        fi
        if systemctl restart vsftpd; then ok 'vsftpd: no anonymous login, users jailed to home, logging on'
        else restore "$f"; systemctl restart vsftpd; warn 'vsftpd failed to restart - restored original config'; fi
    fi

    if [[ -f /etc/samba/smb.conf ]] && ask 'Samba is installed - harden it (README needs file sharing)?'; then
        f=/etc/samba/smb.conf
        ini_set "$f" global 'server min protocol' SMB2
        ini_set "$f" global 'restrict anonymous' 2
        ini_set "$f" global 'map to guest' never
        ini_set "$f" global 'usershare allow guests' no
        ini_set "$f" global 'server signing' mandatory
        sed -i -E 's/^([[:space:]]*(guest ok|public)[[:space:]]*=[[:space:]]*)yes/\1no/I' "$f"
        if testparm -s "$f" > /dev/null 2>&1 && systemctl restart smbd; then ok 'Samba: SMB1 off, no guest/anonymous access, signing required'
        else restore "$f"; systemctl restart smbd; warn 'Samba config invalid - restored original'; fi
        info "Shares: $(testparm -s 2> /dev/null | grep -oE '^\[[^]]+\]' | tr '\n' ' ')  - remove any the README does not list"
    fi

    if [[ -f /etc/nginx/nginx.conf ]] && ask 'nginx is installed - harden it?'; then
        f=/etc/nginx/nginx.conf; backup "$f"
        sed -i -E 's/^([[:space:]]*)#?[[:space:]]*server_tokens[[:space:]]+(on|off);/\1server_tokens off;/' "$f"
        grep -q 'server_tokens off' "$f" || sed -i '/^[[:space:]]*http[[:space:]]*{/a \        server_tokens off;' "$f"
        if nginx -t > /dev/null 2>&1 && systemctl reload nginx; then ok 'nginx: version hidden'
        else restore "$f"; warn 'nginx config test failed - restored original'; fi
    fi
}

# ==================================================================================
# 16. Forensics toolkit
# ==================================================================================
forensics() {
    local c p r t f h d u s
    while :; do
        echo
        echo "  1 Find file by name      2 Search text in files     3 Hash file / find file by hash"
        echo "  4 Decode string          5 Recently modified files  6 File info (type, owner, strings)"
        echo "  7 User info + logins     8 Hidden files in homes    9 Which package owns a file"
        read -rp '  Forensics (Enter = back): ' c
        case $c in
            '') return ;;
            1) read -rp '  Name pattern (e.g. *.mp3 or *secret*): ' p; read -rp '  Root [/]: ' r
               find "${r:-/}" \( -path /proc -o -path /sys -o -path /run \) -prune -o -iname "$p" -print 2> /dev/null | sed 's/^/  /' ;;
            2) read -rp '  Text to find: ' t; read -rp '  Root [/home]: ' r
               grep -rIn -F -- "$t" "${r:-/home}" 2> /dev/null | head -200 | sed 's/^/  /' ;;
            3) read -rp '  File or folder: ' f
               if [[ -f $f ]]; then for h in md5 sha1 sha256 sha512; do printf '  %-7s %s\n' "$h" "$(${h}sum "$f" | cut -d' ' -f1)"; done
               else
                   read -rp '  Hash to look for: ' h; h=${h,,}
                   case ${#h} in 32) t=md5 ;; 40) t=sha1 ;; 128) t=sha512 ;; *) t=sha256 ;; esac
                   find "$f" -type f -exec "${t}sum" {} + 2> /dev/null | awk -v h="$h" '$1 == h { $1 = ""; print "  match:" $0 }'
               fi ;;
            4) read -rp '  Encoded string: ' s
               echo "  base64 : $(printf '%s' "$s" | base64 -d 2> /dev/null | tr -d '\0')"
               echo "  base32 : $(printf '%s' "$s" | base32 -d 2> /dev/null | tr -d '\0')"
               h=${s//[^0-9a-fA-F]/}; ((${#h} % 2 == 0 && ${#h} > 0)) && echo "  hex    : $(printf '%b' "$(sed 's/../\\x&/g' <<< "$h")")"
               if [[ $s =~ ^[01\ ]+$ ]]; then
                   local out='' b; for b in $s; do out+=$(printf "\\$(printf '%03o' "$((2#$b))")"); done; echo "  binary : $out"
               fi
               echo "  rot13  : $(tr 'A-Za-z' 'N-ZA-Mn-za-m' <<< "$s")"
               echo "  url    : $(printf '%b' "${s//%/\\x}")"
               echo "  reverse: $(rev <<< "$s")" ;;
            5) read -rp '  Days back [3]: ' d; read -rp '  Root [/home]: ' r
               find "${r:-/home}" -xdev -type f -mtime -"${d:-3}" -not -path '*/.cache/*' -printf '%TY-%Tm-%Td %TH:%TM  %p\n' 2> /dev/null | sort -r | head -100 | sed 's/^/  /' ;;
            6) read -rp '  File: ' f
               file "$f" | sed 's/^/  /'; stat -c '  %A %U:%G  %s bytes  modified %y' "$f"
               ask 'Show readable strings?' && grep -aoE '[[:print:]]{6,}' "$f" | head -60 | sed 's/^/    /' ;;
            7) read -rp '  Username: ' u
               id "$u"; chage -l "$u" | sed 's/^/  /'; last -n 10 "$u" 2> /dev/null | sed 's/^/  /'
               lastlog -u "$u" 2> /dev/null | sed 's/^/  /'; grep -rn "$u" /etc/sudoers /etc/sudoers.d/ 2> /dev/null | sed 's/^/  sudoers: /' ;;
            8) find /home /root -maxdepth 3 -name '.*' -not -name '.bash*' -not -name '.profile' -not -name '.cache' \
                    -not -name '.config' -not -name '.local' -not -name '.mozilla' -not -name '.Xauthority' -not -name '.xsession-errors*' \
                    -not -name '.ICEauthority' -not -name '.sudo_as_admin_successful' -not -name '.gnupg' -not -name '.pki' -not -name '.dbus' 2> /dev/null | sed 's/^/  /' ;;
            9) read -rp '  Full path: ' f; dpkg -S "$f" 2> /dev/null || echo '  not from any package' ;;
        esac
    done
}

quick_run() { password_policy; sysctl_harden; protection; login_harden; }

# ==================================================================================
# Menu
# ==================================================================================
MENU=(
    '1|Users: remove/create/demote per README, passwords, hidden users|users_audit'
    '2|Groups: edit members|groups_edit'
    '3|Password policy, aging, PAM (pwquality, nullok, lockout)|password_policy'
    '4|Kernel/network hardening (sysctl, Ctrl+Alt+Del, core dumps)|sysctl_harden'
    '5|Firewall (UFW), AppArmor, auditd, ClamAV|protection'
    '6|Login screen and root (guest, autologin, lock root)|login_harden'
    '7|SSH (secure if required, otherwise remove)|ssh_harden'
    '8|Services (FTP, web, Samba, DNS, telnet...)|services_audit'
    '9|Prohibited software, games, stray programs|software_audit'
    '10|Prohibited / media files|files_audit'
    '11|Hunt: processes, ports, cron, units, sudoers, perms, SUID, hosts|hunt'
    '12|System upgrade (apt full-upgrade)|os_update'
    '13|Pick packages to update / install README software|pkg_update'
    '14|Automatic updates|auto_updates'
    '15|Harden critical services (Apache, PHP, MySQL, vsftpd, Samba, nginx)|critical_harden'
    '16|Forensics toolkit|forensics'
    'A|Quick run: 3, 4, 5, 6|quick_run'
)

while :; do
    clear
    echo "  ${C}$(printf '=%.0s' {1..66})${N}"
    echo "   ${W}CYBERPATRIOT LINUX TOOLKIT${N}"
    echo "   ${D}$OSNAME  |  $(hostname)  |  you: $ME${N}"
    echo "   ${D}Log: $LOG${N}"
    echo "  ${C}$(printf '=%.0s' {1..66})${N}"
    for m in "${MENU[@]}"; do IFS='|' read -r k label _ <<< "$m"; printf '   %3s  %s\n' "$k" "$label"; done
    echo '     Q  Quit'
    read -rp $'\n  Select: ' choice
    choice=${choice^^}
    [[ $choice == Q ]] && break
    for m in "${MENU[@]}"; do
        IFS='|' read -r k label fn <<< "$m"
        if [[ $k == "$choice" ]]; then
            echo; echo "  ${M}==== $label ====${N}"
            $fn
            read -rp $'\n  Done. Press Enter for menu ' _
        fi
    done
done
