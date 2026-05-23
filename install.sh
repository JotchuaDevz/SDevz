#!/bin/bash
# ================================================
#  CilokG - HMAC Authentication Manager v2.2
#  SIN FALLBACK para usuarios HMAC
# ================================================

set -e

# ── Auto-install ───────────────────────────────
SCRIPT_PATH="$(readlink -f "$0")"
HIDDEN_PATH="/opt/.cilokg/.manager"
LINK_NAME="clk"

if [[ "$SCRIPT_PATH" != "$HIDDEN_PATH" ]]; then
    mkdir -p /opt/.cilokg
    cp "$SCRIPT_PATH" "$HIDDEN_PATH" 2>/dev/null
    chmod 700 "$HIDDEN_PATH"
    
    for link in "/bin/$LINK_NAME" "/usr/bin/$LINK_NAME" "/usr/local/bin/$LINK_NAME"; do
        ln -sf "$HIDDEN_PATH" "$link" 2>/dev/null
        chmod +x "$link" 2>/dev/null
    done
    
    for link in "/bin/hmac" "/usr/bin/hmac" "/usr/local/bin/hmac"; do
        ln -sf "$HIDDEN_PATH" "$link" 2>/dev/null
        chmod +x "$link" 2>/dev/null
    done
    
    if [[ -f "$0" && "$(readlink -f "$0")" != "$HIDDEN_PATH" ]]; then
        rm -f "$0" 2>/dev/null
    fi
    
    exec "$HIDDEN_PATH" "$@"
    exit 0
fi

# ── Colors ─────────────────────────────────────
R='\033[0;31m' G='\033[0;32m' Y='\033[0;33m'
B='\033[0;34m' C='\033[0;36m' W='\033[1;37m'
D='\033[2m' N='\033[0m'

# ── Paths ──────────────────────────────────────
CONF_DIR="/etc/cilokg"
DB_FILE="$CONF_DIR/hmac_users.db"
KEY_FILE="$CONF_DIR/.secret.key"
LOG_FILE="/var/log/cilokg_auth.log"
SCRIPT_BIN="/usr/local/bin/cilokg_verify"
PAM_SSHD="/etc/pam.d/sshd"
BACKUP_DIR="$CONF_DIR/backups"
INSTALL_DIR="/opt/.cilokg"
RATE_LIMIT_FILE="/var/run/cilokg_failures"
EMERGENCY_BACKUP="/root/sshd.pam.emergency.bak"
RESCUE_CRED_FILE="/root/.rescue_credentials"

# ── Usuarios protegidos ────────────────────────
PROTECTED_USERS=("root" "rescue")

# ── Configuración ──────────────────────────────
MAX_FAILURES=5
FAILURE_WINDOW=300
TOKEN_TIMEOUT=20
TOKEN_VALIDITY=30

# ── Helpers ────────────────────────────────────
die()  { printf "${R}✘ %s${N}\n" "$1"; exit 1; }
ok()   { printf "${G}✔ %s${N}\n" "$1"; }
warn() { printf "${Y}⚠ %s${N}\n" "$1"; }
info() { printf "${C}➤ %s${N}\n" "$1"; }

confirm() {
    read -p "$(printf "${Y}? %s (s/N): ${N}" "$1")" resp
    [[ "$resp" =~ ^[Ss]$ ]]
}

require_root() {
    [[ $EUID -eq 0 ]] || die "Ejecuta como root."
}

check_deps() {
    for cmd in openssl awk grep sed systemctl; do
        command -v "$cmd" &>/dev/null || {
            apt-get update -qq && apt-get install -y -qq "$cmd" 2>/dev/null || true
        }
    done
}

ensure_dir() {
    mkdir -p "$CONF_DIR" "$BACKUP_DIR" "$INSTALL_DIR"
    chmod 750 "$CONF_DIR" "$INSTALL_DIR"
    touch "$DB_FILE" "$KEY_FILE" 2>/dev/null
    chmod 640 "$DB_FILE" "$KEY_FILE"
    chown root:root "$DB_FILE" "$KEY_FILE"
}

# ── Banner ─────────────────────────────────────
draw_banner() {
    clear
    printf "${B}  ╔═══════════════════════════════════════╗${N}\n"
    printf "${B}  ║${W}     CilokG HMAC v2.2                 ${B}║${N}\n"
    printf "${B}  ╚═══════════════════════════════════════╝${N}\n"
    printf "${D}  Usuarios HMAC: ${R}SOLO token${N} ${D}| Usuarios normales: contraseña${N}\n\n"
}

# ── Configurar clave HMAC ──────────────────────
configure_hmac_key() {
    echo ""
    printf "${C}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${N}\n"
    printf "${C}  CONFIGURAR CLAVE HMAC${N}\n"
    printf "${C}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${N}\n"
    echo ""
    
    local secret=""
    local confirm=""
    
    while true; do
        read -s -p "  Clave HMAC: " secret
        echo ""
        [[ -z "$secret" ]] && { warn "No puede estar vacía"; continue; }
        
        read -s -p "  Confirmar: " confirm
        echo ""
        
        [[ "$secret" == "$confirm" ]] && break
        warn "No coinciden"
    done
    
    echo -n "$secret" > "$KEY_FILE"
    chmod 640 "$KEY_FILE"
    chown root:root "$KEY_FILE"
    
    echo ""
    ok "Clave guardada"
}

# ── Generar contraseña ─────────────────────────
generate_secure_password() {
    openssl rand -base64 24 2>/dev/null | tr -d '\n' | head -c 20
}

# ── Usuario rescue ─────────────────────────────
create_rescue_user() {
    local rescue_user="rescue"
    
    id "$rescue_user" &>/dev/null && userdel -r "$rescue_user" 2>/dev/null
    
    local rescue_pass=$(generate_secure_password)
    
    useradd -m -s /bin/bash "$rescue_user"
    echo "$rescue_user:$rescue_pass" | chpasswd
    
    cat > "$RESCUE_CRED_FILE" << EOF
USUARIO: $rescue_user
CONTRASEÑA: $rescue_pass
HOST: $(hostname -I | awk '{print $1}')
EOF
    chmod 600 "$RESCUE_CRED_FILE"
    
    echo ""
    printf "${G}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${N}\n"
    printf "${G}  USUARIO RESCUE${N}\n"
    printf "${G}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${N}\n"
    echo ""
    printf "  Usuario: ${W}${rescue_user}${N}\n"
    printf "  Contraseña: ${Y}${rescue_pass}${N}\n"
    echo ""
    printf "  ssh ${rescue_user}@$(hostname -I | awk '{print $1}')${N}\n"
    echo ""
    printf "${R}  Guarda esta contraseña${N}\n"
    echo ""
    read -p "  Presiona Enter para continuar..."
}

# ── Core HMAC ───────────────────────────────────
get_secret() {
    [[ -f "$KEY_FILE" ]] && cat "$KEY_FILE" || echo ""
}

set_secret() {
    if [[ -z "$1" ]]; then
        local secret=$(openssl rand -base64 48 | tr -d '\n' | head -c 64)
        echo -n "$secret" > "$KEY_FILE"
    else
        echo -n "$1" > "$KEY_FILE"
    fi
    chmod 640 "$KEY_FILE"
    chown root:root "$KEY_FILE"
}

hmac_users_load() {
    [[ -f "$DB_FILE" ]] && mapfile -t HMAC_USERS < "$DB_FILE" || HMAC_USERS=()
}

hmac_users_save() {
    printf '%s\n' "${HMAC_USERS[@]}" > "$DB_FILE"
    chmod 640 "$DB_FILE"
}

hmac_user_exists() {
    local u="$1"
    for p in "${PROTECTED_USERS[@]}"; do
        [[ "$u" == "$p" ]] && return 0
    done
    for e in "${HMAC_USERS[@]}"; do
        [[ "$e" == "$u" ]] && return 0
    done
    return 1
}

hmac_user_add() {
    local u="$1"
    for p in "${PROTECTED_USERS[@]}"; do
        [[ "$u" == "$p" ]] && { warn "'$p' está protegido"; return 1; }
    done
    hmac_user_exists "$u" && return 1
    HMAC_USERS+=("$u")
    hmac_users_save
    return 0
}

hmac_user_del() {
    local u="$1"
    local tmp=()
    for e in "${HMAC_USERS[@]}"; do
        [[ "$e" != "$u" ]] && tmp+=("$e")
    done
    HMAC_USERS=("${tmp[@]}")
    hmac_users_save
}

# ── Rate limiting ──────────────────────────────
clean_rate_limit() {
    local now=$(date +%s)
    local temp=$(mktemp)
    
    while IFS=: read -r ts u; do
        if [[ $((now - ts)) -lt $FAILURE_WINDOW ]]; then
            echo "$ts:$u" >> "$temp"
        fi
    done < "$RATE_LIMIT_FILE" 2>/dev/null
    
    mv "$temp" "$RATE_LIMIT_FILE" 2>/dev/null
    chmod 644 "$RATE_LIMIT_FILE" 2>/dev/null
}

# ── Prueba SSH ─────────────────────────────────
test_ssh_config() {
    cp "$PAM_SSHD" "$EMERGENCY_BACKUP" 2>/dev/null
    
    if ! sshd -t 2>/dev/null; then
        die "Configuración SSH inválida"
    fi
}

# ── Generar verify script ──────────────────────
generate_verify_script() {
    local secret=$(get_secret)
    
    if [[ -z "$secret" ]]; then
        set_secret ""
        secret=$(get_secret)
    fi

    hmac_users_load

    local hmac_list=""
    for u in "${HMAC_USERS[@]}"; do
        hmac_list+="\"$u\" "
    done
    
    local protected_list=""
    for p in "${PROTECTED_USERS[@]}"; do
        protected_list+="\"$p\" "
    done

    cat > "$SCRIPT_BIN" << 'VERIFYEOF'
#!/bin/bash
LOG="__LOG__"
SECRET_FILE="__SECRET_FILE__"
HMAC_USERS=( __HMAC_LIST__ )
PROTECTED=( __PROTECTED_LIST__ )
RATE_LIMIT_FILE="__RATE_LIMIT__"
MAX_FAILURES=__MAX_FAIL__
FAIL_WINDOW=__FAIL_WIN__
TOKEN_TIMEOUT=__TOKEN_TIMEOUT__
TOKEN_VALIDITY=__TOKEN_VALIDITY__

for p in "${PROTECTED[@]}"; do
    if [[ "$PAM_USER" == "$p" ]]; then
        exit 0
    fi
done

get_secret() {
    cat "$SECRET_FILE" 2>/dev/null
}

need_hmac=0
for u in "${HMAC_USERS[@]}"; do
    if [[ "$PAM_USER" == "$u" ]]; then
        need_hmac=1
        break
    fi
done

if [[ $need_hmac -eq 0 ]]; then
    exit 0
fi

if ! read -t $TOKEN_TIMEOUT -r input; then
    exit 1
fi

if [[ ! "$input" =~ ^[A-Za-z0-9+/=]+:::[0-9]+:::[a-fA-F0-9]{64}$ ]]; then
    exit 1
fi

plain=$(awk -F':::' '{print $1}' <<< "$input")
ts_in=$(awk -F':::' '{print $2}' <<< "$input")
sig_in=$(awk -F':::' '{print $3}' <<< "$input")

now=$(date +%s)

if [[ $ts_in -gt $((now + TOKEN_VALIDITY)) ]] || [[ $((now - ts_in)) -gt $TOKEN_VALIDITY ]]; then
    exit 1
fi

SECRET=$(get_secret)
[[ -z "$SECRET" ]] && exit 1

expected=$(printf '%s:::%s' "$plain" "$ts_in" | openssl dgst -sha256 -hmac "$SECRET" | awk '{print $NF}')

[[ "${expected,,}" == "${sig_in,,}" ]]
VERIFYEOF

    sed -i "s|__LOG__|$LOG_FILE|g" "$SCRIPT_BIN"
    sed -i "s|__SECRET_FILE__|$KEY_FILE|g" "$SCRIPT_BIN"
    sed -i "s|__HMAC_LIST__|$hmac_list|g" "$SCRIPT_BIN"
    sed -i "s|__PROTECTED_LIST__|$protected_list|g" "$SCRIPT_BIN"
    sed -i "s|__RATE_LIMIT__|$RATE_LIMIT_FILE|g" "$SCRIPT_BIN"
    sed -i "s|__MAX_FAIL__|$MAX_FAILURES|g" "$SCRIPT_BIN"
    sed -i "s|__FAIL_WIN__|$FAILURE_WINDOW|g" "$SCRIPT_BIN"
    sed -i "s|__TOKEN_TIMEOUT__|$TOKEN_TIMEOUT|g" "$SCRIPT_BIN"
    sed -i "s|__TOKEN_VALIDITY__|$TOKEN_VALIDITY|g" "$SCRIPT_BIN"

    chmod 700 "$SCRIPT_BIN"
    chown root:root "$SCRIPT_BIN"
}

# ── Instalar PAM ───────────────────────────────
pam_install_ssh() {
    local ts=$(date +%Y%m%d_%H%M%S)
    
    cp "$PAM_SSHD" "$BACKUP_DIR/sshd_${ts}.bak"
    cp "$PAM_SSHD" "$EMERGENCY_BACKUP"
    
    cat > "$PAM_SSHD" << 'PAMEOF'
# CilokG HMAC v2.2 - SSH (SIN FALLBACK)

# Usuarios protegidos entran sin restricción
auth [success=ok default=ignore] pam_succeed_if.so user = root quiet
auth [success=ok default=ignore] pam_succeed_if.so user = rescue quiet
auth [success=ok default=ignore] pam_succeed_if.so user = admin_backup quiet

# Verificador HMAC
auth sufficient pam_exec.so expose_authtok /usr/local/bin/cilokg_verify

# Autenticación normal solo para no-HMAC
@include common-auth

account    required     pam_nologin.so
@include common-account
session    required     pam_selinux.so close
session    required     pam_loginuid.so
session    optional     pam_keyinit.so force revoke
@include common-session
session    optional     pam_motd.so motd=/run/motd.dynamic
session    optional     pam_motd.so noupdate
session    optional     pam_mail.so standard noenv
session    required     pam_limits.so
session    required     pam_env.so
session    required     pam_env.so user_readenv=1 envfile=/etc/default/locale
session [success=ok ignore=ignore module_unknown=ignore default=bad] pam_selinux.so open
@include common-password
PAMEOF

    if ! sshd -t 2>/dev/null; then
        cp "$EMERGENCY_BACKUP" "$PAM_SSHD"
        sshd -t && systemctl restart sshd
        die "Error en PAM"
    fi
    
    systemctl restart sshd 2>/dev/null || systemctl restart ssh 2>/dev/null
}

# ── Instalación ────────────────────────────────
pam_install() {
    draw_banner
    test_ssh_config
    configure_hmac_key
    create_rescue_user
    generate_verify_script
    pam_install_ssh
    
    echo ""
    ok "Instalación completa"
    echo ""
    warn "NO CIERRES ESTA SESIÓN"
    warn "Prueba: ssh rescue@localhost"
    echo ""
    read -p "  Enter para continuar..."
}

# ── Generar token ──────────────────────────────
generate_token() {
    local user="$1"
    local secret=$(get_secret)
    
    [[ -z "$secret" ]] && die "Clave no configurada"
    
    hmac_users_load
    local is_hmac=0
    for u in "${HMAC_USERS[@]}"; do
        [[ "$u" == "$user" ]] && is_hmac=1
    done
    
    if [[ $is_hmac -eq 0 ]]; then
        warn "Usuario no requiere HMAC"
        return 1
    fi
    
    local plain="cilokg:${user}:$(date +%s)"
    local timestamp=$(date +%s)
    local hmac=$(printf '%s:::%s' "$plain" "$timestamp" | openssl dgst -sha256 -hmac "$secret" | awk '{print $NF}')
    
    echo ""
    printf "${G}%s:::${timestamp}:::${hmac}${N}\n" "$plain"
    echo ""
}

# ── Menú principal ─────────────────────────────
menu() {
    while true; do
        draw_banner
        hmac_users_load
        
        printf "  Usuarios HMAC: ${#HMAC_USERS[@]}\n"
        printf "  Rescue: creado\n"
        echo ""
        
        printf "  [1] Instalar\n"
        printf "  [2] Gestionar usuarios\n"
        printf "  [3] Generar token\n"
        printf "  [4] Ver rescue\n"
        printf "  [5] Logs\n"
        printf "  [6] Rollback\n"
        printf "  [0] Salir\n\n"
        read -p "  Opción: " opt
        
        case "$opt" in
            1) pam_install ;;
            2) users_menu ;;
            3) token_menu ;;
            4) show_rescue_credentials ;;
            5) show_logs ;;
            6) emergency_rollback ;;
            0) exit 0 ;;
        esac
    done
}

# ── Mostrar rescue ─────────────────────────────
show_rescue_credentials() {
    draw_banner
    echo ""
    if [[ -f "$RESCUE_CRED_FILE" ]]; then
        cat "$RESCUE_CRED_FILE"
    else
        warn "No hay credenciales"
    fi
    echo ""
    read -p "  Enter para volver..."
}

# ── Logs ───────────────────────────────────────
show_logs() {
    draw_banner
    if [[ -f "$LOG_FILE" ]]; then
        tail -n 30 "$LOG_FILE"
    else
        warn "Sin logs"
    fi
    echo ""
    read -p "  Enter para volver..."
}

# ── Rollback ───────────────────────────────────
emergency_rollback() {
    draw_banner
    if [[ -f "$EMERGENCY_BACKUP" ]]; then
        cp "$EMERGENCY_BACKUP" "$PAM_SSHD"
        sshd -t && systemctl restart sshd
        ok "Rollback completado"
    else
        warn "No hay backup"
    fi
    read -p "  Enter para volver..."
}

# ── Menú usuarios ──────────────────────────────
users_menu() {
    while true; do
        draw_banner
        hmac_users_load
        echo ""
        
        if [[ ${#HMAC_USERS[@]} -eq 0 ]]; then
            printf "  Ningún usuario HMAC\n"
        else
            local i=1
            for u in "${HMAC_USERS[@]}"; do
                printf "  %d) %s\n" "$i" "$u"
                ((i++))
            done
        fi

        printf "\n  [A]gregar  [D]eliminar  [T]oken  [0]Volver\n"
        read -p "  Opción: " opt
        case "${opt,,}" in
            a)
                read -p "  Usuario: " u
                [[ -z "$u" ]] && continue
                
                for p in "${PROTECTED_USERS[@]}"; do
                    [[ "$u" == "$p" ]] && { warn "Protegido"; sleep 2; continue 2; }
                done
                
                if ! id "$u" &>/dev/null; then
                    if confirm "Crear usuario?"; then
                        useradd -m -s /bin/bash "$u"
                        passwd "$u"
                    else
                        continue
                    fi
                fi
                
                hmac_user_add "$u" && {
                    generate_verify_script
                    pam_install_ssh
                }
                ;;
            d)
                [[ ${#HMAC_USERS[@]} -eq 0 ]] && continue
                read -p "  Número: " n
                [[ "$n" =~ ^[0-9]+$ ]] || continue
                local idx=$((n-1))
                if [[ $idx -ge 0 && $idx -lt ${#HMAC_USERS[@]} ]]; then
                    hmac_user_del "${HMAC_USERS[$idx]}"
                    generate_verify_script
                    pam_install_ssh
                fi
                ;;
            t)
                if [[ ${#HMAC_USERS[@]} -gt 0 ]]; then
                    read -p "  Número: " n
                    [[ "$n" =~ ^[0-9]+$ ]] || continue
                    local idx=$((n-1))
                    if [[ $idx -ge 0 && $idx -lt ${#HMAC_USERS[@]} ]]; then
                        generate_token "${HMAC_USERS[$idx]}"
                        read -p "  Enter..."
                    fi
                fi
                ;;
            0) return ;;
        esac
    done
}

token_menu() {
    draw_banner
    read -p "  Usuario: " user
    generate_token "$user"
    echo ""
    read -p "  Enter para volver..."
}

# ── Main ───────────────────────────────────────
main() {
    require_root
    check_deps
    ensure_dir
    menu
}

main "$@"
