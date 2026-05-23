#!/bin/bash
# ================================================
#  CilokG - HMAC Authentication Manager v2.0
#  PowerBy: BlackHanzoX
#  VPN totalmente compatible
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
PAM_VPN="/etc/pam.d/openvpn"  # Ajusta según tu VPN
BACKUP_DIR="$CONF_DIR/backups"
INSTALL_DIR="/opt/.cilokg"
RATE_LIMIT_FILE="/var/run/cilokg_failures"

# ── Usuarios protegidos (acceso libre) ─────────
PROTECTED_USERS=("root")

# ── Rate limiting ──────────────────────────────
MAX_FAILURES=3
FAILURE_WINDOW=300

# ── Helpers ────────────────────────────────────
die()  { printf "${R}✘ %s${N}\n" "$1"; exit 1; }
ok()   { printf "${G}✔ %s${N}\n" "$1"; }
warn() { printf "${Y}⚠ %s${N}\n" "$1"; }
info() { printf "${C}➤ %s${N}\n" "$1"; }

require_root() {
    [[ $EUID -eq 0 ]] || die "Ejecuta como root."
}

check_deps() {
    for cmd in openssl awk grep sed systemctl figlet; do
        command -v "$cmd" &>/dev/null || {
            warn "Instalando $cmd..."
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
    if command -v figlet &>/dev/null; then
        figlet -f slant "CilokG" 2>/dev/null || figlet "CilokG"
    else
        printf "${B}  ___ _ _ _      _  ___\n"
        printf " / __(_) | ___| |/ / __|\n"
        printf "| (__| | |/ _ \ ' / (_ |\n"
        printf " \___|_|_|\___/_|\_\___|${N}\n"
    fi
    printf "${D}  HMAC Auth Manager v2.0 - SIN FALLBACK${N}\n"
    printf "  ${D}Usuarios HMAC: ${R}SOLO token${N} ${D}| Usuarios normales: sin cambio${N}\n"
    printf "  ${D}VPN: ${G}compatible${N}\n\n"
}

# ── Y/N Prompt ─────────────────────────────────
confirm() {
    local msg="$1"
    local def="${2:-N}"
    local prompt
    [[ "$def" == "Y" ]] && prompt="[Y/n]" || prompt="[y/N]"
    
    while true; do
        printf "  ${W}%s %s: ${N}" "$msg" "$prompt"
        read -r resp
        resp=${resp:-$def}
        case "${resp,,}" in
            y|yes) return 0 ;;
            n|no)  return 1 ;;
            *) warn "Responde Y o N." ;;
        esac
    done
}

# ── Core ───────────────────────────────────────
get_secret() {
    [[ -f "$KEY_FILE" ]] && cat "$KEY_FILE" || echo ""
}

set_secret() {
    if [[ -z "$1" ]]; then
        local secret=$(openssl rand -base64 32 | tr -d '\n')
        echo -n "$secret" > "$KEY_FILE"
    else
        echo -n "$1" > "$KEY_FILE"
    fi
    chmod 640 "$KEY_FILE"
    chown root:root "$KEY_FILE"
    ok "Clave secreta generada/actualizada"
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
        [[ "$u" == "$p" ]] && { warn "'$p' está protegido."; return 1; }
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
record_failure() {
    local user="$1"
    local now=$(date +%s)
    echo "$now:$user" >> "$RATE_LIMIT_FILE"
    # Limpiar entradas viejas
    local temp=$(mktemp)
    while IFS=: read -r ts u; do
        if [[ $((now - ts)) -lt $FAILURE_WINDOW ]]; then
            echo "$ts:$u" >> "$temp"
        fi
    done < "$RATE_LIMIT_FILE"
    mv "$temp" "$RATE_LIMIT_FILE"
    chmod 644 "$RATE_LIMIT_FILE"
}

# ── Generar verify script (SIN FALLBACK) ───────
generate_verify_script() {
    local secret
    secret=$(get_secret)
    
    if [[ -z "$secret" ]]; then
        warn "Generando clave secreta de emergencia..."
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
# CilokG HMAC Verifier v2.0 - SIN FALLBACK
# Los usuarios HMAC SOLO entran con token válido

LOG="__LOG__"
SECRET_FILE="__SECRET_FILE__"
HMAC_USERS=( __HMAC_LIST__ )
PROTECTED=( __PROTECTED_LIST__ )
RATE_LIMIT_FILE="__RATE_LIMIT__"
MAX_FAILURES=__MAX_FAIL__
FAIL_WINDOW=__FAIL_WIN__

# ==============================================
# ROOT siempre entra (PROTECCIÓN)
# ==============================================
if [[ "$PAM_USER" == "root" ]]; then
    exit 0
fi

# Leer secret
get_secret() {
    if [[ -f "$SECRET_FILE" ]]; then
        cat "$SECRET_FILE" 2>/dev/null
    else
        echo ""
    fi
}

ts() { date '+%Y-%m-%d %H:%M:%S'; }

# Rate limiting
record_failure() {
    local user="$1"
    local now=$(date +%s)
    echo "$now:$user" >> "$RATE_LIMIT_FILE"
}

check_failures() {
    local user="$1"
    local now=$(date +%s)
    local count=0
    if [[ -f "$RATE_LIMIT_FILE" ]]; then
        while IFS=: read -r ts u; do
            if [[ $((now - ts)) -lt $FAIL_WINDOW ]] && [[ "$u" == "$user" ]]; then
                ((count++))
            fi
        done < "$RATE_LIMIT_FILE"
    fi
    echo $count
}

# 1. Usuarios protegidos (root ya se fue, esto es para otros como admin)
for p in "${PROTECTED[@]}"; do
    if [[ "$PAM_USER" == "$p" ]]; then
        echo "[$(ts)] FREE $PAM_USER (protegido)" >> "$LOG"
        exit 0
    fi
done

# 2. Rate limiting
failures=$(check_failures "$PAM_USER")
if [[ $failures -ge $MAX_FAILURES ]]; then
    echo "[$(ts)] RATE_LIMIT $PAM_USER - $failures fallos" >> "$LOG"
    sleep 10
    exit 1
fi

# 3. Verificar si el usuario REQUIERE HMAC
need_hmac=0
for u in "${HMAC_USERS[@]}"; do
    if [[ "$PAM_USER" == "$u" ]]; then
        need_hmac=1
        break
    fi
done

# 4. Si NO requiere HMAC → acceso libre
if [[ $need_hmac -eq 0 ]]; then
    echo "[$(ts)] FREE $PAM_USER (sin HMAC)" >> "$LOG"
    exit 0
fi

# ==============================================
# USUARIO HMAC - OBLIGATORIO TOKEN
# NO hay fallback a contraseña
# ==============================================
echo "[$(ts)] CHALLENGE $PAM_USER (HMAC requerido)" >> "$LOG"

# Timeout de 15 segundos para pegar token
if ! read -t 15 -r input; then
    echo "[$(ts)] REJECT $PAM_USER - timeout sin token" >> "$LOG"
    record_failure "$PAM_USER"
    exit 1
fi

# Validar formato: base64:::timestamp:::hash
if [[ ! "$input" =~ ^[A-Za-z0-9+/=]+:::[0-9]+:::[a-fA-F0-9]{64}$ ]]; then
    echo "[$(ts)] REJECT $PAM_USER - formato inválido" >> "$LOG"
    record_failure "$PAM_USER"
    exit 1
fi

plain=$(awk -F':::' '{print $1}' <<< "$input")
ts_in=$(awk -F':::' '{print $2}' <<< "$input")
sig_in=$(awk -F':::' '{print $3}' <<< "$input")

now=$(date +%s)

# Timestamp válido: ±30 segundos (evita replay)
if [[ $ts_in -gt $((now + 30)) ]] || [[ $((now - ts_in)) -gt 30 ]]; then
    echo "[$(ts)] REJECT $PAM_USER - timestamp inválido (now=$now, ts=$ts_in)" >> "$LOG"
    record_failure "$PAM_USER"
    exit 1
fi

# Verificar HMAC
SECRET=$(get_secret)
if [[ -z "$SECRET" ]]; then
    echo "[$(ts)] ERROR $PAM_USER - secret no disponible" >> "$LOG"
    exit 1
fi

expected=$(printf '%s:::%s' "$plain" "$ts_in" | openssl dgst -sha256 -hmac "$SECRET" | awk '{print $NF}')

if [[ "${expected,,}" == "${sig_in,,}" ]]; then
    echo "[$(ts)] ACCEPT $PAM_USER - HMAC válido" >> "$LOG"
    # Limpiar fallos previos
    sed -i "/:$PAM_USER$/d" "$RATE_LIMIT_FILE" 2>/dev/null
    exit 0
else
    echo "[$(ts)] REJECT $PAM_USER - HMAC inválido (esperado: ${expected:0:16}...)" >> "$LOG"
    record_failure "$PAM_USER"
    exit 1
fi
VERIFYEOF

    # Reemplazar variables
    sed -i "s|__LOG__|$LOG_FILE|g" "$SCRIPT_BIN"
    sed -i "s|__SECRET_FILE__|$KEY_FILE|g" "$SCRIPT_BIN"
    sed -i "s|__HMAC_LIST__|$hmac_list|g" "$SCRIPT_BIN"
    sed -i "s|__PROTECTED_LIST__|$protected_list|g" "$SCRIPT_BIN"
    sed -i "s|__RATE_LIMIT__|$RATE_LIMIT_FILE|g" "$SCRIPT_BIN"
    sed -i "s|__MAX_FAIL__|$MAX_FAILURES|g" "$SCRIPT_BIN"
    sed -i "s|__FAIL_WIN__|$FAILURE_WINDOW|g" "$SCRIPT_BIN"

    chmod 700 "$SCRIPT_BIN"
    chown root:root "$SCRIPT_BIN"
    
    ok "Script verify generado (SIN FALLBACK para usuarios HMAC)"
}

# ── PAM para SSH (con control preciso) ─────────
pam_install_ssh() {
    local ts=$(date +%Y%m%d_%H%M%S)
    
    # Backup
    if [[ ! -f "$BACKUP_DIR/sshd_original.bak" ]]; then
        cp "$PAM_SSHD" "$BACKUP_DIR/sshd_original.bak"
        ok "Backup SSH original guardado"
    fi
    cp "$PAM_SSHD" "$BACKUP_DIR/sshd_${ts}.bak"
    
    # Configuración SSH: Sin fallback para usuarios HMAC
    cat > "$PAM_SSHD" << 'PAMEOF'
# CilokG HMAC v2.0 - SSH (SIN FALLBACK para usuarios HMAC)
# Los usuarios normales entran normal
# Los usuarios HMAC SOLO con token válido

# Root siempre entra (protección)
auth [success=ok default=ignore] pam_succeed_if.so user = root quiet

# Para otros: usar el verificador HMAC
# Si el usuario requiere HMAC y falla → NO pasa a common-auth
# Si el usuario NO requiere HMAC → pasa a common-auth
auth sufficient pam_exec.so expose_authtok /usr/local/bin/cilokg_verify

# Fallback SOLO para usuarios que NO requieren HMAC
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

    restart_ssh
    ok "PAM SSH instalado - usuarios HMAC SOLO token"
}

# ── PAM para VPN (sin cambios, normal) ─────────
pam_install_vpn() {
    # Detectar qué VPN está instalada
    local vpn_pam=""
    if [[ -f "/etc/pam.d/openvpn" ]]; then
        vpn_pam="/etc/pam.d/openvpn"
    elif [[ -f "/etc/pam.d/wireguard" ]]; then
        vpn_pam="/etc/pam.d/wireguard"
    elif [[ -f "/etc/pam.d/pptpd" ]]; then
        vpn_pam="/etc/pam.d/pptpd"
    fi
    
    if [[ -n "$vpn_pam" ]]; then
        # Backup
        cp "$vpn_pam" "$BACKUP_DIR/vpn_$(basename $vpn_pam).bak"
        
        # Asegurar que la VPN NO use HMAC (para que funcione)
        sed -i '/cilokg_verify/d' "$vpn_pam"
        
        ok "VPN configurada - usa autenticación normal (sin HMAC)"
        info "Si tu VPN usa otro archivo PAM, configúralo manualmente"
    else
        info "No se detectó VPN común. Si usas VPN, asegúrate que NO use HMAC"
        info "Los archivos PAM comunes: /etc/pam.d/{openvpn,wireguard,pptpd}"
    fi
}

# ── Instalación completa ───────────────────────
pam_install() {
    pam_install_ssh
    pam_install_vpn
}

pam_uninstall() {
    # Restaurar SSH
    if [[ -f "$BACKUP_DIR/sshd_original.bak" ]]; then
        cp "$BACKUP_DIR/sshd_original.bak" "$PAM_SSHD"
        ok "SSH restaurado"
    else
        sed -i '/cilokg_verify/d' "$PAM_SSHD"
        sed -i '/pam_succeed_if.so.*root/d' "$PAM_SSHD"
        ok "SSH limpiado"
    fi
    
    # Restaurar VPN si tenía backup
    for bak in "$BACKUP_DIR"/vpn_*.bak; do
        if [[ -f "$bak" ]]; then
            local original="/etc/pam.d/$(basename "$bak" .bak | sed 's/vpn_//')"
            cp "$bak" "$original" 2>/dev/null
        fi
    done
    
    restart_ssh
    ok "Desinstalación PAM completa"
}

restart_ssh() {
    if sshd -t 2>/dev/null; then
        systemctl restart sshd 2>/dev/null || systemctl restart ssh 2>/dev/null
        ok "SSH reiniciado"
        
        # Verificación de seguridad
        if ssh -o ConnectTimeout=2 root@localhost exit 2>/dev/null; then
            ok "✓ Root puede conectar"
        else
            warn "⚠ Test de root falló - mantén sesión abierta"
        fi
    else
        warn "Configuración SSH inválida - restaurando backup"
        local latest=$(ls -t "$BACKUP_DIR"/sshd_*.bak 2>/dev/null | head -1)
        [[ -n "$latest" ]] && cp "$latest" "$PAM_SSHD"
        systemctl restart sshd 2>/dev/null
    fi
}

# ── Generar token ──────────────────────────────
generate_token() {
    local user="$1"
    local secret=$(get_secret)
    
    [[ -z "$secret" ]] && die "Clave secreta no configurada"
    
    # Verificar que el usuario requiera HMAC
    hmac_users_load
    local is_hmac=0
    for u in "${HMAC_USERS[@]}"; do
        [[ "$u" == "$user" ]] && is_hmac=1
    done
    
    if [[ $is_hmac -eq 0 ]]; then
        warn "El usuario '$user' NO requiere HMAC"
        info "Agrégalo primero con la opción 2"
        return 1
    fi
    
    local plain="cilokg:${user}:$(date +%s)"
    local timestamp=$(date +%s)
    local hmac=$(printf '%s:::%s' "$plain" "$timestamp" | openssl dgst -sha256 -hmac "$secret" | awk '{print $NF}')
    
    echo ""
    info "TOKEN HMAC para $user (válido por 30 segundos):"
    echo "${G}${plain}:::${timestamp}:::${hmac}${N}"
    echo ""
    info "Uso: ssh $user@host"
    info "Cuando pida 'Password:', pega el token completo"
    warn "La contraseña normal NO funcionará para este usuario"
}

# ── Status Box ─────────────────────────────────
status_box() {
    local secret=$(get_secret)
    hmac_users_load

    printf "  %-22s" "Clave secreta:"
    [[ -n "$secret" ]] && printf "${G}Configurada${N}\n" || printf "${R}No${N}\n"

    printf "  %-22s" "Script verify:"
    [[ -x "$SCRIPT_BIN" ]] && printf "${G}OK${N}\n" || printf "${R}No${N}\n"

    printf "  %-22s" "PAM SSH:"
    grep -q "cilokg_verify" "$PAM_SSHD" 2>/dev/null && printf "${G}Activo${N}\n" || printf "${R}Inactivo${N}\n"

    printf "  %-22s" "Usuarios HMAC:"
    printf "${C}%d${N}\n" "${#HMAC_USERS[@]}"
    
    if [[ ${#HMAC_USERS[@]} -gt 0 ]]; then
        printf "  %-22s" "  → Lista:"
        printf "${Y}%s${N}\n" "${HMAC_USERS[*]}"
    fi
    
    printf "  %-22s" "Modo HMAC:"
    printf "${R}SIN FALLBACK${N} (solo token)\n"
    
    printf "  %-22s" "VPN:"
    printf "${G}Compatible${N}\n"
    
    echo
}

# ── Menús ──────────────────────────────────────
menu() {
    while true; do
        draw_banner
        status_box
        printf "  ${W}[1]${N} Instalar / Configurar\n"
        printf "  ${W}[2]${N} Gestionar usuarios HMAC\n"
        printf "  ${W}[3]${N} Cambiar clave secreta\n"
        printf "  ${W}[4]${N} Ver logs\n"
        printf "  ${W}[5]${N} Generar token HMAC\n"
        printf "  ${W}[6]${N} Reparar instalación\n"
        printf "  ${R}[7]${N} Desinstalar\n"
        printf "  ${D}[0]${N} Salir\n\n"
        read -p "  Opción: " opt
        case "$opt" in
            1) wizard ;;
            2) users_menu ;;
            3) change_secret ;;
            4) logs ;;
            5) token_menu ;;
            6) repair ;;
            7) uninstall ;;
            0) echo; info "Adiós."; exit 0 ;;
            *) warn "Inválido."; sleep 1 ;;
        esac
    done
}

wizard() {
    draw_banner
    echo; info "INSTALACIÓN CILOKG v2.0 (SIN FALLBACK)"; echo

    # Configurar secret
    local secret=$(get_secret)
    if [[ -z "$secret" ]]; then
        if confirm "¿Generar clave secreta automáticamente?"; then
            set_secret ""
        else
            read -s -p "  Clave secreta: " secret; echo
            [[ -z "$secret" ]] && die "No puede estar vacía."
            set_secret "$secret"
        fi
    fi

    # Agregar usuarios HMAC
    echo
    if confirm "¿Agregar usuarios que SOLO usen token HMAC?"; then
        users_menu
    fi

    # Generar script y configurar PAM
    generate_verify_script
    pam_install
    
    echo
    ok "INSTALACIÓN COMPLETA"
    echo
    info "RESUMEN:"
    info "• Usuarios HMAC: SOLO pueden entrar con token"
    info "• Usuarios normales: siguen con contraseña"
    info "• VPN: funciona normalmente (sin HMAC)"
    info "• Root: siempre puede entrar (emergencia)"
    echo
    read -p "  Enter para volver..."
}

users_menu() {
    while true; do
        draw_banner
        hmac_users_load
        echo; info "USUARIOS HMAC (SOLO TOKEN)"; echo
        
        if [[ ${#HMAC_USERS[@]} -eq 0 ]]; then
            printf "  ${D}Ningún usuario requiere HMAC aún.${N}\n"
        else
            printf "  ${R}⚠ Estos usuarios NO pueden usar contraseña${N}\n\n"
            local i=1
            for u in "${HMAC_USERS[@]}"; do
                id "$u" &>/dev/null && local s="${G}✓${N}" || local s="${R}✗${N}"
                printf "  ${C}%d)${N} %-20s %s\n" "$i" "$u" "$s"
                ((i++))
            done
        fi

        printf "\n  ${G}[A]${N}gregar  ${R}[D]${N} eliminar  ${C}[T]${N} token  ${D}[0]${N} volver\n"
        read -p "  Opción: " opt
        case "${opt,,}" in
            a)
                read -p "  Usuario: " u
                [[ -z "$u" ]] && continue
                
                # No permitir root como HMAC
                if [[ "$u" == "root" ]]; then
                    warn "No se puede agregar root a HMAC"
                    sleep 2
                    continue
                fi
                
                # Crear usuario si no existe
                if ! id "$u" &>/dev/null; then
                    if confirm "Usuario '$u' no existe. ¿Crearlo?"; then
                        useradd -m -s /bin/bash "$u"
                        ok "Creado."
                        echo
                        info "Establece una contraseña (no la usará, pero es necesaria):"
                        passwd "$u"
                    else
                        continue
                    fi
                fi
                
                if hmac_user_add "$u"; then
                    ok "'$u' ahora SOLO entra con token HMAC"
                    warn "La contraseña de '$u' NO funcionará para SSH"
                    generate_verify_script
                    pam_install_ssh
                else
                    warn "'$u' ya está en la lista"
                fi
                ;;
            d)
                [[ ${#HMAC_USERS[@]} -eq 0 ]] && continue
                read -p "  Número a eliminar: " n
                [[ "$n" =~ ^[0-9]+$ ]] || continue
                local idx=$((n-1))
                if [[ $idx -ge 0 && $idx -lt ${#HMAC_USERS[@]} ]]; then
                    local del="${HMAC_USERS[$idx]}"
                    hmac_user_del "$del"
                    ok "'$del' removido. Ahora usa contraseña normal."
                    generate_verify_script
                    pam_install_ssh
                fi
                ;;
            t)
                if [[ ${#HMAC_USERS[@]} -gt 0 ]]; then
                    read -p "  Número de usuario: " n
                    [[ "$n" =~ ^[0-9]+$ ]] || continue
                    local idx=$((n-1))
                    if [[ $idx -ge 0 && $idx -lt ${#HMAC_USERS[@]} ]]; then
                        generate_token "${HMAC_USERS[$idx]}"
                        echo
                        read -p "  Enter para continuar..."
                    fi
                else
                    warn "No hay usuarios HMAC"
                    sleep 1
                fi
                ;;
            0) return ;;
            *) warn "Inválido."; sleep 1 ;;
        esac
    done
}

token_menu() {
    draw_banner
    echo; info "GENERAR TOKEN HMAC"; echo
    read -p "  Usuario: " user
    if [[ -z "$user" ]]; then
        warn "Usuario no puede estar vacío"
        sleep 1
        return
    fi
    
    generate_token "$user"
    echo
    read -p "  Enter para volver..."
}

change_secret() {
    draw_banner
    echo; info "CAMBIAR CLAVE SECRETA"; echo
    warn "Esto invalidará TODOS los tokens existentes"
    echo
    
    if confirm "¿Generar nueva clave automáticamente?"; then
        set_secret ""
    else
        read -s -p "  Nueva clave: " s1; echo
        read -s -p "  Repetir: " s2; echo
        [[ "$s1" != "$s2" ]] && die "No coinciden."
        set_secret "$s1"
    fi
    
    generate_verify_script
    pam_install_ssh
    ok "Clave actualizada"
    read -p "  Enter para volver..."
}

logs() {
    draw_banner
    echo; info "LOGS (Ctrl+C para salir)"; echo
    if [[ -f "$LOG_FILE" ]]; then
        tail -n 50 "$LOG_FILE"
        echo
        info "Follow mode (Ctrl+C para salir)..."
        tail -f "$LOG_FILE" 2>/dev/null || true
    else
        warn "Sin logs aún"
    fi
    read -p "  Enter para volver..."
}

repair() {
    draw_banner
    info "Reparando instalación..."
    generate_verify_script
    pam_install_ssh
    ok "Reparación completa"
    read -p "  Enter para volver..."
}

uninstall() {
    draw_banner
    echo; warn "DESINSTALAR COMPLETAMENTE"; echo
    
    if confirm "¿Eliminar todo?"; then
        pam_uninstall
        rm -f "$SCRIPT_BIN" "$LOG_FILE" "$RATE_LIMIT_FILE"
        rm -rf "$CONF_DIR" "$INSTALL_DIR"
        for link in /bin/clk /usr/bin/clk /usr/local/bin/clk /bin/hmac /usr/bin/hmac /usr/local/bin/hmac; do
            rm -f "$link" 2>/dev/null
        done
        ok "Desinstalación completa"
        echo
        exit 0
    fi
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
