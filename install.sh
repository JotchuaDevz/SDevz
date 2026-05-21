#!/bin/bash
# ================================================
#  CilokG - HMAC Authentication Manager v1.1
#  PowerBy: BlackHanzo
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

# ── Usuarios protegidos (NUNCA requieren HMAC) ──
PROTECTED_USERS=("root" "ubuntu")

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
    chmod 700 "$CONF_DIR" "$INSTALL_DIR"
    touch "$DB_FILE" "$KEY_FILE" 2>/dev/null
    chmod 600 "$DB_FILE" "$KEY_FILE" 2>/dev/null
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
    printf "${D}  HMAC Auth Manager v1.1${N}\n"
    printf "  ${D}Comandos: ${W}clk${D} | ${W}hmac${N}\n"
    printf "  ${D}Usuarios HMAC: ${R}sin fallback${N} ${D}(solo HMAC)${N}\n\n"
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
    echo -n "$1" > "$KEY_FILE"
    chmod 600 "$KEY_FILE"
}

hmac_users_load() {
    [[ -f "$DB_FILE" ]] && mapfile -t HMAC_USERS < "$DB_FILE" || HMAC_USERS=()
}

hmac_users_save() {
    printf '%s\n' "${HMAC_USERS[@]}" > "$DB_FILE"
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

# ── Generar verify script ──────────────────────
generate_verify_script() {
    local secret
    secret=$(get_secret)
    [[ -z "$secret" ]] && die "Clave secreta no configurada."

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
# CilokG HMAC Verifier
LOG="__LOG__"
SECRET="__SECRET__"
HMAC_USERS=( __HMAC_LIST__ )
PROTECTED=( __PROTECTED_LIST__ )

mkdir -p "$(dirname "$LOG")"
ts() { date '+%Y-%m-%d %H:%M:%S'; }

# Protegidos: acceso libre siempre
for p in "${PROTECTED[@]}"; do
    if [[ "$PAM_USER" == "$p" ]]; then
        echo "[$(ts)] FREE $PAM_USER (protegido)" >> "$LOG"
        exit 0
    fi
done

# Verificar si requiere HMAC
local need_hmac=0
for u in "${HMAC_USERS[@]}"; do
    if [[ "$PAM_USER" == "$u" ]]; then
        need_hmac=1
        break
    fi
done

# Si no está en lista HMAC, acceso libre
if [[ $need_hmac -eq 0 ]]; then
    echo "[$(ts)] FREE $PAM_USER (sin HMAC)" >> "$LOG"
    exit 0
fi

# ── USUARIO REQUIERE HMAC - NO tiene fallback ──
read -r input
echo "[$(ts)] CHALLENGE $PAM_USER" >> "$LOG"

# Validar formato
if [[ ! "$input" =~ ^[^:]+:::[0-9]+:::[a-fA-F0-9]{64}$ ]]; then
    echo "[$(ts)] REJECT $PAM_USER - formato inválido" >> "$LOG"
    exit 1
fi

plain=$(awk -F':::' '{print $1}' <<< "$input")
ts_in=$(awk -F':::' '{print $2}' <<< "$input")
sig_in=$(awk -F':::' '{print $3}' <<< "$input")

now=$(date +%s)
delta=$((now - ts_in))
delta=${delta#-}

if (( delta > 60 )); then
    echo "[$(ts)] REJECT $PAM_USER - timestamp expirado (${delta}s)" >> "$LOG"
    exit 1
fi

expected=$(printf '%s:::%s' "$plain" "$ts_in" | openssl dgst -sha256 -hmac "$SECRET" | awk '{print $NF}')

if [[ "${expected,,}" == "${sig_in,,}" ]]; then
    echo "[$(ts)] ACCEPT $PAM_USER - HMAC válido" >> "$LOG"
    exit 0
else
    echo "[$(ts)] REJECT $PAM_USER - HMAC inválido" >> "$LOG"
    exit 1
fi
VERIFYEOF

    sed -i "s|__LOG__|$LOG_FILE|g" "$SCRIPT_BIN"
    sed -i "s|__SECRET__|$secret|g" "$SCRIPT_BIN"
    sed -i "s|__HMAC_LIST__|$hmac_list|g" "$SCRIPT_BIN"
    sed -i "s|__PROTECTED_LIST__|$protected_list|g" "$SCRIPT_BIN"

    chmod 700 "$SCRIPT_BIN"
    chown root:root "$SCRIPT_BIN"
}

# ── PAM (sin fallback para usuarios HMAC) ──────
pam_install() {
    local ts=$(date +%Y%m%d_%H%M%S)
    cp "$PAM_SSHD" "$BACKUP_DIR/sshd_${ts}.bak"
    sed -i '/cilokg_verify/d' "$PAM_SSHD"
    
    # ─── PAM LIMPIO ───
    # auth sufficient: si verify script retorna 0, acceso directo
    # Si retorna 1, PASA a common-auth (contraseña del sistema)
    # PERO los usuarios protegidos (root, ubuntu) siempre retornan 0
    # Los usuarios HMAC válidos retornan 0
    # Los usuarios HMAC inválidos retornan 1 → common-auth → SI SABEN la pass del sistema, entran
    # Los usuarios no listados retornan 0 → acceso libre
    
    cat > "$PAM_SSHD" << 'PAMEOF'
# CilokG HMAC v1.1
# Root siempre entra sin HMAC
auth sufficient pam_succeed_if.so user = root

# Otros usuarios: HMAC obligatorio (sin fallback)
auth required pam_exec.so expose_authtok /usr/local/bin/cilokg_verify

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
    ok "PAM instalado correctamente"
}

pam_uninstall() {
    local latest=$(ls -t "$BACKUP_DIR"/sshd_*.bak 2>/dev/null | head -1)
    if [[ -n "$latest" ]]; then
        cp "$latest" "$PAM_SSHD"
        ok "PAM restaurado desde backup"
    else
        sed -i '/cilokg_verify/d' "$PAM_SSHD"
        ok "Líneas CilokG removidas"
    fi
    restart_ssh
}

restart_ssh() {
    systemctl restart sshd 2>/dev/null || systemctl restart ssh 2>/dev/null && ok "SSH reiniciado." || warn "Reinicia SSH manual."
}

# ── Status Box ─────────────────────────────────
status_box() {
    local secret=$(get_secret)
    hmac_users_load

    printf "  %-22s" "Clave secreta:"
    [[ -n "$secret" ]] && printf "${G}Configurada${N}\n" || printf "${R}No${N}\n"

    printf "  %-22s" "Script verify:"
    [[ -x "$SCRIPT_BIN" ]] && printf "${G}OK${N}\n" || printf "${R}No${N}\n"

    printf "  %-22s" "PAM sshd:"
    grep -q "cilokg_verify" "$PAM_SSHD" 2>/dev/null && printf "${G}Activo${N}\n" || printf "${R}Inactivo${N}\n"

    printf "  %-22s" "Usuarios HMAC:"
    printf "${C}%d${N}\n" "${#HMAC_USERS[@]}"
    
    printf "  %-22s" "Protegidos:"
    printf "${G}%s${N}\n" "${PROTECTED_USERS[*]}"
    echo
}

# ── Menús ──────────────────────────────────────
menu() {
    while true; do
        draw_banner
        status_box
        printf "  ${W}[1]${N} Asistente de instalación\n"
        printf "  ${W}[2]${N} Gestionar usuarios HMAC\n"
        printf "  ${W}[3]${N} Cambiar clave secreta\n"
        printf "  ${W}[4]${N} Ver logs\n"
        printf "  ${W}[5]${N} Reparar / reinstalar\n"
        printf "  ${R}[6]${N} Desinstalar\n"
        printf "  ${D}[0]${N} Salir\n\n"
        read -p "  Opción: " opt
        case "$opt" in
            1) wizard ;;
            2) users_menu ;;
            3) change_secret ;;
            4) logs ;;
            5) repair ;;
            6) uninstall ;;
            0) echo; info "Adiós."; exit 0 ;;
            *) warn "Inválido."; sleep 1 ;;
        esac
    done
}

wizard() {
    draw_banner
    echo; info "ASISTENTE DE INSTALACIÓN"; echo

    local secret=$(get_secret)
    if [[ -z "$secret" ]]; then
        read -s -p "  Clave secreta HMAC: " secret; echo
        [[ -z "$secret" ]] && die "No puede estar vacía."
        set_secret "$secret"
        ok "Clave guardada."
    else
        ok "Clave ya configurada."
    fi

    echo
    if confirm "¿Agregar usuarios que requieran HMAC?"; then
        users_menu
    fi

    generate_verify_script
    pam_install
    echo
    ok "INSTALACIÓN COMPLETA"
    read -p "  Enter para volver..."
}

users_menu() {
    while true; do
        draw_banner
        hmac_users_load
        echo; info "GESTIÓN DE USUARIOS HMAC"; echo
        printf "  ${D}Estos usuarios SOLO entran con HMAC válido.${N}\n"
        printf "  ${D}No tienen fallback a contraseña del sistema.${N}\n\n"

        if [[ ${#HMAC_USERS[@]} -eq 0 ]]; then
            printf "  ${D}Ningún usuario requiere HMAC aún.${N}\n"
        else
            local i=1
            for u in "${HMAC_USERS[@]}"; do
                id "$u" &>/dev/null && local s="${G}✓${N}" || local s="${R}✗${N}"
                printf "  ${C}%d)${N} %-20s %s\n" "$i" "$u" "$s"
                ((i++))
            done
        fi

        printf "\n  ${G}[A]${N}gregar  ${R}[D]${N} eliminar  ${D}[0]${N} volver\n"
        read -p "  Opción: " opt
        case "${opt,,}" in
            a)
                read -p "  Usuario: " u
                [[ -z "$u" ]] && continue
                for p in "${PROTECTED_USERS[@]}"; do
                    [[ "$u" == "$p" ]] && { warn "'$p' está protegido, no puede requerir HMAC."; sleep 2; continue 2; }
                done
                if ! id "$u" &>/dev/null; then
                    if confirm "Usuario '$u' no existe. ¿Crearlo?"; then
                        useradd -m -s /bin/bash "$u"
                        ok "Creado."; echo
                        passwd "$u"
                    else
                        continue
                    fi
                fi
                if hmac_user_add "$u"; then
                    ok "'$u' ahora SOLO entra con HMAC."
                    warn "La contraseña del sistema NO funcionará para '$u'."
                else
                    warn "'$u' ya está en la lista."
                fi
                generate_verify_script
                pam_install
                ;;
            d)
                [[ ${#HMAC_USERS[@]} -eq 0 ]] && continue
                read -p "  Número a eliminar: " n
                [[ "$n" =~ ^[0-9]+$ ]] || continue
                local idx=$((n-1))
                if [[ $idx -ge 0 && $idx -lt ${#HMAC_USERS[@]} ]]; then
                    local del="${HMAC_USERS[$idx]}"
                    hmac_user_del "$del"
                    ok "'$del' removido. Ahora entra sin HMAC."
                    generate_verify_script
                    pam_install
                fi
                ;;
            0) return ;;
            *) warn "Inválido."; sleep 1 ;;
        esac
    done
}

change_secret() {
    draw_banner
    echo; info "CAMBIAR CLAVE SECRETA"; echo
    warn "Esto invalidará todas las sesiones HMAC activas."
    echo
    read -s -p "  Nueva clave: " s1; echo
    read -s -p "  Repetir: " s2; echo
    [[ "$s1" != "$s2" ]] && die "No coinciden."
    set_secret "$s1"
    generate_verify_script
    pam_install
    ok "Clave actualizada."
    read -p "  Enter para volver..."
}

logs() {
    draw_banner
    echo; info "LOGS (Ctrl+C para salir)"; echo
    [[ -f "$LOG_FILE" ]] && tail -n 40 "$LOG_FILE" || warn "Sin logs aún."
    echo
    tail -f "$LOG_FILE" 2>/dev/null || true
    read -p "  Enter para volver..."
}

repair() {
    draw_banner
    info "Reparando instalación..."
    generate_verify_script
    pam_install
    ok "Reparación completa."
    read -p "  Enter para volver..."
}

uninstall() {
    draw_banner
    echo; warn "DESINSTALAR CILOKG"; echo
    
    printf "  ${D}Se eliminará:${N}\n"
    printf "  ${R}•${N} $INSTALL_DIR\n"
    printf "  ${R}•${N} $CONF_DIR\n"
    printf "  ${R}•${N} $SCRIPT_BIN\n"
    printf "  ${R}•${N} $LOG_FILE\n"
    printf "  ${R}•${N} Symlinks clk/hmac\n"
    echo
    
    if confirm "¿Eliminar completamente?"; then
        pam_uninstall
        rm -f "$SCRIPT_BIN" "$LOG_FILE"
        rm -rf "$CONF_DIR" "$INSTALL_DIR"
        for link in /bin/clk /usr/bin/clk /usr/local/bin/clk /bin/hmac /usr/bin/hmac /usr/local/bin/hmac; do
            rm -f "$link" 2>/dev/null
        done
        ok "Desinstalación completa."
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
