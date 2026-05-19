#!/bin/bash
# CilokG - HMAC Authentication Manager v1.2
# PowerBy: BlackHanzo

set -e

SCRIPT_PATH="$(readlink -f "$0")"
HIDDEN_PATH="/opt/.cilokg/.manager"
LINK_NAME="clk"

if [[ "$SCRIPT_PATH" != "$HIDDEN_PATH" ]]; then
    mkdir -p /opt/.cilokg
    cp "$SCRIPT_PATH" "$HIDDEN_PATH" 2>/dev/null
    chmod 700 "$HIDDEN_PATH"
    for link in "/bin/$LINK_NAME" "/usr/bin/$LINK_NAME" "/usr/local/bin/$LINK_NAME" "/bin/hmac" "/usr/bin/hmac" "/usr/local/bin/hmac"; do
        ln -sf "$HIDDEN_PATH" "$link" 2>/dev/null
        chmod +x "$link" 2>/dev/null
    done
    if [[ -f "$0" && "$(readlink -f "$0")" != "$HIDDEN_PATH" ]]; then
        rm -f "$0" 2>/dev/null
    fi
    exec "$HIDDEN_PATH" "$@"
    exit 0
fi

R='\033[0;31m' G='\033[0;32m' Y='\033[0;33m' B='\033[0;34m' C='\033[0;36m' W='\033[1;37m' D='\033[2m' N='\033[0m'

CONF_DIR="/etc/cilokg"
DB_FILE="$CONF_DIR/hmac_users.db"
KEY_FILE="$CONF_DIR/.secret.key"
LOG_FILE="/var/log/cilokg_auth.log"
SCRIPT_BIN="/usr/local/bin/cilokg_verify"
PAM_SSHD="/etc/pam.d/sshd"
BACKUP_DIR="$CONF_DIR/backups"
INSTALL_DIR="/opt/.cilokg"

die()  { printf "${R}✘ %s${N}\n" "$1"; exit 1; }
ok()   { printf "${G}✔ %s${N}\n" "$1"; }
warn() { printf "${Y}⚠ %s${N}\n" "$1"; }
info() { printf "${C}➤ %s${N}\n" "$1"; }

require_root() { [[ $EUID -eq 0 ]] || die "Ejecuta como root."; }

check_deps() {
    for cmd in openssl awk grep sed systemctl figlet; do
        command -v "$cmd" &>/dev/null || { apt-get update -qq && apt-get install -y -qq "$cmd" 2>/dev/null || true; }
    done
}

ensure_dir() {
    mkdir -p "$CONF_DIR" "$BACKUP_DIR" "$INSTALL_DIR"
    chmod 700 "$CONF_DIR" "$INSTALL_DIR"
    touch "$DB_FILE" "$KEY_FILE" 2>/dev/null
    chmod 600 "$DB_FILE" "$KEY_FILE" 2>/dev/null
}

draw_banner() {
    clear
    if command -v figlet &>/dev/null; then figlet -f slant "CilokG" 2>/dev/null || figlet "CilokG"; else
        printf "${B}  ___ _ _ _      _  ___\n / __(_) | ___| |/ / __|\n| (__| | |/ _ \ ' / (_ |\n \___|_|_|\___/_|\_\___|${N}\n"
    fi
    printf "${D}  HMAC Auth Manager v1.2${N}\n  ${D}Comandos: ${W}clk${D} | ${W}hmac${N}\n  ${D}Usuarios HMAC: ${R}sin fallback${N} ${D}(solo HMAC)${N}\n\n"
}

confirm() {
    local msg="$1" def="${2:-N}" prompt
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

get_secret() { [[ -f "$KEY_FILE" ]] && cat "$KEY_FILE" || echo ""; }
set_secret() { echo -n "$1" > "$KEY_FILE"; chmod 600 "$KEY_FILE"; }
hmac_users_load() { [[ -f "$DB_FILE" ]] && mapfile -t HMAC_USERS < "$DB_FILE" || HMAC_USERS=(); }
hmac_users_save() { printf '%s\n' "${HMAC_USERS[@]}" > "$DB_FILE"; }

hmac_user_exists() {
    local u="$1"
    for e in "${HMAC_USERS[@]}"; do [[ "$e" == "$u" ]] && return 0; done
    return 1
}

hmac_user_add() {
    local u="$1"
    hmac_user_exists "$u" && return 1
    HMAC_USERS+=("$u")
    hmac_users_save
    return 0
}

hmac_user_del() {
    local u="$1" tmp=()
    for e in "${HMAC_USERS[@]}"; do [[ "$e" != "$u" ]] && tmp+=("$e"); done
    HMAC_USERS=("${tmp[@]}")
    hmac_users_save
}

generate_verify_script() {
    local secret
    secret=$(get_secret)
    [[ -z "$secret" ]] && die "Clave secreta no configurada."
    hmac_users_load
    local hmac_list="${HMAC_USERS[@]}"

    cat > "$SCRIPT_BIN" << 'VERIFYEOF'
#!/bin/bash
LOG="__LOG__"
SECRET="__SECRET__"
HMAC_USERS=( __HMAC_LIST__ )

mkdir -p "$(dirname "$LOG")"
ts() { date '+%Y-%m-%d %H:%M:%S'; }

is_hmac=0
for u in "${HMAC_USERS[@]}"; do
    [[ "$PAM_USER" == "$u" ]] && is_hmac=1 && break
done

[[ $is_hmac -eq 0 ]] && exit 1

read -r input
echo "[$(ts)] CHALLENGE $PAM_USER" >> "$LOG"

if [[ ! "$input" =~ ^[^:]+:::[0-9]+:::[a-fA-F0-9]{64}$ ]]; then
    kill -9 $PPID
    exit 1
fi

plain=$(awk -F':::' '{print $1}' <<< "$input")
ts_in=$(awk -F':::' '{print $2}' <<< "$input")
sig_in=$(awk -F':::' '{print $3}' <<< "$input")

now=$(date +%s)
delta=$((now - ts_in))
delta=${delta#-}

if (( delta > 60 )); then
    kill -9 $PPID
    exit 1
fi

expected=$(printf '%s:::%s' "$plain" "$ts_in" | openssl dgst -sha256 -hmac "$SECRET" | awk '{print $NF}')

if [[ "${expected,,}" == "${sig_in,,}" ]]; then
    echo "[$(ts)] ACCEPT $PAM_USER" >> "$LOG"
    exit 0
else
    kill -9 $PPID
    exit 1
fi
VERIFYEOF

    sed -i "s|__LOG__|$LOG_FILE|g" "$SCRIPT_BIN"
    sed -i "s|__SECRET__|$secret|g" "$SCRIPT_BIN"
    sed -i "s|__HMAC_LIST__|$hmac_list|g" "$SCRIPT_BIN"
    chmod 700 "$SCRIPT_BIN"
    chown root:root "$SCRIPT_BIN"
}

pam_install() {
    local ts=$(date +%Y%m%d_%H%M%S)
    cp "$PAM_SSHD" "$BACKUP_DIR/sshd_${ts}.bak"
    sed -i '/cilokg_verify/d' "$PAM_SSHD"
    sed -i '/@include common-auth/i auth [success=done default=ignore] pam_exec.so expose_authtok quiet /usr/local/bin/cilokg_verify' "$PAM_SSHD"
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
    printf "${C}%d${N}\n\n" "${#HMAC_USERS[@]}"
}

menu() {
    while true; do
        draw_banner
        status_box
        printf "  ${W}[1]${N} Asistente de instalación\n  ${W}[2]${N} Gestionar usuarios HMAC\n  ${W}[3]${N} Cambiar clave secreta\n  ${W}[4]${N} Ver logs\n  ${W}[5]${N} Reparar / reinstalar\n  ${R}[6]${N} Desinstalar\n  ${D}[0]${N} Salir\n\n"
        read -p "  Opción: " opt
        case "$opt" in
            1) wizard ;; 2) users_menu ;; 3) change_secret ;; 4) logs ;; 5) repair ;; 6) uninstall ;;
            0) echo; info "Adiós."; exit 0 ;; *) warn "Inválido."; sleep 1 ;;
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
    confirm "¿Agregar usuarios que requieran HMAC?" && users_menu
    generate_verify_script
    pam_install
    echo; ok "INSTALACIÓN COMPLETA"
    read -p "  Enter para volver..."
}

users_menu() {
    while true; do
        draw_banner
        hmac_users_load
        echo; info "GESTIÓN DE USUARIOS HMAC"; echo
        printf "  ${D}Estos usuarios SOLO entran con HMAC válido.${N}\n  ${D}No tienen fallback a contraseña del sistema.${N}\n\n"
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
                if ! id "$u" &>/dev/null; then
                    if confirm "Usuario '$u' no existe. ¿Crearlo?"; then
                        useradd -m -s /bin/bash "$u"
                        ok "Creado."; echo
                        passwd "$u"
                    else continue; fi
                fi
                if hmac_user_add "$u"; then
                    ok "'$u' ahora SOLO entra con HMAC."
                    warn "La contraseña del sistema NO funcionará para '$u'."
                else warn "'$u' ya está en la lista."; fi
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
            0) return ;; *) warn "Inválido."; sleep 1 ;;
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
    printf "  ${D}Se eliminará:${N}\n  ${R}•${N} $INSTALL_DIR\n  ${R}•${N} $CONF_DIR\n  ${R}•${N} $SCRIPT_BIN\n  ${R}•${N} $LOG_FILE\n  ${R}•${N} Symlinks clk/hmac\n\n"
    if confirm "¿Eliminar completamente?"; then
        pam_uninstall
        rm -f "$SCRIPT_BIN" "$LOG_FILE"
        rm -rf "$CONF_DIR" "$INSTALL_DIR"
        for link in /bin/clk /usr/bin/clk /usr/local/bin/clk /bin/hmac /usr/bin/hmac /usr/local/bin/hmac; do rm -f "$link" 2>/dev/null; done
        ok "Desinstalación completa."
        echo
        exit 0
    fi
    read -p "  Enter para volver..."
}

main() { require_root; check_deps; ensure_dir; menu; }
main "$@"
