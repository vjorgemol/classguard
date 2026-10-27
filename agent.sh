#!/usr/bin/env bash
#
# agent.sh — se ejecuta EN CADA EQUIPO DE ALUMNO con sudo.
# Lo despliega automáticamente el orquestador del profesor (classguard.py).
#
# Uso:
#   sudo bash agent.sh blockall  <lan_cidr> <teacher_ip>
#   sudo bash agent.sh whitelist <lan_cidr> <teacher_ip> <lista_dominios.txt>
#   sudo bash agent.sh blockai   <lan_cidr> <teacher_ip> <lista_dominios.txt>
#   sudo bash agent.sh restore
#   sudo bash agent.sh status
#   sudo bash agent.sh message    <archivo_mensaje.txt>
#   sudo bash agent.sh screenshot <archivo_salida.png>
#   sudo bash agent.sh lock
#   sudo bash agent.sh unlock
#   sudo bash agent.sh poweroff
#
# Toda la configuración vive en una tabla nftables propia ("classguard"),
# de modo que no interfiere con otras reglas y se puede borrar por completo.

set -euo pipefail

MODE="${1:-status}"
LAN_CIDR="${2:-}"
TEACHER_IP="${3:-}"
LIST_FILE="${4:-}"

TABLE="classguard"
CONF_DIR="/etc/classguard"
RESOLVER="$CONF_DIR/resolve.sh"
SERVICE_NAME="classguard-resolver.service"
SERVICE_PATH="/etc/systemd/system/$SERVICE_NAME"

require_root() {
  if [ "$(id -u)" -ne 0 ]; then
    echo "ERROR: agent.sh debe ejecutarse como root (sudo)." >&2
    exit 1
  fi
}

# ---------------------------------------------------------------------------
# Limpieza total: para el servicio, borra la tabla y la configuración.
# ---------------------------------------------------------------------------
flush_all() {
  systemctl stop    "$SERVICE_NAME" 2>/dev/null || true
  systemctl disable "$SERVICE_NAME" 2>/dev/null || true
  rm -f "$SERVICE_PATH"
  systemctl daemon-reload 2>/dev/null || true
  nft delete table inet "$TABLE" 2>/dev/null || true
  rm -rf "$CONF_DIR"
}

# ---------------------------------------------------------------------------
# Instala el demonio que re-resuelve los dominios periódicamente y actualiza
# los conjuntos (sets) de nftables. KIND = "allow" o "block".
# ---------------------------------------------------------------------------
install_resolver() {
  local kind="$1"
  mkdir -p "$CONF_DIR"
  cp "$LIST_FILE" "$CONF_DIR/domains.txt"
  echo "$kind" > "$CONF_DIR/kind"

  cat > "$RESOLVER" <<'RESOLVER_EOF'
#!/usr/bin/env bash
# Re-resuelve los dominios y actualiza los sets de nftables cada 30 s.
set -u
TABLE="classguard"
KIND="$(cat /etc/classguard/kind 2>/dev/null || echo allow)"
DOMAINS="/etc/classguard/domains.txt"

resolve_once() {
  while IFS= read -r d; do
    d="${d%%#*}"                      # quita comentarios en línea
    d="$(echo "$d" | tr -d '[:space:]')"
    [ -z "$d" ] && continue
    # El dominio desnudo y su www. suelen resolver a IPs distintas
    # (p. ej. youtube.com frente a www.youtube.com): resuelve ambos.
    names="$d"
    case "$d" in www.*) ;; *) names="$d www.$d" ;; esac
    for n in $names; do
      for ip in $(getent ahostsv4 "$n" 2>/dev/null | awk '{print $1}' | sort -u); do
        nft add element inet "$TABLE" "${KIND}4" "{ $ip }" 2>/dev/null || true
      done
      for ip in $(getent ahostsv6 "$n" 2>/dev/null | awk '{print $1}' | sort -u); do
        nft add element inet "$TABLE" "${KIND}6" "{ $ip }" 2>/dev/null || true
      done
    done
  done < "$DOMAINS"
}

while true; do
  resolve_once
  sleep 30
done
RESOLVER_EOF
  chmod +x "$RESOLVER"

  cat > "$SERVICE_PATH" <<SERVICE_EOF
[Unit]
Description=ClassGuard resolver (actualiza listas de nftables)
After=network-online.target
Wants=network-online.target

[Service]
ExecStart=$RESOLVER
Restart=always
RestartSec=2

[Install]
WantedBy=multi-user.target
SERVICE_EOF

  systemctl daemon-reload
  systemctl enable "$SERVICE_NAME" >/dev/null 2>&1 || true
  # restart lanza el resolver, cuya primera iteración resuelve de inmediato.
  systemctl restart "$SERVICE_NAME"
}

# ---------------------------------------------------------------------------
# MODO 1: cortar TODO internet (se mantiene la LAN del aula para gestión).
# ---------------------------------------------------------------------------
apply_blockall() {
  [ -n "$LAN_CIDR" ]   || { echo "Falta lan_cidr" >&2; exit 2; }
  [ -n "$TEACHER_IP" ] || { echo "Falta teacher_ip" >&2; exit 2; }
  flush_all
  nft -f - <<NFT_EOF
table inet $TABLE {
  chain output {
    type filter hook output priority 0; policy drop;
    oifname "lo" accept
    ct state established,related accept
    meta l4proto { icmp, ipv6-icmp } accept
    udp dport { 67, 68 } accept
    ip  daddr $LAN_CIDR accept
    ip  daddr $TEACHER_IP accept
    ip6 daddr fe80::/10 accept
  }
}
NFT_EOF
  echo "OK blockall"
}

# ---------------------------------------------------------------------------
# MODO 2: cortar internet SALVO los dominios de la lista blanca.
# ---------------------------------------------------------------------------
apply_whitelist() {
  [ -n "$LAN_CIDR" ]   || { echo "Falta lan_cidr" >&2; exit 2; }
  [ -n "$TEACHER_IP" ] || { echo "Falta teacher_ip" >&2; exit 2; }
  [ -f "$LIST_FILE" ]  || { echo "Falta lista de dominios" >&2; exit 2; }
  flush_all
  nft -f - <<NFT_EOF
table inet $TABLE {
  set allow4 { type ipv4_addr; flags interval; }
  set allow6 { type ipv6_addr; flags interval; }
  chain output {
    type filter hook output priority 0; policy drop;
    oifname "lo" accept
    ct state established,related accept
    meta l4proto { icmp, ipv6-icmp } accept
    udp dport { 67, 68 } accept
    ip  daddr $LAN_CIDR accept
    ip  daddr $TEACHER_IP accept
    ip6 daddr fe80::/10 accept
    udp dport 53 accept
    tcp dport 53 accept
    ip  daddr @allow4 accept
    ip6 daddr @allow6 accept
  }
}
NFT_EOF
  install_resolver allow
  echo "OK whitelist"
}

# ---------------------------------------------------------------------------
# MODO 3: internet normal pero BLOQUEANDO servicios/APIs de IA.
# ---------------------------------------------------------------------------
apply_blockai() {
  [ -f "$LIST_FILE" ] || { echo "Falta lista de dominios" >&2; exit 2; }
  flush_all
  nft -f - <<NFT_EOF
table inet $TABLE {
  set block4 { type ipv4_addr; flags interval; }
  set block6 { type ipv6_addr; flags interval; }
  chain output {
    type filter hook output priority 0; policy accept;
    ip  daddr @block4 reject
    ip6 daddr @block6 reject
  }
}
NFT_EOF
  install_resolver block
  echo "OK blockai"
}

show_status() {
  if nft list table inet "$TABLE" >/dev/null 2>&1; then
    echo "ACTIVO"
    nft list table inet "$TABLE"
    echo "--- servicio resolver ---"
    systemctl is-active "$SERVICE_NAME" 2>/dev/null || echo "inactivo"
  else
    echo "LIBRE (sin reglas de classguard)"
  fi
}

# ---------------------------------------------------------------------------
# Sesión gráfica activa: devuelve "sid|uid|usuario|display|escritorio" de la
# sesión de escritorio (x11/wayland) para avisar/capturar/bloquear al usuario.
# 'escritorio' se normaliza a kde / gnome / other. Prefiere la sesión "active";
# si no, la primera gráfica encontrada. El separador es '|' porque DISPLAY
# contiene ':' (p. ej. ":0").
# ---------------------------------------------------------------------------
de_class() {
  case "$(echo "${1:-}" | tr 'A-Z' 'a-z')" in
    *kde*|*plasma*)  echo kde ;;
    *gnome*|*unity*) echo gnome ;;
    *)               echo other ;;
  esac
}

gui_session() {
  local fallback="" sid type state uid user disp desk de
  while read -r sid; do
    [ -z "$sid" ] && continue
    type="$(loginctl show-session "$sid" -p Type --value 2>/dev/null)"
    [ "$type" = "x11" ] || [ "$type" = "wayland" ] || continue
    state="$(loginctl show-session "$sid" -p State --value 2>/dev/null)"
    uid="$(loginctl show-session "$sid" -p User --value 2>/dev/null)"
    user="$(loginctl show-session "$sid" -p Name --value 2>/dev/null)"
    disp="$(loginctl show-session "$sid" -p Display --value 2>/dev/null)"
    desk="$(loginctl show-session "$sid" -p Desktop --value 2>/dev/null)"
    de="$(de_class "$desk")"
    if [ "$state" = "active" ]; then
      echo "$sid|$uid|$user|$disp|$de"; return 0
    fi
    [ -z "$fallback" ] && fallback="$sid|$uid|$user|$disp|$de"
  done < <(loginctl list-sessions --no-legend 2>/dev/null | awk '{print $1}')
  [ -n "$fallback" ] && { echo "$fallback"; return 0; }
  return 1
}

# ¿Está disponible este comando en la sesión del usuario de escritorio?
user_has() {
  run_as_user "$1" "$2" "$3" sh -c "command -v $4 >/dev/null 2>&1"
}

# Ejecuta un comando como el usuario del escritorio, con su entorno gráfico
# (DISPLAY, DBUS y XDG_RUNTIME_DIR) para que notificaciones y capturas lleguen
# a su sesión.
run_as_user() {
  local uid="$1" user="$2" disp="$3"; shift 3
  [ -z "$disp" ] && disp=":0"
  sudo -u "$user" env \
    DISPLAY="$disp" \
    XDG_RUNTIME_DIR="/run/user/$uid" \
    DBUS_SESSION_BUS_ADDRESS="unix:path=/run/user/$uid/bus" \
    "$@"
}

# ---------------------------------------------------------------------------
# ACCIÓN: mostrar un aviso del profesor en el escritorio del alumno.
# El mensaje llega en un archivo para no depender del escapado del shell.
# ---------------------------------------------------------------------------
do_message() {
  local msgfile="$1"
  [ -n "$msgfile" ] && [ -f "$msgfile" ] || { echo "Falta el archivo de mensaje" >&2; exit 2; }
  local msg; msg="$(cat "$msgfile")"
  local info; info="$(gui_session)" || { echo "sin sesión gráfica activa" >&2; exit 3; }
  local sid uid user disp de; IFS='|' read -r sid uid user disp de <<< "$info"

  # Orden de herramientas de diálogo según el escritorio; notify-send al final.
  local order
  case "$de" in
    kde)   order="kdialog zenity notify-send" ;;
    gnome) order="zenity notify-send kdialog" ;;
    *)     order="zenity kdialog notify-send" ;;
  esac

  local tool
  for tool in $order; do
    user_has "$uid" "$user" "$disp" "$tool" || continue
    case "$tool" in
      kdialog)
        # setsid + & : el diálogo queda en pantalla sin bloquear la conexión SSH.
        run_as_user "$uid" "$user" "$disp" setsid kdialog \
          --title "Aviso del profesor" --msgbox "$msg" >/dev/null 2>&1 &
        ;;
      zenity)
        run_as_user "$uid" "$user" "$disp" setsid zenity \
          --warning --title="Aviso del profesor" --width=460 --text="$msg" >/dev/null 2>&1 &
        ;;
      notify-send)
        run_as_user "$uid" "$user" "$disp" notify-send -u critical \
          "Aviso del profesor" "$msg" >/dev/null 2>&1 || true
        ;;
    esac
    echo "OK aviso ($tool) a $user [$de]"
    return 0
  done
  echo "no hay kdialog/zenity/notify-send para avisar a $user" >&2; exit 4
}

# ---------------------------------------------------------------------------
# ACCIÓN: capturar el escritorio del alumno a un PNG (para dejar constancia).
# Prueba gnome-screenshot (X11/Wayland), luego scrot e import (solo X11).
# ---------------------------------------------------------------------------
# Comando de captura (al fichero "$1") para cada herramienta conocida.
screenshot_cmd() {
  case "$1" in
    spectacle)        echo 'spectacle -b -n -f -o "$1"' ;;   # KDE (X11/Wayland)
    gnome-screenshot) echo 'gnome-screenshot -f "$1"' ;;     # GNOME (X11/Wayland)
    grim)             echo 'grim "$1"' ;;                    # Wayland (wlroots)
    scrot)            echo 'scrot -o "$1"' ;;                # X11
    import)           echo 'import -window root "$1"' ;;     # X11 (ImageMagick)
  esac
}

do_screenshot() {
  local out="$1"
  [ -n "$out" ] || { echo "Falta el archivo de salida" >&2; exit 2; }
  local info; info="$(gui_session)" || { echo "sin sesión gráfica activa" >&2; exit 3; }
  local sid uid user disp de; IFS='|' read -r sid uid user disp de <<< "$info"
  local tmp="/run/user/$uid/classguard_shot.png"

  # Orden de herramientas según el escritorio; el resto quedan como respaldo.
  local order
  case "$de" in
    kde)   order="spectacle grim gnome-screenshot scrot import" ;;
    gnome) order="gnome-screenshot spectacle grim scrot import" ;;
    *)     order="gnome-screenshot spectacle grim scrot import" ;;
  esac

  run_as_user "$uid" "$user" "$disp" sh -c 'rm -f "$1"' _ "$tmp" 2>/dev/null || true
  local tool used=""
  for tool in $order; do
    user_has "$uid" "$user" "$disp" "$tool" || continue
    run_as_user "$uid" "$user" "$disp" sh -c "$(screenshot_cmd "$tool")" _ "$tmp" >/dev/null 2>&1 || true
    if run_as_user "$uid" "$user" "$disp" sh -c 'test -s "$1"' _ "$tmp" 2>/dev/null; then
      used="$tool"; break
    fi
  done

  if [ -z "$used" ]; then
    echo "no se pudo capturar (¿falta spectacle/gnome-screenshot?) [$de]" >&2; exit 5
  fi
  # Copiar a la ruta de salida (root) y dejarla legible para traerla por SFTP.
  cp "$tmp" "$out"
  chmod 644 "$out"
  run_as_user "$uid" "$user" "$disp" sh -c 'rm -f "$1"' _ "$tmp" 2>/dev/null || true
  echo "OK captura de $user [$de/$used] ($(stat -c%s "$out") bytes)"
}

# ---------------------------------------------------------------------------
# ACCIÓN: bloquear / desbloquear al alumno.
#
# En X11 el bloqueo es FUERTE: root deshabilita los dispositivos de entrada
# (teclado y ratón) con xinput, de modo que el alumno —que no tiene sudo— no
# puede reactivarlos; el profesor los reactiva con 'unlock'. Además muestra un
# aviso en pantalla.
#
# Si no hay X11/xinput (p. ej. Wayland, que impide capturar el input de otra
# sesión), cae al bloqueo de sesión de systemd-logind, que el alumno puede
# desbloquear con SU contraseña; se informa de ello como bloqueo "DÉBIL".
# ---------------------------------------------------------------------------

# Busca un proceso del usuario con entorno X y devuelve "DISPLAY|XAUTHORITY".
find_xenv() {
  local uid="$1" pid disp xauth
  for pid in $(pgrep -u "$uid" 2>/dev/null); do
    [ -r "/proc/$pid/environ" ] || continue
    grep -qz '^DISPLAY=' "/proc/$pid/environ" 2>/dev/null || continue
    disp="$(tr '\0' '\n' < "/proc/$pid/environ" | sed -n 's/^DISPLAY=//p' | head -1)"
    xauth="$(tr '\0' '\n' < "/proc/$pid/environ" | sed -n 's/^XAUTHORITY=//p' | head -1)"
    [ -n "$disp" ] && { echo "$disp|$xauth"; return 0; }
  done
  return 1
}

# Habilita/deshabilita todos los dispositivos de entrada del display X.
xinput_all() {
  local action="$1" disp="$2" xauth="$3" id
  for id in $(DISPLAY="$disp" XAUTHORITY="$xauth" xinput --list --id-only 2>/dev/null); do
    DISPLAY="$disp" XAUTHORITY="$xauth" xinput "$action" "$id" >/dev/null 2>&1 || true
  done
}

# Muestra un aviso de bloqueo en la sesión del alumno (marca 'ClassGuard-lock'
# en la línea de comandos para poder cerrarlo luego con pkill).
show_lock_msg() {
  local uid="$1" user="$2" disp="$3" msg="$4" title="ClassGuard-lock"
  if user_has "$uid" "$user" "$disp" zenity; then
    run_as_user "$uid" "$user" "$disp" setsid zenity --info \
      --title="$title" --width=520 --text="$msg" >/dev/null 2>&1 &
  elif user_has "$uid" "$user" "$disp" kdialog; then
    run_as_user "$uid" "$user" "$disp" setsid kdialog \
      --title "$title" --msgbox "$msg" >/dev/null 2>&1 &
  elif user_has "$uid" "$user" "$disp" notify-send; then
    run_as_user "$uid" "$user" "$disp" notify-send -u critical "$title" "$msg" >/dev/null 2>&1 || true
  fi
}

do_lock() {
  local action="$1"   # lock | unlock
  local info; info="$(gui_session)" || { echo "sin sesión gráfica activa" >&2; exit 3; }
  local sid uid user disp de; IFS='|' read -r sid uid user disp de <<< "$info"
  local stype; stype="$(loginctl show-session "$sid" -p Type --value 2>/dev/null)"

  # Entorno X para que root pueda operar sobre el display del alumno.
  local xinfo xdisp xauth
  xinfo="$(find_xenv "$uid")" || xinfo=""
  IFS='|' read -r xdisp xauth <<< "$xinfo"
  [ -z "$xdisp" ] && xdisp="$disp"
  [ -z "$xauth" ] && xauth="$(getent passwd "$user" | cut -d: -f6)/.Xauthority"

  local strong=0
  if [ "$stype" = "x11" ] && [ -n "$xdisp" ] && command -v xinput >/dev/null 2>&1; then
    DISPLAY="$xdisp" XAUTHORITY="$xauth" xinput --list >/dev/null 2>&1 && strong=1
  fi

  if [ "$action" = "lock" ]; then
    if [ "$strong" = 1 ]; then
      show_lock_msg "$uid" "$user" "$disp" \
        "Pantalla bloqueada por el profesor. Avisa cuando debas continuar."
      xinput_all disable "$xdisp" "$xauth"
      echo "OK lock FUERTE de $user [x11: entrada deshabilitada]"
    else
      loginctl lock-session "$sid" 2>/dev/null || true
      echo "OK lock DEBIL de $user [${stype:-?}: bloqueo de sesión; el alumno puede desbloquear con su contraseña]"
    fi
  else  # unlock
    [ "$strong" = 1 ] && xinput_all enable "$xdisp" "$xauth"
    loginctl unlock-session "$sid" 2>/dev/null || true
    pkill -u "$user" -f 'ClassGuard-lock' 2>/dev/null || true
    echo "OK unlock de $user"
  fi
}

# ---------------------------------------------------------------------------
# ACCIÓN: apagar el equipo. Se responde OK de inmediato y el apagado se lanza
# unos segundos después (en segundo plano), para que la conexión SSH reciba la
# confirmación antes de que la máquina se apague. '-i' ignora inhibidores
# (sesiones abiertas), para que el apagado no quede bloqueado.
# ---------------------------------------------------------------------------
do_poweroff() {
  setsid sh -c 'sleep 3; systemctl poweroff -i 2>/dev/null || poweroff -f' >/dev/null 2>&1 &
  echo "OK apagando"
}

require_root
case "$MODE" in
  blockall)   apply_blockall  ;;
  whitelist)  apply_whitelist ;;
  blockai)    apply_blockai   ;;
  restore)    flush_all; echo "OK restore" ;;
  status)     show_status ;;
  message)    do_message    "${2:-}" ;;
  screenshot) do_screenshot "${2:-}" ;;
  lock)       do_lock lock ;;
  unlock)     do_lock unlock ;;
  poweroff)   do_poweroff ;;
  *) echo "Modo desconocido: $MODE" >&2; exit 2 ;;
esac
