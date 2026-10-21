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
    for ip in $(getent ahostsv4 "$d" 2>/dev/null | awk '{print $1}' | sort -u); do
      nft add element inet "$TABLE" "${KIND}4" "{ $ip }" 2>/dev/null || true
    done
    for ip in $(getent ahostsv6 "$d" 2>/dev/null | awk '{print $1}' | sort -u); do
      nft add element inet "$TABLE" "${KIND}6" "{ $ip }" 2>/dev/null || true
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

require_root
case "$MODE" in
  blockall)  apply_blockall  ;;
  whitelist) apply_whitelist ;;
  blockai)   apply_blockai   ;;
  restore)   flush_all; echo "OK restore" ;;
  status)    show_status ;;
  *) echo "Modo desconocido: $MODE" >&2; exit 2 ;;
esac
