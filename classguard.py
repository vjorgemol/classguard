#!/usr/bin/env python3
"""
classguard.py — Orquestador de aula (se ejecuta en el equipo del PROFESOR).

Recorre el rango de IPs del aula, se conecta por SSH a cada equipo de alumno
con el usuario/contraseña que indica el profesor, y aplica reglas de red
(nftables) mediante agent.sh con sudo.

El propio equipo del profesor queda excluido: sus IPs locales se detectan y se
saltan automáticamente, y nunca se conecta a sí mismo.

Acciones:
  blockall   Corta TODO internet (mantiene la LAN del aula).
  whitelist  Corta internet salvo los dominios de whitelist.txt.
  blockai    Internet normal, pero bloquea los dominios de ai-blocklist.txt.
  restore    Quita todas las reglas y devuelve los equipos a la normalidad.
  status     Muestra el estado de cada equipo.
  update     Actualiza el sistema (apt) de los equipos de alumno.

Uso:
  python3 classguard.py <accion> [--config config.json]

Requisitos: Python 3, paramiko  (pip install -r requirements.txt)
"""

import argparse
import concurrent.futures
import getpass
import ipaddress
import json
import os
import shutil
import socket
import subprocess
import sys
import time

try:
    import paramiko
except ImportError:
    sys.exit("Falta paramiko. Instala con: pip install -r requirements.txt")

HERE = os.path.dirname(os.path.abspath(__file__))
AGENT_LOCAL = os.path.join(HERE, "agent.sh")
AGENT_REMOTE = "/tmp/classguard_agent.sh"
LIST_REMOTE = "/tmp/classguard_domains.txt"
MSG_REMOTE = "/tmp/classguard_msg.txt"
SHOT_REMOTE = "/tmp/classguard_shot.png"
DEFAULT_DATA_FILES = ("config.example.json", "whitelist.txt", "ai-blocklist.txt")


def data_dir():
    """Carpeta de los datos editables (config.json, listas, state.json).

    Por defecto, junto al código. Dentro de un AppImage (solo lectura) se usa
    ~/.config/classguard, que se siembra con las listas y el ejemplo de config
    la primera vez. CLASSGUARD_DATA permite elegir otra carpeta.
    """
    path = os.environ.get("CLASSGUARD_DATA")
    if not path and os.environ.get("APPIMAGE"):
        base = os.environ.get("XDG_CONFIG_HOME") or os.path.expanduser("~/.config")
        path = os.path.join(base, "classguard")
    if not path:
        return HERE
    os.makedirs(path, exist_ok=True)
    for name in DEFAULT_DATA_FILES:
        dst = os.path.join(path, name)
        if not os.path.exists(dst):
            shutil.copy(os.path.join(HERE, name), dst)
    return path


DATA = data_dir()
STATE_PATH = os.path.join(DATA, "state.json")
MACS_PATH = os.path.join(DATA, "macs.json")

BLOCKING_MODES = ("blockall", "whitelist", "blockai")

GREEN, RED, YELLOW, RESET = "\033[32m", "\033[31m", "\033[33m", "\033[0m"


def load_enforced():
    """Equipos que quedaron bajo bloqueo y aún no se han restaurado."""
    try:
        with open(STATE_PATH) as fh:
            return set(json.load(fh).get("enforced", []))
    except Exception:
        return set()


def save_enforced(hosts):
    try:
        with open(STATE_PATH, "w") as fh:
            json.dump({"enforced": sorted(hosts)}, fh, indent=2)
    except Exception:
        pass


# ---------------------------------------------------------------------------
# Wake-on-LAN: aprendizaje de MAC (desde ARP) y envío de magic packets.
# ---------------------------------------------------------------------------
def load_macs():
    try:
        with open(MACS_PATH) as fh:
            return {str(k): str(v).lower() for k, v in json.load(fh).items()}
    except Exception:
        return {}


def save_macs(macs):
    try:
        with open(MACS_PATH, "w") as fh:
            json.dump(macs, fh, indent=2, sort_keys=True)
    except Exception:
        pass


def update_macs(ips):
    """Aprende las MAC de las IPs indicadas leyendo la tabla ARP (ip neigh).

    Se llama tras los barridos de ping: con los equipos encendidos, el sistema
    ya conoce su MAC, y así se pueden encender por WoL cuando estén apagados.
    """
    wanted = set(ips)
    if not wanted:
        return
    try:
        out = subprocess.check_output(["ip", "neigh", "show"], text=True)
    except Exception:
        return
    macs = load_macs()
    changed = False
    for line in out.splitlines():
        parts = line.split()
        if len(parts) >= 1 and parts[0] in wanted and "lladdr" in parts:
            mac = parts[parts.index("lladdr") + 1].lower()
            if mac and macs.get(parts[0]) != mac:
                macs[parts[0]] = mac
                changed = True
    if changed:
        save_macs(macs)


def known_macs(cfg):
    """MAC conocidas: las aprendidas (macs.json) más el mapa 'macs' de config."""
    macs = load_macs()
    for ip, mac in (cfg.get("macs") or {}).items():
        macs[str(ip)] = str(mac).lower()
    return macs


def _magic_packet(mac):
    clean = mac.replace(":", "").replace("-", "").replace(".", "").strip()
    if len(clean) != 12:
        raise ValueError(f"MAC inválida: {mac}")
    return b"\xff" * 6 + bytes.fromhex(clean) * 16


def broadcast_for(cfg):
    net = ipaddress.ip_network(cfg["subnet"], strict=False)
    return str(net.broadcast_address)


def wake(mac, broadcast, ports=(9, 7)):
    """Envía el magic packet de WoL a la MAC por la dirección de difusión."""
    pkt = _magic_packet(mac)
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    try:
        for port in ports:
            s.sendto(pkt, (broadcast, port))
    finally:
        s.close()


def local_ipv4s():
    """IPs IPv4 de este equipo (profesor), para excluirlas del rango."""
    ips = set()
    try:
        out = subprocess.check_output(["ip", "-o", "-4", "addr", "show"], text=True)
        for line in out.splitlines():
            parts = line.split()
            if len(parts) >= 4:
                ips.add(parts[3].split("/")[0])
    except Exception:
        pass
    return ips


def load_config(path):
    if not os.path.exists(path):
        sys.exit(f"No existe {path}. Copia config.example.json a config.json "
                 f"en {os.path.dirname(path)} y edítalo.")
    with open(path) as fh:
        cfg = json.load(fh)
    required = ["subnet", "ssh_user"]
    for key in required:
        if key not in cfg:
            sys.exit(f"Config: falta la clave obligatoria '{key}'")
    return cfg


def build_targets(cfg):
    """Lista de IPs de alumnos a partir de la subred, excluyendo profesor y
    las IPs indicadas en 'exclude', y respetando el rango de últimos octetos."""
    net = ipaddress.ip_network(cfg["subnet"], strict=False)
    lo, hi = cfg.get("host_range", [1, 254])
    exclude = set(cfg.get("exclude", [])) | local_ipv4s()
    gateway = cfg.get("gateway")
    if gateway:
        exclude.add(gateway)

    targets = []
    for host in net.hosts():
        last = int(str(host).split(".")[-1])
        if lo <= last <= hi and str(host) not in exclude:
            targets.append(str(host))
    return targets, str(net)


def run_on_host(ip, cfg, password, mode, list_path):
    """Conecta a un alumno, sube agent.sh (+ lista) y lo ejecuta con sudo."""
    user = cfg["ssh_user"]
    lan_cidr = cfg["subnet"]
    teacher_ip = cfg.get("teacher_ip", "")
    timeout = cfg.get("ssh_timeout", 5)

    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        client.connect(
            ip, username=user, password=password,
            timeout=timeout, banner_timeout=timeout, auth_timeout=timeout,
            look_for_keys=False, allow_agent=False,
        )
    except Exception as exc:
        return ip, False, f"sin conexión SSH ({exc.__class__.__name__})"

    try:
        sftp = client.open_sftp()
        sftp.put(AGENT_LOCAL, AGENT_REMOTE)
        if list_path:
            sftp.put(list_path, LIST_REMOTE)
        sftp.close()

        if mode in ("whitelist", "blockai"):
            cmd = (f"sudo -S -p '' bash {AGENT_REMOTE} {mode} "
                   f"{lan_cidr} {teacher_ip} {LIST_REMOTE}")
        elif mode == "blockall":
            cmd = (f"sudo -S -p '' bash {AGENT_REMOTE} blockall "
                   f"{lan_cidr} {teacher_ip}")
        else:  # restore / status / update
            cmd = f"sudo -S -p '' bash {AGENT_REMOTE} {mode}"

        # Actualizar descarga e instala paquetes: puede tardar muchos minutos.
        run_timeout = cfg.get("update_timeout", 1800) if mode == "update" else 30
        stdin, stdout, stderr = client.exec_command(cmd, timeout=run_timeout)
        stdin.write(password + "\n")
        stdin.flush()
        rc = stdout.channel.recv_exit_status()
        out = stdout.read().decode(errors="replace").strip()
        err = stderr.read().decode(errors="replace").strip()
        if rc == 0:
            return ip, True, out or "OK"
        return ip, False, (err or out or f"código {rc}")
    except Exception as exc:
        return ip, False, f"error: {exc}"
    finally:
        client.close()


def _connect(ip, cfg, password):
    """Abre una conexión SSH al equipo del alumno (como en run_on_host)."""
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    timeout = cfg.get("ssh_timeout", 5)
    client.connect(
        ip, username=cfg["ssh_user"], password=password,
        timeout=timeout, banner_timeout=timeout, auth_timeout=timeout,
        look_for_keys=False, allow_agent=False,
    )
    return client


def _run_agent(client, password, argv, timeout=30):
    """Ejecuta agent.sh con sudo y devuelve (rc, stdout, stderr)."""
    cmd = f"sudo -S -p '' bash {AGENT_REMOTE} " + argv
    stdin, stdout, stderr = client.exec_command(cmd, timeout=timeout)
    stdin.write(password + "\n")
    stdin.flush()
    rc = stdout.channel.recv_exit_status()
    out = stdout.read().decode(errors="replace").strip()
    err = stderr.read().decode(errors="replace").strip()
    return rc, out, err


def send_message(ip, cfg, password, text):
    """Muestra un aviso del profesor en el escritorio de un alumno concreto.

    Pensado para equipos del aula gestionados por el centro: avisa de forma
    visible al alumno (p. ej. que deje de consultar webs no permitidas).
    Devuelve (ip, ok, mensaje).
    """
    try:
        client = _connect(ip, cfg, password)
    except Exception as exc:
        return ip, False, f"sin conexión SSH ({exc.__class__.__name__})"
    try:
        sftp = client.open_sftp()
        sftp.put(AGENT_LOCAL, AGENT_REMOTE)
        with sftp.open(MSG_REMOTE, "w") as fh:
            fh.write(text)
        sftp.close()
        rc, out, err = _run_agent(client, password, f"message {MSG_REMOTE}")
        if rc == 0:
            return ip, True, out or "OK"
        return ip, False, (err or out or f"código {rc}")
    except Exception as exc:
        return ip, False, f"error: {exc}"
    finally:
        client.close()


def lock_screen(ip, cfg, password, unlock=False):
    """Bloquea (o desbloquea) la sesión gráfica de un alumno concreto.

    Usa loginctl en el equipo del alumno; lo respetan KDE y GNOME. Útil para
    detener a un alumno en el momento. Devuelve (ip, ok, mensaje).
    """
    try:
        client = _connect(ip, cfg, password)
    except Exception as exc:
        return ip, False, f"sin conexión SSH ({exc.__class__.__name__})"
    try:
        sftp = client.open_sftp()
        sftp.put(AGENT_LOCAL, AGENT_REMOTE)
        sftp.close()
        rc, out, err = _run_agent(client, password, "unlock" if unlock else "lock")
        if rc == 0:
            return ip, True, out or "OK"
        return ip, False, (err or out or f"código {rc}")
    except Exception as exc:
        return ip, False, f"error: {exc}"
    finally:
        client.close()


def power_off(ip, cfg, password):
    """Apaga el equipo de un alumno. Devuelve (ip, ok, mensaje)."""
    try:
        client = _connect(ip, cfg, password)
    except Exception as exc:
        return ip, False, f"sin conexión SSH ({exc.__class__.__name__})"
    try:
        sftp = client.open_sftp()
        sftp.put(AGENT_LOCAL, AGENT_REMOTE)
        sftp.close()
        rc, out, err = _run_agent(client, password, "poweroff")
        if rc == 0:
            return ip, True, out or "OK"
        return ip, False, (err or out or f"código {rc}")
    except Exception as exc:
        return ip, False, f"error: {exc}"
    finally:
        client.close()


def capture_screenshot(ip, cfg, password, out_dir, filename=None):
    """Captura el escritorio de un alumno y trae el PNG al equipo del profesor.

    Deja constancia de lo que se ve en pantalla para justificar una medida.
    Si 'filename' se indica, se guarda con ese nombre (se sobrescribe, útil para
    el mural de pantallas); si no, se usa un nombre con IP y marca de tiempo.
    Devuelve (ip, ok, mensaje, ruta_local|None).
    """
    try:
        client = _connect(ip, cfg, password)
    except Exception as exc:
        return ip, False, f"sin conexión SSH ({exc.__class__.__name__})", None
    try:
        sftp = client.open_sftp()
        sftp.put(AGENT_LOCAL, AGENT_REMOTE)
        rc, out, err = _run_agent(client, password, f"screenshot {SHOT_REMOTE}")
        if rc != 0:
            sftp.close()
            return ip, False, (err or out or f"código {rc}"), None
        os.makedirs(out_dir, exist_ok=True)
        if filename:
            local = os.path.join(out_dir, filename)
        else:
            stamp = time.strftime("%Y%m%d-%H%M%S")
            local = os.path.join(out_dir, f"{ip}_{stamp}.png")
        sftp.get(SHOT_REMOTE, local)
        try:
            sftp.remove(SHOT_REMOTE)
        except Exception:
            pass
        sftp.close()
        return ip, True, out or "OK", local
    except Exception as exc:
        return ip, False, f"error: {exc}", None
    finally:
        client.close()


def max_attempts_for(cfg, mode):
    """Nº total de intentos (1 inicial + reintentos) según el modo."""
    if mode in ("status", "update"):
        return 1          # consultar estado o actualizar no reintenta
    base = cfg.get("retries", 2)
    if mode == "restore":
        base = cfg.get("restore_retries", base)
    return max(1, base + 1)


def _ip_key(ip):
    try:
        return tuple(int(x) for x in ip.split("."))
    except ValueError:
        return (0,)


def ping_host(ip, timeout=1):
    """True si el equipo responde a un ping (1 paquete)."""
    try:
        r = subprocess.run(
            ["ping", "-c", "1", "-W", str(timeout), ip],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return r.returncode == 0
    except Exception:  # noqa: BLE001 (p. ej. 'ping' no instalado)
        return False


def ping_available(timeout=1):
    """Comprueba que 'ping' funciona en este equipo (evita filtrar de más si
    ping no está disponible o no tiene permisos)."""
    return ping_host("127.0.0.1", timeout)


def ping_sweep(ips, timeout=1, workers=64, cancelled=lambda: False):
    """Devuelve la lista de IPs que responden a ping, en paralelo."""
    alive = []
    workers = min(workers, len(ips)) or 1
    pool = concurrent.futures.ThreadPoolExecutor(max_workers=workers)
    try:
        futs = {pool.submit(ping_host, ip, timeout): ip for ip in ips}
        for fut in concurrent.futures.as_completed(futs):
            if cancelled():
                break
            if fut.result():
                alive.append(futs[fut])
    finally:
        pool.shutdown(wait=not cancelled(), cancel_futures=cancelled())
    alive = sorted(alive, key=_ip_key)
    if not cancelled():
        try:
            update_macs(alive)        # aprende MAC para poder encender por WoL
        except Exception:
            pass
    return alive


def drive_action(cfg, password, mode, list_path, targets, emit, note=None,
                 should_cancel=None, on_hosts=None):
    """Ejecuta la acción en todos los equipos y REINTENTA los que fallen.

    emit(ip, success, msg, final): se llama por cada equipo en cada ronda.
       'final' es True si no habrá más reintentos para ese equipo.
    note(texto): mensajes de cabecera de ronda (opcional).
    should_cancel(): si devuelve True, se aborta cuanto antes (opcional).
    on_hosts(encendidos, total): tras el ping, nº de equipos vivos (opcional).
    Devuelve (nº_ok, lista_de_ips_que_siguen_fallando).
    """
    cancelled = (lambda: bool(should_cancel and should_cancel()))
    max_attempts = max_attempts_for(cfg, mode)
    delay = cfg.get("retry_delay", 15)
    pending = list(targets)
    ok_total = 0

    track = mode in BLOCKING_MODES or mode == "restore"
    enforced = load_enforced() if track else set()

    # Barrido de ping: solo se procede con los equipos encendidos.
    if cfg.get("ping_first", True) and not cancelled():
        ptimeout = cfg.get("ping_timeout", 1)
        if ping_available(ptimeout):
            if note:
                note(f"Detectando equipos encendidos (ping) entre {len(pending)}…")
            total = len(pending)
            alive = ping_sweep(pending, ptimeout,
                               cfg.get("ping_workers", 64), cancelled)
            if not cancelled():
                off = total - len(alive)
                if note:
                    note(f"{len(alive)} encendido(s); {off} apagado(s), omitidos.")
                if on_hosts:
                    on_hosts(len(alive), total)
                pending = alive
                if not pending:
                    return 0, []
        elif note:
            note("Aviso: 'ping' no disponible; se intentará por SSH directamente.")

    for attempt in range(1, max_attempts + 1):
        if not pending or cancelled():
            break
        if attempt > 1 and note:
            note(f"Reintento {attempt - 1}/{max_attempts - 1} sobre "
                 f"{len(pending)} equipo(s)…")
        failed = []
        changed = False
        workers = min(cfg.get("parallelism", 20), len(pending))
        pool = concurrent.futures.ThreadPoolExecutor(max_workers=workers)
        try:
            futs = {pool.submit(run_on_host, ip, cfg, password, mode, list_path): ip
                    for ip in pending}
            for fut in concurrent.futures.as_completed(futs):
                if cancelled():
                    break
                ip, success, msg = fut.result()
                emit(ip, success, msg, success or attempt == max_attempts)
                if success:
                    ok_total += 1
                    if mode in BLOCKING_MODES and ip not in enforced:
                        enforced.add(ip); changed = True
                    elif mode == "restore" and ip in enforced:
                        enforced.discard(ip); changed = True
                else:
                    failed.append(ip)
        finally:
            # Si se cancela, descarta las tareas aún no iniciadas y no esperes.
            pool.shutdown(wait=not cancelled(), cancel_futures=cancelled())
        # Persistir tras cada ronda: si la app se cierra, el estado es fiel.
        if track and changed:
            save_enforced(enforced)
        pending = failed
        if cancelled():
            if note:
                note("Cancelado por el usuario.")
            break
        if pending and attempt < max_attempts:
            # Espera entre rondas, interrumpible si se cancela.
            for _ in range(delay):
                if cancelled():
                    break
                time.sleep(1)

    return ok_total, pending


def main():
    parser = argparse.ArgumentParser(description="Control de red y gestión del aula")
    parser.add_argument("action",
                        choices=["blockall", "whitelist", "blockai",
                                 "restore", "status", "update"])
    parser.add_argument("--config", default=os.path.join(DATA, "config.json"))
    args = parser.parse_args()

    if not os.path.exists(AGENT_LOCAL):
        sys.exit(f"No encuentro agent.sh en {AGENT_LOCAL}")
    cfg = load_config(args.config)

    # Lista de dominios según la acción.
    list_path = None
    if args.action == "whitelist":
        list_path = os.path.join(DATA, cfg.get("whitelist_file", "whitelist.txt"))
    elif args.action == "blockai":
        list_path = os.path.join(DATA, cfg.get("ai_blocklist_file", "ai-blocklist.txt"))
    if list_path and not os.path.exists(list_path):
        sys.exit(f"No encuentro la lista de dominios: {list_path}")

    targets, net = build_targets(cfg)

    pending_prev = load_enforced()
    if args.action == "restore":
        # Restaura también equipos pendientes de exámenes anteriores, aunque
        # ya no estén en el rango actual.
        targets = sorted(set(targets) | pending_prev)
    elif pending_prev:
        print(f"{YELLOW}Aviso: {len(pending_prev)} equipo(s) del examen anterior "
              f"sin restaurar: {', '.join(sorted(pending_prev))}")
        print(f"Ejecuta 'restore' para limpiarlos.{RESET}")

    if not targets:
        sys.exit("No hay equipos objetivo (revisa subnet/host_range/exclude).")

    print(f"Aula: {net}  |  acción: {args.action}  |  equipos: {len(targets)}")
    print(f"Excluido (profesor): {', '.join(sorted(local_ipv4s())) or '—'}")
    password = getpass.getpass(f"Contraseña sudo del usuario '{cfg['ssh_user']}': ")

    def emit(ip, success, msg, final):
        if success:
            first = msg.splitlines()[0] if msg else ""
            print(f"  {GREEN}✓{RESET} {ip:<15} {first}")
        elif final:
            print(f"  {RED}✗{RESET} {ip:<15} {msg}")
        else:
            print(f"  {YELLOW}✗{RESET} {ip:<15} {msg}  (se reintentará)")

    def note(text):
        print(f"  {YELLOW}↻ {text}{RESET}")

    ok, pending = drive_action(cfg, password, args.action, list_path, targets,
                               emit, note)
    fail = len(pending)
    print(f"\nResultado: {GREEN}{ok} OK{RESET}, {RED}{fail} con fallo{RESET}")
    if fail:
        print(f"{YELLOW}Sin respuesta tras los reintentos: {', '.join(pending)}")
        print(f"Suelen estar apagados o sin SSH.{RESET}")


if __name__ == "__main__":
    main()
