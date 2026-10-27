#!/usr/bin/env python3
"""
classguard_web.py — Interfaz WEB local para el profesor.

Sirve una página en http://127.0.0.1:8765 (solo localhost) con botones para
cada modo y registro en vivo. Reutiliza toda la lógica
de classguard.py (SSH + nftables + estado + reintentos).

Uso:
    python3 classguard_web.py           # abre el navegador solo
    python3 classguard_web.py --no-open # no abrir navegador
    python3 classguard_web.py --port 9000

Seguridad: el servidor se ata únicamente a 127.0.0.1 (nadie más en la red lo
ve) y las llamadas a la API exigen un token aleatorio incrustado en la página,
lo que impide que otra web del navegador haga peticiones a este servidor.
"""

import argparse
import json
import os
import queue
import secrets
import socket
import threading
import webbrowser

try:
    from flask import (Flask, Response, jsonify, render_template, request,
                       send_from_directory)
except ImportError:
    raise SystemExit("Falta Flask. Instala con: pip install -r requirements.txt")

import classguard as cg

HERE = os.path.dirname(os.path.abspath(__file__))
TOKEN = secrets.token_urlsafe(16)
SHOTS_DIR = os.path.join(cg.DATA, "capturas")

LABELS = {
    "blockall":  "Cortar internet",
    "whitelist": "Solo lista blanca",
    "blockai":   "Bloquear IA",
    "restore":   "Restaurar examen",
    "status":    "Ver estado",
    "update":    "Actualizar equipos",
}

app = Flask(__name__, template_folder=os.path.join(HERE, "templates"))

# --- Estado del proceso (un único servidor local) --------------------------
_lock = threading.Lock()
_running = False
_cancel_event = threading.Event()
_subscribers = []            # colas SSE
_cfg = None
_cfg_error = None
_screens_running = False     # hay un barrido del mural de pantallas en curso
_bulk_running = False        # hay una acción masiva (aviso/bloqueo a todos) en curso


# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------
def load_cfg():
    global _cfg, _cfg_error
    path = os.path.join(cg.DATA, "config.json")
    if not os.path.exists(path):
        _cfg, _cfg_error = None, ("No existe config.json. Pulsa «Cargar .json…» "
                                  "o copia config.example.json a config.json en "
                                  f"{cg.DATA}, edítalo y pulsa «Recargar config».")
        return
    try:
        _cfg = cg.load_config(path)
        _cfg_error = None
    except SystemExit as exc:
        _cfg, _cfg_error = None, str(exc)
    except Exception as exc:  # noqa: BLE001
        _cfg, _cfg_error = None, f"Error leyendo config.json: {exc}"


def info_payload():
    data = {"pending": sorted(cg.load_enforced()), "running": _running,
            "error": _cfg_error}
    if _cfg:
        try:
            targets, net = cg.build_targets(_cfg)
            data.update(ok=True, net=net, count=len(targets),
                        ssh_user=_cfg.get("ssh_user", "?"),
                        excluded=sorted(cg.local_ipv4s()))
        except Exception as exc:  # noqa: BLE001
            data.update(ok=False, error=f"config.json inválido: {exc}")
    else:
        data["ok"] = False
    return data


# ---------------------------------------------------------------------------
# SSE (registro + estado en vivo)
# ---------------------------------------------------------------------------
def publish(event):
    for q in list(_subscribers):
        q.put(event)


def _sse(event):
    return f"data: {json.dumps(event)}\n\n"


@app.route("/api/events")
def events():
    if request.args.get("t") != TOKEN:
        return Response("forbidden", status=403)

    def stream():
        q = queue.Queue()
        _subscribers.append(q)
        try:
            yield _sse({"type": "snapshot", **info_payload()})
            while True:
                yield _sse(q.get())
        except GeneratorExit:
            pass
        finally:
            if q in _subscribers:
                _subscribers.remove(q)
    return Response(stream(), mimetype="text/event-stream")


# ---------------------------------------------------------------------------
# Ejecución de acciones (en hilo), reutiliza cg.drive_action
# ---------------------------------------------------------------------------
def _list_path_for(mode):
    if mode == "whitelist":
        return os.path.join(cg.DATA, _cfg.get("whitelist_file", "whitelist.txt"))
    if mode == "blockai":
        return os.path.join(cg.DATA, _cfg.get("ai_blocklist_file", "ai-blocklist.txt"))
    return None


def _run_action(mode, password, targets):
    global _running
    with _lock:
        if _running:
            return False
        _running = True
    _cancel_event.clear()
    publish({"type": "clear"})
    publish({"type": "run", "running": True})
    publish({"type": "head",
             "text": f"▶ {LABELS[mode]} — {len(targets)} equipos"})
    list_path = _list_path_for(mode)

    def emit(ip, ok, msg, final):
        first = msg.splitlines()[0] if msg else ""
        if ok:
            publish({"type": "log", "level": "ok", "text": f"✓ {ip:<15} {first}"})
        else:
            tail = "" if final else "  (se reintentará)"
            publish({"type": "log", "level": "err",
                     "text": f"✗ {ip:<15} {msg}{tail}"})

    def note(text):
        publish({"type": "log", "level": "info", "text": f"↻ {text}"})

    def on_hosts(alive, total):
        publish({"type": "hosts", "alive": alive, "total": total})

    try:
        ok, pending = cg.drive_action(_cfg, password, mode, list_path,
                                      targets, emit, note,
                                      should_cancel=_cancel_event.is_set,
                                      on_hosts=on_hosts)
    finally:
        _running = False

    publish({"type": "log", "level": "info",
             "text": f"Resultado: {ok} OK, {len(pending)} con fallo"})
    if pending:
        publish({"type": "log", "level": "err",
                 "text": f"Sin respuesta tras reintentos: {', '.join(pending)}"})
    publish({"type": "run", "running": False})
    publish({"type": "info", **info_payload()})


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------
def _check_token():
    return request.headers.get("X-Token") == TOKEN


@app.route("/")
def index():
    return render_template("index.html", token=TOKEN)


@app.route("/api/info")
def api_info():
    if not _check_token():
        return jsonify(error="forbidden"), 403
    return jsonify(info_payload())


@app.route("/api/reload", methods=["POST"])
def api_reload():
    if not _check_token():
        return jsonify(error="forbidden"), 403
    load_cfg()
    publish({"type": "info", **info_payload()})
    return jsonify(info_payload())


@app.route("/api/upload_config", methods=["POST"])
def api_upload_config():
    """Recibe el contenido de un .json elegido en el navegador, lo valida y lo
    guarda como config.json."""
    if not _check_token():
        return jsonify(error="forbidden"), 403
    if _running:
        return jsonify(error="hay una operación en curso"), 409
    body = request.get_json(force=True, silent=True) or {}
    content = body.get("content", "")
    try:
        data = json.loads(content)
    except Exception as exc:  # noqa: BLE001
        return jsonify(error=f"JSON no válido: {exc}"), 400
    if not isinstance(data, dict):
        return jsonify(error="el archivo no es un objeto JSON"), 400
    for key in ("subnet", "ssh_user"):
        if key not in data:
            return jsonify(error=f"falta la clave obligatoria '{key}'"), 400
    try:
        with open(os.path.join(cg.DATA, "config.json"), "w") as fh:
            json.dump(data, fh, indent=2, ensure_ascii=False)
    except Exception as exc:  # noqa: BLE001
        return jsonify(error=f"no se pudo guardar config.json: {exc}"), 500
    load_cfg()
    publish({"type": "info", **info_payload()})
    return jsonify(info_payload())


@app.route("/api/action", methods=["POST"])
def api_action():
    if not _check_token():
        return jsonify(error="forbidden"), 403
    body = request.get_json(force=True, silent=True) or {}
    mode = body.get("mode")
    password = body.get("password", "")
    if mode not in LABELS:
        return jsonify(error="acción desconocida"), 400
    if _cfg is None:
        return jsonify(error="config.json no válido"), 400
    if not password:
        return jsonify(error="falta la contraseña"), 400
    if _running:
        return jsonify(error="ya hay una operación en curso"), 409
    try:
        targets, _ = cg.build_targets(_cfg)
    except Exception as exc:  # noqa: BLE001
        return jsonify(error=f"config inválida: {exc}"), 400
    if not targets:
        return jsonify(error="no hay equipos objetivo"), 400

    threading.Thread(target=_run_action,
                     args=(mode, password, targets), daemon=True).start()
    return jsonify(started=True)


@app.route("/api/restore_pending", methods=["POST"])
def api_restore_pending():
    if not _check_token():
        return jsonify(error="forbidden"), 403
    body = request.get_json(force=True, silent=True) or {}
    password = body.get("password", "")
    enforced = sorted(cg.load_enforced())
    if not enforced:
        return jsonify(error="no hay equipos pendientes"), 400
    if _cfg is None:
        return jsonify(error="config.json no válido"), 400
    if not password:
        return jsonify(error="falta la contraseña"), 400
    if _running:
        return jsonify(error="ya hay una operación en curso"), 409
    threading.Thread(target=_run_action,
                     args=("restore", password, enforced), daemon=True).start()
    return jsonify(started=True)


def _valid_target(ip):
    """La IP debe ser una IPv4 válida y estar dentro de la subred del aula."""
    try:
        import ipaddress
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    try:
        net = ipaddress.ip_network(_cfg["subnet"], strict=False)
    except Exception:
        return False
    return addr in net


def _per_host_precheck(ip, password):
    """Validaciones comunes a las acciones por equipo. Devuelve un error
    (texto, código) o None si todo está correcto."""
    if _cfg is None:
        return "config.json no válido", 400
    if not ip or not _valid_target(ip):
        return "IP no válida o fuera de la subred del aula", 400
    if not password:
        return "falta la contraseña", 400
    return None


@app.route("/api/message", methods=["POST"])
def api_message():
    if not _check_token():
        return jsonify(error="forbidden"), 403
    body = request.get_json(force=True, silent=True) or {}
    ip = (body.get("ip") or "").strip()
    text = (body.get("text") or "").strip()
    password = body.get("password", "")
    err = _per_host_precheck(ip, password)
    if err:
        return jsonify(error=err[0]), err[1]
    if not text:
        return jsonify(error="falta el mensaje"), 400

    def worker():
        publish({"type": "log", "level": "info", "text": f"✉ Enviando aviso a {ip}…"})
        _, ok, msg = cg.send_message(ip, _cfg, password, text)
        publish({"type": "log", "level": "ok" if ok else "err",
                 "text": f"{'✓' if ok else '✗'} {ip:<15} {msg}"})

    threading.Thread(target=worker, daemon=True).start()
    return jsonify(started=True)


@app.route("/api/screenshot", methods=["POST"])
def api_screenshot():
    if not _check_token():
        return jsonify(error="forbidden"), 403
    body = request.get_json(force=True, silent=True) or {}
    ip = (body.get("ip") or "").strip()
    password = body.get("password", "")
    err = _per_host_precheck(ip, password)
    if err:
        return jsonify(error=err[0]), err[1]

    def worker():
        publish({"type": "log", "level": "info", "text": f"📷 Capturando pantalla de {ip}…"})
        _, ok, msg, local = cg.capture_screenshot(ip, _cfg, password, SHOTS_DIR)
        publish({"type": "log", "level": "ok" if ok else "err",
                 "text": f"{'✓' if ok else '✗'} {ip:<15} {msg}"})
        if ok and local:
            publish({"type": "shot", "src": "host", "ip": ip,
                     "file": os.path.basename(local)})

    threading.Thread(target=worker, daemon=True).start()
    return jsonify(started=True)


@app.route("/api/lock", methods=["POST"])
def api_lock():
    if not _check_token():
        return jsonify(error="forbidden"), 403
    body = request.get_json(force=True, silent=True) or {}
    ip = (body.get("ip") or "").strip()
    password = body.get("password", "")
    unlock = bool(body.get("unlock"))
    err = _per_host_precheck(ip, password)
    if err:
        return jsonify(error=err[0]), err[1]

    def worker():
        verb = "Desbloqueando" if unlock else "Bloqueando"
        publish({"type": "log", "level": "info", "text": f"🔒 {verb} pantalla de {ip}…"})
        _, ok, msg = cg.lock_screen(ip, _cfg, password, unlock=unlock)
        publish({"type": "log", "level": "ok" if ok else "err",
                 "text": f"{'✓' if ok else '✗'} {ip:<15} {msg}"})
        if ok:
            publish({"type": "lock", "ip": ip, "locked": (not unlock)})

    threading.Thread(target=worker, daemon=True).start()
    return jsonify(started=True)


def _alive_targets():
    """Equipos objetivo encendidos (ping previo si está activado)."""
    targets, _ = cg.build_targets(_cfg)
    if _cfg.get("ping_first", True):
        pt = _cfg.get("ping_timeout", 1)
        if cg.ping_available(pt):
            return cg.ping_sweep(targets, pt, _cfg.get("ping_workers", 64))
    return targets


def _bulk_precheck(password):
    """Validaciones y reserva del cerrojo para una acción masiva."""
    global _bulk_running
    if _cfg is None:
        return "config.json no válido", 400
    if not password:
        return "falta la contraseña", 400
    try:
        targets, _ = cg.build_targets(_cfg)
    except Exception as exc:  # noqa: BLE001
        return f"config inválida: {exc}", 400
    if not targets:
        return "no hay equipos objetivo", 400
    with _lock:
        if _bulk_running:
            return "ya hay una acción masiva en curso", 409
        _bulk_running = True
    return None


def _run_bulk(kind, password, text=None, unlock=False):
    """Aplica una acción por equipo a todos los encendidos, en paralelo."""
    global _bulk_running
    import concurrent.futures as cf
    try:
        alive = _alive_targets()
        titles = {"message": "Aviso a todos",
                  "lock": "Desbloquear todos" if unlock else "Bloquear todos",
                  "poweroff": "Apagar todos"}
        publish({"type": "log", "level": "info",
                 "text": f"▶ {titles[kind]} — {len(alive)} equipo(s) encendido(s)"})
        if not alive:
            return
        workers = min(_cfg.get("parallelism", 20), len(alive)) or 1

        def one(ip):
            if kind == "message":
                return cg.send_message(ip, _cfg, password, text)
            if kind == "poweroff":
                return cg.power_off(ip, _cfg, password)
            return cg.lock_screen(ip, _cfg, password, unlock=unlock)

        with cf.ThreadPoolExecutor(max_workers=workers) as pool:
            futs = {pool.submit(one, ip): ip for ip in alive}
            for fut in cf.as_completed(futs):
                ip = futs[fut]
                try:
                    _, ok, msg = fut.result()
                except Exception as exc:  # noqa: BLE001
                    ok, msg = False, str(exc)
                publish({"type": "log", "level": "ok" if ok else "err",
                         "text": f"{'✓' if ok else '✗'} {ip:<15} {msg}"})
                if kind == "lock" and ok:
                    publish({"type": "lock", "ip": ip, "locked": (not unlock)})
                elif kind == "poweroff" and ok:
                    publish({"type": "screenfail", "ip": ip, "msg": "apagado"})
        publish({"type": "log", "level": "info", "text": f"Fin: {titles[kind]}"})
    finally:
        _bulk_running = False


@app.route("/api/message_all", methods=["POST"])
def api_message_all():
    if not _check_token():
        return jsonify(error="forbidden"), 403
    body = request.get_json(force=True, silent=True) or {}
    text = (body.get("text") or "").strip()
    password = body.get("password", "")
    if not text:
        return jsonify(error="falta el mensaje"), 400
    err = _bulk_precheck(password)
    if err:
        return jsonify(error=err[0]), err[1]
    threading.Thread(target=_run_bulk, args=("message", password),
                     kwargs={"text": text}, daemon=True).start()
    return jsonify(started=True)


@app.route("/api/lock_all", methods=["POST"])
def api_lock_all():
    if not _check_token():
        return jsonify(error="forbidden"), 403
    body = request.get_json(force=True, silent=True) or {}
    password = body.get("password", "")
    unlock = bool(body.get("unlock"))
    err = _bulk_precheck(password)
    if err:
        return jsonify(error=err[0]), err[1]
    threading.Thread(target=_run_bulk, args=("lock", password),
                     kwargs={"unlock": unlock}, daemon=True).start()
    return jsonify(started=True)


@app.route("/api/poweroff_all", methods=["POST"])
def api_poweroff_all():
    if not _check_token():
        return jsonify(error="forbidden"), 403
    body = request.get_json(force=True, silent=True) or {}
    password = body.get("password", "")
    err = _bulk_precheck(password)
    if err:
        return jsonify(error=err[0]), err[1]
    threading.Thread(target=_run_bulk, args=("poweroff", password),
                     daemon=True).start()
    return jsonify(started=True)


@app.route("/api/wake_all", methods=["POST"])
def api_wake_all():
    """Enciende por Wake-on-LAN todos los equipos con MAC conocida."""
    global _bulk_running
    if not _check_token():
        return jsonify(error="forbidden"), 403
    if _cfg is None:
        return jsonify(error="config.json no válido"), 400
    with _lock:
        if _bulk_running:
            return jsonify(error="ya hay una acción masiva en curso"), 409
        _bulk_running = True

    def worker():
        global _bulk_running
        try:
            macs = cg.known_macs(_cfg)
            if not macs:
                publish({"type": "log", "level": "err",
                         "text": "No hay MAC conocidas todavía. Con los equipos "
                                 "encendidos, pulsa «Actualizar pantallas» (o "
                                 "cualquier acción) una vez para aprenderlas; "
                                 "o define 'macs' en config.json."})
                return
            try:
                bcast = cg.broadcast_for(_cfg)
            except Exception as exc:  # noqa: BLE001
                publish({"type": "log", "level": "err", "text": f"subnet inválida: {exc}"})
                return
            publish({"type": "log", "level": "info",
                     "text": f"▶ Encender por WoL — {len(macs)} equipo(s) con MAC conocida"})
            for ip in sorted(macs, key=cg._ip_key):
                mac = macs[ip]
                try:
                    cg.wake(mac, bcast)
                    publish({"type": "log", "level": "ok",
                             "text": f"✓ {ip:<15} magic packet → {mac}"})
                except Exception as exc:  # noqa: BLE001
                    publish({"type": "log", "level": "err",
                             "text": f"✗ {ip:<15} {exc}"})
            publish({"type": "log", "level": "info", "text": "Fin: Encender por WoL"})
        finally:
            _bulk_running = False

    threading.Thread(target=worker, daemon=True).start()
    return jsonify(started=True)


@app.route("/api/screens", methods=["POST"])
def api_screens():
    """Captura en paralelo la pantalla de todos los equipos encendidos del aula
    y las publica una a una para el mural ('Pantallas')."""
    global _screens_running
    if not _check_token():
        return jsonify(error="forbidden"), 403
    body = request.get_json(force=True, silent=True) or {}
    password = body.get("password", "")
    if _cfg is None:
        return jsonify(error="config.json no válido"), 400
    if not password:
        return jsonify(error="falta la contraseña"), 400
    try:
        targets, _ = cg.build_targets(_cfg)
    except Exception as exc:  # noqa: BLE001
        return jsonify(error=f"config inválida: {exc}"), 400
    if not targets:
        return jsonify(error="no hay equipos objetivo"), 400
    with _lock:
        if _screens_running:
            return jsonify(error="ya hay un barrido de pantallas en curso"), 409
        _screens_running = True

    threading.Thread(target=_run_screens, args=(password, targets),
                     daemon=True).start()
    return jsonify(started=True)


def _run_screens(password, targets):
    global _screens_running
    import concurrent.futures as cf
    try:
        alive = targets
        if _cfg.get("ping_first", True):
            ptimeout = _cfg.get("ping_timeout", 1)
            if cg.ping_available(ptimeout):
                alive = cg.ping_sweep(targets, ptimeout,
                                      _cfg.get("ping_workers", 64))
        publish({"type": "screens", "phase": "start", "total": len(alive),
                 "alive": alive})
        if not alive:
            return
        done = 0
        workers = min(_cfg.get("parallelism", 20), len(alive)) or 1
        with cf.ThreadPoolExecutor(max_workers=workers) as pool:
            futs = {pool.submit(cg.capture_screenshot, ip, _cfg, password,
                                SHOTS_DIR, f"wall_{ip}.png"): ip
                    for ip in alive}
            for fut in cf.as_completed(futs):
                ip = futs[fut]
                try:
                    _, ok, msg, local = fut.result()
                except Exception as exc:  # noqa: BLE001
                    ok, local, msg = False, None, str(exc)
                done += 1
                if ok and local:
                    publish({"type": "shot", "src": "wall", "ip": ip,
                             "file": os.path.basename(local)})
                else:
                    publish({"type": "screenfail", "ip": ip, "msg": msg})
                publish({"type": "screens", "phase": "progress",
                         "done": done, "total": len(alive)})
        publish({"type": "screens", "phase": "done",
                 "done": done, "total": len(alive)})
    finally:
        _screens_running = False


@app.route("/api/capture")
def api_capture():
    # El <img> de la página no puede enviar cabeceras; el token va por query.
    if request.args.get("t") != TOKEN:
        return Response("forbidden", status=403)
    name = request.args.get("file", "")
    if "/" in name or "\\" in name or ".." in name:
        return Response("bad request", status=400)
    return send_from_directory(SHOTS_DIR, name)


@app.route("/api/cancel_action", methods=["POST"])
def api_cancel_action():
    if not _check_token():
        return jsonify(error="forbidden"), 403
    if _running:
        _cancel_event.set()
    return jsonify(ok=True)


@app.route("/api/shutdown", methods=["POST"])
def api_shutdown():
    if not _check_token():
        return jsonify(error="forbidden"), 403
    if _running:
        return jsonify(error="hay una operación en curso; cancélala antes de salir"), 409
    publish({"type": "shutdown"})
    # Se cierra tras responder, para que la página reciba la confirmación.
    threading.Timer(0.5, lambda: os._exit(0)).start()
    return jsonify(ok=True)


def _port_in_use(port):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        return s.connect_ex(("127.0.0.1", port)) == 0


def main():
    parser = argparse.ArgumentParser(description="Interfaz web de ClassGuard")
    parser.add_argument("--port", type=int, default=8765)
    parser.add_argument("--no-open", action="store_true",
                        help="no abrir el navegador automáticamente")
    args = parser.parse_args()

    url = f"http://127.0.0.1:{args.port}/"
    if _port_in_use(args.port):
        # Ya hay una instancia abierta (p. ej. doble clic otra vez en el
        # AppImage): basta con mostrarla.
        print(f"ClassGuard ya está en marcha en {url}")
        if not args.no_open:
            webbrowser.open(url)
        return

    load_cfg()
    print(f"ClassGuard web en {url}")
    print("Pulsa Ctrl+C para detener.")
    if not args.no_open:
        threading.Timer(0.8, lambda: webbrowser.open(url)).start()
    # host fijo a localhost; threaded para que SSE no bloquee.
    app.run(host="127.0.0.1", port=args.port, threaded=True)


if __name__ == "__main__":
    main()
