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
import threading
import webbrowser

try:
    from flask import Flask, Response, jsonify, render_template, request
except ImportError:
    raise SystemExit("Falta Flask. Instala con: pip install -r requirements.txt")

import classguard as cg

HERE = os.path.dirname(os.path.abspath(__file__))
TOKEN = secrets.token_urlsafe(16)

LABELS = {
    "blockall":  "Cortar internet",
    "whitelist": "Solo lista blanca",
    "blockai":   "Bloquear IA",
    "restore":   "Restaurar examen",
    "status":    "Ver estado",
}

app = Flask(__name__, template_folder=os.path.join(HERE, "templates"))

# --- Estado del proceso (un único servidor local) --------------------------
_lock = threading.Lock()
_running = False
_cancel_event = threading.Event()
_subscribers = []            # colas SSE
_cfg = None
_cfg_error = None


# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------
def load_cfg():
    global _cfg, _cfg_error
    path = os.path.join(HERE, "config.json")
    if not os.path.exists(path):
        _cfg, _cfg_error = None, ("No existe config.json. Copia "
                                  "config.example.json a config.json, edítalo y "
                                  "pulsa «Recargar config».")
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
        return os.path.join(HERE, _cfg.get("whitelist_file", "whitelist.txt"))
    if mode == "blockai":
        return os.path.join(HERE, _cfg.get("ai_blocklist_file", "ai-blocklist.txt"))
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
        with open(os.path.join(HERE, "config.json"), "w") as fh:
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


@app.route("/api/cancel_action", methods=["POST"])
def api_cancel_action():
    if not _check_token():
        return jsonify(error="forbidden"), 403
    if _running:
        _cancel_event.set()
    return jsonify(ok=True)


def main():
    parser = argparse.ArgumentParser(description="Interfaz web de ClassGuard")
    parser.add_argument("--port", type=int, default=8765)
    parser.add_argument("--no-open", action="store_true",
                        help="no abrir el navegador automáticamente")
    args = parser.parse_args()

    load_cfg()
    url = f"http://127.0.0.1:{args.port}/"
    print(f"ClassGuard web en {url}")
    print("Pulsa Ctrl+C para detener.")
    if not args.no_open:
        threading.Timer(0.8, lambda: webbrowser.open(url)).start()
    # host fijo a localhost; threaded para que SSE no bloquee.
    app.run(host="127.0.0.1", port=args.port, threaded=True)


if __name__ == "__main__":
    main()
