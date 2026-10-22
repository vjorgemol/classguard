# ClassGuard — control de red del aula durante exámenes

Herramienta para que el **profesor**, desde su equipo, controle el acceso a la
red de los equipos de los **alumnos** del aula durante un examen. Pensada para
equipos Ubuntu 22.04+ que el centro administra y en los que existe un usuario
con `sudo`.

> Es una herramienta de administración de una flota de equipos gestionados por
> el centro. No evade controles de terceros: aplica políticas de red a equipos
> sobre los que ya se tiene acceso administrativo legítimo.

## Qué hace

Tres funciones, más la vuelta atrás:

| Acción       | Efecto en los equipos de alumno |
|--------------|---------------------------------|
| `blockall`   | Corta **todo** internet. Se mantiene la LAN del aula (para poder seguir gestionándolos). |
| `whitelist`  | Corta internet **salvo** los dominios de `whitelist.txt`. |
| `blockai`    | Internet normal, pero **bloquea** los dominios de IA de `ai-blocklist.txt`. |
| `restore`    | Quita todas las reglas: los equipos vuelven a la normalidad. |
| `status`     | Muestra el estado de cada equipo. |

## Arquitectura

- `classguard.py` corre **solo en el equipo del profesor**. Recorre el rango de
  IPs del aula, entra por SSH en cada alumno con el usuario/contraseña que tú
  escribes, y ejecuta `agent.sh` con `sudo`.
- `agent.sh` se ejecuta **en cada alumno**. Crea una tabla `nftables` propia
  (`classguard`) con las reglas del modo elegido. Para `whitelist` y `blockai`
  instala un pequeño servicio (`classguard-resolver`) que re-resuelve los
  dominios cada 30 s y mantiene al día los conjuntos de IPs.
- **El equipo del profesor nunca se toca**: sus IPs locales se detectan con
  `ip -o -4 addr` y se excluyen del rango automáticamente.

## Instalación (equipo del profesor)

```bash
cd /home/vicdejor/Proyectos/exam-offline
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
cp config.example.json config.json
$EDITOR config.json          # ajusta subnet, teacher_ip, ssh_user, etc.
```

Los equipos de alumno **no necesitan instalación**: `agent.sh` se sube solo por
SSH en cada ejecución. Solo requieren tener SSH activo y el usuario con `sudo`.

## Uso con interfaz web (recomendado)

```bash
python3 classguard_web.py          # abre el navegador solo en http://127.0.0.1:8765
```

Opciones: `--port 9000` para cambiar el puerto, `--no-open` para no abrir el
navegador. Se sirve una página con un botón por cada modo (Cortar internet /
Solo lista blanca / Bloquear IA / Restaurar examen / Ver estado). Escribe la
contraseña `sudo`, pulsa el botón y el **registro** (panel derecho) muestra el
resultado equipo por equipo en vivo (✓/✗). Las acciones que bloquean piden
confirmación. La configuración se lee de `config.json`; puedes elegir otro
archivo con «Cargar .json…» o releer el actual con «Recargar config».

Mientras una operación está en curso, el botón **«Cancelar operación»** (barra
inferior) la aborta cuanto antes: descarta los equipos pendientes de contactar y
no espera a los reintentos. **«Ver estado» no reintenta** (consultar equipos
apagados no tiene sentido), así que termina en una sola pasada.

**Seguridad de la web:** el servidor se ata **solo a `127.0.0.1`** (nadie más en
la red lo ve) y la API exige un token aleatorio incrustado en la página, de modo
que ninguna otra web abierta en el navegador puede enviarle peticiones. La
contraseña `sudo` solo viaja del navegador al servidor local, en memoria.

## Uso por terminal

```bash
python3 classguard.py blockall     # corta todo internet
python3 classguard.py whitelist    # solo dominios de whitelist.txt
python3 classguard.py blockai      # bloquea IA (ai-blocklist.txt)
python3 classguard.py status       # ver estado
python3 classguard.py restore      # volver a la normalidad  ← al terminar el examen
```

Al lanzarlo te pedirá **una vez** la contraseña `sudo` del usuario (la misma
para SSH y para `sudo` en los alumnos). No se guarda en disco ni aparece en la
lista de procesos de los equipos de alumno (se pasa por stdin a `sudo -S`).

## Configuración (`config.json`)

- `subnet`: red del aula, p. ej. `"192.168.1.0/24"`.
- `host_range`: rango de últimos octetos de los alumnos, p. ej. `[1, 254]`.
- `teacher_ip`: IP del profesor (se permite expresamente en los alumnos).
- `gateway` / `exclude`: IPs a no tocar (router, servidores…).
- `ssh_user`: usuario con `sudo` existente en los equipos de alumno.
- `whitelist_file` / `ai_blocklist_file`: ficheros de dominios.
- `ping_first`: si es `true` (por defecto), antes de cada acción se hace un
  barrido de **ping** y solo se procede con los equipos encendidos; los apagados
  se omiten (evita esperar el timeout SSH en cada uno). Ponlo en `false` si en tu
  red el ping está bloqueado.
- `ping_timeout` / `ping_workers`: segundos por ping (1) y pings en paralelo (64).
- `retries`: reintentos sobre los equipos que fallen (por defecto 2).
- `restore_retries`: reintentos al restaurar (por defecto 5; los equipos que
  tardan en encenderse acaban limpiándose solos).
- `retry_delay`: segundos de espera entre rondas de reintento (por defecto 15).

## Reintento automático

Cualquier acción que falle en un equipo (apagado, sin red todavía…) se
**reintenta automáticamente** en rondas sucesivas, esperando `retry_delay`
segundos entre ellas. Mientras hay reintentos pendientes verás `↻ Reintento…`
en el registro, y cada equipo solo se marca como fallo definitivo (✗) cuando se
agotan los intentos. El `restore` usa más reintentos (`restore_retries`), de modo
que un equipo que se encienda tarde tras el examen también queda limpio sin
intervención. Esto se aplica igual en la interfaz web y en la terminal.

### Reintento al reabrir la app

Los equipos a los que se aplica un bloqueo se anotan en `state.json`, y se borran
de ahí cuando se restauran correctamente. Así, si cierras la app con equipos sin
restaurar (apagados, etc.):

- **Interfaz web:** al abrirla muestra un aviso «⚠ N equipo(s) sin restaurar»
  y un botón **«Restaurar pendientes»**. Escribe la contraseña y púlsalo: solo se
  restauran esos equipos (con reintentos), y desaparecen del aviso al lograrlo.
- **Terminal:** al arrancar avisa de los pendientes; `restore` limpia el aula
  **más** esos equipos anotados, aunque ya no estén en el rango actual.

`state.json` y `config.json` están en `.gitignore` (no se versionan).

## Limitaciones honestas

- El filtrado es **por IP resuelta del dominio**. Con CDNs las IPs rotan; el
  servicio re-resuelve cada 30 s, pero puede haber un breve desfase. Para la
  lista blanca, conviene usar dominios estables (el Moodle del centro, etc.).
- Un alumno **que conozca la contraseña `sudo`** puede deshacer las reglas
  (`sudo nft delete table inet classguard`). Esto es inevitable con control
  local: si el alumno es administrador de su equipo, siempre podrá revertir.
  Para un control a prueba de manipulación, el filtrado debe hacerse en el
  **router/cortafuegos del aula**, no en cada equipo.
- `blockai` bloquea por lista de dominios conocidos; amplíala según necesites.
  No detecta IA accedida por IP cruda ni servicios no listados.

## Recomendación

Para exámenes puntuales en equipos gestionados, esta herramienta es práctica y
reversible. Si buscas algo infranqueable, combínala con filtrado en el router
del aula o un DNS controlado (p. ej. las mismas listas en un Pi-hole/AdGuard).

## Licencia

[MIT](LICENSE) © 2026 Víctor Jorge Molina
