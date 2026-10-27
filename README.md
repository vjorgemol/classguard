# ClassGuard — control de red del aula durante exámenes

Herramienta para que el **profesor**, desde su equipo, controle el acceso a la
red de los equipos de los **alumnos** del aula durante un examen. Pensada para
equipos Ubuntu 22.04+ que el centro administra y en los que existe un usuario
con `sudo`.

> Es una herramienta de administración de una flota de equipos gestionados por
> el centro. No evade controles de terceros: aplica políticas de red a equipos
> sobre los que ya se tiene acceso administrativo legítimo.

## Descarga y manual

- **Descarga:** [última versión publicada](https://github.com/vjorgemol/classguard/releases/latest)
  (`classguard-vX.Y.Z.tar.xz`, listo para usar).
- **Manual de uso:** <https://vjorgemol.github.io/classguard/manual.html>

## Qué hace

Tres funciones, más la vuelta atrás:

| Acción       | Efecto en los equipos de alumno |
|--------------|---------------------------------|
| `blockall`   | Corta **todo** internet. Se mantiene la LAN del aula (para poder seguir gestionándolos). |
| `whitelist`  | Corta internet **salvo** los dominios de `whitelist.txt`. |
| `blockai`    | Internet normal, pero **bloquea** los dominios de IA de `ai-blocklist.txt`. |
| `restore`    | Quita todas las reglas: los equipos vuelven a la normalidad. |
| `status`     | Muestra el estado de cada equipo. |
| `update`     | **Actualiza el sistema** (`apt`) de los equipos encendidos. Botón «Actualizar equipos» en la interfaz web. |

Además, **por equipo concreto** (no a toda el aula):

| Acción       | Efecto en el equipo del alumno |
|--------------|---------------------------------|
| aviso        | Muestra un **mensaje del profesor** en la pantalla del alumno (p. ej. que deje de consultar un recurso no permitido). |
| captura      | Hace una **captura del escritorio** del alumno y la trae al equipo del profesor para dejar constancia. |

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

## AppImage (lo más sencillo)

En cada versión publicada hay un `ClassGuard-<versión>-x86_64.AppImage` que
incluye Python y todas las dependencias. Funciona en **Ubuntu 22.04 o
posterior** sin instalar nada:

```bash
chmod +x ClassGuard-*-x86_64.AppImage
./ClassGuard-*-x86_64.AppImage              # abre la interfaz web
./ClassGuard-*-x86_64.AppImage cli status   # uso por terminal
```

También se puede abrir con doble clic (activando antes «Permitir ejecutar como
programa» en sus propiedades). Si ya está abierto, volver a lanzarlo solo
muestra la ventana existente en el navegador.

Como el AppImage es de solo lectura, los datos editables se guardan en
**`~/.config/classguard/`**: `config.json`, `whitelist.txt`, `ai-blocklist.txt`,
`state.json`, `macs.json` (MAC aprendidas para WoL) y las capturas en `capturas/`.
La primera vez se crea con las listas por defecto y
`config.example.json`. La configuración se puede cargar desde la propia web con
«Cargar .json…».

Para construirlo: `packaging/appimage/build.sh` (deja el resultado en `dist/`).

## Instalación desde el código (equipo del profesor)

```bash
cd classguard              # carpeta descomprimida o clonada
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

El botón **«Salir»** (barra inferior) detiene el servidor. Avisa si quedan
equipos con bloqueo y no deja salir con una operación en curso. Cerrar solo la
pestaña del navegador no detiene la aplicación.

**Seguridad de la web:** el servidor se ata **solo a `127.0.0.1`** (nadie más en
la red lo ve) y la API exige un token aleatorio incrustado en la página, de modo
que ninguna otra web abierta en el navegador puede enviarle peticiones. La
contraseña `sudo` solo viaja del navegador al servidor local, en memoria.

### Aviso y captura a un equipo concreto

Se hacen desde la tarjeta de cada alumno en el mural de la pestaña
**«Pantallas»** (ver más abajo):

- **Aviso:** muestra un mensaje del profesor en el escritorio del alumno (un
  diálogo que el alumno debe cerrar o, si no es posible, una notificación).
  Útil para avisar en el momento de que deje de consultar un recurso no
  permitido.
- **Captura («📷»):** toma una captura del escritorio del alumno y la trae al
  equipo del profesor, donde queda guardada en `capturas/` (dentro de la carpeta
  de datos) con el nombre `IP_fecha-hora.png`. Las miniaturas aparecen en la
  tarjeta «Capturas guardadas»; al pulsarlas se abren a tamaño completo. Sirve
  para **dejar constancia** de lo que había en pantalla y justificar cualquier
  medida.

ClassGuard **detecta el escritorio** de cada alumno (KDE/Plasma o GNOME) y usa
la herramienta adecuada:

- **Captura:** `spectacle` en KDE, `gnome-screenshot` en GNOME (ambos funcionan
  en X11 y Wayland). Como respaldo prueba `grim` (Wayland wlroots) y
  `scrot`/`import` (X11).
- **Aviso:** `kdialog` en KDE, `zenity` en GNOME y, si no hay ninguno, una
  notificación `notify-send`.

Esas utilidades vienen de serie en la mayoría de instalaciones de escritorio,
pero conviene confirmarlo en un equipo del aula antes del examen.

### Mural de pantallas

La pestaña **«Pantallas»** muestra una rejilla con la pantalla de cada alumno
**encendido** (se capturan en paralelo, omitiendo los apagados). Desde ahí:

- **Pulsa sobre una pantalla** para enviar el aviso a ese alumno directamente,
  sin teclear la IP (el texto es el del recuadro superior; se pide confirmación).
- **«🔒»** bloquea la pantalla del alumno (vuelve a pulsarlo —ya como «🔓»— para
  desbloquearla). La tarjeta se marca en rojo mientras está bloqueada. Ver
  «[Cómo funciona el bloqueo](#cómo-funciona-el-bloqueo)» más abajo.
- **«📷»** guarda una captura con fecha y hora (constancia).
- **«⤢»** abre esa captura a tamaño completo.

La fila **«A todos»** aplica estas acciones a la vez (en paralelo). Sobre los
equipos **encendidos**: **Avisar** (con el texto del recuadro), **Bloquear**,
**Desbloquear** y **Apagar**. Y, aparte, **Encender** (Wake-on-LAN) sobre los
**apagados**. Cada una pide confirmación (el apagado, doble).

- **Apagar** se lanza con `systemctl poweroff -i`, así que no lo bloquean las
  sesiones abiertas de los alumnos; útil para apagar el aula al terminar.
- **Encender** envía un *magic packet* de Wake-on-LAN a la MAC de cada equipo.
  ClassGuard **aprende las MAC** solo: cada vez que hace un barrido de ping con
  los equipos encendidos (al abrir el mural o lanzar cualquier acción), guarda la
  correspondencia IP→MAC en `macs.json`. Así, otro día puede encenderlos aunque
  estén apagados. También puedes fijarlas a mano en `config.json`:

  ```json
  "macs": { "192.168.1.23": "aa:bb:cc:dd:ee:ff" }
  ```

  Requisitos del WoL: la **BIOS/UEFI** y la tarjeta de red de cada alumno deben
  tener Wake-on-LAN **activado** (en Linux, `sudo ethtool -s eth0 wol g`), y el
  equipo del profesor debe estar en la **misma red** (dominio de difusión). Si un
  equipo nunca se ha visto encendido y no está en `macs.json` ni en config, no se
  puede encender (ClassGuard avisa de que aún no conoce ninguna MAC).

#### Cómo funciona el bloqueo

- **En X11 el bloqueo es fuerte:** el agente (como root) **deshabilita el teclado
  y el ratón** del alumno con `xinput` y muestra un aviso. Como el alumno no tiene
  `sudo`, **no puede reactivarlos**; solo el profesor los reactiva con
  «Desbloquear». `xinput` viene de serie en el escritorio de Ubuntu/Kubuntu.
- **En Wayland (o si no hay `xinput`) el bloqueo es débil:** Wayland impide por
  seguridad que un programa capture la entrada de otra sesión, así que se recurre
  al bloqueo de sesión de `logind`, que el alumno **puede** quitar con su propia
  contraseña. El agente lo indica en el registro como `lock DEBIL`.
- En ningún caso es infranqueable: con acceso físico el alumno puede cambiar de
  terminal virtual (Ctrl+Alt+F3) o reiniciar. Es para detenerle en el momento,
  no una barrera total (para eso, el control va en el router del aula).
- **«Actualizar pantallas»** rehace el barrido; marca **«auto cada N s»** para
  refrescarlo solo. Las imágenes del mural se sobrescriben por equipo
  (`wall_<IP>.png`), así que no acumulan archivos; las capturas de la pestaña
  «Examen» sí se guardan con fecha y hora para dejar constancia.

> Como el resto de ClassGuard, es una función de administración de equipos
> gestionados por el centro. Úsala de forma transparente y conforme a la política
> del centro sobre el uso de los equipos del aula durante los exámenes.

## Uso por terminal

```bash
python3 classguard.py blockall     # corta todo internet
python3 classguard.py whitelist    # solo dominios de whitelist.txt
python3 classguard.py blockai      # bloquea IA (ai-blocklist.txt)
python3 classguard.py status       # ver estado
python3 classguard.py restore      # volver a la normalidad  ← al terminar el examen
python3 classguard.py update       # actualizar el sistema de los alumnos (apt)
```

`update` ejecuta en cada alumno `apt-get update` y `apt-get upgrade
--with-new-pkgs` (instala dependencias nuevas, como kernels, pero nunca
desinstala paquetes; conserva los ficheros de configuración locales). Necesita
internet, así que se niega en los equipos con reglas de ClassGuard activas:
restaura antes. No se reintenta; el registro indica cuántos paquetes se
actualizaron y si el equipo **requiere reiniciar**. La salida completa de apt
queda en `/var/log/classguard-update.log` de cada alumno.

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
- `update_timeout`: segundos máximos de espera por equipo al actualizar
  (por defecto 1800).

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
- El **bloqueo de pantalla** es fuerte en X11 (se deshabilitan teclado y ratón
  como root; el alumno sin `sudo` no los reactiva) y débil en Wayland (bloqueo de
  sesión, que el alumno quita con su contraseña). En ningún caso impide cambiar de
  terminal virtual o reiniciar. Ver «[Cómo funciona el bloqueo](#cómo-funciona-el-bloqueo)».

## Recomendación

Para exámenes puntuales en equipos gestionados, esta herramienta es práctica y
reversible. Si buscas algo infranqueable, combínala con filtrado en el router
del aula o un DNS controlado (p. ej. las mismas listas en un Pi-hole/AdGuard).

## Licencia

[MIT](LICENSE) © 2026 Víctor Jorge Molina
