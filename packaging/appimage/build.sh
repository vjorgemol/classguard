#!/bin/bash
# Construye dist/ClassGuard-<versión>-x86_64.AppImage.
#
# Incluye un Python autónomo (python-appimage, manylinux2014 → glibc 2.17)
# con Flask y paramiko, de modo que funciona en Ubuntu 22.04 o posterior sin
# instalar nada. El runtime estático de appimagetool solo necesita fusermount3,
# que Ubuntu trae de serie (no hace falta libfuse2).
#
# Uso: packaging/appimage/build.sh [versión]   (por defecto, git describe)
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
PKG="$ROOT/packaging/appimage"
WORK="$ROOT/build/appimage"
DIST="$ROOT/dist"
PY_MINOR="3.12"
VERSION="${1:-$(git -C "$ROOT" describe --tags --always 2>/dev/null || echo dev)}"
VERSION="${VERSION#v}"

asset_url() {  # asset_url <repo> <tag> <regex>
    curl -fsSL "https://api.github.com/repos/$1/releases/tags/$2" |
        python3 -c 'import json,re,sys
for a in json.load(sys.stdin)["assets"]:
    if re.fullmatch(sys.argv[1], a["name"]):
        print(a["browser_download_url"]); break' "$3"
}

rm -rf "$WORK" && mkdir -p "$WORK" "$DIST"
cd "$WORK"

echo "→ Descargando Python $PY_MINOR y appimagetool…"
curl -fsSLo python.AppImage "$(asset_url niess/python-appimage "python$PY_MINOR" \
    "python$PY_MINOR\.[0-9]+-cp${PY_MINOR/./}-cp${PY_MINOR/./}-manylinux2014_x86_64\.AppImage")"
curl -fsSLo appimagetool "$(asset_url AppImage/appimagetool continuous 'appimagetool-x86_64\.AppImage')"
chmod +x python.AppImage appimagetool

echo "→ Preparando AppDir…"
./python.AppImage --appimage-extract >/dev/null
mv squashfs-root AppDir
APPDIR="$WORK/AppDir"
# Quita la identidad de la imagen de Python (escritorio, icono, AppRun).
rm -f "$APPDIR"/AppRun "$APPDIR"/.DirIcon "$APPDIR"/*.desktop "$APPDIR"/*.png
rm -rf "$APPDIR/usr/share/applications" "$APPDIR/usr/share/icons" \
       "$APPDIR/usr/share/metainfo" "$APPDIR/usr/share/tcltk"
ln -s "python$PY_MINOR" "$APPDIR/opt/python"
ln -s "python$PY_MINOR" "$APPDIR/opt/python/bin/python3"

echo "→ Instalando dependencias…"
"$APPDIR/opt/python/bin/python$PY_MINOR" -s -E -m pip install -q \
    --no-warn-script-location --disable-pip-version-check \
    -r "$ROOT/requirements.txt"

echo "→ Copiando ClassGuard…"
APP="$APPDIR/usr/share/classguard"
mkdir -p "$APP"
cp -r "$ROOT"/{classguard.py,classguard_web.py,agent.sh,config.example.json,whitelist.txt,ai-blocklist.txt,templates,LICENSE} "$APP/"
cp "$PKG/AppRun" "$APPDIR/AppRun"
cp "$PKG/classguard.desktop" "$APPDIR/"
mkdir -p "$APPDIR/usr/share/icons/hicolor/scalable/apps"
cp "$PKG/classguard.svg" "$APPDIR/usr/share/icons/hicolor/scalable/apps/"
cp "$PKG/classguard.svg" "$APPDIR/classguard.svg"
ln -s classguard.svg "$APPDIR/.DirIcon"
find "$APPDIR" -name __pycache__ -type d -prune -exec rm -rf {} +

echo "→ Empaquetando…"
OUT="$DIST/ClassGuard-$VERSION-x86_64.AppImage"
ARCH=x86_64 ./appimagetool --appimage-extract-and-run -n "$APPDIR" "$OUT" >/dev/null
echo "✓ $OUT"
