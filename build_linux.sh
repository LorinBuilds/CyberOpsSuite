#!/usr/bin/env bash
# build_linux.sh — Build an AppImage for CyberOpsSuite
# Usage: bash build_linux.sh
# Requirements: python3, pip, curl (appimagetool is downloaded automatically)

set -euo pipefail

PROJECT_ROOT="$(cd "$(dirname "$0")" && pwd)"
cd "$PROJECT_ROOT"

APP_NAME="CyberOpsSuite"
APP_VERSION="1.3.0"
DIST_DIR="${PROJECT_ROOT}/dist_linux"
BUILD_DIR="${PROJECT_ROOT}/build_linux"
APPDIR="${BUILD_DIR}/${APP_NAME}.AppDir"
TOOLS_DIR="${BUILD_DIR}/tools"

ARCH="$(uname -m)"
if [[ "$ARCH" == "x86_64" || "$ARCH" == "amd64" ]]; then
    APPIMAGE_ARCH="x86_64"
elif [[ "$ARCH" == "aarch64" || "$ARCH" == "arm64" ]]; then
    APPIMAGE_ARCH="aarch64"
else
    echo "Unsupported architecture: $ARCH"
    exit 1
fi

echo "=== 1. Installing PyInstaller (if needed) ==="
python3 -m pip install --quiet pyinstaller

echo "=== 2. Building with PyInstaller ==="
python3 -m PyInstaller \
    --noconfirm \
    --clean \
    --onedir \
    --windowed \
    --name="${APP_NAME}" \
    --distpath="${DIST_DIR}" \
    --workpath="${BUILD_DIR}/work" \
    --specpath="${BUILD_DIR}" \
    --paths="${PROJECT_ROOT}" \
    --collect-submodules=core \
    --collect-submodules=dashboard \
    --collect-submodules=ip_rotator \
    --collect-data=customtkinter \
    "${PROJECT_ROOT}/dashboard/main.py"

echo "=== 3. Preparing AppDir ==="
rm -rf "${APPDIR}"
mkdir -p "${APPDIR}/usr/bin"
mkdir -p "${APPDIR}/usr/share/applications"
mkdir -p "${APPDIR}/usr/share/icons/hicolor/256x256/apps"

cp -r "${DIST_DIR}/${APP_NAME}/"* "${APPDIR}/usr/bin/"

cat > "${APPDIR}/${APP_NAME}.desktop" << EOF
[Desktop Entry]
Type=Application
Name=CyberOpsSuite
Comment=Security Dashboard
Exec=${APP_NAME}
Icon=${APP_NAME}
Categories=Utility;Security;
Terminal=false
EOF

cp "${APPDIR}/${APP_NAME}.desktop" "${APPDIR}/usr/share/applications/"

if [ -f "${PROJECT_ROOT}/assets/icons/cyberopssuite.png" ]; then
    cp "${PROJECT_ROOT}/assets/icons/cyberopssuite.png" "${APPDIR}/${APP_NAME}.png"
    cp "${PROJECT_ROOT}/assets/icons/cyberopssuite.png" "${APPDIR}/usr/share/icons/hicolor/256x256/apps/${APP_NAME}.png"
fi

cat > "${APPDIR}/AppRun" << EOF
#!/bin/sh
SELF=\$(readlink -f "\$0")
HERE=\${SELF%/*}
exec "\${HERE}/usr/bin/${APP_NAME}" "\$@"
EOF
chmod +x "${APPDIR}/AppRun"

echo "=== 4. Downloading appimagetool ==="
mkdir -p "${TOOLS_DIR}"
APPIMAGETOOL="${TOOLS_DIR}/appimagetool-${APPIMAGE_ARCH}.AppImage"
if [ ! -x "${APPIMAGETOOL}" ]; then
    if [[ "$APPIMAGE_ARCH" == "x86_64" ]]; then
        URL="https://github.com/AppImage/appimagetool/releases/download/continuous/appimagetool-x86_64.AppImage"
    else
        URL="https://github.com/AppImage/appimagetool/releases/download/continuous/appimagetool-aarch64.AppImage"
    fi
    echo "Downloading from: $URL"
    curl -fsSL -o "${APPIMAGETOOL}" "$URL"
    chmod +x "${APPIMAGETOOL}"
fi

echo "=== 5. Building AppImage ==="
OUTPUT="${DIST_DIR}/${APP_NAME}-${APP_VERSION}-${APPIMAGE_ARCH}.AppImage"
rm -f "$OUTPUT"
ARCH="${APPIMAGE_ARCH}" "${APPIMAGETOOL}" "${APPDIR}" "${OUTPUT}"
chmod +x "$OUTPUT"

echo ""
echo "✅ Build complete: $OUTPUT"