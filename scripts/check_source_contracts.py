#!/usr/bin/env python3
"""Fail closed on cross-product mistakes and unsupported native VPN claims."""
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

def read(path):
    p = ROOT / path
    assert p.is_file(), f"Missing first-party source: {path}"
    return p.read_text(encoding="utf-8")

read("go.mod")
assert "GoreeCloud/VPN" in read("go.mod")
assert not (ROOT / "deploy/netbird").exists(), "NetBird deployments must not be in GoreeCloud VPN"
assert not (ROOT / "tools/netbird-cli").exists(), "NetBird CLI belongs to Mesh integration, not VPN"

wg = read("internal/wireguard/config.go")
assert "AllowedIPs = 10.77.0.0/24" in wg
assert "RenderClientConfig" in wg
assert "config-client" in read("cmd/vpnctl/main.go")

go = read("internal/api/handler.go")
assert '"tunnel_operational":false' in go, "Source must explicitly deny tunnel activation"
assert "ConstantTimeCompare" in go and "MaxBytesReader" in go
assert "Cache-Control" in go
daemon = read("cmd/vpnd/main.go")
assert "non-loopback listener requires TLS" in daemon
assert "127.0.0.1:8788" in daemon

web = read("web/app.js")
assert 'localStorage.setItem' not in web and 'sessionStorage.setItem' not in web
assert 'credentials: "omit"' in web
assert 'redirect: "error"' in web

qml = read("desktop/linux/Main.qml")
cmake = read("desktop/linux/CMakeLists.txt")
assert "ApplicationWindow" in qml and "import QtQuick" in qml
assert "find_package(Qt6 6.12.0" in cmake
assert "qt_add_qml_module" in cmake
assert not (ROOT / "desktop/linux/package.json").exists()

android = read("android/app/src/main/java/com/goreecloud/vpn/MainActivity.kt")
manifest = read("android/app/src/main/AndroidManifest.xml")
gradle = read("android/app/build.gradle.kts")
assert "MaterialTheme" in android and "OutlinedTextField" in android
assert "material3" in gradle and "compose-bom" in gradle
assert 'android:usesCleartextTraffic="false"' in manifest
assert 'android:allowBackup="false"' in manifest
assert "VpnService" not in manifest, "No untested tunnel claim is allowed"

read("LICENSE")
read("docs/SECURITY.md")
read("docs/ARCHITECTURE.md")
read("docs/CLI_COMMANDS.md")
print("PASS: first-party ownership, secure API, Qt Quick, native Compose and truthful tunnel status")
