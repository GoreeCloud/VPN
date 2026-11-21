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
assert "export-peers" in read("cmd/vpnctl/main.go")
assert "RevokedAt == nil" in read("cmd/vpnctl/export.go")
assert "ApprovedAt != nil" in read("cmd/vpnctl/export.go")
assert '"approved_at,omitempty"' in read("internal/control/store.go")
assert "os.O_EXCL" in read("cmd/vpnctl/export.go")

go = read("internal/api/handler.go")
assert '"tunnel_operational"' in go and "false" in go, "Source must explicitly deny automatic tunnel activation"
assert "ConstantTimeCompare" in go and "MaxBytesReader" in go
assert "Cache-Control" in go
daemon = read("cmd/vpnd/main.go")
assert "non-loopback listener requires TLS" in daemon
assert "127.0.0.1:8788" in daemon

web = read("web/src/main.tsx")
assert '"react": "19.2.0"' in read("web/package.json")
assert 'vite build' in read("web/package.json")
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
assert "GoBackend$VpnService" in manifest, "Android WireGuard VpnService must be declared"
assert "VpnService.prepare(this)" in android
assert "Tunnel.State.UP" in android and "Tunnel.State.DOWN" in android
assert "com.wireguard.android:tunnel" in gradle

read("LICENSE")
read("docs/SECURITY.md")
read("docs/ARCHITECTURE.md")
read("docs/CLI_COMMANDS.md")
print("PASS: first-party ownership, secure API, Qt Quick, native Compose and truthful tunnel status")


# A peer enrolled by an authenticated admin is pending until independently approved.
assert "ApprovedAt *time.Time" in read("internal/control/store.go")
assert "ErrLocked" in read("internal/control/store.go")
assert "syscall.Flock" in read("internal/control/store.go")
assert "/approve" in read("internal/api/handler.go")
assert 'case "approve":' in read("cmd/vpnctl/main.go")
assert '"/approve"' in read("web/src/main.tsx")

assert "config-acl" in read("cmd/vpnctl/main.go")
acl = read("internal/policy/nft.go")
assert 'iifname \\"gateway\\" drop' in acl
assert "chain forward" in acl

assert "accessibleName:" not in read("desktop/linux/Main.qml"), "Qt Quick Accessible.name is an attached property"
assert 'Accessible.name: "Administrator token"' in read("desktop/linux/Main.qml")

assert "backup-registry" in read("cmd/vpnctl/main.go")
assert "restore-registry" in read("cmd/vpnctl/main.go")
assert "cipher.NewGCM" in read("internal/backup/crypto.go")
assert "ValidateSnapshotJSON" in read("internal/control/store.go")
