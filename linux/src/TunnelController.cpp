#include "TunnelController.h"

#include <QFileInfo>
#include <QFileDevice>
#include <QProcess>

namespace {
const QString interfaceName = QStringLiteral("gcvpn");
const QString configPath = QStringLiteral("/etc/wireguard/gcvpn.conf");
const QString wg = QStringLiteral("/usr/bin/wg");
const QString wgQuick = QStringLiteral("/usr/bin/wg-quick");
const QString pkexec = QStringLiteral("/usr/bin/pkexec");
}

TunnelController::TunnelController(QObject *parent) : QObject(parent) {
    connect(&m_operation, &QProcess::finished, this,
            [this](int code, QProcess::ExitStatus exitStatus) {
        setBusy(false);
        if (exitStatus != QProcess::NormalExit || code != 0)
            setDetail(QStringLiteral("Operation failed or permission was denied. Check local system logs."));
        else
            setDetail(QStringLiteral("Command completed. Reading actual WireGuard state."));
        refresh();
    });
    refresh();
}
void TunnelController::setStatus(const QString &value) {
    if (m_status != value) { m_status = value; emit statusChanged(); }
}
void TunnelController::setDetail(const QString &value) {
    if (m_detail != value) { m_detail = value; emit detailChanged(); }
}
void TunnelController::setBusy(bool value) {
    if (m_busy != value) { m_busy = value; emit busyChanged(); }
}
void TunnelController::refresh() {
    if (m_busy) return;
    if (!QFileInfo::exists(wg)) {
        setStatus(QStringLiteral("Unavailable"));
        setDetail(QStringLiteral("Install trusted WireGuard tools to check local tunnel state."));
        return;
    }
    QProcess probe;
    probe.start(wg, {QStringLiteral("show"), interfaceName});
    if (!probe.waitForFinished(2500) || probe.exitCode() != 0) {
        setStatus(QStringLiteral("Disconnected"));
        setDetail(QStringLiteral("Interface gcvpn is not active; no live tunnel was verified."));
        return;
    }
    setStatus(QStringLiteral("Connected"));
    setDetail(QStringLiteral("WireGuard reports interface gcvpn. End-to-end access is not verified."));
}
void TunnelController::runPrivileged(const QString &verb) {
    if (m_busy) return;
    if (!QFileInfo::exists(pkexec) || !QFileInfo::exists(wgQuick)) {
        setDetail(QStringLiteral("Install polkit (pkexec) and trusted wireguard-tools first."));
        return;
    }
    if (!QFileInfo::exists(configPath)) {
        setDetail(QStringLiteral("Administrator must install and review /etc/wireguard/gcvpn.conf (mode 0600) first."));
        return;
    }
    // No arbitrary path or shell arguments. Administrator controls the root-owned config.
    QFileInfo config(configPath);
    if (config.isSymLink() || config.ownerId() != 0 || (config.permissions() &
        (QFileDevice::ReadGroup | QFileDevice::WriteGroup |
         QFileDevice::ReadOther | QFileDevice::WriteOther))) {
        setDetail(QStringLiteral("Config is not a secure root-owned 0600 file."));
        return;
    }
    setBusy(true);
    setDetail(QStringLiteral("Requesting system authorization; no password is collected by GoreeCloud VPN."));
    m_operation.start(pkexec, {wgQuick, verb, configPath});
}
void TunnelController::connectTunnel() { runPrivileged(QStringLiteral("up")); }
void TunnelController::disconnectTunnel() { runPrivileged(QStringLiteral("down")); }
