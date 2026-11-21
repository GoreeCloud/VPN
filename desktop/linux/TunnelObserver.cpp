#include "TunnelObserver.h"

#include <QDateTime>
#include <QFileInfo>
#include <QProcess>
#include <QStringList>
#include <QtGlobal>

TunnelObserver::TunnelObserver(QObject* parent)
    : QObject(parent), summary_(QStringLiteral("Local interface not inspected")) {
}

void TunnelObserver::updateSummary(const QString& next) {
    if (summary_ == next) return;
    summary_ = next;
    emit summaryChanged();
}

QString TunnelObserver::classifyHandshakes(const QByteArray& payload, qint64 nowSeconds) {
    // Never surface public keys, untrusted command output or IP addresses.
    if (payload.size() > 32768 || nowSeconds < 1) {
        return QStringLiteral("Handshake observation unavailable");
    }
    qint64 newest = 0;
    const QList<QByteArray> lines = payload.split('\n');
    for (const QByteArray& line : lines) {
        if (line.isEmpty()) continue;
        const QList<QByteArray> columns = line.trimmed().split('\t');
        if (columns.size() != 2 || columns[0].size() != 44) {
            return QStringLiteral("Handshake observation unavailable");
        }
        bool ok = false;
        const qint64 timestamp = columns[1].toLongLong(&ok, 10);
        if (!ok || timestamp < 0 || timestamp > nowSeconds + 5) {
            return QStringLiteral("Handshake observation unavailable");
        }
        if (timestamp > newest) newest = timestamp;
    }
    if (newest == 0) return QStringLiteral("No authenticated WireGuard handshake observed");
    if (nowSeconds - newest <= 180) {
        return QStringLiteral("Recent authenticated WireGuard handshake (local observation)");
    }
    return QStringLiteral("Only an older WireGuard handshake observed; reachability unverified");
}

void TunnelObserver::refresh() {
    if (!QFileInfo::exists(QStringLiteral("/sys/class/net/gcvpn0"))) {
        updateSummary(QStringLiteral("No GoreeCloud VPN interface detected (gcvpn0)"));
        return;
    }
    // Absolute system paths: do not execute a script, PATH-replaced binary,
    // privileged helper or an arbitrary user-configured command.
    QString executable;
    for (const QString& path : {QStringLiteral("/usr/bin/wg"), QStringLiteral("/usr/sbin/wg")}) {
        if (QFileInfo(path).isExecutable()) {
            executable = path;
            break;
        }
    }
    if (executable.isEmpty()) {
        updateSummary(QStringLiteral("Interface detected; handshake unverified (WireGuard tool unavailable)"));
        return;
    }
    updateSummary(QStringLiteral("Inspecting local WireGuard handshake without privileges…"));
    auto* process = new QProcess(this);
    process->setProgram(executable);
    process->setArguments({QStringLiteral("show"), QStringLiteral("gcvpn0"), QStringLiteral("latest-handshakes")});
    process->setProcessChannelMode(QProcess::SeparateChannels);
    connect(process, &QProcess::finished, this,
            [this, process](int exitCode, QProcess::ExitStatus exitStatus) {
        const QByteArray output = process->readAllStandardOutput();
        if (exitStatus != QProcess::NormalExit || exitCode != 0) {
            updateSummary(QStringLiteral("Interface detected; handshake unavailable or permission denied"));
        } else {
            updateSummary(classifyHandshakes(output, QDateTime::currentSecsSinceEpoch()));
        }
        process->deleteLater();
    });
    connect(process, &QProcess::errorOccurred, this, [this, process](QProcess::ProcessError) {
        updateSummary(QStringLiteral("Interface detected; handshake inspection unavailable"));
        process->deleteLater();
    });
    process->start();
}

bool TunnelObserver::runSelfTest() {
    const qint64 now = 1800000000;
    const QByteArray key(44, 'a');
    const QByteArray valid = key + "\t" + QByteArray::number(now - 60) + "\n";
    const QByteArray stale = key + "\t" + QByteArray::number(now - 3600) + "\n";
    const QByteArray future = key + "\t" + QByteArray::number(now + 60) + "\n";
    return classifyHandshakes(valid, now).startsWith(QStringLiteral("Recent authenticated")) &&
           classifyHandshakes(stale, now).startsWith(QStringLiteral("Only an older")) &&
           classifyHandshakes(key + "\t0\n", now).startsWith(QStringLiteral("No authenticated")) &&
           classifyHandshakes(future, now).startsWith(QStringLiteral("Handshake observation unavailable")) &&
           classifyHandshakes("bad-data\n", now).startsWith(QStringLiteral("Handshake observation unavailable"));
}
