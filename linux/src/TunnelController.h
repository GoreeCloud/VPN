#pragma once

#include <QObject>
#include <QProcess>
#include <QString>

class TunnelController : public QObject {
    Q_OBJECT
    Q_PROPERTY(QString status READ status NOTIFY statusChanged)
    Q_PROPERTY(QString detail READ detail NOTIFY detailChanged)
    Q_PROPERTY(bool busy READ busy NOTIFY busyChanged)
public:
    explicit TunnelController(QObject *parent = nullptr);
    QString status() const { return m_status; }
    QString detail() const { return m_detail; }
    bool busy() const { return m_busy; }
    Q_INVOKABLE void refresh();
    Q_INVOKABLE void connectTunnel();
    Q_INVOKABLE void disconnectTunnel();
signals:
    void statusChanged();
    void detailChanged();
    void busyChanged();
private:
    void runPrivileged(const QString &verb);
    void setStatus(const QString &value);
    void setDetail(const QString &value);
    void setBusy(bool busy);
    QProcess m_operation;
    QString m_status = QStringLiteral("Unknown");
    QString m_detail = QStringLiteral("Checking local WireGuard interface…");
    bool m_busy = false;
};
