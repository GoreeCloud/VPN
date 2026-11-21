#pragma once

#include <QObject>
#include <QString>
#include <QByteArray>

// Unprivileged, read-only health observations of GoreeCloud's dedicated
// Linux gcvpn0 interface. No secrets, shell, sudo, route or firewall changes.
class TunnelObserver final : public QObject {
    Q_OBJECT
    Q_PROPERTY(QString summary READ summary NOTIFY summaryChanged)
public:
    explicit TunnelObserver(QObject* parent = nullptr);
    QString summary() const { return summary_; }
    Q_INVOKABLE void refresh();

    static QString classifyHandshakes(const QByteArray& payload, qint64 nowSeconds);
    static bool runSelfTest();

signals:
    void summaryChanged();

private:
    void updateSummary(const QString& summary);
    QString summary_;
};
