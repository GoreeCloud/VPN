#include <QGuiApplication>
#include <QQmlApplicationEngine>
#include <QQmlContext>
#include "TunnelController.h"

int main(int argc, char *argv[]) {
    QGuiApplication app(argc, argv);
    app.setApplicationName(QStringLiteral("GoreeCloud VPN"));
    app.setOrganizationName(QStringLiteral("GoreeCloud"));
    TunnelController tunnel;
    QQmlApplicationEngine engine;
    engine.rootContext()->setContextProperty(QStringLiteral("vpn"), &tunnel);
    engine.loadFromModule(QStringLiteral("GoreeCloud.VPN"), QStringLiteral("Main"));
    if (engine.rootObjects().isEmpty()) return 1;
    return app.exec();
}
