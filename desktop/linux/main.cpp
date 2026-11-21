#include <QGuiApplication>
#include <QQmlApplicationEngine>
#include <QtQml>
#include <QTimer>
#include <QCoreApplication>

int main(int argc, char *argv[]) {
    QGuiApplication application(argc, argv);
    application.setApplicationName("GoreeCloud VPN");
    application.setOrganizationName("GoreeCloud");
    QQmlApplicationEngine engine;
    engine.loadFromModule("GoreeCloud.VPN", "Main");
    if (engine.rootObjects().isEmpty()) {
        return 1;
    }
    // Explicit, non-network, offscreen QML runtime smoke path for isolated CI.
    // Does not activate a tunnel, contact APIs or change device routes.
    if (QCoreApplication::arguments().contains("--smoke-test")) {
        QTimer::singleShot(800, &application, &QCoreApplication::quit);
    }
    return application.exec();
}
