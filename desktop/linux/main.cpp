#include <QGuiApplication>
#include <QQmlApplicationEngine>
#include <QtQml>

int main(int argc, char *argv[]) {
    QGuiApplication application(argc, argv);
    application.setApplicationName("GoreeCloud VPN");
    application.setOrganizationName("GoreeCloud");
    QQmlApplicationEngine engine;
    engine.loadFromModule("GoreeCloud.VPN", "Main");
    if (engine.rootObjects().isEmpty()) {
        return 1;
    }
    return application.exec();
}
