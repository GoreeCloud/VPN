cmake_minimum_required(VERSION 3.25)
project(GoreeCloudVPN VERSION 0.1.0 LANGUAGES CXX)

# GoreeCloud Linux UI standard: native Qt Quick 6.12.0; no Electron wrapper.
set(CMAKE_CXX_STANDARD 17)
find_package(Qt6 6.12.0 REQUIRED COMPONENTS Quick)
qt_standard_project_setup(REQUIRES 6.12)

qt_add_executable(goreecloud-vpn-linux main.cpp TunnelObserver.cpp TunnelObserver.h)
qt_add_qml_module(goreecloud-vpn-linux
    URI GoreeCloud.VPN
    VERSION 1.0
    QML_FILES Main.qml
)

target_link_libraries(goreecloud-vpn-linux PRIVATE Qt6::Quick)
install(TARGETS goreecloud-vpn-linux BUNDLE DESTINATION . RUNTIME DESTINATION bin)
