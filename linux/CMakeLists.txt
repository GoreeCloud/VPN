cmake_minimum_required(VERSION 3.25)
project(GoreeCloudVPN VERSION 0.1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
find_package(Qt6 6.12 REQUIRED COMPONENTS Core Gui Quick QuickControls2)
qt_standard_project_setup(REQUIRES 6.12)
qt_add_executable(goreecloud-vpn-linux src/main.cpp src/TunnelController.cpp src/TunnelController.h)
qt_add_qml_module(goreecloud-vpn-linux URI GoreeCloud.VPN VERSION 1.0
    QML_FILES qml/Main.qml)
target_link_libraries(goreecloud-vpn-linux PRIVATE
    Qt6::Core Qt6::Gui Qt6::Quick Qt6::QuickControls2)
set_target_properties(goreecloud-vpn-linux PROPERTIES
    MACOSX_BUNDLE FALSE WIN32_EXECUTABLE FALSE)
install(TARGETS goreecloud-vpn-linux RUNTIME DESTINATION bin)
