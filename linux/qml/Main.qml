import QtQuick
import QtQuick.Controls
import QtQuick.Layouts

ApplicationWindow {
    id: window
    visible: true
    width: 920
    height: 660
    minimumWidth: 470
    minimumHeight: 500
    title: "GoreeCloud VPN"
    color: "#0D121D"

    readonly property color canvas: "#0D121D"
    readonly property color surface: "#171D2A"
    readonly property color tonal: "#252D3D"
    readonly property color accent: "#8BE7F1"
    readonly property color ink: "#F2F4FB"
    readonly property color muted: "#CED5E5"

    ScrollView {
        anchors.fill: parent
        ScrollBar.horizontal.policy: ScrollBar.AlwaysOff
        ColumnLayout {
            width: Math.max(window.width - 72, 390)
            anchors.horizontalCenter: parent.horizontalCenter
            spacing: 24

            Item { Layout.preferredHeight: 16 }
            RowLayout {
                spacing: 12
                Rectangle {
                    width: 46; height: 46; radius: 14
                    color: window.surface
                    border.color: "#505B70"
                    Text { anchors.centerIn: parent; text: "◈"; font.pixelSize: 28; color: window.accent }
                }
                ColumnLayout {
                    spacing: 0
                    Label { text: "GoreeCloud"; color: window.ink; font.bold: true; font.pixelSize: 20 }
                    Label { text: "VPN · Linux desktop"; color: window.muted; font.pixelSize: 13 }
                }
                Item { Layout.fillWidth: true }
                Button { text: "Refresh"; enabled: !vpn.busy; onClicked: vpn.refresh() }
            }
            Item { Layout.preferredHeight: 18 }
            Label {
                text: "Your private network."
                color: window.ink
                font.bold: true
                font.pixelSize: 38
                wrapMode: Text.WordWrap
                Layout.fillWidth: true
            }
            Label {
                text: "A native connection manager powered by WireGuard."
                color: window.muted
                font.pixelSize: 16
                Layout.fillWidth: true
                wrapMode: Text.WordWrap
            }
            Rectangle {
                Layout.fillWidth: true
                implicitHeight: 230
                radius: 26
                color: window.surface
                border.color: "#505B70"
                ColumnLayout {
                    anchors.fill: parent
                    anchors.margins: 28
                    spacing: 12
                    Label { text: "LOCAL TUNNEL"; font.bold: true; color: window.accent; font.pixelSize: 12 }
                    Label { text: vpn.status; color: window.ink; font.pixelSize: 32; font.bold: true }
                    Label {
                        text: vpn.detail
                        wrapMode: Text.WordWrap
                        color: window.muted
                        Layout.fillWidth: true
                    }
                    Item { Layout.fillHeight: true }
                    RowLayout {
                        spacing: 12
                        Button {
                            text: vpn.busy ? "Working…" : "Connect"
                            enabled: !vpn.busy && vpn.status !== "Connected"
                            onClicked: vpn.connectTunnel()
                        }
                        Button {
                            text: "Disconnect"
                            enabled: !vpn.busy && vpn.status === "Connected"
                            onClicked: vpn.disconnectTunnel()
                        }
                    }
                }
            }
            Rectangle {
                Layout.fillWidth: true
                implicitHeight: 140
                radius: 26
                color: window.surface
                border.color: "#505B70"
                ColumnLayout {
                    anchors.fill: parent
                    anchors.margins: 24
                    Label { text: "Secure configuration"; font.bold: true; color: window.ink; font.pixelSize: 19 }
                    Label {
                        text: "An administrator must provision /etc/wireguard/gcvpn.conf as a root-owned private file. Network commands require an explicit polkit authorization."
                        color: window.muted
                        wrapMode: Text.WordWrap
                        Layout.fillWidth: true
                    }
                }
            }
            Label {
                text: "Development preview · GoreeCloud UI Lagoon · Tunnel status does not prove end-to-end connectivity."
                font.pixelSize: 12; color: window.muted; wrapMode: Text.WordWrap; Layout.fillWidth: true
            }
            Item { Layout.preferredHeight: 20 }
        }
    }
}
