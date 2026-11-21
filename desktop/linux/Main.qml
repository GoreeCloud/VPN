import QtQuick
import QtQuick.Controls
import QtQuick.Layouts

ApplicationWindow {
    id: root
    width: 800
    height: 600
    minimumWidth: 440
    minimumHeight: 420
    visible: true
    title: "GoreeCloud VPN — Control Plane Preview"

    property string bearer: ""
    property bool authenticated: false
    Component.onCompleted: tunnelObserver.refresh()

    function request(path, method, body, callback) {
        if (!authenticated && path !== "/v1/info") {
            statusLabel.text = "Sign in first"
            return
        }
        const endpoint = endpointField.text.replace(/\/+$/, "")
        if (endpoint !== "http://127.0.0.1:8788" &&
            endpoint !== "http://localhost:8788" && !endpoint.startsWith("https://")) {
            statusLabel.text = "Remote API requires HTTPS"
            return
        }
        const xhr = new XMLHttpRequest()
        xhr.open(method, endpoint + path)
        xhr.setRequestHeader("Authorization", "Bearer " + bearer)
        xhr.setRequestHeader("Accept", "application/json")
        if (body !== null) xhr.setRequestHeader("Content-Type", "application/json")
        xhr.timeout = 10000
        xhr.onreadystatechange = function() {
            if (xhr.readyState !== XMLHttpRequest.DONE) return
            if (xhr.status < 200 || xhr.status >= 300) {
                statusLabel.text = "API request failed (HTTP " + xhr.status + ")"
                return
            }
            try { callback(JSON.parse(xhr.responseText)) }
            catch (e) { statusLabel.text = "Invalid response from API" }
        }
        xhr.ontimeout = function() { statusLabel.text = "API timeout" }
        xhr.send(body === null ? undefined : JSON.stringify(body))
    }

    function refreshPeers() {
        request("/v1/peers", "GET", null, function(data) {
            peerModel.clear()
            const list = data.peers || []
            for (let i = 0; i < list.length; ++i)
                peerModel.append({
                    name: list[i].name,
                    address: list[i].address,
                    state: list[i].revoked_at ? "Revoked" :
                        (list[i].approved_at ? "Approved (gateway apply required)" : "Pending administrator approval")
                })
            statusLabel.text = "Connected · " + list.length + " registered identities"
        })
    }

    ListModel { id: peerModel }

    ScrollView {
        anchors.fill: parent
        contentWidth: availableWidth
        ColumnLayout {
            width: parent.width
            spacing: 14
            anchors.margins: 20

            Label {
                text: "GoreeCloud VPN"
                font.pixelSize: 28
                font.bold: true
                Layout.fillWidth: true
            }
            Label {
                text: "First-party enrollment preview — tunnel status not verified from this view"
                wrapMode: Text.WordWrap
                Layout.fillWidth: true
            }
            GroupBox {
                title: "Connection"
                Layout.fillWidth: true
                ColumnLayout {
                    anchors.fill: parent
                    TextField {
                        id: endpointField
                        text: "http://127.0.0.1:8788"
                        placeholderText: "HTTPS control-plane origin"
                        Layout.fillWidth: true
                        Accessible.name: "Control-plane URL"
                    }
                    TextField {
                        id: tokenField
                        echoMode: TextInput.Password
                        placeholderText: "Administrator token (held in memory only)"
                        Layout.fillWidth: true
                        Accessible.name: "Administrator token"
                    }
                    RowLayout {
                        Button {
                            text: "Connect"
                            onClicked: {
                                if (tokenField.text.length < 32) {
                                    statusLabel.text = "Token is too short"
                                    return
                                }
                                bearer = tokenField.text
                                tokenField.clear()
                                request("/v1/info", "GET", null, function(info) {
                                    if (info.tunnel_operational !== false) {
                                        statusLabel.text = "Unexpected control-plane API"
                                        bearer = ""
                                        return
                                    }
                                    authenticated = true
                                    refreshPeers()
                                })
                            }
                        }
                        Button {
                            text: "Disconnect"
                            enabled: authenticated
                            onClicked: {
                                bearer = ""
                                authenticated = false
                                peerModel.clear()
                                statusLabel.text = "Disconnected"
                            }
                        }
                        Button {
                            text: "Refresh"
                            enabled: authenticated
                            onClicked: refreshPeers()
                        }
                    }
                }
            }
            Label {
                id: statusLabel
                text: "Disconnected"
                Accessible.role: Accessible.StaticText
                Layout.fillWidth: true
            }
            GroupBox {
                title: "Local WireGuard diagnostics — unprivileged"
                Layout.fillWidth: true
                ColumnLayout {
                    anchors.fill: parent
                    Label {
                        text: tunnelObserver.summary
                        wrapMode: Text.WordWrap
                        Accessible.name: "Observed native Linux WireGuard tunnel status"
                        Layout.fillWidth: true
                    }
                    Label {
                        text: "Read-only gcvpn0 inspection. A recent handshake is not proof of packet access or DNS safety."
                        wrapMode: Text.WordWrap
                        Layout.fillWidth: true
                    }
                    Button {
                        text: "Refresh local status"
                        onClicked: tunnelObserver.refresh()
                    }
                }
            }
            GroupBox {
                title: "Registered peer identities (not tunnel sessions)"
                Layout.fillWidth: true
                ColumnLayout {
                    anchors.fill: parent
                    Repeater {
                        model: peerModel
                        delegate: Label {
                            required property string name
                            required property string address
                            required property string state
                            text: name + " • " + address + " • " + state
                            wrapMode: Text.WordWrap
                            Layout.fillWidth: true
                        }
                    }
                }
            }
        }
    }
}
