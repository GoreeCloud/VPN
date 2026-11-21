package com.goreecloud.vpn

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material3.Button
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.unit.dp
import org.json.JSONObject
import java.net.HttpURLConnection
import java.net.URI
import java.net.URL

/**
 * Native Compose control-plane preview, not an Android VPN tunnel.
 * No VpnService, keys, or bearer tokens persist to device storage.
 */
class MainActivity : ComponentActivity() {
    private var sessionToken by mutableStateOf("")
    private var endpoint by mutableStateOf("")
    private var enteredToken by mutableStateOf("")
    private var state by mutableStateOf("Disconnected")
    private var peers by mutableStateOf(emptyList<String>())
    private var loading by mutableStateOf(false)

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContent {
            MaterialTheme {
                VpnScreen(
                    endpoint, { endpoint = it },
                    enteredToken, { enteredToken = it },
                    state, peers, loading, sessionToken.isNotEmpty(),
                    ::connect, ::refresh, ::disconnect
                )
            }
        }
    }

    override fun onStop() {
        super.onStop()
        disconnect()
    }

    private fun disconnect() {
        sessionToken = ""
        enteredToken = ""
        peers = emptyList()
        loading = false
        state = "Disconnected — token cleared from memory"
    }

    private fun validOrigin(value: String): Boolean {
        return try {
            val u = URI(value)
            u.scheme == "https" && u.host != null &&
                u.rawUserInfo == null && u.rawQuery == null &&
                u.rawFragment == null && (u.rawPath == null || u.rawPath.isEmpty())
        } catch (_: Exception) { false }
    }

    private fun readApi(path: String, token: String): JSONObject {
        if (!validOrigin(endpoint)) error("HTTPS required")
        val connection = (URL(endpoint + path).openConnection() as HttpURLConnection)
        connection.connectTimeout = 7000
        connection.readTimeout = 7000
        connection.instanceFollowRedirects = false
        connection.requestMethod = "GET"
        connection.setRequestProperty("Accept", "application/json")
        connection.setRequestProperty("Authorization", "Bearer " + token)
        try {
            if (connection.responseCode != 200) error("API request rejected")
            val bytes = connection.inputStream.use { it.readNBytes(65537) }
            if (bytes.size > 65536) error("Response size exceeded")
            return JSONObject(bytes.toString(Charsets.UTF_8))
        } finally {
            connection.disconnect()
        }
    }

    private fun parsePeers(data: JSONObject): List<String> {
        val array = data.optJSONArray("peers") ?: return emptyList()
        return (0 until array.length()).map { index ->
            val peer = array.getJSONObject(index)
            val status = if (peer.has("revoked_at")) "Revoked" else "Registered only"
            peer.optString("name") + " · " + peer.optString("address") + " · " + status
        }
    }

    private fun connect() {
        if (!validOrigin(endpoint) || enteredToken.length < 32) {
            state = "Enter a valid HTTPS control-plane origin and token"
            return
        }
        val candidate = enteredToken
        enteredToken = ""
        loading = true
        Thread {
            try {
                val info = readApi("/v1/info", candidate)
                if (info.optBoolean("tunnel_operational", true)) error("Unexpected API")
                val result = parsePeers(readApi("/v1/peers", candidate))
                runOnUiThread {
                    sessionToken = candidate
                    peers = result
                    loading = false
                    state = "Control plane connected — no tunnel active"
                }
            } catch (_: Exception) {
                runOnUiThread {
                    sessionToken = ""
                    loading = false
                    state = "Authentication or TLS connection failed"
                }
            }
        }.start()
    }

    private fun refresh() {
        val token = sessionToken
        if (token.isEmpty()) return
        loading = true
        Thread {
            try {
                val result = parsePeers(readApi("/v1/peers", token))
                runOnUiThread {
                    if (sessionToken == token) {
                        peers = result
                        state = "Loaded " + result.size + " registered identities"
                    }
                    loading = false
                }
            } catch (_: Exception) {
                runOnUiThread {
                    loading = false
                    state = "Unable to refresh peer identities"
                }
            }
        }.start()
    }
}

@Composable
private fun VpnScreen(
    endpoint: String, onEndpoint: (String) -> Unit,
    enteredToken: String, onToken: (String) -> Unit,
    state: String, peers: List<String>, loading: Boolean, connected: Boolean,
    onConnect: () -> Unit, onRefresh: () -> Unit, onDisconnect: () -> Unit
) {
    Scaffold { insets ->
        Column(
            modifier = Modifier.fillMaxSize().padding(insets).padding(20.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp)
        ) {
            Text("GoreeCloud VPN", style = MaterialTheme.typography.headlineMedium)
            Text("First-party control-plane preview. No encrypted tunnel is active.")
            OutlinedTextField(
                value = endpoint, onValueChange = onEndpoint,
                label = { Text("HTTPS control-plane origin") },
                singleLine = true, enabled = !connected,
                modifier = Modifier.fillMaxWidth()
            )
            OutlinedTextField(
                value = enteredToken, onValueChange = onToken,
                label = { Text("Administrator token (memory only)") },
                visualTransformation = PasswordVisualTransformation(),
                singleLine = true, enabled = !connected,
                modifier = Modifier.fillMaxWidth()
            )
            if (connected) {
                TextButton(onClick = onDisconnect) { Text("Disconnect") }
                Button(onClick = onRefresh, enabled = !loading) { Text("Refresh peers") }
            } else {
                Button(onClick = onConnect, enabled = !loading) { Text("Connect") }
            }
            Text(state)
            Spacer(Modifier.height(4.dp))
            Text("Peer identities (not VPN sessions)", style = MaterialTheme.typography.titleMedium)
            LazyColumn {
                items(peers) { peer ->
                    Text(peer, modifier = Modifier.fillMaxWidth().padding(vertical = 8.dp))
                }
            }
        }
    }
}
