package com.goreecloud.vpn

import android.os.Bundle
import android.app.Activity
import android.content.Intent
import android.net.VpnService
import android.view.WindowManager
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.darkColorScheme
import androidx.compose.ui.graphics.Color
import com.wireguard.android.backend.GoBackend
import com.wireguard.android.backend.Tunnel
import com.wireguard.config.Config
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.IOException
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
 * GoreeCloud VPN Android: management inventory and opt-in WireGuard tunnel.
 * Imported private configuration and admin token remain in process memory only.
 */
class MainActivity : ComponentActivity() {
    // All runtime state remains in process memory, but survives Activity recreation.
    // The WireGuard GoBackend identifies an active tunnel by its Tunnel object.
    private val tunnelBackend get() = TunnelRuntime.backend(applicationContext)
    private var localTunnelConfig: Config?
        get() = TunnelRuntime.config
        set(value) { TunnelRuntime.config = value }
    private var tunnelBusy: Boolean
        get() = TunnelRuntime.busy
        set(value) { TunnelRuntime.busy = value }
    private var tunnelActive: Boolean
        get() = TunnelRuntime.active
        set(value) { TunnelRuntime.active = value }
    private var tunnelMessage: String
        get() = TunnelRuntime.message
        set(value) { TunnelRuntime.message = value }
    private val nativeTunnel get() = TunnelRuntime.tunnel
    private val importTunnel = registerForActivityResult(ActivityResultContracts.GetContent()) { uri ->
        if (uri == null) return@registerForActivityResult
        if (tunnelActive || tunnelBusy) {
            tunnelMessage = "Disconnect the active VPN before importing another config"
            return@registerForActivityResult
        }
        var bytes: ByteArray? = null
        try {
            bytes = contentResolver.openInputStream(uri)?.use { stream ->
                val output = ByteArrayOutputStream()
                val chunk = ByteArray(4096)
                while (true) {
                    val n = stream.read(chunk)
                    if (n <= 0) break
                    if (output.size() + n > 65536) throw IOException("Config exceeds 64 KiB")
                    output.write(chunk, 0, n)
                }
                chunk.fill(0)
                output.toByteArray()
            } ?: throw IOException("File unavailable")
            if (!DevelopmentProfileGuard.accepts(bytes.toString(Charsets.UTF_8))) {
                throw IOException("Imported profile is outside the reviewed private split-tunnel scope")
            }
            localTunnelConfig = Config.parse(ByteArrayInputStream(bytes))
            tunnelMessage = "Development split-tunnel profile imported: private 10.77.0.0/24 route only."
        } catch (_: Exception) {
            localTunnelConfig = null
            tunnelMessage = "Import rejected: only one peer, private 10.77.0.0/24 split route, and reviewed DNS are accepted"
        } finally {
            bytes?.fill(0)
        }
    }
    private val vpnPermission = registerForActivityResult(ActivityResultContracts.StartActivityForResult()) { result ->
        if (result.resultCode == Activity.RESULT_OK) startTunnel()
        else tunnelMessage = "Android VPN consent was denied. No tunnel was started."
    }
    private var sessionToken by mutableStateOf("")
    private var endpoint by mutableStateOf("")
    private var enteredToken by mutableStateOf("")
    private var state by mutableStateOf("Disconnected")
    private var peers by mutableStateOf(emptyList<String>())
    private var loading by mutableStateOf(false)
    private var sessionGeneration = 0L

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        window.addFlags(WindowManager.LayoutParams.FLAG_SECURE)
        setContent {
            // Color values from GoreeCloud UI canonical Lagoon alpha palette.
            val palette = darkColorScheme(
                primary = Color(0xFF8BE7F1), onPrimary = Color(0xFF003A42),
                background = Color(0xFF0D121D), onBackground = Color(0xFFF2F4FB),
                surface = Color(0xFF171D2A), onSurface = Color(0xFFF2F4FB),
                surfaceVariant = Color(0xFF252D3D), onSurfaceVariant = Color(0xFFCED5E5)
            )
            MaterialTheme(colorScheme = palette) {
                VpnScreen(
                    endpoint, { endpoint = it },
                    enteredToken, { enteredToken = it },
                    state, peers, loading, sessionToken.isNotEmpty(),
                    ::connect, ::refresh, ::disconnect,
                    tunnelActive, tunnelBusy, localTunnelConfig != null, tunnelMessage,
                    { importTunnel.launch("*/*") }, ::requestTunnel, ::stopTunnel
                )
            }
        }
    }

    override fun onResume() {
        super.onResume()
        // Re-check actual GoBackend state after foreground return, activity
        // rotation or Android VPN service revocation. Never claim a handshake.
        Thread {
            val current = try { tunnelBackend.getState(nativeTunnel) }
            catch (_: Exception) { null }
            runOnUiThread {
                if (current != null && !tunnelBusy) {
                    tunnelActive = current == Tunnel.State.UP
                    if (tunnelActive) {
                        tunnelMessage = "Local WireGuard interface active; remote handshake not established by this check"
                    }
                }
            }
        }.start()
    }

    override fun onStop() {
        super.onStop()
        // The management bearer token must not outlive the foreground screen.
        // This intentionally does NOT stop a user-consented Android VPN tunnel.
        disconnect()
    }


    private fun requestTunnel() {
        if (tunnelActive || tunnelBusy) return
        if (localTunnelConfig == null) {
            tunnelMessage = "Import a trusted WireGuard configuration before connecting"
            return
        }
        try {
            val consent: Intent? = VpnService.prepare(this)
            if (consent == null) startTunnel() else vpnPermission.launch(consent)
        } catch (_: Exception) {
            tunnelMessage = "Android VPN permission could not be requested"
        }
    }

    private fun startTunnel() {
        val config = localTunnelConfig ?: return
        if (tunnelBusy || tunnelActive) return
        tunnelBusy = true
        tunnelMessage = "Starting the WireGuard tunnel…"
        Thread {
            try {
                val current = tunnelBackend.setState(nativeTunnel, Tunnel.State.UP, config)
                runOnUiThread {
                    tunnelActive = current == Tunnel.State.UP
                    tunnelMessage = if (tunnelActive)
                        "Local WireGuard interface active; no remote handshake or DNS-leak protection proven"
                    else "WireGuard did not report a started tunnel"
                }
            } catch (_: Exception) {
                runOnUiThread {
                    tunnelActive = false
                    tunnelMessage = "Connection failed. Inspect configuration and VPN permission."
                }
            } finally { runOnUiThread { tunnelBusy = false } }
        }.start()
    }

    private fun stopTunnel() {
        if (tunnelBusy || !tunnelActive) return
        tunnelBusy = true
        Thread {
            try {
                val current = tunnelBackend.setState(nativeTunnel, Tunnel.State.DOWN, null)
                runOnUiThread {
                    tunnelActive = current == Tunnel.State.UP
                    tunnelMessage = if (tunnelActive)
                        "WireGuard still reports an active local interface"
                    else "WireGuard tunnel disconnected"
                }
            } catch (_: Exception) {
                runOnUiThread { tunnelMessage = "Unable to disconnect. Check Android VPN settings." }
            } finally { runOnUiThread { tunnelBusy = false } }
        }.start()
    }

    private fun disconnect() {
        sessionGeneration += 1
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

    private fun readApi(path: String, token: String, origin: String): JSONObject {
        if (!validOrigin(origin)) error("HTTPS required")
        val connection = (URL(origin + path).openConnection() as HttpURLConnection)
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
            val status = when {
                peer.has("revoked_at") -> "Revoked"
                peer.has("approved_at") -> "Approved; gateway apply pending"
                else -> "Pending administrator approval"
            }
            peer.optString("name") + " · " + peer.optString("address") + " · " + status
        }
    }

    private fun connect() {
        if (!validOrigin(endpoint) || enteredToken.length < 32) {
            state = "Enter a valid HTTPS control-plane origin and token"
            return
        }
        val candidate = enteredToken
        val origin = endpoint
        val generation = ++sessionGeneration
        enteredToken = ""
        loading = true
        Thread {
            try {
                val info = readApi("/v1/info", candidate, origin)
                if (info.optBoolean("tunnel_operational", true)) error("Unexpected API")
                val result = parsePeers(readApi("/v1/peers", candidate, origin))
                runOnUiThread {
                    if (sessionGeneration != generation) return@runOnUiThread
                    sessionToken = candidate
                    peers = result
                    loading = false
                    state = "Control plane connected — local tunnel status shown above"
                }
            } catch (_: Exception) {
                runOnUiThread {
                    if (sessionGeneration != generation) return@runOnUiThread
                    sessionToken = ""
                    loading = false
                    state = "Authentication or TLS connection failed"
                }
            }
        }.start()
    }

    private fun refresh() {
        val token = sessionToken
        val origin = endpoint
        val generation = sessionGeneration
        if (token.isEmpty()) return
        loading = true
        Thread {
            try {
                val result = parsePeers(readApi("/v1/peers", token, origin))
                runOnUiThread {
                    if (sessionGeneration == generation && sessionToken == token) {
                        peers = result
                        state = "Loaded " + result.size + " registered identities"
                    }
                    loading = false
                }
            } catch (_: Exception) {
                runOnUiThread {
                    if (sessionGeneration != generation) return@runOnUiThread
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
    onConnect: () -> Unit, onRefresh: () -> Unit, onDisconnect: () -> Unit,
    tunnelActive: Boolean, tunnelBusy: Boolean, hasTunnelConfig: Boolean,
    tunnelMessage: String, onImport: () -> Unit, onTunnelConnect: () -> Unit,
    onTunnelDisconnect: () -> Unit
) {
    Scaffold { insets ->
        Column(
            modifier = Modifier.fillMaxSize().padding(insets).padding(20.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp)
        ) {
            Text("GoreeCloud VPN", style = MaterialTheme.typography.headlineMedium)
            Text("Self-hosted private networking with explicit Android VPN consent.")
            Card(
                modifier = Modifier.fillMaxWidth(),
                colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceVariant)
            ) {
                Column(modifier = Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(10.dp)) {
                    Text("Local WireGuard tunnel", style = MaterialTheme.typography.titleLarge)
                    Text(if (tunnelActive) "Active" else "Disconnected")
                    Text(tunnelMessage)
                    OutlinedButton(onClick = onImport, enabled = !tunnelActive && !tunnelBusy) {
                        Text("Import WireGuard .conf")
                    }
                    Button(
                        onClick = if (tunnelActive) onTunnelDisconnect else onTunnelConnect,
                        enabled = !tunnelBusy && (tunnelActive || hasTunnelConfig)
                    ) {
                        Text(if (tunnelBusy) "Working…" else if (tunnelActive) "Disconnect VPN" else "Connect VPN")
                    }
                    Text("Development-only split routing: 10.77.0.0/24. Full tunnel, IPv6 routing, DNS leak protection and kill switch are not supported or verified.")
                    Text("VPN tunnel state is separate from the control-plane session.")
                }
            }
            Text("Private control-plane inventory", style = MaterialTheme.typography.titleLarge)
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
