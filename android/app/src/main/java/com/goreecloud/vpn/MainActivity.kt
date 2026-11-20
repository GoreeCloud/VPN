package com.goreecloud.vpn

import android.app.Activity
import android.content.Intent
import android.net.VpnService
import android.os.Bundle
import android.view.WindowManager
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.wireguard.android.backend.GoBackend
import com.wireguard.android.backend.Tunnel
import com.wireguard.config.Config
import java.io.ByteArrayInputStream
import java.io.IOException
import kotlin.concurrent.thread

private val canvas = Color(0xFF0D121D)
private val surface = Color(0xFF171D2A)
private val tonal = Color(0xFF252D3D)
private val ink = Color(0xFFF2F4FB)
private val muted = Color(0xFFCED5E5)
private val accent = Color(0xFF8BE7F1)

class MainActivity : ComponentActivity() {
    private val backend by lazy { GoBackend(applicationContext) }
    private var config: Config? = null
    private var busy by mutableStateOf(false)
    private var connected by mutableStateOf(false)
    private var label by mutableStateOf("No configuration imported")
    private var notice by mutableStateOf("Import a trusted WireGuard .conf file to begin.")
    private val tunnel = object : Tunnel {
        override fun getName(): String = "gcvpn"
        override fun onStateChange(newState: Tunnel.State) {
            runOnUiThread { connected = newState == Tunnel.State.UP }
        }
    }

    private val importConfig = registerForActivityResult(ActivityResultContracts.GetContent()) { uri ->
        if (uri == null) return@registerForActivityResult
        if (connected || busy) {
            notice = "Disconnect before importing another configuration."
            return@registerForActivityResult
        }
        try {
            val bytes = contentResolver.openInputStream(uri)?.use { stream ->
                val data = stream.readNBytes(65537)
                if (data.size > 65536) throw IOException("Configuration exceeds 64 KiB")
                data
            } ?: throw IOException("Unable to read configuration")
            try {
                config = Config.parse(ByteArrayInputStream(bytes))
            } finally {
                bytes.fill(0)
            }
            label = "WireGuard configuration loaded"
            notice = "Ready. Only tap Connect when you trust the target server."
        } catch (_: Exception) {
            config = null
            label = "No configuration imported"
            notice = "Invalid or unsupported WireGuard configuration."
        }
    }
    private val vpnConsent = registerForActivityResult(ActivityResultContracts.StartActivityForResult()) {
        result ->
        if (result.resultCode == Activity.RESULT_OK) turnOn()
        else notice = "Android VPN permission was denied; no connection started."
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        window.addFlags(WindowManager.LayoutParams.FLAG_SECURE)
        setContent { ApplicationView() }
    }

    private fun requestConnection() {
        if (busy || connected) return
        if (config == null) {
            notice = "Import a WireGuard configuration first."
            return
        }
        val intent: Intent? = VpnService.prepare(this)
        if (intent == null) turnOn() else vpnConsent.launch(intent)
    }

    private fun turnOn() {
        val candidate = config ?: return
        busy = true
        notice = "Starting WireGuard tunnel…"
        thread(name = "gcvpn-up") {
            try {
                backend.setState(tunnel, Tunnel.State.UP, candidate)
                runOnUiThread {
                    connected = true
                    notice = "WireGuard reports connected. Remote reachability is not yet verified."
                }
            } catch (_: Exception) {
                runOnUiThread { notice = "Unable to connect. Check configuration and Android VPN permissions." }
            } finally {
                runOnUiThread { busy = false }
            }
        }
    }

    private fun turnOff() {
        if (busy) return
        busy = true
        thread(name = "gcvpn-down") {
            try {
                backend.setState(tunnel, Tunnel.State.DOWN, null)
                runOnUiThread {
                    connected = false
                    notice = "WireGuard disconnected."
                }
            } catch (_: Exception) {
                runOnUiThread { notice = "Unable to disconnect; inspect VPN status in Android Settings." }
            } finally {
                runOnUiThread { busy = false }
            }
        }
    }

    @Composable
    private fun ApplicationView() {
        val palette = darkColorScheme(
            primary = accent, onPrimary = Color(0xFF003A42), background = canvas,
            onBackground = ink, surface = surface, onSurface = ink,
            surfaceVariant = tonal, onSurfaceVariant = muted
        )
        MaterialTheme(colorScheme = palette) {
            Column(
                modifier = Modifier.fillMaxSize().background(canvas)
                    .verticalScroll(rememberScrollState()).padding(24.dp),
                verticalArrangement = Arrangement.spacedBy(22.dp)
            ) {
                Spacer(Modifier.height(10.dp))
                Text("◈  GoreeCloud", color = ink, fontSize = 23.sp, fontWeight = FontWeight.Bold)
                Text("VPN  •  PRIVATE NETWORK", color = accent, fontSize = 12.sp, fontWeight = FontWeight.Bold)
                Spacer(Modifier.height(12.dp))
                Text("A quieter way\nto connect.", color = ink, fontSize = 37.sp,
                    lineHeight = 43.sp, fontWeight = FontWeight.Bold)
                Text("Encrypted networking, powered by WireGuard. You control when the VPN starts.",
                    color = muted, fontSize = 15.sp)
                Card(
                    modifier = Modifier.fillMaxWidth(),
                    shape = RoundedCornerShape(26.dp),
                    colors = CardDefaults.cardColors(containerColor = surface),
                    border = BorderStroke(1.dp, Color(0xFF505B70))
                ) {
                    Column(Modifier.padding(24.dp), verticalArrangement = Arrangement.spacedBy(18.dp)) {
                        Text("TUNNEL STATUS", color = accent, fontWeight = FontWeight.Bold, fontSize = 12.sp)
                        Text(if (connected) "Connected" else "Disconnected", fontWeight = FontWeight.Bold, fontSize = 30.sp)
                        Text(label, color = muted)
                        Button(
                            onClick = { if (connected) turnOff() else requestConnection() },
                            enabled = !busy, modifier = Modifier.fillMaxWidth().heightIn(min = 52.dp)
                        ) { Text(if (busy) "Working…" else if (connected) "Disconnect" else "Connect") }
                    }
                }
                Card(
                    modifier = Modifier.fillMaxWidth(),
                    shape = RoundedCornerShape(26.dp),
                    colors = CardDefaults.cardColors(containerColor = surface)
                ) {
                    Column(Modifier.padding(24.dp), verticalArrangement = Arrangement.spacedBy(14.dp)) {
                        Text("Configuration", color = ink, fontWeight = FontWeight.Bold, fontSize = 21.sp)
                        Text("Select a locally generated WireGuard config. The app does not upload or persist its private key.",
                            color = muted)
                        OutlinedButton(
                            onClick = { importConfig.launch("*/*") },
                            enabled = !busy && !connected,
                            modifier = Modifier.fillMaxWidth().heightIn(min = 48.dp)
                        ) { Text("Import .conf file") }
                    }
                }
                Text(notice, color = muted, fontSize = 14.sp, modifier = Modifier.fillMaxWidth())
                Text(
                    "Development preview · GoreeCloud UI Lagoon · Android VPN permission is requested only when you connect.",
                    color = muted, fontSize = 12.sp, textAlign = TextAlign.Start
                )
            }
        }
    }
}
