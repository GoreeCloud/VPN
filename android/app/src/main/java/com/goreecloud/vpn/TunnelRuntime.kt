package com.goreecloud.vpn

import android.content.Context
import android.os.Handler
import android.os.Looper
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import com.wireguard.android.backend.GoBackend
import com.wireguard.android.backend.Tunnel
import com.wireguard.config.Config

/**
 * Process-only tunnel session, retaining the *same* backend and Tunnel object
 * through Activity recreation so GoBackend's identity-based state tracking
 * remains accurate. Never store config or token in Android preferences.
 */
internal object TunnelRuntime {
    private var backendInstance: GoBackend? = null
    var config: Config? by mutableStateOf(null)
    var busy by mutableStateOf(false)
    var active by mutableStateOf(false)
    var message by mutableStateOf("No WireGuard configuration imported")

    val tunnel: Tunnel = object : Tunnel {
        override fun getName(): String = "gcvpn"
        override fun onStateChange(newState: Tunnel.State) {
            Handler(Looper.getMainLooper()).post {
                active = newState == Tunnel.State.UP
                if (newState == Tunnel.State.DOWN) {
                    message = "WireGuard is disconnected"
                }
            }
        }
    }

    @Synchronized
    fun backend(context: Context): GoBackend {
        return backendInstance ?: GoBackend(context.applicationContext).also {
            backendInstance = it
        }
    }
}
