package com.goreecloud.vpn

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class DevelopmentProfileGuardTest {
    private fun configuration(
        address: String = "10.77.0.2/32",
        allowed: String = "10.77.0.0/24",
        dns: String = "",
        peer: String = ""
    ): String = """
        [Interface]
        PrivateKey = PLACEHOLDER_SECRET_NOT_VALIDATED_IN_SCOPE_TEST
        Address = $address
        $dns
        [Peer]
        PublicKey = PLACEHOLDER_PUBLIC
        AllowedIPs = $allowed
        Endpoint = vpn.example.test:51820
        $peer
    """.trimIndent()

    @Test fun permitsOnlyReviewedPrivateIPv4SplitTunnel() {
        assertTrue(DevelopmentProfileGuard.accepts(configuration()))
        assertTrue(DevelopmentProfileGuard.accepts(configuration(address = "10.77.0.254/32")))
        assertTrue(DevelopmentProfileGuard.accepts(configuration(dns = "DNS = 10.77.0.1")))
        assertTrue(DevelopmentProfileGuard.accepts("# Example\n" + configuration() + "\n"))
    }

    @Test fun rejectsFullTunnelIPv6BroadRoutingOutsideClientAddress() {
        for (prefix in listOf("0.0.0.0/0", "::/0", "10.0.0.0/8", "10.77.0.0/16",
                              "10.77.0.0/24, 0.0.0.0/0", "10.77.0.1/32")) {
            assertFalse(prefix, DevelopmentProfileGuard.accepts(configuration(allowed = prefix)))
        }
        for (address in listOf("10.77.0.1/32", "10.77.0.255/32", "10.77.0.2/24",
                               "172.16.0.2/32", "10.77.0.2/32, ::1/128")) {
            assertFalse(address, DevelopmentProfileGuard.accepts(configuration(address = address)))
        }
    }

    @Test fun rejectsMultiplePeersAndAmbiguousOverrides() {
        assertFalse(DevelopmentProfileGuard.accepts(configuration(peer =
            "[Peer]\nAllowedIPs = 0.0.0.0/0")))
        assertFalse(DevelopmentProfileGuard.accepts(configuration(peer =
            "AllowedIPs = 0.0.0.0/0")))
        assertFalse(DevelopmentProfileGuard.accepts(configuration(peer =
            "Endpoint = other.example:51820")))
        assertFalse(DevelopmentProfileGuard.accepts(configuration(dns = "DNS = 8.8.8.8")))
        assertFalse(DevelopmentProfileGuard.accepts(configuration(dns = "DNS = 10.77.0.1, 8.8.8.8")))
        assertFalse(DevelopmentProfileGuard.accepts(configuration().replace("[Peer]", "[Unknown]")))
        assertFalse(DevelopmentProfileGuard.accepts(configuration().replace("Endpoint = vpn.example.test:51820", "")))
    }

    @Test fun rejectsEmptyTruncatedAndBinaryContent() {
        assertFalse(DevelopmentProfileGuard.accepts(""))
        assertFalse(DevelopmentProfileGuard.accepts(configuration() + "\u0000"))
        assertFalse(DevelopmentProfileGuard.accepts("X".repeat(65537)))
    }
}
