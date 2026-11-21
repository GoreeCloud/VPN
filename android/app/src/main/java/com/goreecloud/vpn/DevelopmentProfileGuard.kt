package com.goreecloud.vpn

/**
 * Developer-preview import policy. This checks the routing scope before handing
 * the full WireGuard grammar to the upstream Config.parse implementation.
 * It never logs, serializes or persists private keys.
 *
 * This is a product safety restriction, NOT a validated DNS leak test or
 * a zero-trust packet filter. Full tunnel, IPv6 and custom LAN routing are
 * intentionally unsupported until separately reviewed.
 */
internal object DevelopmentProfileGuard {
    private val address = Regex("""^10\.77\.0\.(\d{1,3})/32$""")
    fun accepts(raw: String): Boolean {
        if (raw.isBlank() || raw.length > 65536 || '\u0000' in raw) return false
        var section = ""
        var interfaceSections = 0
        var peerSections = 0
        var addressSeen = false
        var allowedSeen = false
        var endpointSeen = false
        var dnsSeen = false
        for (original in raw.lineSequence()) {
            val line = original.substringBefore('#').trim()
            if (line.isEmpty()) continue
            if (line.startsWith("[") || line.endsWith("]")) {
                when (line) {
                    "[Interface]" -> {
                        if (++interfaceSections != 1 || peerSections != 0) return false
                        section = "interface"
                    }
                    "[Peer]" -> {
                        if (interfaceSections != 1 || ++peerSections != 1) return false
                        section = "peer"
                    }
                    else -> return false
                }
                continue
            }
            val parts = line.split('=', limit = 2)
            if (parts.size != 2 || section.isEmpty()) return false
            val key = parts[0].trim().lowercase()
            val value = parts[1].trim()
            if (value.isEmpty()) return false
            when (section to key) {
                "interface" to "address" -> {
                    if (addressSeen) return false
                    val octet = address.matchEntire(value)?.groupValues?.get(1)?.toIntOrNull()
                    if (octet == null || octet !in 2..254) return false
                    addressSeen = true
                }
                "interface" to "dns" -> {
                    if (dnsSeen || value != "10.77.0.1") return false
                    dnsSeen = true
                }
                "peer" to "allowedips" -> {
                    if (allowedSeen || value != "10.77.0.0/24") return false
                    allowedSeen = true
                }
                "peer" to "endpoint" -> {
                    if (endpointSeen) return false
                    endpointSeen = true
                }
                else -> Unit // Every other directive is parsed by upstream WireGuard.
            }
        }
        return interfaceSections == 1 && peerSections == 1 &&
            addressSeen && allowedSeen && endpointSeen
    }
}
