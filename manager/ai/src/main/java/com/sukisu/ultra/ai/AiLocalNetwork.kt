package com.sukisu.ultra.ai

import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import androidx.core.content.ContextCompat
import okhttp3.HttpUrl.Companion.toHttpUrlOrNull

/**
 * Android 17 (API 37) blocks local-network sockets for apps targeting 37 until
 * the user grants ACCESS_LOCAL_NETWORK. Local inference servers are the main
 * use case for this assistant, so the permission must be requested before the
 * first request to a LAN address. Loopback is a separate install-time
 * permission (USE_LOOPBACK_INTERFACE) and is not gated here.
 */
object AiLocalNetwork {

    const val PERMISSION = "android.permission.ACCESS_LOCAL_NETWORK"

    private const val ANDROID_17_API = 37

    fun isSupported(): Boolean = Build.VERSION.SDK_INT >= ANDROID_17_API

    fun needsPermission(context: Context, config: AiConfig): Boolean =
        isSupported() &&
            isLanEndpoint(config) &&
            ContextCompat.checkSelfPermission(context, PERMISSION) !=
            PackageManager.PERMISSION_GRANTED

    /** True for private/loopback-adjacent LAN destinations, false for public APIs. */
    fun isLanEndpoint(config: AiConfig): Boolean {
        val host = config.resolvedEndpoint()
            .toHttpUrlOrNull()
            ?.host
            ?.lowercase()
            ?.trim('[', ']')
            ?: return false

        if (host == "localhost" || host == "::1" || host.startsWith("127.")) return false
        if (host == "host.docker.internal" || host == "gateway.docker.internal") return true
        if (host.endsWith(".local") || host.endsWith(".lan") ||
            host.endsWith(".home") || host.endsWith(".internal")
        ) {
            return true
        }
        if (host.startsWith("::ffff:")) {
            return isPrivateIpv4(host.removePrefix("::ffff:"))
        }
        if (host.contains(':')) return isPrivateIpv6(host)
        // Hostnames without a dot are normally resolved through the LAN or a
        // local search domain; ask for the permission rather than timing out.
        if (!host.contains('.')) return true
        return isPrivateIpv4(host)
    }

    private fun isPrivateIpv4(host: String): Boolean {
        val octets = host.split('.').map { it.toIntOrNull() ?: return false }
        if (octets.size != 4 || octets.any { it !in 0..255 }) return false
        val first = octets[0]
        val second = octets[1]
        return first == 10 ||
            (first == 172 && second in 16..31) ||
            (first == 192 && second == 168) ||
            (first == 169 && second == 254) ||
            (first == 100 && second in 64..127)
    }

    private fun isPrivateIpv6(host: String): Boolean =
        host.startsWith("fe80:") ||
            host.startsWith("fc") ||
            host.startsWith("fd")
}
