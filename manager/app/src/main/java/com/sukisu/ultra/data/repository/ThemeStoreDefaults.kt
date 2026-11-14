package com.sukisu.ultra.data.repository

import android.content.Context
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import com.sukisu.ultra.ksuApp
import java.net.NetworkInterface
import java.util.Locale
import java.util.TimeZone

/**
 * Picks the default mirror from the device's region instead of probing all of
 * them. Region detection is local and instant, so opening the store never
 * waits for network health checks.
 */
object ThemeStoreDefaults {
    private const val INTERNATIONAL_BASE_URL = "https://themes.oddnexus.top/"
    private const val MAINLAND_PRIMARY_BASE_URL = "https://themes.neko.shirkneko.top:8443/"
    private const val MAINLAND_SECONDARY_BASE_URL = "https://themes.zako.shirkneko.top:20005/"
    private const val MAINLAND_TERTIARY_BASE_URL = "https://themes.shirkneko.top:41112/"

    /** First entry is the international mirror; the other three serve mainland China. */
    val BASE_URLS = listOf(
        INTERNATIONAL_BASE_URL,
        MAINLAND_PRIMARY_BASE_URL,
        MAINLAND_SECONDARY_BASE_URL,
        MAINLAND_TERTIARY_BASE_URL,
    )

    /**
     * Mainland mirrors in failover order: primary, then secondary, then tertiary.
     * The tertiary host is a home node behind a private root CA, so it only gets
     * traffic when both public mirrors are down.
     */
    private val MAINLAND_BASE_URLS = listOf(
        MAINLAND_PRIMARY_BASE_URL,
        MAINLAND_SECONDARY_BASE_URL,
        MAINLAND_TERTIARY_BASE_URL,
    )

    /**
     * IANA zones that map to mainland China. `Asia/Shanghai` is what Android
     * normally reports; the others exist on older devices and in `PRC`.
     */
    private val MAINLAND_TIME_ZONES = setOf(
        "Asia/Shanghai",
        "Asia/Chongqing",
        "Asia/Harbin",
        "Asia/Urumqi",
        "Asia/Kashgar",
        "PRC",
    )

    /** How long a failed primary stays out of automatic selection. */
    private const val FAILOVER_COOLDOWN_MS = 30 * 60 * 1000L

    /** ConnectivityManager lookups are cached because this runs on every source resolution. */
    private const val VPN_CACHE_MS = 10_000L

    private val VPN_INTERFACE_PREFIXES = listOf("tun", "tap", "ppp", "utun")

    @Volatile
    private var unavailableBaseUrl: String? = null

    @Volatile
    private var unavailableUntilMs: Long = 0L

    @Volatile
    private var vpnDetected: Boolean = false

    @Volatile
    private var vpnCheckedAtMs: Long = 0L

    /** The mirror this device should use for the current region. */
    fun preferredBaseUrl(): String {
        val mirrors = regionalBaseUrls()
        if (mirrors.size > 1 && isPrimaryUnavailable()) return mirrors[1]
        return mirrors.first()
    }

    /**
     * Built-in mirrors for the current egress. A VPN moves traffic out of the
     * device's own region, so it always uses the international mirror even when
     * the time zone says mainland China.
     */
    private fun regionalBaseUrls(): List<String> =
        if (isMainlandChina() && !isVpnActive()) {
            MAINLAND_BASE_URLS
        } else {
            listOf(INTERNATIONAL_BASE_URL)
        }

    /**
     * True when the active network is a VPN (or routes through a proxy), i.e.
     * the exit region is not the device region. Resolved from ConnectivityManager
     * with a short cache, falling back to the tun/ppp interface list.
     */
    fun isVpnActive(): Boolean {
        val now = System.currentTimeMillis()
        if (now - vpnCheckedAtMs < VPN_CACHE_MS) return vpnDetected
        val detected = runCatching {
            val manager = ksuApp.getSystemService(Context.CONNECTIVITY_SERVICE) as? ConnectivityManager
            val network = manager?.activeNetwork ?: return@runCatching false
            val capabilities = manager.getNetworkCapabilities(network) ?: return@runCatching false
            capabilities.hasTransport(NetworkCapabilities.TRANSPORT_VPN) ||
                manager.getLinkProperties(network)?.httpProxy != null
        }.getOrDefault(false) || hasVpnInterface()
        vpnDetected = detected
        vpnCheckedAtMs = now
        return detected
    }

    private fun hasVpnInterface(): Boolean = runCatching {
        NetworkInterface.getNetworkInterfaces()?.toList().orEmpty().any { iface ->
            iface.isUp && !iface.isLoopback &&
                VPN_INTERFACE_PREFIXES.any { prefix -> iface.name.startsWith(prefix) }
        }
    }.getOrDefault(false)

    private fun isPrimaryUnavailable(): Boolean {
        val primary = ThemeStoreRepository.normalizeBaseUrl(regionalBaseUrls().first()) ?: return false
        return unavailableBaseUrl == primary && System.currentTimeMillis() < unavailableUntilMs
    }

    /**
     * The next built-in mirror to try when [baseUrl] cannot be reached, or null
     * when the URL is not a regional mirror or has nothing after it.
     */
    fun fallbackBaseUrl(baseUrl: String): String? {
        val normalized = ThemeStoreRepository.normalizeBaseUrl(baseUrl) ?: return null
        val mirrors = regionalBaseUrls().mapNotNull { ThemeStoreRepository.normalizeBaseUrl(it) }
        val index = mirrors.indexOf(normalized)
        return if (index < 0) null else mirrors.getOrNull(index + 1)
    }

    /**
     * Marks a regional primary as unreachable so automatic selection uses the
     * next mirror for [FAILOVER_COOLDOWN_MS]. The primary is retried after the
     * cooldown without any background probing.
     */
    fun reportUnreachable(baseUrl: String) {
        val normalized = ThemeStoreRepository.normalizeBaseUrl(baseUrl) ?: return
        val primary = ThemeStoreRepository.normalizeBaseUrl(regionalBaseUrls().first()) ?: return
        if (normalized != primary) return
        unavailableBaseUrl = normalized
        unavailableUntilMs = System.currentTimeMillis() + FAILOVER_COOLDOWN_MS
    }

    /** Clears the failover state once a request to the marked mirror succeeds. */
    fun reportReachable(baseUrl: String) {
        val normalized = ThemeStoreRepository.normalizeBaseUrl(baseUrl) ?: return
        if (normalized == unavailableBaseUrl) {
            unavailableBaseUrl = null
            unavailableUntilMs = 0L
        }
    }

    /**
     * Mainland China is detected from the device time zone first, then from the
     * region of the selected locale. Both are offline lookups.
     */
    fun isMainlandChina(): Boolean {
        val zone = runCatching { TimeZone.getDefault().id }.getOrNull().orEmpty()
        if (MAINLAND_TIME_ZONES.any { it.equals(zone, ignoreCase = true) }) return true
        val country = runCatching { Locale.getDefault().country }.getOrNull().orEmpty()
        return country.equals("CN", ignoreCase = true)
    }

    /** True when [raw] points at one of the built-in mirrors. */
    fun isBuiltInBaseUrl(raw: String): Boolean {
        val normalized = ThemeStoreRepository.normalizeBaseUrl(raw) ?: return false
        return BASE_URLS.any { base -> ThemeStoreRepository.normalizeBaseUrl(base) == normalized }
    }

    /**
     * True when the user has not pinned a mirror. An empty value follows the
     * regional/VPN default; anything else is a manual choice.
     */
    fun usesAutoBaseUrl(configured: String): Boolean = configured.trim().isEmpty()

    /**
     * The effective default source: a manually selected mirror is used exactly
     * as stored, so a region or VPN change never overrides it. A blank value
     * resolves to the regional mirror.
     */
    fun resolveConfiguredBaseUrl(configured: String): String {
        val trimmed = configured.trim()
        return if (trimmed.isEmpty()) preferredBaseUrl() else trimmed
    }

    /** The regional mirror, resolved without any network request. */
    fun resolveBestBaseUrl(): String = preferredBaseUrl()
}
