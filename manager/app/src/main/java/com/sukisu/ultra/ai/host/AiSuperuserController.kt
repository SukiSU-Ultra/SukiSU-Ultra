package com.sukisu.ultra.ai.host

import android.os.Process
import com.sukisu.ultra.Natives
import com.sukisu.ultra.ai.api.AiSuperuserService
import com.sukisu.ultra.data.repository.SettingsRepositoryImpl
import com.sukisu.ultra.data.repository.SuperUserRepositoryImpl
import com.sukisu.ultra.ksuApp
import com.sukisu.ultra.ui.component.profile.TemporaryRoot
import com.sukisu.ultra.ui.util.getSepolicy
import com.sukisu.ultra.ui.util.rootAvailable
import com.sukisu.ultra.ui.util.setSepolicy
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import kotlinx.serialization.json.add
import kotlinx.serialization.json.buildJsonArray
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import kotlinx.serialization.json.putJsonArray

private data class AiAppTarget(
    val uid: Int,
    val packageName: String,
    val profileKey: String,
    val label: String,
    val special: Boolean,
    val packages: List<String>,
)

/**
 * Per-app root and temporary-root control, plus the global su compatibility
 * switch. Writes always go through ksud's `temporary-root apply` (the same path
 * AppProfileScreen uses), never [Natives.setAppProfile] directly.
 */
object AiSuperuserController : AiSuperuserService {

    private val repo = SettingsRepositoryImpl()

    override suspend fun capabilities(): String = withContext(Dispatchers.IO) {
        val manager = runCatching { Natives.isManager }.getOrDefault(false)
        val root = manager && runCatching { rootAvailable() }.getOrDefault(false)
        val suStatus = if (root) runCatching { repo.getSuCompatStatus() }.getOrDefault("unknown") else "unknown"
        buildJsonObject {
            put("manager", manager)
            put("root", root)
            put("su_compat_status", suStatus)
            put("su_enabled", root && runCatching { repo.isSuEnabled() }.getOrDefault(false))
            put("default_temporary_root_minutes", TemporaryRoot.defaultMinutes(ksuApp))
            put("temporary_root_max_seconds", MAX_TEMP_ROOT_SECONDS)
            putJsonArray("commands") {
                add("superuser_apps")
                add("superuser_app_info")
                add("superuser_set_root")
                add("superuser_set_temporary_root")
                add("superuser_set_global_su")
            }
            if (!manager || !root) {
                put("reason", "A SukiSU kernel and root access are required.")
            }
        }.toString()
    }

    override suspend fun readApps(limit: Int, includeDenied: Boolean): String =
        withContext(Dispatchers.IO) {
            ensureRoot()
            val apps = SuperUserRepositoryImpl().getAppList().getOrThrow().first
            val visible = apps
                .filter { it.packageName != ksuApp.packageName }
                .filter { includeDenied || it.allowSu }
                .take(limit.coerceIn(1, 200))
            buildJsonObject {
                put("include_denied", includeDenied)
                put("count", visible.size)
                put("apps", buildJsonArray {
                    visible.forEach { app ->
                        add(buildJsonObject {
                            put("package", app.displayIdentifier)
                            put("label", app.label)
                            put("uid", app.uid)
                            put("allow_su", app.allowSu)
                            put("special", app.special)
                            put("custom_profile", app.hasCustomProfile)
                            app.profile?.let { profile ->
                                put("root_use_default", profile.rootUseDefault)
                                put("non_root_use_default", profile.nonRootUseDefault)
                                put("namespace", profile.namespace)
                                put("umount_modules", profile.umountModules)
                            }
                            if (app.allowSu) {
                                put(
                                    "temporary_root",
                                    runCatching { TemporaryRoot.status(app.uid) }.getOrDefault("unknown"),
                                )
                            }
                        })
                    }
                })
            }.toString()
        }

    override suspend fun appInfo(packageName: String?, uid: Int?): String =
        withContext(Dispatchers.IO) {
            ensureRoot()
            val target = resolveTarget(packageName, uid)
            val profile = Natives.getAppProfile(target.profileKey, target.uid)
            buildJsonObject {
                put("package", target.packageName)
                put("label", target.label)
                put("uid", target.uid)
                put("shared_uid_packages", buildJsonArray { target.packages.forEach { add(it) } })
                put("special", target.special)
                put("allow_su", profile.allowSu)
                put("temporary_root", runCatching { TemporaryRoot.status(target.uid) }.getOrDefault("unknown"))
                put("root_use_default", profile.rootUseDefault)
                put("root_template", profile.rootTemplate ?: "")
                put("non_root_use_default", profile.nonRootUseDefault)
                put("namespace", profile.namespace)
                put("umount_modules", profile.umountModules)
                put(
                    "can_grant_permanent",
                    !target.special && (target.uid == 1000 || target.uid >= 2000),
                )
                put(
                    "can_grant_temporary",
                    !target.special && target.uid >= 2000 && target.uid != Process.myUid(),
                )
            }.toString()
        }

    override suspend fun setRoot(packageName: String?, uid: Int?, enabled: Boolean): String =
        withContext(Dispatchers.IO) {
            ensureRootAndSu()
            val target = resolveTarget(packageName, uid)
            require(!target.special) { "WebView Zygote cannot receive root." }
            if (enabled) {
                require(target.uid == 1000 || target.uid >= 2000) {
                    "UID ${target.uid} cannot receive root (only UID 1000 or UID >= 2000)."
                }
            }
            val current = Natives.getAppProfile(target.profileKey, target.uid)
            if (current.allowSu == enabled) {
                return@withContext describe(target, current.allowSu, "already in the requested state")
            }
            val updated = current.copy(allowSu = enabled)
            if (enabled && !current.rootUseDefault) {
                val rules = runCatching { getSepolicy(current.name) }.getOrDefault("")
                require(rules.isBlank() || setSepolicy(current.name, rules)) {
                    "Failed to restore the app's SELinux rules; use the app profile page."
                }
            }
            check(TemporaryRoot.saveProfile(
                profile = updated,
                expectedRoot = current.allowSu,
                updateLease = true,
                seconds = null,
            )) { "ksud rejected the profile update." }
            val verified = Natives.getAppProfile(target.profileKey, target.uid)
            check(verified.allowSu == enabled) { "The kernel did not apply the requested root state." }
            SuperUserRepositoryImpl.invalidateAppList()
            describe(target, verified.allowSu, if (enabled) "root granted" else "root revoked")
        }

    override suspend fun setTemporaryRoot(
        packageName: String?,
        uid: Int?,
        seconds: Long?,
        untilReboot: Boolean,
        revoke: Boolean,
    ): String = withContext(Dispatchers.IO) {
        ensureRootAndSu()
        val target = resolveTarget(packageName, uid)
        require(!target.special) { "WebView Zygote cannot receive root." }
        val current = Natives.getAppProfile(target.profileKey, target.uid)

        if (revoke) {
            check(TemporaryRoot.saveProfile(
                profile = current.copy(allowSu = false),
                expectedRoot = current.allowSu,
                updateLease = true,
                seconds = null,
            )) { "ksud rejected the revoke." }
            val verified = Natives.getAppProfile(target.profileKey, target.uid)
            check(!verified.allowSu) { "The kernel did not revoke root." }
            SuperUserRepositoryImpl.invalidateAppList()
            return@withContext describe(target, false, "temporary root revoked")
        }

        require(target.uid >= 2000) {
            "Temporary root requires UID >= 2000 (UID ${target.uid} is not allowed)."
        }
        require(target.uid != Process.myUid()) {
            "The manager cannot grant temporary root to itself."
        }
        val leaseSeconds = when {
            untilReboot -> 0L
            seconds != null -> {
                require(seconds in 1..MAX_TEMP_ROOT_SECONDS) {
                    "seconds must be between 1 and $MAX_TEMP_ROOT_SECONDS, or use until_reboot."
                }
                seconds
            }
            else -> (TemporaryRoot.defaultMinutes(ksuApp) * 60L).coerceIn(1L, MAX_TEMP_ROOT_SECONDS)
        }
        check(TemporaryRoot.saveProfile(
            profile = current.copy(allowSu = true),
            expectedRoot = current.allowSu,
            updateLease = true,
            seconds = leaseSeconds,
        )) { "ksud rejected the temporary root grant." }
        val verified = Natives.getAppProfile(target.profileKey, target.uid)
        check(verified.allowSu) { "The kernel did not grant root." }
        SuperUserRepositoryImpl.invalidateAppList()
        val status = runCatching { TemporaryRoot.status(target.uid) }.getOrDefault("timed")
        val duration = if (leaseSeconds == 0L) "until reboot" else "${leaseSeconds}s"
        "Granted temporary root to ${target.label} (${target.packageName}, uid ${target.uid}) " +
            "for $duration; ksud status=$status."
    }

    override suspend fun setGlobalSu(mode: String): String = withContext(Dispatchers.IO) {
        ensureRoot()
        val status = repo.getSuCompatStatus()
        require(status == "supported") {
            "The global su switch is not user-configurable on this kernel (status=$status)."
        }
        val normalized = mode.trim().lowercase().replace('-', '_')
        when (normalized) {
            "enable", "enabled", "on" -> {
                require(repo.setSuEnabled(true)) { "The kernel rejected enabling su." }
                repo.execKsudFeatureSave()
                repo.setSuCompatModePref(0)
            }

            "disable_until_reboot", "until_reboot", "temporary_off" -> {
                require(repo.setSuEnabled(true)) { "The kernel rejected the persistent state." }
                repo.execKsudFeatureSave()
                require(repo.setSuEnabled(false)) { "The kernel rejected the runtime disable." }
                repo.setSuCompatModePref(0)
            }

            "disable_always", "disable", "off" -> {
                require(repo.setSuEnabled(false)) { "The kernel rejected disabling su." }
                repo.execKsudFeatureSave()
                repo.setSuCompatModePref(2)
            }

            else -> throw IllegalArgumentException(
                "mode must be enable, disable_until_reboot or disable_always"
            )
        }
        val enabled = runCatching { repo.isSuEnabled() }.getOrDefault(false)
        "Global su mode set to '$normalized'; runtime su is ${if (enabled) "enabled" else "disabled"}."
    }

    private fun ensureRoot() {
        check(runCatching { Natives.isManager }.getOrDefault(false)) {
            "Superuser control is unavailable: no SukiSU kernel is active."
        }
        check(runCatching { rootAvailable() }.getOrDefault(false)) {
            "Superuser control is unavailable: the manager does not have root."
        }
    }

    private fun ensureRootAndSu() {
        ensureRoot()
        check(runCatching { Natives.isSuEnabled() }.getOrDefault(true)) {
            "Global su is currently disabled; enable it before changing app root grants."
        }
    }

    private suspend fun resolveTarget(packageName: String?, uid: Int?): AiAppTarget {
        val apps = SuperUserRepositoryImpl().getAppList(force = true).getOrThrow().first
        val named = packageName?.trim()?.takeIf { it.isNotEmpty() }
        val app = when {
            named != null -> apps.firstOrNull {
                it.packageName == named || it.profileKey == named ||
                    it.displayIdentifier.equals(named, ignoreCase = true)
            }

            uid != null -> apps.firstOrNull { it.uid == uid }
            else -> null
        } ?: throw IllegalArgumentException(
            "App not found. Provide an installed package name or a uid from superuser_apps."
        )
        require(app.packageName != ksuApp.packageName) {
            "The manager's own root profile is not exposed to the assistant."
        }
        return AiAppTarget(
            uid = app.uid,
            packageName = app.packageName.ifBlank { app.profileKey },
            profileKey = app.profileKey,
            label = app.label,
            special = app.special || app.isWebViewZygote,
            packages = apps.filter { it.uid == app.uid }.map { it.displayIdentifier }.distinct(),
        )
    }

    private fun describe(target: AiAppTarget, allowSu: Boolean, action: String): String {
        val shared = if (target.packages.size > 1) {
            " This affects all packages sharing uid ${target.uid}: ${target.packages.joinToString()}."
        } else {
            ""
        }
        return "${target.label} (${target.packageName}, uid ${target.uid}): $action; allow_su=$allowSu.$shared"
    }

    private const val MAX_TEMP_ROOT_SECONDS = 604_800L
}
