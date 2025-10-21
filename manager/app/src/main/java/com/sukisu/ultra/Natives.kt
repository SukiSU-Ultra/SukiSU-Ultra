package com.sukisu.ultra

import android.os.Parcelable
import androidx.annotation.Keep
import androidx.compose.runtime.Immutable
import kotlinx.parcelize.Parcelize

/**
 * @author weishu
 * @date 2022/12/8.
 */
object Natives {
    // minimal supported kernel version
    // 10915: allowlist breaking change, add app profile
    // 10931: app profile struct add 'version' field
    // 10946: add capabilities
    // 10977: change groups_count and groups to avoid overflow write
    // 11071: Fix the issue of failing to set a custom SELinux type.
    const val MINIMAL_SUPPORTED_KERNEL = 11071
    const val MINIMAL_SUPPORTED_KERNEL_FULL = "v3.1.8"

    // 11640: Support query working mode, LKM or GKI
    // when MINIMAL_SUPPORTED_KERNEL > 11640, we can remove this constant.
    const val MINIMAL_SUPPORTED_KERNEL_LKM = 11648

    // 12040: Support disable sucompat mode
    const val MINIMAL_SUPPORTED_SU_COMPAT = 12040
    const val KERNEL_SU_DOMAIN = "u:r:su:s0"

    const val MINIMAL_SUPPORTED_KPM = 12800

    const val MINIMAL_SUPPORTED_DYNAMIC_MANAGER = 13215

    const val MINIMAL_SUPPORTED_UID_SCANNER = 13347

    const val ROOT_UID = 0
    const val ROOT_GID = 0

    // 获取完整版本号
    external fun getFullVersion(): String

    fun isVersionLessThan(v1Full: String, v2Full: String): Boolean {
        fun extractVersionParts(version: String): List<Int> {
            val match = Regex("""v\d+(\.\d+)*""").find(version)
            val simpleVersion = match?.value ?: version
            return simpleVersion.trimStart('v').split('.').map { it.toIntOrNull() ?: 0 }
        }

        val v1Parts = extractVersionParts(v1Full)
        val v2Parts = extractVersionParts(v2Full)
        val maxLength = maxOf(v1Parts.size, v2Parts.size)
        for (i in 0 until maxLength) {
            val num1 = v1Parts.getOrElse(i) { 0 }
            val num2 = v2Parts.getOrElse(i) { 0 }
            if (num1 != num2) return num1 < num2
        }
        return false
    }

    fun getSimpleVersionFull(): String = getFullVersion().let { version ->
        Regex("""v\d+(\.\d+)*""").find(version)?.value ?: version
    }

    init {
        System.loadLibrary("zakosign")
        System.loadLibrary("kernelsu")
    }

    // become root manager, return true if success.
    external fun becomeManager(pkg: String?): Boolean
    val version: Int
        external get

    // get the uid list of allowed su processes.
    val allowList: IntArray
        external get

    val isSafeMode: Boolean
        external get

    val isLkmMode: Boolean
        external get

    external fun uidShouldUmount(uid: Int): Boolean

    /**
     * Get the profile of the given package.
     * @param key usually the package name
     * @return return null if failed.
     */
    external fun getAppProfile(key: String?, uid: Int): Profile
    external fun setAppProfile(profile: Profile?): Boolean

    /**
     * `su` compat mode can be disabled temporarily.
     *  0: disabled
     *  1: enabled
     *  negative : error
     */
    external fun isSuEnabled(): Boolean
    external fun setSuEnabled(enabled: Boolean): Boolean
    external fun isKPMEnabled(): Boolean
    external fun getHookType(): String

    /**
     * Get SUSFS feature status from kernel
     * @return SusfsFeatureStatus object containing all feature states, or null if failed
     */

    /**
     * Set dynamic managerature configuration
     * @param size APK signature size
     * @param hash APK signature hash (64 character hex string)
     * @return true if successful, false otherwise
     */
    external fun setDynamicManager(size: Int, hash: String): Boolean


    /**
     * Get current dynamic managerature configuration
     * @return DynamicManagerConfig object containing current configuration, or null if not set
     */
    external fun getDynamicManager(): DynamicManagerConfig?

    /**
     * Clear dynamic managerature configuration
     * @return true if successful, false otherwise
     */
    external fun clearDynamicManager(): Boolean

    /**
     * Get active managers list when dynamic manager is enabled
     * @return ManagersList object containing active managers, or null if failed or not enabled
     */
    external fun getManagersList(): ManagersList?

    // 模块签名验证
    external fun verifyModuleSignature(modulePath: String): Boolean

    /**
     * Check if UID scanner is currently enabled
     * @return true if UID scanner is enabled, false otherwise
     */
    external fun isUidScannerEnabled(): Boolean

    /**
     * Enable or disable UID scanner
     * @param enabled true to enable, false to disable
     * @return true if operation was successful, false otherwise
     */
    external fun setUidScannerEnabled(enabled: Boolean): Boolean

    /**
     * Clear UID scanner environment (force exit)
     * This will forcefully stop all UID scanner operations and clear the environment
     * @return true if operation was successful, false otherwise
     */
    external fun clearUidScannerEnvironment(): Boolean

    private const val NON_ROOT_DEFAULT_PROFILE_KEY = "$"
    private const val NOBODY_UID = 9999

    fun setDefaultUmountModules(umountModules: Boolean): Boolean {
        Profile(
            NON_ROOT_DEFAULT_PROFILE_KEY,
            NOBODY_UID,
            false,
            umountModules = umountModules
        ).let {
            return setAppProfile(it)
        }
    }

    fun isDefaultUmountModules(): Boolean {
        getAppProfile(NON_ROOT_DEFAULT_PROFILE_KEY, NOBODY_UID).let {
            return it.umountModules
        }
    }

    fun requireNewKernel(): Boolean {
        if (version < MINIMAL_SUPPORTED_KERNEL) return true
        return isVersionLessThan(getFullVersion(), MINIMAL_SUPPORTED_KERNEL_FULL)
    }

    @Immutable
    @Parcelize
    @Keep
    data class DynamicManagerConfig(
        val size: Int = 0,
        val hash: String = ""
    ) : Parcelable {

        fun isValid(): Boolean {
            return size > 0 && hash.length == 64 && hash.all {
                it in '0'..'9' || it in 'a'..'f' || it in 'A'..'F'
            }
        }
    }

    @Immutable
    @Parcelize
    @Keep
    data class ManagersList(
        val count: Int = 0,
        val managers: List<ManagerInfo> = emptyList()
    ) : Parcelable

    @Immutable
    @Parcelize
    @Keep
    data class ManagerInfo(
        val uid: Int = 0,
        val signatureIndex: Int = 0
    ) : Parcelable

    @Immutable
    @Parcelize
    @Keep
    data class Profile(
        // and there is a default profile for root and non-root
        val name: String,
        // current uid for the package, this is convivent for kernel to check
        // if the package name doesn't match uid, then it should be invalidated.
        val currentUid: Int = 0,

        // if this is true, kernel will grant root permission to this package
        val allowSu: Boolean = false,

        // these are used for root profile
        val rootUseDefault: Boolean = true,
        val rootTemplate: String? = null,
        val uid: Int = ROOT_UID,
        val gid: Int = ROOT_GID,
        val groups: List<Int> = mutableListOf(),
        val capabilities: List<Int> = mutableListOf(),
        val context: String = KERNEL_SU_DOMAIN,
        val namespace: Int = Namespace.INHERITED.ordinal,

        val nonRootUseDefault: Boolean = true,
        val umountModules: Boolean = true,
        var rules: String = "", // this field is save in ksud!!
    ) : Parcelable {
        enum class Namespace {
            INHERITED,
            GLOBAL,
            INDIVIDUAL,
        }

        constructor() : this("")
    }
}