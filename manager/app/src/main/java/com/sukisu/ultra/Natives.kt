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

    // 11640: Support query working mode, LKM or GKI
    // when MINIMAL_SUPPORTED_KERNEL > 11640, we can remove this constant.
    const val MINIMAL_SUPPORTED_KERNEL_LKM = 11648

    // 12040: Support disable sucompat mode
    const val MINIMAL_SUPPORTED_SU_COMPAT = 12040
    const val KERNEL_SU_DOMAIN = "u:r:su:s0"

    const val MINIMAL_SUPPORTED_KPM = 12800

    const val ROOT_UID = 0
    const val ROOT_GID = 0

    init {
        System.loadLibrary("zako")
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
    external fun getSusfsFeatureStatus(): SusfsFeatureStatus?

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
        return version < MINIMAL_SUPPORTED_KERNEL
    }

    @Immutable
    @Parcelize
    @Keep
    data class SusfsFeatureStatus(
        val statusSusPath: Boolean = false,
        val statusSusMount: Boolean = false,
        val statusAutoDefaultMount: Boolean = false,
        val statusAutoBindMount: Boolean = false,
        val statusSusKstat: Boolean = false,
        val statusTryUmount: Boolean = false,
        val statusAutoTryUmountBind: Boolean = false,
        val statusSpoofUname: Boolean = false,
        val statusEnableLog: Boolean = false,
        val statusHideSymbols: Boolean = false,
        val statusSpoofCmdline: Boolean = false,
        val statusOpenRedirect: Boolean = false,
        val statusMagicMount: Boolean = false,
        val statusOverlayfsAutoKstat: Boolean = false,
        val statusSusSu: Boolean = false
    ) : Parcelable {
        fun toMap(): Map<String, Boolean> {
            return mapOf(
                "CONFIG_KSU_SUSFS_SUS_PATH" to statusSusPath,
                "CONFIG_KSU_SUSFS_SUS_MOUNT" to statusSusMount,
                "CONFIG_KSU_SUSFS_AUTO_ADD_SUS_KSU_DEFAULT_MOUNT" to statusAutoDefaultMount,
                "CONFIG_KSU_SUSFS_AUTO_ADD_SUS_BIND_MOUNT" to statusAutoBindMount,
                "CONFIG_KSU_SUSFS_SUS_KSTAT" to statusSusKstat,
                "CONFIG_KSU_SUSFS_TRY_UMOUNT" to statusTryUmount,
                "CONFIG_KSU_SUSFS_AUTO_ADD_TRY_UMOUNT_FOR_BIND_MOUNT" to statusAutoTryUmountBind,
                "CONFIG_KSU_SUSFS_SPOOF_UNAME" to statusSpoofUname,
                "CONFIG_KSU_SUSFS_ENABLE_LOG" to statusEnableLog,
                "CONFIG_KSU_SUSFS_HIDE_KSU_SUSFS_SYMBOLS" to statusHideSymbols,
                "CONFIG_KSU_SUSFS_SPOOF_CMDLINE_OR_BOOTCONFIG" to statusSpoofCmdline,
                "CONFIG_KSU_SUSFS_OPEN_REDIRECT" to statusOpenRedirect,
                "CONFIG_KSU_SUSFS_HAS_MAGIC_MOUNT" to statusMagicMount,
                "CONFIG_KSU_SUSFS_SUS_OVERLAYFS" to statusOverlayfsAutoKstat,
                "CONFIG_KSU_SUSFS_SUS_SU" to statusSusSu
            )
        }
    }


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