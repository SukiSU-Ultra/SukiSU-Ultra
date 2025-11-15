package com.sukisu.ultra.ui.viewmodel

import android.content.*
import android.content.pm.ApplicationInfo
import android.content.pm.PackageInfo
import android.graphics.drawable.Drawable
import android.os.IBinder
import android.os.Parcelable
import android.util.Log
import androidx.compose.runtime.*
import androidx.core.content.edit
import androidx.lifecycle.ViewModel
import com.sukisu.ultra.Natives
import com.sukisu.ultra.ksuApp
import com.sukisu.ultra.ui.KsuService
import com.sukisu.ultra.ui.util.*
import com.topjohnwu.superuser.Shell
import kotlinx.coroutines.*
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.parcelize.Parcelize
import java.text.Collator
import java.util.*
import java.util.concurrent.LinkedBlockingQueue
import java.util.concurrent.ThreadPoolExecutor
import java.util.concurrent.TimeUnit
import kotlin.coroutines.resume
import kotlin.coroutines.suspendCoroutine
import com.sukisu.zako.IKsuInterface

enum class AppCategory(val displayNameRes: Int, val persistKey: String) {
    ALL(com.sukisu.ultra.R.string.category_all_apps, "ALL"),
    ROOT(com.sukisu.ultra.R.string.category_root_apps, "ROOT"),
    CUSTOM(com.sukisu.ultra.R.string.category_custom_apps, "CUSTOM"),
    DEFAULT(com.sukisu.ultra.R.string.category_default_apps, "DEFAULT");

    companion object {
        fun fromPersistKey(key: String): AppCategory = entries.find { it.persistKey == key } ?: ALL
    }
}

enum class SortType(val displayNameRes: Int, val persistKey: String) {
    NAME_ASC(com.sukisu.ultra.R.string.sort_name_asc, "NAME_ASC"),
    NAME_DESC(com.sukisu.ultra.R.string.sort_name_desc, "NAME_DESC"),
    INSTALL_TIME_NEW(com.sukisu.ultra.R.string.sort_install_time_new, "INSTALL_TIME_NEW"),
    INSTALL_TIME_OLD(com.sukisu.ultra.R.string.sort_install_time_old, "INSTALL_TIME_OLD"),
    SIZE_DESC(com.sukisu.ultra.R.string.sort_size_desc, "SIZE_DESC"),
    SIZE_ASC(com.sukisu.ultra.R.string.sort_size_asc, "SIZE_ASC"),
    USAGE_FREQ(com.sukisu.ultra.R.string.sort_usage_freq, "USAGE_FREQ");

    companion object {
        fun fromPersistKey(key: String): SortType = entries.find { it.persistKey == key } ?: NAME_ASC
    }
}

class SuperUserViewModel : ViewModel() {
    companion object {
        private const val TAG = "SuperUserViewModel"
        private val appsLock = Any()
        var apps by mutableStateOf<List<AppInfo>>(emptyList())
        var appGroups by mutableStateOf<List<AppGroup>>(emptyList())

        @JvmStatic
        fun getAppIconDrawable(context: Context, packageName: String): Drawable? {
            val appList = synchronized(appsLock) { apps }
            return appList.find { it.packageName == packageName }
                ?.packageInfo?.applicationInfo?.loadIcon(context.packageManager)
        }

        private const val PREFS_NAME = "settings"
        private const val KEY_SHOW_SYSTEM_APPS = "show_system_apps"
        private const val KEY_SELECTED_CATEGORY = "selected_category"
        private const val KEY_CURRENT_SORT_TYPE = "current_sort_type"
        private const val CORE_POOL_SIZE = 8
        private const val MAX_POOL_SIZE = 16
        private const val KEEP_ALIVE_TIME = 60L
        private const val BATCH_SIZE = 20
    }

    @Parcelize
    data class AppInfo(
        val label: String,
        val packageInfo: PackageInfo,
        val profile: Natives.Profile?,
    ) : Parcelable {
        val packageName: String get() = packageInfo.packageName
        val uid: Int get() = packageInfo.applicationInfo!!.uid
        val allowSu: Boolean get() = profile?.allowSu == true
        val hasCustomProfile: Boolean
            get() = profile?.let {
                if (it.allowSu) !it.rootUseDefault else !it.nonRootUseDefault
            } ?: false
    }

    @Parcelize
    data class AppGroup(
        val uid: Int,
        val apps: List<AppInfo>,
        val profile: Natives.Profile?
    ) : Parcelable {
        val mainApp: AppInfo get() = apps.first()
        val packageNames: List<String> get() = apps.map { it.packageName }
        val allowSu: Boolean get() = profile?.allowSu == true

        val userName: String? get() = Natives.getUserName(uid)
        val hasCustomProfile: Boolean
            get() = profile?.let {
                if (it.allowSu) !it.rootUseDefault else !it.nonRootUseDefault
            } ?: false
    }

    private val appProcessingThreadPool = ThreadPoolExecutor(
        CORE_POOL_SIZE, MAX_POOL_SIZE, KEEP_ALIVE_TIME, TimeUnit.SECONDS,
        LinkedBlockingQueue()
    ) { runnable ->
        Thread(runnable, "AppProcessing-${System.currentTimeMillis()}").apply {
            isDaemon = true
            priority = Thread.NORM_PRIORITY
        }
    }.asCoroutineDispatcher()

    private val appListMutex = Mutex()
    private val configChangeListeners = mutableSetOf<(String) -> Unit>()
    private val prefs = ksuApp.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)

    var search by mutableStateOf("")
    var showSystemApps by mutableStateOf(prefs.getBoolean(KEY_SHOW_SYSTEM_APPS, false))
        private set
    var selectedCategory by mutableStateOf(loadSelectedCategory())
        private set
    var currentSortType by mutableStateOf(loadCurrentSortType())
        private set
    var isRefreshing by mutableStateOf(false)
        private set
    var showBatchActions by mutableStateOf(false)
        internal set
    var selectedApps by mutableStateOf<Set<String>>(emptySet())
        internal set
    var loadingProgress by mutableFloatStateOf(0f)
        private set

    private fun loadSelectedCategory(): AppCategory {
        val categoryKey = prefs.getString(KEY_SELECTED_CATEGORY, AppCategory.ALL.persistKey)
            ?: AppCategory.ALL.persistKey
        return AppCategory.fromPersistKey(categoryKey)
    }

    private fun loadCurrentSortType(): SortType {
        val sortKey = prefs.getString(KEY_CURRENT_SORT_TYPE, SortType.NAME_ASC.persistKey)
            ?: SortType.NAME_ASC.persistKey
        return SortType.fromPersistKey(sortKey)
    }

    fun updateShowSystemApps(newValue: Boolean) {
        showSystemApps = newValue
        prefs.edit { putBoolean(KEY_SHOW_SYSTEM_APPS, newValue) }
        notifyAppListChanged()
    }

    private fun notifyAppListChanged() {
        val currentApps = apps
        apps = emptyList()
        apps = currentApps
    }

    fun updateSelectedCategory(newCategory: AppCategory) {
        selectedCategory = newCategory
        prefs.edit { putString(KEY_SELECTED_CATEGORY, newCategory.persistKey) }
    }

    fun updateCurrentSortType(newSortType: SortType) {
        currentSortType = newSortType
        prefs.edit { putString(KEY_CURRENT_SORT_TYPE, newSortType.persistKey) }
    }

    private val sortedList by derivedStateOf {
        val comparator = compareBy<AppInfo> {
            when {
                it.allowSu -> 0
                it.hasCustomProfile -> 1
                else -> 2
            }
        }.then(compareBy(Collator.getInstance(Locale.getDefault()), AppInfo::label))
        apps.sortedWith(comparator).also { isRefreshing = false }
    }

    val appList by derivedStateOf {
        sortedList.filter {
            it.label.contains(search, true) ||
                    it.packageName.contains(search, true) ||
                    HanziToPinyin.getInstance().toPinyinString(it.label).contains(search, true)
        }.filter {
            it.uid == 2000 || showSystemApps ||
                    it.packageInfo.applicationInfo!!.flags.and(ApplicationInfo.FLAG_SYSTEM) == 0
        }
    }

    fun toggleBatchMode() {
        showBatchActions = !showBatchActions
        if (!showBatchActions) clearSelection()
    }

    fun toggleAppSelection(packageName: String) {
        selectedApps = if (selectedApps.contains(packageName)) {
            selectedApps - packageName
        } else {
            selectedApps + packageName
        }
    }

    fun clearSelection() {
        selectedApps = emptySet()
    }

    suspend fun updateBatchPermissions(allowSu: Boolean, umountModules: Boolean? = null) {
        selectedApps.forEach { packageName ->
            apps.find { it.packageName == packageName }?.let { app ->
                val profile = Natives.getAppProfile(packageName, app.uid)
                val updatedProfile = profile.copy(
                    allowSu = allowSu,
                    umountModules = umountModules ?: profile.umountModules,
                    nonRootUseDefault = false
                )
                if (Natives.setAppProfile(updatedProfile)) {
                    updateAppProfileLocally(packageName, updatedProfile)
                    notifyConfigChange(packageName)
                }
            }
        }
        clearSelection()
        showBatchActions = false
        refreshAppConfigurations()
    }

    fun updateAppProfileLocally(packageName: String, updatedProfile: Natives.Profile) {
        appListMutex.tryLock().let { locked ->
            if (locked) {
                try {
                    apps = apps.map { app ->
                        if (app.packageName == packageName) {
                            app.copy(profile = updatedProfile)
                        } else app
                    }
                } finally {
                    appListMutex.unlock()
                }
            }
        }
    }

    private fun notifyConfigChange(packageName: String) {
        configChangeListeners.forEach { listener ->
            try {
                listener(packageName)
            } catch (e: Exception) {
                Log.e(TAG, "Error notifying config change for $packageName", e)
            }
        }
    }

    suspend fun refreshAppConfigurations() {
        withContext(appProcessingThreadPool) {
            supervisorScope {
                val currentApps = apps.toList()
                val batches = currentApps.chunked(BATCH_SIZE)
                loadingProgress = 0f

                val updatedApps = batches.mapIndexed { batchIndex, batch ->
                    async {
                        val batchResult = batch.map { app ->
                            try {
                                val updatedProfile = Natives.getAppProfile(app.packageName, app.uid)
                                app.copy(profile = updatedProfile)
                            } catch (e: Exception) {
                                Log.e(TAG, "Error refreshing profile for ${app.packageName}", e)
                                app
                            }
                        }
                        loadingProgress = (batchIndex + 1).toFloat() / batches.size
                        batchResult
                    }
                }.awaitAll().flatten()

                appListMutex.withLock { apps = updatedApps }
                loadingProgress = 1f
            }
        }
    }

    private var serviceConnection: ServiceConnection? = null

    private suspend fun connectKsuService(onDisconnect: () -> Unit = {}): IBinder? =
        suspendCoroutine { continuation ->
            val connection = object : ServiceConnection {
                override fun onServiceDisconnected(name: ComponentName?) {
                    onDisconnect()
                    serviceConnection = null
                }
                override fun onServiceConnected(name: ComponentName?, binder: IBinder?) {
                    continuation.resume(binder)
                }
            }
            serviceConnection = connection
            val intent = Intent(ksuApp, KsuService::class.java)
            try {
                val task = com.topjohnwu.superuser.ipc.RootService.bindOrTask(
                    intent, Shell.EXECUTOR, connection
                )
                task?.let { Shell.getShell().execTask(it) }
            } catch (e: Exception) {
                Log.e(TAG, "Failed to bind KsuService", e)
                continuation.resume(null)
            }
        }

    private fun stopKsuService() {
        serviceConnection?.let {
            try {
                val intent = Intent(ksuApp, KsuService::class.java)
                com.topjohnwu.superuser.ipc.RootService.stop(intent)
                serviceConnection = null
            } catch (e: Exception) {
                Log.e(TAG, "Failed to stop KsuService", e)
            }
        }
    }

    suspend fun fetchAppList() {
        isRefreshing = true
        loadingProgress = 0f

        val binder = connectKsuService() ?: run { isRefreshing = false; return }

        withContext(Dispatchers.IO) {
            val pm = ksuApp.packageManager
            val allPackages = IKsuInterface.Stub.asInterface(binder)
            val total = allPackages.packageCount
            val pageSize = 100
            val result = mutableListOf<AppInfo>()

            var start = 0
            while (start < total) {
                val page = allPackages.getPackages(start, pageSize)
                if (page.isEmpty()) break

                result += page.mapNotNull { packageInfo ->
                    packageInfo.applicationInfo?.let { appInfo ->
                        AppInfo(
                            label = appInfo.loadLabel(pm).toString(),
                            packageInfo = packageInfo,
                            profile = Natives.getAppProfile(packageInfo.packageName, appInfo.uid)
                        )
                    }
                }
                start += page.size
                loadingProgress = start.toFloat() / total
            }

            stopKsuService()

            appListMutex.withLock {
                val filteredApps = result.filter { it.packageName != ksuApp.packageName }
                apps = filteredApps
                appGroups = groupAppsByUid(filteredApps)
            }
            loadingProgress = 1f
        }
        isRefreshing = false
    }

    val appGroupList by derivedStateOf {
        appGroups.filter { group ->
            group.apps.any { app ->
                app.label.contains(search, true) ||
                        app.packageName.contains(search, true) ||
                        HanziToPinyin.getInstance().toPinyinString(app.label).contains(search, true)
            }
        }.filter { group ->
            group.uid == 2000 || showSystemApps ||
                    group.apps.any { it.packageInfo.applicationInfo!!.flags.and(ApplicationInfo.FLAG_SYSTEM) == 0 }
        }
    }

    private fun groupAppsByUid(appList: List<AppInfo>): List<AppGroup> {
    return appList.groupBy { it.uid }
        .map { (uid, apps) ->
            val sortedApps = apps.sortedBy { it.label }
            val profile = apps.firstOrNull()?.let { Natives.getAppProfile(it.packageName, uid) }
            AppGroup(uid = uid, apps = sortedApps, profile = profile)
        }
        .sortedWith(
            compareBy<AppGroup> {
                when {
                    it.allowSu -> 0
                    it.hasCustomProfile -> 1
                    else -> 2
                }
            }.thenBy(Collator.getInstance(Locale.getDefault())) {
                it.userName?.takeIf { name -> name.isNotBlank() } ?: it.uid.toString()
            }.thenBy(Collator.getInstance(Locale.getDefault())) { it.mainApp.label }
        )
}
    override fun onCleared() {
        super.onCleared()
        try {
            stopKsuService()
            appProcessingThreadPool.close()
            configChangeListeners.clear()
        } catch (e: Exception) {
            Log.e(TAG, "Error cleaning up resources", e)
        }
    }
}