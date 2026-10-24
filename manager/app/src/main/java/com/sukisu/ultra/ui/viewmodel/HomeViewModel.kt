package com.sukisu.ultra.ui.viewmodel

import android.content.Context
import android.os.Build
import android.system.Os
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import com.sukisu.ultra.BuildConfig
import com.sukisu.ultra.Natives
import com.sukisu.ultra.data.repository.SettingsRepository
import com.sukisu.ultra.data.repository.SettingsRepositoryImpl
import com.sukisu.ultra.getKernelVersion
import com.sukisu.ultra.ksuApp
import com.sukisu.ultra.ui.screen.home.HomeLoadState
import com.sukisu.ultra.ui.screen.home.HomeUiState
import com.sukisu.ultra.ui.screen.home.SystemInfo
import com.sukisu.ultra.ui.screen.home.getHomeModuleCount
import com.sukisu.ultra.ui.screen.home.getManagerVersion
import com.sukisu.ultra.ui.util.checkNewCiVersion
import com.sukisu.ultra.ui.screen.home.getZygiskImplementation
import com.sukisu.ultra.ui.util.checkNewVersion
import com.sukisu.ultra.ui.util.getKpmModuleCount
import com.sukisu.ultra.ui.util.getKpmVersion
import com.sukisu.ultra.ui.util.getSuperuserCount
import com.sukisu.ultra.ui.util.getSELinuxStatusRaw
import com.sukisu.ultra.ui.util.listModules
import com.sukisu.ultra.ui.util.module.LatestVersionInfo
import com.sukisu.ultra.ui.util.resolveDeviceName
import com.sukisu.ultra.ui.util.rootAvailable

class HomeViewModel(
    private val settingsRepo: SettingsRepository = SettingsRepositoryImpl()
) : ViewModel() {

    private val _uiState = MutableStateFlow(HomeLoadState())
    val uiState: StateFlow<HomeLoadState> = _uiState.asStateFlow()
    private var refreshJob: Job? = null
    private var refreshPending = false
    private var hasResumed = false

    init {
        refresh()
    }

    fun onResume(isCurrentPage: Boolean) {
        // Match the probe's lifetime, not saved UI state restored after process death.
        if (hasResumed && isCurrentPage) refresh()
        hasResumed = true
    }

    fun refresh() {
        // Main-thread callers share one probe; a resume during it requests one trailing refresh.
        if (refreshJob?.isActive == true) {
            refreshPending = true
            return
        }
        refreshJob = viewModelScope.launch {
            do {
                refreshPending = false
                _uiState.update { it.copy(isRefreshing = true, error = null) }
                try {
                    val baseState = withContext(Dispatchers.IO) { buildState() }
                    _uiState.update { current ->
                        current.copy(
                            content = baseState.copy(ciUpdateBusy = current.content?.ciUpdateBusy ?: false),
                            isRefreshing = false,
                        )
                    }
                    if (baseState.checkUpdateEnabled) {
                        val latestVersionInfo = withContext(Dispatchers.IO) { checkNewVersion() }
                        updateContent { it.copy(latestVersionInfo = latestVersionInfo) }
                    }
                    if (baseState.checkCiUpdateEnabled) {
                        val ciVersionInfo = withContext(Dispatchers.IO) { checkNewCiVersion() }
                        updateContent { it.copy(ciLatestVersionInfo = ciVersionInfo) }
                    }
                } catch (cancelled: CancellationException) {
                    throw cancelled
                } catch (error: Exception) {
                    _uiState.update {
                        it.copy(isRefreshing = false, error = error.message ?: error.javaClass.simpleName)
                    }
                }
                currentCoroutineContext().ensureActive()
            } while (refreshPending)
        }
    }

    private fun updateContent(transform: (HomeUiState) -> HomeUiState) {
        _uiState.update { current ->
            current.content?.let { current.copy(content = transform(it)) } ?: current
        }
    }

    fun installCiUpdate() = installUpdate(isCi = true)

    fun installReleaseUpdate() = installUpdate(isCi = false)

    private fun installUpdate(isCi: Boolean) {
        val content = _uiState.value.content ?: return
        val info = if (isCi) content.ciLatestVersionInfo else content.latestVersionInfo
        if (info.versionCode <= content.currentManagerVersionCode || info.downloadUrl.isBlank()) return
        if (!settingsRepo.checkUpdate || (isCi && !settingsRepo.checkCiUpdate) || content.ciUpdateBusy) return
        updateContent { it.copy(ciUpdateBusy = true) }
        viewModelScope.launch {
            try {
                val installed = withContext(Dispatchers.IO) {
                    com.sukisu.ultra.data.repository.CiManagerUpdater(ksuApp).updateAndInstall(info)
                }
                val message = if (installed) com.sukisu.ultra.R.string.ci_update_install_success
                    else com.sukisu.ultra.R.string.ci_update_install_submitted
                android.widget.Toast.makeText(ksuApp, message, android.widget.Toast.LENGTH_LONG).show()
            } catch (e: kotlinx.coroutines.CancellationException) {
                throw e
            } catch (e: Exception) {
                android.widget.Toast.makeText(ksuApp, e.message ?: ksuApp.getString(com.sukisu.ultra.R.string.ci_update_download_failed), android.widget.Toast.LENGTH_LONG).show()
            } finally {
                updateContent { it.copy(ciUpdateBusy = false) }
            }
        }
    }

    private fun loadCounts(lkmMode: Boolean?, preview: Boolean, modulesJson: String?): Triple<Int?, Int?, Int?> {
        // The allowlist and KPM live in the kernel; there is nothing to count without one.
        val superuserCount = if (preview) null else runCatching { getSuperuserCount() }.getOrNull()
        val moduleCount = modulesJson?.let(::getHomeModuleCount)
        // KPM only exists on built-in kernels.
        val kpmCount = if (preview || lkmMode == true) null else runCatching {
            val version = getKpmVersion()
            if (version.isEmpty() || version.contains("Error", ignoreCase = true)) null else getKpmModuleCount()
        }.getOrNull()
        return Triple(superuserCount, moduleCount, kpmCount)
    }

    private suspend fun buildState(): HomeUiState {
        val kernelVersion = getKernelVersion()
        val isManager = Natives.isManager
        val ksuVersion = if (isManager) Natives.version else null
        val kernelUAPIVersion = if (isManager) Natives.kernelUAPIVersion else null
        val managerUAPIVersion = Natives.managerUAPIVersion
        val lkmMode = ksuVersion?.let { if (kernelVersion.isGKI()) Natives.isLkmMode else null }
        val isRootAvailable = rootAvailable()
        val managerVersion = getManagerVersion(ksuApp)
        val kernelFullVersion = if (isManager) Natives.getFullVersion() else null
        val isPreviewMode = !isManager && isRootAvailable

        currentCoroutineContext().ensureActive()
        // Keep the raw provider/running flags and reuse this exact snapshot for the count.
        val modulesJson = if (isRootAvailable) runCatching { listModules() }.getOrNull() else null
        currentCoroutineContext().ensureActive()
        val counts = if (isRootAvailable) {
            loadCounts(lkmMode, isPreviewMode, modulesJson)
        } else {
            Triple(null, null, null)
        }
        currentCoroutineContext().ensureActive()
        val zygiskImplementation = if (isManager && isRootAvailable) {
            getZygiskImplementation(
                modulesJson = modulesJson.orEmpty(),
                notInstalledText = ksuApp.getString(com.sukisu.ultra.R.string.home_zygisk_not_installed),
                disabledText = ksuApp.getString(com.sukisu.ultra.R.string.home_zygisk_disabled),
                rebootRequiredText = ksuApp.getString(com.sukisu.ultra.R.string.home_zygisk_reboot_required),
            )
        } else null

        return HomeUiState(
            kernelVersion = kernelVersion,
            ksuVersion = ksuVersion,
            lkmMode = lkmMode,
            isLkmBundled = lkmMode == true && Natives.isLkmBundled,
            isManager = isManager,
            isManagerPrBuild = BuildConfig.IS_PR_BUILD,
            isKernelPrBuild = Natives.isPrBuild,
            requiresNewKernel = isManager && Natives.managerUAPIVersion > Natives.kernelUAPIVersion,
            requiresNewManager = isManager && Natives.managerUAPIVersion < Natives.kernelUAPIVersion,
            kernelUAPIVersion = kernelUAPIVersion,
            managerUAPIVersion = managerUAPIVersion,
            isRootAvailable = isRootAvailable,
            isPreviewMode = isPreviewMode,
            superuserCount = counts.first,
            moduleCount = counts.second,
            kpmCount = counts.third,
            isSafeMode = Natives.isSafeMode,
            isLateLoadMode = Natives.isLateLoadMode,
            checkUpdateEnabled = settingsRepo.checkUpdate,
            checkCiUpdateEnabled = settingsRepo.checkUpdate && settingsRepo.checkCiUpdate,
            showFullStatus = ksuApp.getSharedPreferences("settings", Context.MODE_PRIVATE)
                .getBoolean("show_fingerprint", true),
            latestVersionInfo = LatestVersionInfo(),
            currentManagerVersionCode = managerVersion.versionCode,
            systemInfo = SystemInfo(
                kernelVersion = Os.uname().release,
                managerVersion = "${managerVersion.versionName} (${managerVersion.versionCode}-${managerUAPIVersion})",
                deviceModel = resolveDeviceName(),
                kernelFullVersion = kernelFullVersion,
                fingerprint = Build.FINGERPRINT,
                selinuxStatus = getSELinuxStatusRaw(),
                seccompStatus = runCatching {
                    Os.prctl(21 /* PR_GET_SECCOMP */, 0, 0, 0, 0)
                }.getOrDefault(-1),
                zygiskImplementation = zygiskImplementation,
            ),
        )
    }
}
