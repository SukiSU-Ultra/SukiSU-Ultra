package com.sukisu.ultra.ui.screen.appprofile

import com.sukisu.ultra.ui.component.profile.TemporaryRoot
import android.widget.Toast
import androidx.compose.material3.SnackbarHostState
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.derivedStateOf
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.lifecycle.compose.dropUnlessResumed
import androidx.lifecycle.viewmodel.compose.viewModel
import kotlinx.coroutines.launch
import kotlinx.coroutines.delay
import com.sukisu.ultra.Natives
import com.sukisu.ultra.R
import com.sukisu.ultra.ui.LocalUiMode
import com.sukisu.ultra.ui.UiMode
import com.sukisu.ultra.ui.navigation3.LocalNavigator
import com.sukisu.ultra.ui.navigation3.Route
import com.sukisu.ultra.ui.util.forceStopApp
import com.sukisu.ultra.ui.util.getSepolicy
import com.sukisu.ultra.ui.util.launchApp
import com.sukisu.ultra.ui.util.restartApp
import com.sukisu.ultra.ui.util.setSepolicy
import com.sukisu.ultra.ui.viewmodel.SuperUserViewModel
import com.sukisu.ultra.ui.viewmodel.getTemplateInfoById

@Composable
fun AppProfileScreen(uid: Int) {
    val uiMode = LocalUiMode.current
    val navigator = LocalNavigator.current
    val context = LocalContext.current
    val snackbarHost = remember { SnackbarHostState() }
    val scope = rememberCoroutineScope()
    val viewModel: SuperUserViewModel = viewModel()
    val appGroupState = remember(uid) {
        derivedStateOf {
            viewModel.uiState.value.groupedApps.find { it.uid == uid } ?: SuperUserViewModel.getGroupedApp(uid)
        }
    }
    val appGroup = appGroupState.value
    val primaryAppInfo = appGroup?.primary
    if (primaryAppInfo == null) {
        LaunchedEffect(Unit) {
            navigator.pop()
        }
        return
    }

    val packageName = primaryAppInfo.profileKey
    val sharedUserId = remember(uid) {
        primaryAppInfo.packageInfo.sharedUserId
            ?: appGroup.apps.firstOrNull { it.packageInfo.sharedUserId != null }?.packageInfo?.sharedUserId
            ?: ""
    }

    val initialProfile = remember(uid, packageName, primaryAppInfo.special) {
        Natives.getAppProfile(packageName, uid).let {
            if (primaryAppInfo.special) it.copy(allowSu = false) else it
        }.also {
            if (it.allowSu && !primaryAppInfo.special) {
                it.rules = getSepolicy(packageName)
            }
        }
    }
    var profile by rememberSaveable(uid, packageName) {
        mutableStateOf(initialProfile)
    }

    val failToUpdateAppProfile = stringResource(R.string.failed_to_update_app_profile).format(primaryAppInfo.label)
    val failToUpdateSepolicy = stringResource(R.string.failed_to_update_sepolicy).format(primaryAppInfo.label)
    val suNotAllowed = stringResource(R.string.su_not_allowed).format(primaryAppInfo.label)

    fun showMessage(message: String) {
        scope.launch {
            if (uiMode == UiMode.Material) {
                snackbarHost.showSnackbar(message)
            } else {
                Toast.makeText(context, message, Toast.LENGTH_SHORT).show()
            }
        }
    }

    var temporaryEnabled by rememberSaveable(uid) { mutableStateOf(false) }
    var saving by remember { mutableStateOf(false) }
    LaunchedEffect(uid) {
        temporaryEnabled = TemporaryRoot.status(uid) in listOf("timed", "boot")
        while (true) {
            delay(1000)
            if (!saving && profile.allowSu) {
                val current = Natives.getAppProfile(packageName, uid)
                if (!current.allowSu) {
                    profile = current
                    temporaryEnabled = false
                    viewModel.loadAppList()
                }
            }
        }
    }

    fun saveProfile(updatedProfile: Natives.Profile, seconds: Long? = null, updateLease: Boolean = false, selectTemporary: Boolean = false) {
        if (saving) return
        saving = true
        scope.launch {
            try {
                val profileToSave = if (primaryAppInfo.special) updatedProfile.copy(allowSu = false) else updatedProfile
                if (profileToSave.allowSu && profile.allowSu
                    && !Natives.getAppProfile(packageName, uid).allowSu) {
                    // Never regrant from a stale editor after ksud has revoked a lease.
                    profile = Natives.getAppProfile(packageName, uid)
                    showMessage(failToUpdateAppProfile)
                    return@launch
                }
                if (profileToSave.allowSu) {
                    if (uid < 2000 && uid != 1000) {
                        showMessage(suNotAllowed)
                        return@launch
                    }
                    if (!profileToSave.rootUseDefault && profileToSave.rules.isNotEmpty()
                        && !primaryAppInfo.special && !setSepolicy(profileToSave.name, profileToSave.rules)) {
                        showMessage(failToUpdateSepolicy)
                        return@launch
                    }
                }
                if (!TemporaryRoot.saveProfile(profileToSave, profile.allowSu, updateLease, seconds)) {
                    // The watcher may have revoked while the editor was open.
                    profile = Natives.getAppProfile(packageName, uid)
                    temporaryEnabled = TemporaryRoot.status(uid) in listOf("timed", "boot")
                    showMessage(failToUpdateAppProfile)
                } else {
                    profile = profileToSave
                    if (!profileToSave.allowSu) temporaryEnabled = selectTemporary
                    else if (updateLease) temporaryEnabled = seconds != null
                    viewModel.loadAppList()
                }
            } catch (e: Exception) {
                if (e is kotlinx.coroutines.CancellationException) throw e
                showMessage(failToUpdateAppProfile)
            } finally {
                saving = false
            }
        }
    }

    val state = AppProfileUiState(
        uid = uid,
        packageName = packageName,
        profile = profile,
        appGroup = appGroup,
        sharedUserId = sharedUserId,
        temporaryRoot = temporaryEnabled,
    )

    val actions = AppProfileActions(
        onBack = dropUnlessResumed { navigator.pop() },
        onLaunchApp = ::launchApp,
        onForceStopApp = ::forceStopApp,
        onRestartApp = ::restartApp,
        onViewTemplate = { templateId ->
            getTemplateInfoById(templateId)?.let { info ->
                navigator.push(Route.TemplateEditor(info, true))
            }
        },
        onManageTemplate = {
            navigator.push(Route.AppProfileTemplate)
        },
        onTemporaryRootChange = { enabled ->
            if (enabled) {
                // Selecting temporary mode must not leave a permanent grant active.
                if (profile.allowSu) saveProfile(profile.copy(allowSu = false), selectTemporary = true)
                else temporaryEnabled = true
            } else if (profile.allowSu && temporaryEnabled) {
                saveProfile(profile.copy(allowSu = false), updateLease = true)
            } else {
                temporaryEnabled = false
            }
        },
        onTemporaryRootGrant = { seconds ->
            if (seconds != null) saveProfile(profile.copy(allowSu = true), seconds, updateLease = true)
        },
        onPermanentRootChange = { enabled ->
            saveProfile(profile.copy(allowSu = enabled), updateLease = true)
        },
        onProfileChange = { updatedProfile -> saveProfile(updatedProfile) },
    )

    when (uiMode) {
        UiMode.Miuix -> AppProfileScreenMiuix(
            state = state,
            actions = actions,
        )

        UiMode.Material -> AppProfileScreenMaterial(
            state = state,
            actions = actions,
            snackBarHost = snackbarHost,
        )
    }
}
