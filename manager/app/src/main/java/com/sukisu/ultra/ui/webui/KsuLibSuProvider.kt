package com.sukisu.ultra.ui.webui

import android.content.Context
import android.content.ServiceConnection
import android.util.Log
import android.content.pm.PackageInfo
import com.dergoogler.mmrl.platform.Platform
import com.dergoogler.mmrl.platform.Platform.Companion.createPlatformIntent
import com.dergoogler.mmrl.platform.PlatformManager
import com.dergoogler.mmrl.platform.PlatformManager.packageManager
import com.dergoogler.mmrl.platform.PlatformManager.userManager
import com.dergoogler.mmrl.platform.model.IProvider
import com.sukisu.ultra.ksuApp
import com.sukisu.ultra.Natives
import com.topjohnwu.superuser.ipc.RootService
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Deferred

class KsuLibSuProvider(
    private val context: Context,
) : IProvider {
    override val name = "SukiLibSu"

    override fun isAvailable() = true

    override suspend fun isAuthorized() = Natives.becomeManager(context.packageName)

    private val intent by lazy {
        context.createPlatformIntent<SuService>(Platform.SukiSU)
    }

    override fun bind(connection: ServiceConnection) {
        RootService.bind(intent, connection)
    }

    override fun unbind(connection: ServiceConnection) {
        RootService.stop(intent)
    }
}

// webui x
suspend fun CoroutineScope.initPlatform(context: Context = ksuApp): Deferred<Boolean> =
    try {
        val active = PlatformManager.init(this) {
            from(KsuLibSuProvider(context))
        }

        active
    } catch (e: Exception) {
        Log.e("KsuLibSu", "Failed to initialize platform", e)
        CompletableDeferred(false)
    }


fun Platform.Companion.getInstalledPackagesAll(catch: (Exception) -> Unit = {}): List<PackageInfo> =
    try {
        val packages = mutableListOf<PackageInfo>()
        val userInfos = userManager.getUsers()

        for (userInfo in userInfos) {
            packages.addAll(packageManager.getInstalledPackages(0, userInfo.id))
        }

        packages
    } catch (e: Exception) {
        catch(e)
        packageManager.getInstalledPackages(0, userManager.myUserId)
    }