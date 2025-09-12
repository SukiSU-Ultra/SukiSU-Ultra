package com.sukisu.ultra.ui.webui

import android.content.ServiceConnection
import android.util.Log
import android.content.pm.PackageInfo
import com.dergoogler.mmrl.platform.Platform
import com.dergoogler.mmrl.platform.model.IProvider
import com.dergoogler.mmrl.platform.model.PlatformIntent
import com.sukisu.ultra.ksuApp
import com.sukisu.ultra.Natives
import com.topjohnwu.superuser.ipc.RootService
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.withContext

class KsuLibSuProvider : IProvider {
    override val name = "KsuLibSu"

    override fun isAvailable() = true

    override suspend fun isAuthorized() = Natives.becomeManager(ksuApp.packageName)

    private val serviceIntent
        get() = PlatformIntent(
            ksuApp,
            Platform.KsuNext,
            SuService::class.java
        )

    override fun bind(connection: ServiceConnection) {
        RootService.bind(serviceIntent.intent, connection)
    }

    override fun unbind(connection: ServiceConnection) {
        RootService.stop(serviceIntent.intent)
    }
}

// webui x
suspend fun initPlatform() = withContext(Dispatchers.IO) {
    try {
        val active = Platform.init {
            this.context = ksuApp
            this.platform = Platform.KsuNext
            this.provider = from(KsuLibSuProvider())
        }

        while (!active) {
            delay(1000)
        }

        return@withContext true
    } catch (e: Exception) {
        Log.e("KsuLibSu", "Failed to initialize platform", e)
        return@withContext false
    }
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