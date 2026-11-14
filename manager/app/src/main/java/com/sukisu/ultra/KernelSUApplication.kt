package com.sukisu.ultra

import android.annotation.SuppressLint
import android.app.Activity
import android.app.Application
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.content.pm.ApplicationInfo
import android.os.Build
import android.os.Bundle
import android.os.UserManager
import android.system.Os
import android.util.Log
import androidx.annotation.RequiresApi
import androidx.core.content.ContextCompat
import androidx.lifecycle.ViewModelProvider
import androidx.lifecycle.ViewModelStore
import androidx.lifecycle.ViewModelStoreOwner
import com.sukisu.ultra.ai.api.AiFeatureBridge
import com.sukisu.ultra.ai.host.ManagerAiHost
import com.sukisu.ultra.data.repository.SettingsRepositoryImpl
import com.sukisu.ultra.data.repository.SuperUserRepositoryImpl
import com.sukisu.ultra.ui.util.BuiltinAppIcons
import com.sukisu.ultra.ui.viewmodel.SuperUserViewModel
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import com.sukisu.ultra.BuildConfig
import okhttp3.Cache
import okhttp3.OkHttpClient
import org.lsposed.hiddenapibypass.HiddenApiBypass
import java.io.File
import java.util.Locale
import kotlin.time.Duration.Companion.milliseconds

lateinit var ksuApp: KernelSUApplication

class KernelSUApplication : Application(), ViewModelStoreOwner {

    companion object {
        private const val TAG = "KernelSUApplication"
        private const val LAUNCHER_RESTORE_DELAY_MS = 1_500L

        @SuppressLint("PrivateApi")
        fun setEnableOnBackInvokedCallback(appInfo: ApplicationInfo, enable: Boolean) {
            runCatching {
                val applicationInfoClass = ApplicationInfo::class.java
                val method = applicationInfoClass.getDeclaredMethod("setEnableOnBackInvokedCallback", Boolean::class.javaPrimitiveType)
                method.isAccessible = true
                method.invoke(appInfo, enable)
            }
        }
    }

    lateinit var okhttpClient: OkHttpClient
    private val appViewModelStore by lazy { ViewModelStore() }
    private val launcherRestoreScope = CoroutineScope(SupervisorJob() + Dispatchers.IO)

    /** Number of activities in the started state, i.e. whether any manager UI is visible. */
    @Volatile
    private var startedActivities = 0

    /** True while a manager activity is visible; launcher components must not move then. */
    val isAppInForeground: Boolean
        get() = startedActivities > 0

    override fun attachBaseContext(base: Context) {
        super.attachBaseContext(com.sukisu.ultra.ui.util.LocaleHelper.wrap(base))
    }

    private fun isUserUnlocked(): Boolean =
        getSystemService(UserManager::class.java)?.isUserUnlocked == true

    @RequiresApi(Build.VERSION_CODES.Q)
    override fun onCreate() {
        super.onCreate()
        ksuApp = this
        if (AiFeatureBridge.isAvailable) AiFeatureBridge.install(ManagerAiHost(this))

        if (!isUserUnlocked()) {
            return
        }

        // Launcher components are intentionally left alone while the process starts. An update
        // resets their enabled states to the manifest defaults, so the first launch after a
        // reinstall arrives through the default alias; disabling that alias underneath the
        // starting task restarts (and visibly kills) the app. AppIconUpdateReceiver restores the
        // selected icon from the update broadcast, and the lifecycle callback below repairs any
        // state it could not fix once the manager is safely in the background.
        registerActivityLifecycleCallbacks(object : ActivityLifecycleCallbacks {
            override fun onActivityStarted(activity: Activity) {
                startedActivities++
            }

            override fun onActivityStopped(activity: Activity) {
                startedActivities--
                if (startedActivities > 0 || activity.isChangingConfigurations) return
                launcherRestoreScope.launch {
                    // Wait out the hand-over between two of our own activities (a shortcut
                    // forwarding to the main screen stops before the target is started); moving
                    // components in that window is the same failure as moving them at startup.
                    delay(LAUNCHER_RESTORE_DELAY_MS.milliseconds)
                    if (startedActivities > 0) return@launch
                    runCatching {
                        val settings = SettingsRepositoryImpl()
                        BuiltinAppIcons.applyIfNeeded(
                            context = this@KernelSUApplication,
                            icon = BuiltinAppIcons.find(settings.appIconId),
                            dynamicColor = settings.appIconDynamicColor,
                        )
                    }.onFailure {
                        Log.w(TAG, "Cannot restore the launcher icon", it)
                    }
                }
            }

            override fun onActivityCreated(activity: Activity, savedInstanceState: Bundle?) = Unit
            override fun onActivityResumed(activity: Activity) = Unit
            override fun onActivityPaused(activity: Activity) = Unit
            override fun onActivitySaveInstanceState(activity: Activity, outState: Bundle) = Unit
            override fun onActivityDestroyed(activity: Activity) = Unit
        })

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
            val enable = SettingsRepositoryImpl().enablePredictiveBack
            HiddenApiBypass.addHiddenApiExemptions("Landroid/content/pm/ApplicationInfo;->setEnableOnBackInvokedCallback")
            setEnableOnBackInvokedCallback(applicationInfo, enable)
        }

        val appListReceiver = object : BroadcastReceiver() {
            override fun onReceive(context: Context, intent: Intent) {
                SuperUserRepositoryImpl.invalidateAppList()
            }
        }
        ContextCompat.registerReceiver(this, appListReceiver, IntentFilter().apply {
            addAction(Intent.ACTION_PACKAGE_ADDED)
            addAction(Intent.ACTION_PACKAGE_REMOVED)
            addAction(Intent.ACTION_PACKAGE_CHANGED)
            addAction(Intent.ACTION_PACKAGE_REPLACED)
            addDataScheme("package")
        }, ContextCompat.RECEIVER_NOT_EXPORTED)
        ContextCompat.registerReceiver(this, appListReceiver, IntentFilter().apply {
            addAction(Intent.ACTION_LOCALE_CHANGED)
            addAction(Intent.ACTION_EXTERNAL_APPLICATIONS_AVAILABLE)
            addAction(Intent.ACTION_EXTERNAL_APPLICATIONS_UNAVAILABLE)
            addAction(Intent.ACTION_MANAGED_PROFILE_ADDED)
            addAction(Intent.ACTION_MANAGED_PROFILE_REMOVED)
            addAction(Intent.ACTION_MANAGED_PROFILE_AVAILABLE)
            addAction(Intent.ACTION_MANAGED_PROFILE_UNAVAILABLE)
            addAction("android.intent.action.USER_ADDED")
            addAction("android.intent.action.USER_REMOVED")
            addAction("android.intent.action.USER_UNLOCKED")
        }, ContextCompat.RECEIVER_NOT_EXPORTED)

        val superUserViewModel = ViewModelProvider(this)[SuperUserViewModel::class.java]
        superUserViewModel.loadAppList()

        val webroot = File(dataDir, "webroot")
        if (!webroot.exists()) {
            webroot.mkdir()
        }

        // Provide working env for rust's temp_dir()
        Os.setenv("TMPDIR", cacheDir.absolutePath, true)

        okhttpClient =
            OkHttpClient.Builder().cache(Cache(File(cacheDir, "okhttp"), 10 * 1024 * 1024))
                .addInterceptor { block ->
                    block.proceed(
                        block.request().newBuilder()
                            .header("User-Agent", "SukiSU/${BuildConfig.VERSION_CODE}")
                            .header("Accept-Language", Locale.getDefault().toLanguageTag()).build()
                    )
                }.build()
    }

    override val viewModelStore: ViewModelStore
        get() = appViewModelStore
}
