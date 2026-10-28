package com.sukisu.ultra.ui.util

import android.content.ClipData
import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.content.pm.ResolveInfo
import android.graphics.Bitmap
import android.os.Build
import android.provider.MediaStore
import androidx.activity.result.ActivityResult
import androidx.core.content.FileProvider
import kotlin.math.roundToInt
import java.io.File

/**
 * Bridges to the crop screen that the device's gallery ships with.
 *
 * `com.android.camera.action.CROP` is a de-facto standard handled by the vendor gallery
 * on most ROMs (MIUI/HyperOS, ColorOS, OriginOS, One UI, EMUI...). It is not part of the
 * public SDK, so every call is resolved first and callers fall back to the in-app editor
 * when no gallery handles it.
 */
object ExternalCropper {
    private const val ACTION_CROP = "com.android.camera.action.CROP"
    private const val MAX_EXTERNAL_OUTPUT = 2560

    /** Vendor galleries first, so the system does not hand the job to a random editor. */
    private val PREFERRED_PACKAGES = listOf(
        "com.miui.gallery",
        "com.coloros.gallery3d",
        "com.oplus.gallery",
        "com.oneplus.gallery",
        "com.vivo.gallery",
        "com.iqoo.gallery",
        "com.sec.android.gallery3d",
        "com.huawei.photos",
        "com.huawei.gallery",
        "com.hihonor.photos",
        "com.hihonor.gallery",
        "com.google.android.apps.photos",
        "com.android.gallery3d",
    )

    fun isAvailable(context: Context): Boolean = cropCandidates(context).isNotEmpty()

    /**
     * Builds the gallery crop intent. [output] must already exist and live under the
     * FileProvider cache path so the gallery can write the result into it.
     */
    fun createIntent(
        context: Context,
        source: File,
        output: File,
        aspectX: Int = 0,
        aspectY: Int = 0,
    ): Intent? {
        if (!source.isFile) return null
        val candidates = cropCandidates(context)
        if (candidates.isEmpty()) return null

        val authority = "${context.packageName}.fileprovider"
        val inputUri = runCatching {
            FileProvider.getUriForFile(context, authority, source)
        }.getOrNull() ?: return null
        val outputUri = runCatching {
            FileProvider.getUriForFile(context, authority, output)
        }.getOrNull() ?: return null

        val intent = Intent(ACTION_CROP).apply {
            setDataAndType(inputUri, "image/*")
            putExtra("crop", "true")
            if (aspectX > 0 && aspectY > 0) {
                val (outputWidth, outputHeight) = externalOutputSize(aspectX, aspectY)
                putExtra("aspectX", aspectX)
                putExtra("aspectY", aspectY)
                putExtra("outputX", outputWidth)
                putExtra("outputY", outputHeight)
            }
            putExtra("return-data", false)
            putExtra("scale", true)
            putExtra("scaleUpIfNeeded", true)
            putExtra("noFaceDetection", true)
            putExtra("outputFormat", Bitmap.CompressFormat.JPEG.toString())
            putExtra(MediaStore.EXTRA_OUTPUT, outputUri)
            addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION or Intent.FLAG_GRANT_WRITE_URI_PERMISSION)
            clipData = ClipData.newRawUri("input", inputUri).apply {
                addItem(ClipData.Item(outputUri))
            }
        }

        preferredCandidate(candidates)?.let { preferred ->
            val packageName = preferred.activityInfo.packageName
            runCatching {
                context.grantUriPermission(
                    packageName,
                    inputUri,
                    Intent.FLAG_GRANT_READ_URI_PERMISSION,
                )
                context.grantUriPermission(
                    packageName,
                    outputUri,
                    Intent.FLAG_GRANT_WRITE_URI_PERMISSION,
                )
            }
            intent.component = ComponentName(packageName, preferred.activityInfo.name)
        }
        return intent
    }

    /**
     * Extracts the gallery result. Vendors disagree about the contract: some honor
     * EXTRA_OUTPUT, some return a Uri and a few still return a Bitmap in "data".
     */
    fun readResult(context: Context, result: ActivityResult, output: File): Boolean {
        if (output.isFile && output.length() > 0L) return true

        val data = result.data
        val bitmap = resultBitmap(result)
        if (bitmap != null) {
            val saved = runCatching {
                output.outputStream().use { stream ->
                    bitmap.compress(Bitmap.CompressFormat.JPEG, 95, stream)
                }
            }.getOrDefault(false)
            bitmap.recycle()
            if (saved && output.length() > 0L) return true
        }

        val uri = data?.data ?: return false
        runCatching {
            context.contentResolver.openInputStream(uri)?.use { input ->
                output.outputStream().use { stream -> input.copyTo(stream) }
            }
        }
        return output.isFile && output.length() > 0L
    }

    private fun cropCandidates(context: Context): List<ResolveInfo> {
        val intent = Intent(ACTION_CROP).setType("image/*")
        return runCatching {
            context.packageManager.queryIntentActivities(
                intent,
                PackageManager.MATCH_DEFAULT_ONLY,
            )
        }.getOrDefault(emptyList()).filter { resolveInfo ->
            resolveInfo.activityInfo.packageName != context.packageName
        }
    }

    private fun preferredCandidate(candidates: List<ResolveInfo>): ResolveInfo? {
        PREFERRED_PACKAGES.forEach { packageName ->
            candidates.firstOrNull {
                it.activityInfo.packageName.equals(packageName, ignoreCase = true)
            }?.let { return it }
        }
        return null
    }

    private fun externalOutputSize(aspectX: Int, aspectY: Int): Pair<Int, Int> {
        val divisor = gcd(aspectX, aspectY).coerceAtLeast(1)
        val ratioX = aspectX / divisor
        val ratioY = aspectY / divisor
        val scale = MAX_EXTERNAL_OUTPUT.toFloat() / maxOf(ratioX, ratioY)
        return (ratioX * scale).roundToInt().coerceAtLeast(1) to
            (ratioY * scale).roundToInt().coerceAtLeast(1)
    }

    private fun gcd(a: Int, b: Int): Int {
        var x = kotlin.math.abs(a)
        var y = kotlin.math.abs(b)
        while (y != 0) {
            val remainder = x % y
            x = y
            y = remainder
        }
        return x
    }

    private fun resultBitmap(result: ActivityResult): Bitmap? {
        val data = result.data ?: return null
        return runCatching {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                data.getParcelableExtra("data", Bitmap::class.java)
            } else {
                @Suppress("DEPRECATION")
                data.getParcelableExtra("data")
            }
        }.getOrNull()
    }
}
