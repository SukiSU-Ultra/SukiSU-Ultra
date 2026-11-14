package com.sukisu.ultra.ui.kernelFlash.util

import android.content.Context
import java.io.File


class KpmTools private constructor(
    private val executable: File,
    private val kpimg: File,
) {
    val command: String
        get() = KpmPatchCommand.quote(executable.absolutePath)

    fun patch(input: File, output: File, undo: Boolean, execute: (String) -> Unit) {
        require(input.canonicalFile != output.canonicalFile) { "KPM output must differ from the input" }
        execute(KpmPatchCommand.buildChecked(
            executable.absolutePath, input.absolutePath, kpimg.absolutePath,
            output.absolutePath, undo,
        ))
    }

    companion object {
        fun prepare(
            context: Context,
            directory: File,
        ): KpmTools {
            val executable = File(context.applicationInfo.nativeLibraryDir, "libkptools.so")
            check(executable.isFile && executable.canExecute()) { "Bundled kptools-android is unavailable" }
            check(directory.isDirectory || directory.mkdirs()) { "Cannot create KPM work directory" }
            val kpimg = File(directory, "kpimg")
            context.assets.open("kpm/kpimg").use { input ->
                kpimg.outputStream().use { input.copyTo(it) }
            }
            check(kpimg.length() >= 1024) { "Bundled kpimg is invalid" }
            return KpmTools(executable, kpimg)
        }
    }
}
