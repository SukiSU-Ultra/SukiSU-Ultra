package zako.zako.zako.utils

import android.content.Context
import java.io.File
import java.io.FileOutputStream
import java.io.IOException

object AssetsUtil {
    @Throws(IOException::class)
    fun exportFiles(context: Context, src: String, out: String) {
        val fileNames = context.assets.list(src)
        if (fileNames?.isNotEmpty() == true) {
            val file = File(out)
            file.mkdirs()
            fileNames.forEach { fileName ->
                exportFiles(context, "$src/$fileName", "$out/$fileName")
            }
        } else {
            context.assets.open(src).use { inputStream ->
                FileOutputStream(File(out)).use { outputStream ->
                    inputStream.copyTo(outputStream)
                }
            }
        }
    }
}