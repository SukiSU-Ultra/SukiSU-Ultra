package com.sukisu.ultra.ui.util

import android.icu.text.Transliterator
import android.os.Build
import androidx.annotation.RequiresApi

object PinyinUtil {

    @get:RequiresApi(Build.VERSION_CODES.Q)
    private val transliterator: Transliterator by lazy {
        Transliterator.getInstance("Han-Latin; Latin-ASCII; Lower")
    }

    @Synchronized
    fun toPinyin(input: String): String =
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            transliterator.transliterate(input).replace(" ", "")
        } else {
            // android.icu.text.Transliterator was added in Android 10; on older
            // releases search still matches the original (e.g. Chinese) name.
            input
        }
}
