package com.sukisu.ultra.ui.util

import android.icu.text.Transliterator
import android.os.Build
import androidx.annotation.RequiresApi

@RequiresApi(Build.VERSION_CODES.Q)
object PinyinUtil {

    @get:RequiresApi(Build.VERSION_CODES.Q)
    private val transliterator: Transliterator by lazy {
        Transliterator.getInstance("Han-Latin; Latin-ASCII; Lower")
    }

    @Synchronized
    fun toPinyin(input: String): String =
        transliterator.transliterate(input).replace(" ", "")
}
