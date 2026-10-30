package com.sukisu.ultra.ui.screen.appicon

import android.content.Context
import androidx.compose.foundation.Image
import androidx.compose.runtime.Composable
import androidx.compose.runtime.remember
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.ImageBitmap
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.layout.ContentScale
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.core.content.ContextCompat
import androidx.core.graphics.drawable.toBitmap
import coil.compose.AsyncImage
import com.sukisu.ultra.ui.util.AppIconEntry
import com.sukisu.ultra.ui.util.AppIconPack
import com.sukisu.ultra.ui.util.AppIconPackStorage
import com.sukisu.ultra.ui.util.BuiltinAppIcon

@Composable
fun BuiltinAppIconPreview(
    icon: BuiltinAppIcon,
    modifier: Modifier = Modifier,
    foregroundOnly: Boolean = false,
) {
    val context = LocalContext.current
    val drawableRes = if (foregroundOnly) icon.foregroundRes else icon.iconRes
    val bitmap = remember(drawableRes) { loadDrawableBitmap(context, drawableRes) }
    if (bitmap != null) {
        Image(
            bitmap = bitmap,
            contentDescription = stringResource(icon.nameRes),
            modifier = modifier,
            contentScale = if (foregroundOnly) ContentScale.Fit else ContentScale.Crop,
        )
    }
}

@Composable
fun CustomAppIconPreview(
    pack: AppIconPack,
    entry: AppIconEntry,
    modifier: Modifier = Modifier,
) {
    val context = LocalContext.current
    val file = remember(pack.id, entry.fileName) {
        AppIconPackStorage.iconFile(context, pack, entry)
    }
    AsyncImage(
        model = file,
        contentDescription = entry.name,
        modifier = modifier,
        contentScale = ContentScale.Crop,
    )
}

private fun loadDrawableBitmap(context: Context, resId: Int): ImageBitmap? = runCatching {
    ContextCompat.getDrawable(context, resId)
        ?.toBitmap(width = 256, height = 256)
        ?.asImageBitmap()
}.getOrNull()
