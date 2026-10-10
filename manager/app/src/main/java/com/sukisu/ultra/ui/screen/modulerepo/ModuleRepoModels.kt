package com.sukisu.ultra.ui.screen.modulerepo

import android.os.Parcelable
import com.sukisu.ultra.data.model.RepoModule
import kotlinx.parcelize.Parcelize

@Parcelize
data class ReleaseAssetArg(
    val name: String,
    val downloadUrl: String,
    val size: Long,
    val downloadCount: Int,
    /** Retried when [downloadUrl] fails; see sameOriginAssetFallback. */
    val downloadUrlFallback: String? = null
) : Parcelable

@Parcelize
data class ReleaseArg(
    val tagName: String,
    val name: String,
    val publishedAt: String,
    val assets: List<ReleaseAssetArg>,
    val descriptionHTML: String = "",
    val changelogUrl: String? = null
) : Parcelable

@Parcelize
data class AuthorArg(
    val name: String,
    val link: String,
) : Parcelable

@Parcelize
data class RepoModuleArg(
    val moduleId: String,
    val moduleName: String,
    val authors: String,
    val authorsList: List<AuthorArg>,
    val latestRelease: String,
    val latestReleaseTime: String,
    val releases: List<ReleaseArg>,
    val sourceId: String = "",
    val sourceName: String = "",
    /** Other repositories publishing the same module, merged away by deduplication. */
    val alternateSourceNames: List<String> = emptyList(),
    val readmeUrl: String? = null,
    val webUrl: String? = null
) : Parcelable {
    val isMmrl: Boolean get() = sourceId.isNotEmpty()
}

/**
 * The releases the detail page shows for [module].
 *
 * An MMRL index lists every published version, so all of them become releases. A KernelSU-array
 * index carries only the newest one, and it has to be turned into a single release: without it
 * such a module reaches its detail page with no assets at all, and so with no way to install it.
 */
internal fun repoModuleReleases(module: RepoModule): List<ReleaseArg> {
    module.mmrl?.let { mmrl ->
        return mmrl.versions.map { version ->
            ReleaseArg(
                tagName = version.version,
                name = version.version,
                publishedAt = version.time,
                assets = listOf(
                    ReleaseAssetArg(
                        name = version.zipUrl.substringAfterLast('/'),
                        downloadUrl = version.zipUrl,
                        size = version.size,
                        downloadCount = 0,
                        downloadUrlFallback = version.zipUrlFallback,
                    )
                ),
                changelogUrl = version.changelogUrl,
            )
        }
    }

    val asset = module.latestAsset ?: return emptyList()
    return listOf(
        ReleaseArg(
            tagName = module.latestRelease,
            name = module.latestRelease,
            publishedAt = module.latestReleaseTime,
            assets = listOf(
                ReleaseAssetArg(
                    name = asset.name,
                    downloadUrl = asset.downloadUrl,
                    size = asset.size,
                    downloadCount = 0,
                )
            ),
        )
    )
}
