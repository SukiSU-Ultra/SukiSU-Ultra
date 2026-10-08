package com.sukisu.ultra.data.repository

/**
 * A module repository offered in the add-source dialog so a user can add it in one tap instead of
 * hunting for the address.
 *
 * [moduleCount] is how many modules the manager can actually install from that index — entries
 * whose format the parser cannot read are not counted — as reviewed on 2026-10-08. It is a
 * snapshot, not a live figure, and it is what the list is ordered by.
 */
data class RepoCandidate(
    val name: String,
    val url: String,
    val moduleCount: Int,
)

/**
 * The repositories worth offering, most modules first.
 *
 * Only repositories that contribute modules no higher-ranked one already carries are listed, so
 * mirrors that add nothing (`Googlers-Repo/mmar`, `juliazero/mrbj`) are left out even though they
 * resolve.
 *
 * Both index formats the manager reads are represented. An MMRL index lists every published
 * version; a KernelSU-array index such as `qianyumeng0228/ShizuSU-Modules` carries only the newest
 * release, which [repoModuleReleases] turns into a single release so the module can be installed.
 * Indexes that carry no module id or no download address are left out because nothing could be
 * installed from them: the Magisk v1 indexes (`Magisk-Modules-Alt-Repo/json`,
 * `Magisk-Modules-Repo/submission`), whose entries have only `zip_url`, and the KernelSU-Next
 * style indexes (`KernelSU-Next/KernelSU-Next-Modules-Repo`, `mprotmod/Modules-KETSU`), whose
 * entries have only `repoUrl` or `url`.
 *
 * A repository that has stopped being updated is safe to list: [aggregateModuleSources] keeps the
 * installable entry and then the newer one, so an out-of-date repository contributes only the
 * modules nobody else publishes.
 */
val defaultRepoCandidates: List<RepoCandidate> = listOf(
    RepoCandidate(
        name = "LeanxModulostk/modulostk",
        url = "https://raw.githubusercontent.com/LeanxModulostk/modulostk/HEAD/json/modules.json",
        moduleCount = 183,
    ),
    RepoCandidate(
        name = "IzzyOnDroid",
        url = "https://apt.izzysoft.de/magisk/json/modules.json",
        moduleCount = 141,
    ),
    RepoCandidate(
        name = "Magisk Modules Alt Repo",
        url = "https://magisk-modules-alt-repo.github.io/json-v2/json/modules.json",
        moduleCount = 117,
    ),
    RepoCandidate(
        name = "Magisk Font Repo",
        url = "https://codeberg.org/fruitsnack/magisk-font-repo/raw/branch/main/json/modules.json",
        moduleCount = 105,
    ),
    RepoCandidate(
        name = "uonou/mmrl-repo",
        url = "https://uonou.github.io/mmrl-repo/json/modules.json",
        moduleCount = 44,
    ),
    RepoCandidate(
        name = "Googlers Repo",
        url = "https://gr.dergoogler.com/gmr/json/modules.json",
        moduleCount = 40,
    ),
    RepoCandidate(
        name = "ZG-R",
        url = "https://zguation-projects.github.io/ZG-R/json/modules.json",
        moduleCount = 37,
    ),
    RepoCandidate(
        name = "ShizuSU Modules",
        url = "https://raw.githubusercontent.com/qianyumeng0228/ShizuSU-Modules/HEAD/modules.json",
        moduleCount = 27,
    ),
    RepoCandidate(
        name = "unatried/Rooting",
        url = "https://unatried.github.io/Rooting/json/modules.json",
        moduleCount = 26,
    ),
    RepoCandidate(
        name = "zelect0r/zamr",
        url = "https://zelect0r.github.io/zamr/json/modules.json",
        moduleCount = 24,
    ),
    RepoCandidate(
        name = "shamratrh-web/mmrl-repo",
        url = "https://shamratrh-web.github.io/mmrl-repo/json/modules.json",
        moduleCount = 23,
    ),
    RepoCandidate(
        name = "Yukari0201/mmrl-repo",
        url = "https://yukari0201.github.io/mmrl-repo/json/modules.json",
        moduleCount = 18,
    ),
    RepoCandidate(
        name = "vc-teahouse/magisk-module-repo",
        url = "https://vc-teahouse.github.io/magisk-module-repo/json/modules.json",
        moduleCount = 14,
    ),
    RepoCandidate(
        name = "mystster/module-repo",
        url = "https://mystster.github.io/module-repo/json/modules.json",
        moduleCount = 11,
    ),
)
