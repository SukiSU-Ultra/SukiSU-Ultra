plugins {
    alias(libs.plugins.agp.app) apply false
    alias(libs.plugins.agp.library) apply false
    alias(libs.plugins.kotlin) apply false
    alias(libs.plugins.compose.compiler) apply false
}

extra["androidMinSdkVersion"] = 24
extra["androidTargetSdkVersion"] = 37
extra["androidCompileSdkVersion"] = 37
extra["androidCompileSdkVersionMinor"] = 0
extra["androidBuildToolsVersion"] = "37.0.0"
extra["androidCompileNdkVersion"] = libs.versions.ndk.get()
extra["androidSourceCompatibility"] = JavaVersion.VERSION_21
extra["androidTargetCompatibility"] = JavaVersion.VERSION_21
extra["managerVersionCode"] = getVersionCode()
extra["managerVersionName"] = getVersionName()

fun getGitCommitCount(): Int {
    val process = Runtime.getRuntime().exec(arrayOf("git", "rev-list", "--count", "HEAD"))
    return process.inputStream.bufferedReader().use { it.readText().trim().toInt() }
}

private fun git(vararg args: String): String =
    Runtime.getRuntime().exec(arrayOf("git") + args)
        .inputStream.bufferedReader().use { it.readText().trim() }

fun getGitDescribe(): String {
    // Only version tags. The repository also carries the rolling `manager-ci`
    // tag, and without the pattern it becomes the version name, so every APK
    // was called SukiSU_Nova_manager-ci_<code>-<abi>-release.apk.
    val described = git("describe", "--tags", "--always", "--abbrev=0", "--match", "v[0-9]*")
    // --always falls back to a commit hash when no version tag is reachable, and a
    // hash in the file name is noise: use the newest version tag instead.
    if (described.isNotEmpty() && !described.matches(Regex("^[0-9a-f]{7,40}$"))) {
        return described
    }
    return git("tag", "--list", "v*", "--sort=-v:refname")
        .lineSequence()
        .map { it.trim() }
        .firstOrNull { it.isNotEmpty() }
        ?: "dev"
}

fun getVersionCode(): Int {
    val commitCount = getGitCommitCount()
    val major = 3
    val end = 996
    return major * 10000 + commitCount + end
}

fun getVersionName(): String {
    return getGitDescribe()
}