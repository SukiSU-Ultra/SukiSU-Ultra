plugins {
    alias(libs.plugins.agp.app) apply false
    alias(libs.plugins.kotlin) apply false
    alias(libs.plugins.compose.compiler) apply false
}

val androidMinSdkVersion by extra(31)
val androidTargetSdkVersion by extra(37)
val androidCompileSdkVersion by extra(37)
val androidCompileSdkVersionMinor by extra(0)
val androidBuildToolsVersion by extra("37.0.0")
val androidCompileNdkVersion: String by extra(libs.versions.ndk.get())
val androidSourceCompatibility by extra(JavaVersion.VERSION_21)
val androidTargetCompatibility by extra(JavaVersion.VERSION_21)
val managerVersionCode by extra(getVersionCode())
val managerVersionName by extra(getVersionName())

fun getGitCommitCount(): Int {
    val process = Runtime.getRuntime().exec(arrayOf("git", "rev-list", "--count", "HEAD"))
    return process.inputStream.bufferedReader().use { it.readText().trim().toInt() }
}

fun getGitDescribe(): String {
    val process = Runtime.getRuntime().exec(arrayOf("git", "describe", "--tags", "--always", "--abbrev=0"))
    return process.inputStream.bufferedReader().use { it.readText().trim() }
}

fun getVersionCode(): Int {
    val commitCount = getGitCommitCount()
    val major = 4
    val end = 2815
    return major * 10000 + commitCount - end
}

fun getVersionName(): String {
    return getGitDescribe()
}