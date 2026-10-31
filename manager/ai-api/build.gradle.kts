@file:Suppress("UnstableApiUsage")

plugins {
    alias(libs.plugins.agp.library)
    alias(libs.plugins.compose.compiler)
}

val androidCompileSdkVersion = rootProject.extra["androidCompileSdkVersion"] as Int
val androidCompileSdkVersionMinor = rootProject.extra["androidCompileSdkVersionMinor"] as Int
val androidBuildToolsVersion = rootProject.extra["androidBuildToolsVersion"] as String
val androidMinSdkVersion = rootProject.extra["androidMinSdkVersion"] as Int
val androidSourceCompatibility = rootProject.extra["androidSourceCompatibility"] as JavaVersion
val androidTargetCompatibility = rootProject.extra["androidTargetCompatibility"] as JavaVersion

android {
    namespace = "com.sukisu.ultra.ai.api"

    compileSdk {
        version =
            release(androidCompileSdkVersion) {
                minorApiLevel = androidCompileSdkVersionMinor
            }
    }
    buildToolsVersion = androidBuildToolsVersion

    defaultConfig {
        minSdk = androidMinSdkVersion
    }

    buildFeatures {
        compose = true
    }

    compileOptions {
        sourceCompatibility = androidSourceCompatibility
        targetCompatibility = androidTargetCompatibility
    }

    lint {
        abortOnError = true
        checkReleaseBuilds = false
    }
}

kotlin {
    compilerOptions {
        freeCompilerArgs.addAll(
            "-opt-in=androidx.compose.material3.ExperimentalMaterial3Api",
            "-opt-in=androidx.compose.material3.ExperimentalMaterial3ExpressiveApi",
        )
    }
}

dependencies {
    implementation(platform(libs.androidx.compose.bom))
    implementation(libs.androidx.compose.ui)
}
