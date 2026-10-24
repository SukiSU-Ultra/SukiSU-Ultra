@file:Suppress("UnstableApiUsage")

import com.google.protobuf.gradle.id
import java.net.HttpURLConnection
import java.net.URI

plugins {
    alias(libs.plugins.agp.app)
    alias(libs.plugins.compose.compiler)
    alias(libs.plugins.kotlin.serialization)
    alias(libs.plugins.lsplugin.apksign)
    alias(libs.plugins.protobuf)
    id("kotlin-parcelize")
}

val androidCompileSdkVersion = rootProject.extra["androidCompileSdkVersion"] as Int
val androidCompileSdkVersionMinor = rootProject.extra["androidCompileSdkVersionMinor"] as Int
val androidCompileNdkVersion = rootProject.extra["androidCompileNdkVersion"] as String
val androidBuildToolsVersion = rootProject.extra["androidBuildToolsVersion"] as String
val androidMinSdkVersion = rootProject.extra["androidMinSdkVersion"] as Int
val androidTargetSdkVersion = rootProject.extra["androidTargetSdkVersion"] as Int
val androidSourceCompatibility = rootProject.extra["androidSourceCompatibility"] as JavaVersion
val androidTargetCompatibility = rootProject.extra["androidTargetCompatibility"] as JavaVersion
val managerVersionCode = rootProject.extra["managerVersionCode"] as Int
val managerVersionName = rootProject.extra["managerVersionName"] as String

val isPrBuild = project.findProperty("IS_PR_BUILD")?.toString()?.toBoolean() ?: false
val defaultManagerPackageName = if (isPrBuild) "com.sukisu.ultra.pr" else "com.sukisu.ultra"
val defaultManagerName = if (isPrBuild) "SukiSU PR" else "SukiSU"
val managerPackageName = project.findProperty("KSU_PACKAGE_NAME")?.toString() ?: defaultManagerPackageName
val managerName = project.findProperty("KSU_NAME")?.toString() ?: defaultManagerName

apksign {
    storeFileProperty = "KEYSTORE_FILE"
    storePasswordProperty = "KEYSTORE_PASSWORD"
    keyAliasProperty = "KEY_ALIAS"
    keyPasswordProperty = "KEY_PASSWORD"
}

protobuf {
    protoc {
        artifact = libs.protobuf.protoc.get().toString()
    }
    generateProtoTasks {
        ofNonTest().forEach { task ->
            task.builtins {
                id("java") {
                    option("lite")
                }
                id("kotlin") {
                    option("lite")
                }
            }
        }
    }
}

val baseCFlags = listOf(
    "-Wall", "-Qunused-arguments", "-fvisibility=hidden", "-fvisibility-inlines-hidden",
    "-fno-exceptions", "-fno-stack-protector", "-fomit-frame-pointer",
    "-Wno-builtin-macro-redefined", "-Wno-unused-value", "-D__FILE__=__FILE_NAME__"
)
val baseCppFlags = baseCFlags + "-fno-rtti"

android {
    namespace = "com.sukisu.ultra"

    buildTypes {
        debug {
            externalNativeBuild {
                cmake {
                    arguments += listOf("-DCMAKE_CXX_FLAGS_DEBUG=-Og", "-DCMAKE_C_FLAGS_DEBUG=-Og")
                }
            }
        }
        release {
            isMinifyEnabled = true
            isShrinkResources = true
            vcsInfo.include = false
            proguardFiles(getDefaultProguardFile("proguard-android-optimize.txt"), "proguard-rules.pro")
            externalNativeBuild {
                cmake {
                    arguments += "-DDEBUG_SYMBOLS_PATH=${layout.buildDirectory.get().asFile.absolutePath}/symbols"
                    arguments += "-DCMAKE_BUILD_TYPE=Release"

                    val releaseFlags = listOf(
                        "-flto", "-ffunction-sections", "-fdata-sections", "-Wl,--gc-sections",
                        "-fno-unwind-tables", "-fno-asynchronous-unwind-tables", "-Wl,--exclude-libs,ALL"
                    )
                    val configFlags = listOf("-Oz", "-DNDEBUG").joinToString(" ")

                    cppFlags += releaseFlags
                    cFlags += releaseFlags

                    arguments += listOf(
                        "-DCMAKE_CXX_FLAGS_RELEASE=$configFlags",
                        "-DCMAKE_C_FLAGS_RELEASE=$configFlags",
                        "-DCMAKE_SHARED_LINKER_FLAGS=-Wl,--gc-sections -Wl,--exclude-libs,ALL -Wl,--icf=all -s -Wl,--hash-style=sysv -Wl,-z,norelro"
                    )
                }
            }
        }
    }

    buildFeatures {
        aidl = true
        buildConfig = true
        resValues = true
        compose = true
        prefab = true
    }

    packaging {
        dex {
            useLegacyPackaging = true
        }
        jniLibs {
            useLegacyPackaging = true
            excludes += "lib/*/libandroidx.graphics.path.so"
        }
    }

    externalNativeBuild {
        cmake {
            path = file("src/main/cpp/CMakeLists.txt")
        }
    }

    dependenciesInfo {
        includeInApk = false
        includeInBundle = false
    }

    androidResources {
        generateLocaleConfig = true
    }
    compileSdk {
        version =
            release(androidCompileSdkVersion) {
                minorApiLevel = androidCompileSdkVersionMinor
            }
    }
    buildToolsVersion = androidBuildToolsVersion
    ndkVersion = androidCompileNdkVersion

    defaultConfig {
        minSdk = androidMinSdkVersion
        targetSdk = androidTargetSdkVersion
        versionCode = managerVersionCode
        versionName = managerVersionName
        applicationId = managerPackageName

        buildConfigField("boolean", "IS_PR_BUILD", isPrBuild.toString())
        val commit = providers.exec { commandLine("git", "rev-parse", "HEAD") }.standardOutput.asText.get().trim()
        buildConfigField("String", "MANAGER_COMMIT", "\"$commit\"")
        resValue("string", "app_name", managerName)

        externalNativeBuild {
            cmake {
                arguments += "-DANDROID_STL=none"
                cFlags += baseCFlags + "-std=c2x"
                cppFlags += baseCppFlags + "-std=c++2b"
            }
        }

        ndk {
            abiFilters += listOf("arm64-v8a", "armeabi-v7a", "x86_64", "riscv64")
        }
    }

    lint {
        abortOnError = true
        checkReleaseBuilds = false
    }

    compileOptions {
        sourceCompatibility = androidSourceCompatibility
        targetCompatibility = androidTargetCompatibility
    }
}

androidComponents {
    onVariants(selector().withBuildType("release")) {
        it.packaging.resources.excludes.addAll(listOf("META-INF/**", "kotlin/**", "**.bin"))
    }
}

base {
    archivesName.set(
        "${managerName.replace(" ", "_")}_${managerVersionName}_${managerVersionCode}"
    )
}

dependencies {
    implementation(libs.androidx.activity.compose)
    implementation(libs.androidx.core.splashscreen)

    implementation(platform(libs.androidx.compose.bom))
    implementation(libs.androidx.compose.material.icons.extended)
    implementation(libs.androidx.compose.material3)
    implementation(libs.androidx.compose.ui)
    implementation(libs.androidx.compose.ui.tooling.preview)
    implementation(libs.androidx.documentfile)

    debugImplementation(libs.androidx.compose.ui.test.manifest)
    debugImplementation(libs.androidx.compose.ui.tooling)

    implementation(libs.androidx.lifecycle.runtime.compose)
    implementation(libs.androidx.lifecycle.runtime.ktx)
    implementation(libs.androidx.lifecycle.viewmodel.compose)
    implementation(libs.androidx.navigationevent.compose)

    implementation(libs.com.github.topjohnwu.libsu.core)
    implementation(libs.com.github.topjohnwu.libsu.service)
    implementation(libs.com.github.topjohnwu.libsu.io)

    implementation(libs.dev.rikka.rikkax.parcelablelist)

    implementation(libs.kotlinx.coroutines.core)
    implementation(libs.kotlinx.serialization.json)

    implementation(libs.commonmark)
    implementation(libs.commonmark.ext.gfm.tables)
    implementation(libs.commonmark.ext.gfm.strikethrough)
    implementation(libs.commonmark.ext.autolink)
    implementation(libs.commonmark.ext.task.list.items)

    implementation(libs.androidx.webkit)

    implementation(libs.lsposed.cxx)

    implementation(libs.hiddenapibypass)

    implementation(libs.miuix.ui)
    implementation(libs.miuix.icons)
    implementation(libs.miuix.nav)
    implementation(libs.miuix.preference)
    implementation(libs.miuix.blur)

    implementation(libs.reorderable)

    implementation(platform(libs.okhttp.bom))
    implementation(libs.okhttp)

    implementation(libs.material.kolor)

    implementation(libs.appiconloader)

    implementation(libs.commons.compress)
    implementation(libs.xz)
    implementation(libs.protobuf.kotlin.lite)
    implementation(libs.coil.compose)

    testImplementation(libs.junit)
}

kotlin {
    compilerOptions {
        freeCompilerArgs.addAll(
            "-opt-in=androidx.compose.material3.ExperimentalMaterial3Api",
            "-opt-in=androidx.compose.material3.ExperimentalMaterial3ExpressiveApi",
        )
    }
}

val kpmToolsDir = layout.buildDirectory.dir("generated/kpmTools")
val downloadKpmTools = tasks.register("downloadKpmTools") {
    description = "Download the latest KPM tools to bundle in the APK"
    outputs.dir(kpmToolsDir)
    // Keep the downloaded tools in the build directory. Once both files are
    // present, subsequent builds use the local copies without contacting GitHub.
    outputs.upToDateWhen {
        val root = kpmToolsDir.get().asFile
        root.resolve("jniLibs/arm64-v8a/libkptools.so").isFile &&
            root.resolve("assets/kpm/kpimg").isFile
    }
    doLast {
        val baseUrl = "https://raw.githubusercontent.com/ShirkNeko/SukiSU_patch/refs/heads/main/kpm"
        val downloads = listOf("kptools-android", "kpimg").associateWith { name ->
            val target = temporaryDir.resolve(name)
            val url = "$baseUrl/$name"
            try {
                val connection = URI(url).toURL().openConnection() as HttpURLConnection
                try {
                    connection.connectTimeout = 10_000
                    connection.readTimeout = 20_000
                    connection.useCaches = false
                    connection.setRequestProperty("User-Agent", "SukiSU-Manager-build")
                    check(connection.responseCode == HttpURLConnection.HTTP_OK) {
                        "Cannot download $name: HTTP ${connection.responseCode}"
                    }
                    val expectedSize = connection.contentLengthLong
                    connection.inputStream.use { input ->
                        target.outputStream().use { input.copyTo(it) }
                    }
                    check(target.length() >= 1024 && (expectedSize < 0 || target.length() == expectedSize)) {
                        "Incomplete KPM tool download: $name"
                    }
                } finally {
                    connection.disconnect()
                }
            } catch (networkError: Exception) {
                logger.warn("Java HTTPS download failed for $name; retrying with curl", networkError)
                val process = ProcessBuilder("curl", "--fail", "--location", "--retry", "3", "--silent", "--show-error", "--output", target.absolutePath, url)
                    .redirectErrorStream(true)
                    .start()
                val output = process.inputStream.bufferedReader().use { it.readText() }
                check(process.waitFor() == 0) { "Cannot download $name with curl: ${output.trim()}" }
                check(target.length() >= 1024) { "Incomplete KPM tool download: $name" }
            }
                if (name == "kptools-android") {
                    val header = target.inputStream().use { it.readNBytes(4) }
                    check(header.contentEquals(byteArrayOf(0x7f.toByte(), 0x45, 0x4c, 0x46))) {
                        "Downloaded kptools-android is not an ELF file"
                    }
                    logger.warn("kptools-android architecture check skipped; verify it is ARM64 before releasing")
                }
                logger.lifecycle("Downloaded $name (${target.length()} bytes)")
                target
            }
        // Publish only after both downloads have passed validation.
        val root = kpmToolsDir.get().asFile
        downloads.forEach { (name, source) ->
            val relativePath = if (name == "kptools-android") "jniLibs/arm64-v8a/libkptools.so" else "assets/kpm/kpimg"
            val output = root.resolve(relativePath)
            check(output.parentFile.isDirectory || output.parentFile.mkdirs()) { "Cannot create $output" }
            source.copyTo(output, overwrite = true)
        }
    }
}
android.sourceSets.getByName("main").apply {
    // The generated directories are populated by downloadKpmTools before preBuild.
    // Register them directly to avoid the deprecated srcDir(Any) overload.
    assets.directories.add(kpmToolsDir.get().dir("assets").asFile.toString())
    // Native libraries are extracted to an executable location by Android.
    jniLibs.directories.add(kpmToolsDir.get().dir("jniLibs").asFile.toString())
}
tasks.named("preBuild").configure { dependsOn(downloadKpmTools) }
