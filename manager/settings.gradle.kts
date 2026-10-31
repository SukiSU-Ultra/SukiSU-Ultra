@file:Suppress("UnstableApiUsage")

enableFeaturePreview("TYPESAFE_PROJECT_ACCESSORS")

pluginManagement {
    repositories {
        gradlePluginPortal()
        google()
        mavenCentral()
    }
}

dependencyResolutionManagement {
    repositories {
        google()
        mavenCentral()
        maven("https://jitpack.io")
    }
}

rootProject.name = "KernelSU"
include(":app")
include(":ai-api")

// The full assistant is optional: drop the module (or build the AAR into
// app/libs) and the host keeps compiling with every AI entry hidden.
val aiEnabled = providers.gradleProperty("ai").orNull?.toBoolean() ?: true
if (aiEnabled && file("ai/build.gradle.kts").isFile) {
    include(":ai")
}
