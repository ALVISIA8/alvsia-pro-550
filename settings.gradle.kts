pluginManagement {
    repositories {
        google()
        mavenCentral()
        gradlePluginPortal()
        maven { url = uri("https://chaquo.com/maven") }
    }
}
dependencyResolutionManagement {
    repositoriesMode.set(RepositoriesMode.FAIL_ON_PROJECT_REPOS)
    repositories {
        google()
        mavenCentral()
        maven { url = uri("https://chaquo.com/maven") }
        maven { url = uri("https://europe-west3-maven.pkg.dev/talsec-artifact-repository/freerasp") }
        // Talsec Community SDK declares fingerprint-android and TrueTime artifacts
        // published through JitPack; without this repository Gradle cannot resolve them.
        maven { url = uri("https://jitpack.io") }
    }
}
rootProject.name = "ALVISIA_PREMIUM_TOOL"
include(":app")
