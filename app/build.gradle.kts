plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
    id("com.chaquo.python")
    id("AndResGuard")
}

android {
    namespace = "com.alvsia.pro"
    compileSdk = 35
    ndkVersion = "27.0.12077973"

    defaultConfig {
        applicationId = "com.alvsia.pro"
        minSdk = 26
        targetSdk = 34
        versionCode = 96
        versionName = "5.5.0-upgrade"
        buildConfigField("int", "PROTO", "2")
        buildConfigField("String", "CERT_SHA256", "\"99b33815c88a17abbcfe22be15250363f6dfc79c11ffc980e71b62b74b1f295c\"")
        ndk {
            abiFilters += listOf("arm64-v8a")
        }
        externalNativeBuild {
            cmake {
                arguments += listOf("-DALVSIA_SEAL_SEED_HEX=${System.getenv("ALVSIA_SEAL_SEED_HEX").orEmpty()}")
            }
        }
    }

    buildTypes {
        release {
            // AGP 8.3+ injects Git revision metadata by default; keep it out of production APKs.
            vcsInfo.include = false
            isMinifyEnabled = true
            isShrinkResources = true
            proguardFiles(
                getDefaultProguardFile("proguard-android-optimize.txt"),
                "proguard-rules.pro"
            )
        }
        debug {
            isMinifyEnabled = false
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    kotlinOptions {
        jvmTarget = "17"
        freeCompilerArgs += listOf(
            "-Xno-call-assertions",
            "-Xno-receiver-assertions",
            "-Xno-param-assertions"
        )
    }
    buildFeatures {
        compose = true
        buildConfig = true
    }
    composeOptions {
        kotlinCompilerExtensionVersion = "1.5.14"
    }
    externalNativeBuild {
        cmake {
            path = file("src/main/cpp/CMakeLists.txt")
            version = "3.22.1"
        }
    }

    packaging {
        resources {
            excludes += "/META-INF/{AL2.0,LGPL2.1}"
            excludes += "**/kotlin-tooling-metadata.json"
            excludes += "**/DebugProbesKt.bin"
            excludes += "**/META-INF/version-control-info.textproto"
            excludes += "META-INF/version-control-info.textproto"
            excludes += "**/version-control-info.textproto"
            excludes += "**/META-INF/com.android.tools/**"
            excludes += "**/META-INF/*.kotlin_module"
            excludes += "**/*.kotlin_builtins"
        }
    }
}


andResGuard {
    // Run on the release APK before production signing. Do not let this plugin sign it.
    mappingFile = null
    use7zip = false
    useSign = false
    keepRoot = false
    fixedResName = "arg"
    mergeDuplicatedRes = true
    whiteList = listOf(
        "R.mipmap.ic_launcher",
        "R.string.app_name",
        "R.drawable.logo_alvisia",
        "R.xml.network_security_config"
    )
}


chaquopy {
    defaultConfig {
        version = "3.8"
        pip {
            install("pycryptodome")
            install("requests")
            install("rich")
            install("zstandard")
        }
    }
}

dependencies {
    implementation(files("libs/unluac_pro.jar"))

    val composeBom = platform("androidx.compose:compose-bom:2024.06.00")
    implementation(composeBom)
    implementation("androidx.compose.ui:ui")
    implementation("androidx.compose.ui:ui-graphics")
    implementation("androidx.compose.foundation:foundation")
    implementation("androidx.compose.material3:material3")
    implementation("androidx.activity:activity-compose:1.9.0")
    implementation("androidx.lifecycle:lifecycle-runtime-ktx:2.8.3")
    implementation("androidx.lifecycle:lifecycle-runtime-compose:2.8.3")
    implementation("com.squareup.okhttp3:okhttp:4.12.0")
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-android:1.8.1")
}


// VANTA release gate: fail the release packaging task if sealed payloads are absent.
// This deliberately blocks release until the runtime actually emits .alv payloads.
tasks.register("verifyReleaseSecurity") {
    group = "verification"
    description = "Verify sealed Python payloads in the release APK before signing."
    doLast {
        val apkDir = layout.buildDirectory.dir("outputs/apk/release").get().asFile
        val apk = apkDir.walkTopDown()
            .filter { it.isFile && it.extension.equals("apk", ignoreCase = true) }
            .maxByOrNull { it.lastModified() }
            ?: throw GradleException("VANTA gate: no release APK found under ${apkDir.absolutePath}")

        val verifier = rootProject.file("scripts/verify_release_security.py")
        if (!verifier.isFile) {
            throw GradleException("VANTA gate: missing ${verifier.path}")
        }
        exec {
            commandLine("python3", verifier.absolutePath, apk.absolutePath)
        }
    }
}

tasks.matching { it.name == "packageRelease" }.configureEach {
    finalizedBy("verifyReleaseSecurity")
}
