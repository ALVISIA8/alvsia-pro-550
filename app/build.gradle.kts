plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
    id("com.chaquo.python")
}

android {
    ndkVersion = "26.1.10909125"
    externalNativeBuild {
        cmake {
            path = file("src/main/cpp/CMakeLists.txt")
        }
    }

    namespace = "com.alvsia.pro"
    compileSdk = 34

    defaultConfig {
        applicationId = "com.alvsia.pro"
        minSdk = 26
        targetSdk = 34
        versionCode = 97
        versionName = "5.5.0-R5.3"
        buildConfigField("int", "PROTO", "2")
        buildConfigField("String", "CERT_SHA256", "\"99b33815c88a17abbcfe22be15250363f6dfc79c11ffc980e71b62b74b1f295c\"")
        ndk {
            abiFilters += listOf("arm64-v8a")
        }
    }

    buildTypes {
        release {
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
    packaging {
        resources {
            excludes += "/META-INF/{AL2.0,LGPL2.1}"
            excludes += "**/kotlin-tooling-metadata.json"
            excludes += "**/DebugProbesKt.bin"
            excludes += "**/META-INF/version-control-info.textproto"
            excludes += "**/META-INF/com.android.tools/**"
            excludes += "**/META-INF/*.kotlin_module"
            excludes += "**/*.kotlin_builtins"
        }
    }
}

chaquopy {
    defaultConfig {
        version = "3.14"
        pip {
            install("requests")
            install("rich")
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


// Fail-closed release security gate. The check runs before assembleRelease so
// legacy client-side bypasses or missing operation-grant wiring cannot ship.
tasks.register("securityReleaseCheck") {
    doLast {
        exec {
            workingDir(rootProject.projectDir)
            commandLine("python3", "tools/security_release_check.py")
        }
    }
}

tasks.matching { it.name == "assembleRelease" }.configureEach {
    dependsOn("securityReleaseCheck")
}
