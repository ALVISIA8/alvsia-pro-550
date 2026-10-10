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
        externalNativeBuild {
            cmake {
                arguments += listOf("-DALVSIA_SEAL_SEED_HEX=${System.getenv("ALVSIA_SEAL_SEED_HEX").orEmpty()}")
            }
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
    finalApkBackupPath = "${project.rootDir}/app/build/outputs/andresguard/ALVISIA_PRO_5.5.0_resguard.apk"
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
