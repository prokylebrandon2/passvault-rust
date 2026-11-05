plugins {
    id("com.android.application")
}

android {
    namespace = "app.passvault"
    compileSdk = 35

    defaultConfig {
        applicationId = "app.passvault"
        minSdk = 26 // the autofill framework arrives in API 26
        // 34 keeps the classic window layout, so the Slint UI isn't drawn under the status bar.
        targetSdk = 34
        versionCode = System.getenv("VERSION_CODE")?.toIntOrNull() ?: 1
        versionName = System.getenv("VERSION_NAME") ?: "1.0.0"
        ndk { abiFilters += "arm64-v8a" }
    }

    // Release signing comes from env vars set by the GitHub workflow; without them the release is unsigned.
    val keystorePath: String? = System.getenv("KEYSTORE_PATH")
    signingConfigs {
        if (keystorePath != null) {
            create("release") {
                storeFile = file(keystorePath)
                storePassword = System.getenv("KEYSTORE_PASSWORD")
                keyAlias = System.getenv("KEY_ALIAS")
                keyPassword = System.getenv("KEY_PASSWORD")
            }
        }
    }

    buildTypes {
        release {
            // Rust calls the Java glue by method name over JNI, and the Java is tiny: don't shrink or rename it.
            isMinifyEnabled = false
            if (keystorePath != null) signingConfig = signingConfigs.getByName("release")
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    packaging { jniLibs { useLegacyPackaging = true } }
    dependenciesInfo { includeInApk = false; includeInBundle = false }
    lint { checkReleaseBuilds = false; abortOnError = false }
}

// The Rust library is built first by `cargo ndk` into src/main/jniLibs (see README and the workflow).
tasks.register("checkNativeLibs") {
    doFirst {
        if (!file("src/main/jniLibs").exists()) {
            throw GradleException("src/main/jniLibs is missing. Build the Rust library first with cargo ndk (see README).")
        }
    }
}
tasks.matching { it.name == "preBuild" }.configureEach { dependsOn("checkNativeLibs") }
