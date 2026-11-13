import java.util.Properties

plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.plugin.compose")
}

// Machine-local build inputs, one precedence chain for all of them: explicit
// -P flags override, then local.properties (a successful CMake configure records
// sdk.dir, vcpkg.root, vcpkg.triplet and ndk.home there), then the usual
// environment variables — a build with the standard env vars set needs no flags.
// The Android SDK itself is located by AGP (local.properties sdk.dir, then
// ANDROID_HOME / ANDROID_SDK_ROOT), so it needs no glue here.
// Default triplet (no flag, no property, no env): arm64-android / arm64-v8a.
val localProps = Properties().apply {
    val f = rootProject.file("local.properties")
    if (f.exists()) f.inputStream().use { load(it) }
}

val vcpkgRoot = (findProperty("vcpkg.root") as String?)
    ?: localProps.getProperty("vcpkg.root")
    ?: System.getenv("VCPKG_ROOT")
    ?: System.getenv("VCPKG_INSTALLATION_ROOT")
val vcpkgTriplet = (findProperty("vcpkg.triplet") as String?)
    ?: localProps.getProperty("vcpkg.triplet")
    ?: System.getenv("VCPKG_TARGET_TRIPLET")
    ?: "arm64-android"
val ndkHomeDir = (findProperty("ndk.home") as String?)
    ?: localProps.getProperty("ndk.home")
    ?: System.getenv("ANDROID_NDK_HOME")
    ?: System.getenv("ANDROID_NDK_ROOT")

android {
    namespace = "org.softether.android"
    compileSdk = 36
    ndkVersion = "30.0.16248370"

    defaultConfig {
        applicationId = "org.softether.android"
        minSdk = 29
        targetSdk = 35
        versionCode = 42
        versionName = "1.0-android-preview"

        ndk {
            // One vcpkg triplet per Gradle build; match the ABI to the triplet.
            abiFilters += when (vcpkgTriplet) {
                "arm64-android" -> listOf("arm64-v8a")
                "x64-android" -> listOf("x86_64")
                "arm-neon-android" -> listOf("armeabi-v7a")
                else -> listOf("arm64-v8a", "x86_64")
            }
        }

        externalNativeBuild {
            cmake {
                arguments += listOf(
                    "-DANDROID_STL=none",
                )
                if (vcpkgRoot != null) {
                    // vcpkg manifest mode: the repo root (parent of the Gradle
                    // root) holds vcpkg.json; the toolchain rebuilds every port
                    // against the selected Android ABI (bionic).
                    val vcpkgRootNorm = vcpkgRoot.replace('\\', '/')
                    // vcpkg's Android chain needs the NDK; feed it the toolchain
                    // directly with slash separators (AGP's own backslash -D
                    // values break the chainloaded NDK toolchain on Windows).
                    val ndkHome = ndkHomeDir
                        ?: throw GradleException(
                            "The NDK path is unknown: pass -Pndk.home=..., set ANDROID_NDK_HOME, " +
                            "or put ndk.home in local.properties " +
                            "(vcpkg builds its Android ports through it).")
                    val ndkNorm = ndkHome.replace('\\', '/')
                    arguments += listOf(
                        "-DCMAKE_TOOLCHAIN_FILE=$vcpkgRootNorm/scripts/buildsystems/vcpkg.cmake",
                        "-DVCPKG_TARGET_TRIPLET=$vcpkgTriplet",
                        "-DVCPKG_MANIFEST_DIR=${rootDir.parentFile?.invariantSeparatorsPath}",
                        "-DVCPKG_CHAINLOAD_TOOLCHAIN_FILE=$ndkNorm/build/cmake/android.toolchain.cmake",
                        "-DANDROID_NDK=$ndkNorm",
                        "-DCMAKE_ANDROID_NDK=$ndkNorm",
                    )
                }
            }
        }
    }

    buildTypes {
        release {
            isMinifyEnabled = false
            signingConfig = signingConfigs.getByName("debug")
        }
    }

    externalNativeBuild {
        cmake {
            // The Android entry point: the Gradle root project folder's
            // CMakeLists (AGP resolves this path against the app module, so
            // ".." lands in SoftEtherVPN-Android).  It pulls the repo root in
            // via add_subdirectory and owns all Android-specific build logic.
            path = file("../CMakeLists.txt")
            version = "4.1.2"
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    buildFeatures {
        compose = true
    }
}

dependencies {
    val composeBom = platform("androidx.compose:compose-bom:2026.05.01")
    implementation(composeBom)
    implementation("androidx.core:core-ktx:1.13.1")
    implementation("androidx.activity:activity-compose:1.9.0")
    implementation("androidx.lifecycle:lifecycle-runtime-ktx:2.8.2")
    implementation("androidx.lifecycle:lifecycle-viewmodel-compose:2.8.2")
    implementation("androidx.compose.ui:ui")
    implementation("androidx.compose.ui:ui-tooling-preview")
    implementation("androidx.compose.material3:material3")
    debugImplementation("androidx.compose.ui:ui-tooling")
}
