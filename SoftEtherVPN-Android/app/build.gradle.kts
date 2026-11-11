plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.plugin.compose")
}

val vcpkgRoot = (findProperty("vcpkg.root") as String?)
    ?: System.getenv("VCPKG_ROOT")
val vcpkgTriplet = (findProperty("vcpkg.triplet") as String?)
    ?: System.getenv("VCPKG_TARGET_TRIPLET")
    ?: "arm64-android"

android {
    namespace = "org.softether.android"
    compileSdk = 36
    ndkVersion = "30.0.16248370"

    defaultConfig {
        applicationId = "org.softether.android"
        minSdk = 29
        targetSdk = 35
        versionCode = 9
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
                    val ndkHome = System.getenv("ANDROID_NDK_HOME")
                        ?: throw GradleException(
                            "ANDROID_NDK_HOME must point to the NDK when vcpkg.root is set " +
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
            // The Android entry point: it pulls the repo root in via
            // add_subdirectory and owns all Android-specific build logic.
            path = file("src/main/cpp/CMakeLists.txt")
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
    implementation("androidx.compose.ui:ui")
    implementation("androidx.compose.ui:ui-tooling-preview")
    implementation("androidx.compose.material3:material3")
    debugImplementation("androidx.compose.ui:ui-tooling")
}
