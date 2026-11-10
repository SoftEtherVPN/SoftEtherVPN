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
        versionCode = 7
        versionName = "1.0-android-preview"

        ndk {
            // One vcpkg triplet per Gradle build; match the ABI to the triplet.
            abiFilters += when (vcpkgTriplet) {
                "arm64-android" -> listOf("arm64-v8a")
                "x64-android" -> listOf("x86_64")
                else -> listOf("arm64-v8a", "x86_64")
            }
        }

        externalNativeBuild {
            cmake {
                arguments += listOf(
                    "-DANDROID_STL=none",
                    "-DSE_SRC_DIR=${rootDir.parentFile?.invariantSeparatorsPath}/src",
                )
                vcpkgRoot?.let {
                    // Skip the vcpkg toolchain (its Android chain breaks on
                    // backslash NDK paths); point at the installed tree instead.
                    arguments += listOf(
                        "-DSE_VCPKG_INSTALL=${rootDir.parentFile?.invariantSeparatorsPath}/vcpkg_installed/$vcpkgTriplet",
                        "-DVCPKG_TARGET_TRIPLET=$vcpkgTriplet",
                    )
                }
            }
        }
    }

    buildTypes {
        release {
            isMinifyEnabled = false
        }
    }

    externalNativeBuild {
        cmake {
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
