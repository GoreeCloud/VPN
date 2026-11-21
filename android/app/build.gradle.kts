plugins {
    id("com.android.application")
    // Android Gradle Plugin 9 includes Kotlin; don't apply kotlin-android separately.
    id("org.jetbrains.kotlin.plugin.compose")
}
android {
    namespace = "com.goreecloud.vpn"
    compileSdk = 37
    defaultConfig {
        applicationId = "com.goreecloud.vpn"
        minSdk = 26
        targetSdk = 36
        versionCode = 1
        versionName = "0.1.0"
    }
    buildFeatures { compose = true }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
}
dependencies {
    implementation(platform("androidx.compose:compose-bom:2026.09.00"))
    implementation("androidx.compose.material3:material3")
    implementation("androidx.compose.foundation:foundation")
    implementation("androidx.activity:activity-compose:1.12.0")
}
