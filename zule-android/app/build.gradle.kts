plugins {
    alias(libs.plugins.android.application)
    alias(libs.plugins.kotlin.android)
    alias(libs.plugins.kotlin.compose)
    alias(libs.plugins.hilt.android)
    alias(libs.plugins.kotlin.serialization)
    alias(libs.plugins.ksp)
}

android {
    namespace = "com.mazzizax.zule"
    compileSdk = 35

    defaultConfig {
        applicationId = "com.mazzizax.zule"
        minSdk = 28
        targetSdk = 35
        versionCode = 1
        versionName = "1.0.0"

        buildConfigField("String", "SUPABASE_URL", "\"https://sgjulzvgcyotebbexfue.supabase.co\"")
        buildConfigField("String", "SUPABASE_ANON_KEY", "\"sb_publishable_xFOHnMnSq51MLWo1WlZxRQ_79esD8cM\"")

        // Host that signs App Links assetlinks.json for the OTP callback flow
        // (email confirmation, magic link, password recovery). Override per
        // environment; production zule signs at zule.mazzizax.net.
        manifestPlaceholders["appAuthHost"] = "zule.mazzizax.net"
        buildConfigField("String", "AUTH_HOST", "\"zule.mazzizax.net\"")

        // Legal / support URLs — opened via Chrome Custom Tabs from LegalFooter.
        buildConfigField("String", "LEGAL_PRIVACY_URL", "\"https://zule.mazzizax.net/privacy\"")
        buildConfigField("String", "LEGAL_TERMS_URL", "\"https://zule.mazzizax.net/terms\"")
        buildConfigField("String", "LEGAL_CONTACT_URL", "\"https://mazzizax.org/contact\"")
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
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    kotlinOptions {
        jvmTarget = "17"
        freeCompilerArgs += listOf("-opt-in=io.ktor.utils.io.InternalAPI")
    }

    buildFeatures {
        compose = true
        buildConfig = true
    }

    packaging {
        jniLibs {
            keepDebugSymbols += "**/*.so"
        }
    }
}

dependencies {
    implementation(libs.androidx.core.ktx)
    implementation(libs.androidx.activity.compose)
    implementation(libs.androidx.lifecycle.runtime.compose)
    implementation(libs.androidx.lifecycle.viewmodel.compose)
    implementation(platform(libs.compose.bom))
    implementation(libs.compose.ui)
    implementation(libs.compose.ui.graphics)
    implementation(libs.compose.ui.tooling.preview)
    implementation(libs.compose.material3)
    implementation(libs.compose.material.icons.extended)
    debugImplementation(libs.compose.ui.tooling)
    implementation(libs.compose.navigation)
    implementation(libs.hilt.android)
    ksp(libs.hilt.compiler)
    implementation(libs.hilt.navigation.compose)
    implementation(libs.supabase.auth)
    implementation(libs.supabase.postgrest)
    implementation(libs.supabase.functions)
    implementation(libs.supabase.realtime)
    implementation(libs.ktor.client.okhttp)
    implementation(libs.ktor.client.content.negotiation)
    implementation(libs.ktor.serialization.json)
    implementation(libs.kotlinx.coroutines.android)
    implementation(libs.kotlinx.serialization.json)
    implementation(libs.credentials)
    implementation(libs.credentials.play.services)
    implementation(libs.biometric)
    implementation(libs.security.crypto)
    implementation(libs.camerax.core)
    implementation(libs.camerax.camera2)
    implementation(libs.camerax.lifecycle)
    implementation(libs.camerax.view)
    implementation(libs.mlkit.barcode)
    implementation(libs.browser)
    implementation(libs.plaid.link)
}
