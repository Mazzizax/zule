# Strip verbose/debug/info logging in release but keep w/e so PrivateLog.safe()
# (HTTP codes, class names, support refs — PII-free) survives for release
# diagnostics.
-assumenosideeffects class android.util.Log {
    public static int v(...);
    public static int d(...);
    public static int i(...);
}

# Kotlin Serialization
-keepattributes *Annotation*, InnerClasses
-dontnote kotlinx.serialization.AnnotationsKt
-keepclassmembers class kotlinx.serialization.json.** { *** Companion; }
-keepclasseswithmembers class kotlinx.serialization.json.** { kotlinx.serialization.KSerializer serializer(...); }
-keep,includedescriptorclasses class com.mazzizax.zule.**$$serializer { *; }
-keepclassmembers class com.mazzizax.zule.** { *** Companion; }
-keepclasseswithmembers class com.mazzizax.zule.** { kotlinx.serialization.KSerializer serializer(...); }

# Ktor
-keep class io.ktor.** { *; }
-dontwarn io.ktor.**

# Supabase
-keep class io.github.jan.supabase.** { *; }
-dontwarn io.github.jan.supabase.**

# Credential Manager
-keep class androidx.credentials.** { *; }
-keep class androidx.credentials.exceptions.** { *; }

# AndroidX Lifecycle ViewModel — preserve constructors for reflection-based
# ViewModel instantiation.
-keep class * extends androidx.lifecycle.ViewModel { <init>(...); }
-keep class * extends androidx.lifecycle.AndroidViewModel { <init>(...); }

# App-local data classes — Supabase serialization relies on them at runtime.
-keep class com.mazzizax.zule.data.** { *; }
-keep class com.mazzizax.zule.data.repository.** { *; }

# Suppress spurious warnings from transitive deps.
-dontwarn org.slf4j.**
-dontwarn org.conscrypt.**
