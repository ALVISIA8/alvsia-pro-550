# === ALVSIA aggressive R8 (Guardsquare/R8 lineage + shield-style) ===
-optimizationpasses 7
-allowaccessmodification
-repackageclasses 'x'
-overloadaggressively
-renamesourcefileattribute SourceFile
-keepattributes *Annotation*,Signature,InnerClasses,EnclosingMethod
-dontwarn javax.**
-dontwarn org.bouncycastle.**

# Keep entry + JNI only
-keep class com.alvsia.pro.AlvisiaApp { *; }
-keep class com.alvsia.pro.MainActivity { *; }
-keep class com.alvsia.pro.sec.NativeGuard { *; }
-keepclassmembers class com.alvsia.pro.sec.NativeGuard { native <methods>; }
-keep class com.alvsia.pro.sec.RaspEngine { *; }
-keep class com.alvsia.pro.sec.Tamper { *; }
-keep class com.alvsia.pro.sec.SessionGate { *; }
-keep class com.alvsia.pro.tool.RamToolVault { *; }

# Compose / AndroidX
-keep class androidx.compose.** { *; }
-dontwarn androidx.compose.**

# Chaquopy
-keep class com.chaquo.python.** { *; }
-keep class com.chaquo.python.android.** { *; }

# OkHttp
-dontwarn okhttp3.**
-dontwarn okio.**
-keepnames class okhttp3.internal.publicsuffix.PublicSuffixDatabase

# securevale
-keep class com.securevale.rasp.android.** { *; }
-keep class com.securevale.rasp.android.api.** { *; }
-keep class com.securevale.rasp.android.api.result.** { *; }

# Enums
-keepclassmembers enum * { public static **[] values(); public static ** valueOf(java.lang.String); }

# Remove log in release (if used)
-assumenosideeffects class android.util.Log {
    public static *** d(...);
    public static *** v(...);
    public static *** i(...);
}


# Unluac (LUA decompile on ART)
-keep class unluac.** { *; }
-dontwarn unluac.**
