# ALVSIA 5.6.0 — aggressive R8 (Guardsquare/R8 lineage)
-optimizationpasses 7
-allowaccessmodification
-repackageclasses 'x'
-overloadaggressively
-renamesourcefileattribute SourceFile
-keepattributes *Annotation*,Signature,InnerClasses,EnclosingMethod
-dontwarn javax.**
-dontwarn org.bouncycastle.**

-keep class com.alvsia.pro.AlvisiaApp { *; }
-keep class com.alvsia.pro.MainActivity { *; }
-keep class com.alvsia.pro.sec.NativeGuard { *; }
-keepclassmembers class com.alvsia.pro.sec.NativeGuard { native <methods>; }
-keep class com.alvsia.pro.sec.RaspEngine { *; }
-keep class com.alvsia.pro.sec.Tamper { *; }
-keep class com.alvsia.pro.sec.SessionGate { *; }
-keep class com.alvsia.pro.sec.Guard { *; }
-keep class com.alvsia.pro.tool.RamToolVault { *; }

-keep class androidx.compose.** { *; }
-dontwarn androidx.compose.**
-keep class com.chaquo.python.** { *; }
-keep class com.chaquo.python.android.** { *; }
-dontwarn okhttp3.**
-dontwarn okio.**
-keepnames class okhttp3.internal.publicsuffix.PublicSuffixDatabase

-keepclassmembers enum * { public static **[] values(); public static ** valueOf(java.lang.String); }

-assumenosideeffects class android.util.Log {
    public static *** d(...);
    public static *** v(...);
    public static *** i(...);
    public static *** w(...);
    public static *** e(...);
}

-keep class unluac.** { *; }
-dontwarn unluac.**

# Hide string constants where possible (R8)
-adaptclassstrings
-adaptresourcefilenames
-adaptresourcefilecontents
