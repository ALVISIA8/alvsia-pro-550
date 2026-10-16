# ─────────────────────────────────────────────────────────────────────
# ALVISIA PRO 5.5.0 — ProGuard / R8 Rules HARDENED v2
# ─────────────────────────────────────────────────────────────────────

# ── Core optimization flags ──────────────────────────────────────────
-optimizationpasses 7
-dontusemixedcaseclassnames
-dontskipnonpubliclibraryclasses
-verbose
-allowaccessmodification
-mergeinterfacesaggressively
-overloadaggressively
-repackageclasses 'a'
-flattenpackagehierarchy 'a'

# ── ALVISIA security layer — hard keep ───────────────────────────────
-keep class com.alvsia.pro.sec.NativeGuard { *; }

# Keep JNI methods (native bridge to librasp_guard.so)
-keepclasseswithmembernames class * {
    native <methods>;
}

# ── ALVISIA licensing / panel ─────────────────────────────────────────
-keep class com.alvsia.pro.panel.PanelClient { *; }
-keep class com.alvsia.pro.AlvisiaApp { *; }
-keep class com.alvsia.pro.MainActivity { *; }

# ── Tool bridge ───────────────────────────────────────────────────────
-keep class com.alvsia.pro.tool.ToolCatalog { *; }
-keep class com.alvsia.pro.tool.SubMenus { *; }
-keep class com.alvsia.pro.tool.RamToolVault { *; }

# ── Keep enums ────────────────────────────────────────────────────────
-keepclassmembers enum * {
    public static **[] values();
    public static ** valueOf(java.lang.String);
}

# ── OkHttp / Retrofit / Gson ──────────────────────────────────────────
-dontwarn okhttp3.**
-dontwarn okio.**
-keep class okhttp3.** { *; }
-keep class okio.** { *; }
-keep class retrofit2.** { *; }
-keepattributes Signature
-keepattributes *Annotation*

# ── Kotlin metadata ───────────────────────────────────────────────────
-keepattributes RuntimeVisibleAnnotations, AnnotationDefault
-keep class kotlin.Metadata { *; }
-dontwarn kotlin.**

# ── Coroutine debug probes — strip from release ───────────────────────
-assumenosideeffects class kotlinx.coroutines.debug.internal.DebugProbesKt {
    public static *** probeCoroutineResumed(...);
    public static *** probeCoroutineSuspended(...);
    public static *** probeCoroutineCreated(...);
}
-dontwarn kotlinx.coroutines.debug.**
-dontwarn kotlin.coroutines.jvm.internal.DebugProbesKt

# ── Remove ALL logging in release ────────────────────────────────────
-assumenosideeffects class android.util.Log {
    public static *** d(...);
    public static *** v(...);
    public static *** i(...);
    public static *** w(...);
    public static *** e(...);
}

# ── Aggressive renaming ───────────────────────────────────────────────
-renamesourcefileattribute SourceFile

# ── Strip unused / known debug libs ──────────────────────────────────
-dontwarn com.securevale.**
-dontwarn io.github.**

# ── Output mapping (keep in secure location, NOT in APK) ─────────────
# -printmapping mapping.txt

# ── Control-flow obfuscation (R8 performs this automatically with -optimizationpasses 7) ──
# R8 in full mode applies: dead code elimination, block merging, inlining, class merging
# This is the R8-native form of CFO — no explicit flag needed in modern R8
-optimizations !code/simplification/advanced  # keep CFO-friendly patterns
-optimizations code/removal/advanced
-optimizations code/merging/*

# Keep unluac entry points and internals: ART invokes main(String[]) reflectively.
# Aggressive repackaging/overload obfuscation otherwise breaks this runtime call.
-keep class unluac.** { *; }
-keep class unluac.Main { public static void main(java.lang.String[]); }
