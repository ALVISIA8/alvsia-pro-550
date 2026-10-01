# ─────────────────────────────────────────────────────────────────────
# ALVISIA PRO 5.5.0 — ProGuard / R8 Rules HARDENED
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

# ── String encryption hint (R8 with dProtect / Paranoid) ─────────────
# If using dProtect / Paranoid gradle plugin, these annotations control it:
# -keep @com.openobfuscator.dprotect.annotations.StringEncryption class * { *; }
# -keep @me.itay.paranoid.annotations.Obfuscate class * { *; }

# ── ALVISIA security layer — hard keep ───────────────────────────────
-keep class com.alvsia.pro.sec.** { *; }
-keepclassmembers class com.alvsia.pro.sec.** { *; }

# Keep JNI methods (native bridge to librasp_guard.so)
-keepclasseswithmembernames class * {
    native <methods>;
}

# ── ALVISIA licensing / panel ─────────────────────────────────────────
-keep class com.alvsia.pro.panel.** { *; }
-keep class com.alvsia.pro.AlvisiaApp { *; }
-keep class com.alvsia.pro.MainActivity { *; }

# ── Tool bridge (called from Kotlin reflectively via bridge) ──────────
-keep class com.alvsia.pro.tool.ToolCatalog { *; }
-keep class com.alvsia.pro.tool.SubMenus { *; }
-keep class com.alvsia.pro.tool.RamToolVault { *; }

# ── Keep enums ────────────────────────────────────────────────────────
-keepclassmembers enum * {
    public static **[] values();
    public static ** valueOf(java.lang.String);
}

# ── OkHttp / Retrofit / Gson (network layer) ──────────────────────────
-dontwarn okhttp3.**
-dontwarn okio.**
-keep class okhttp3.** { *; }
-keep class okio.** { *; }
-keep class retrofit2.** { *; }
-keepattributes Signature
-keepattributes *Annotation*

# ── Kotlin metadata (needed by Kotlin reflection) ─────────────────────
-keepattributes RuntimeVisibleAnnotations, AnnotationDefault
-keep class kotlin.Metadata { *; }
-dontwarn kotlin.**

# ── Remove logging in release ─────────────────────────────────────────
-assumenosideeffects class android.util.Log {
    public static *** d(...);
    public static *** v(...);
    public static *** i(...);
    public static *** w(...);
}

# ── Aggressive class/method renaming for all non-kept code ───────────
-keepattributes SourceFile,LineNumberTable
-renamesourcefileattribute SourceFile

# ── String obfuscation via identifier renaming ────────────────────────
# All non-kept classes get randomized names
# R8 handles this — ensure minifyEnabled=true and shrinkResources=true in build.gradle

# ── Strip unused code aggressively ───────────────────────────────────
-dontwarn com.securevale.**
-dontwarn io.github.**

# ── Output mapping for crash symbolication ───────────────────────────
# Keep the mapping.txt in a SECURE location — not in the APK
# -printmapping mapping.txt
