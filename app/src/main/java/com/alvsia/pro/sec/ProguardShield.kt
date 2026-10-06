package com.alvsia.pro.sec

/**
 * ALVISIA PRO 5.5.0 — ProguardShield
 *
 * ProGuard / R8 rules applied via @Keep and programmatic hints.
 * The actual rules live in proguard-rules.pro — this object
 * provides runtime keep-list markers so R8 doesn't optimize them away.
 *
 * Also acts as a build-time documentation of what IS kept vs stripped.
 */
object ProguardShield {

    /**
     * Classes that must NEVER be renamed or removed.
     * Referenced here to create a keep-alive dependency chain that R8 follows.
     */
    @JvmStatic
    fun keepAliveAnchors(): Array<Class<*>> = arrayOf(
        RaspEngine::class.java,
        FridaProbe::class.java,
        EnvProbe::class.java,
        Guard::class.java,
        Tamper::class.java,
        IntegrityBomb::class.java,
        MemoryGuard::class.java,
        NetworkGuard::class.java,
        SessionGate::class.java,
        NativeGuard::class.java,
        StrHide::class.java,
        ThreatReport::class.java,
    )
}
