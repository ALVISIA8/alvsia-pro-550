package com.alvsia.pro.panel

/** The login-owned client instance; grants reuse the exact active login identity. */
object PanelHolder {
    @Volatile var client: PanelClient? = null
}
