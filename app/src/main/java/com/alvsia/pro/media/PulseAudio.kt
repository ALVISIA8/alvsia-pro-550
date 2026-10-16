package com.alvsia.pro.media

import android.content.Context
import android.media.AudioAttributes
import android.media.MediaPlayer
import android.os.Handler
import android.os.Looper
import com.alvsia.pro.R
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlin.math.sin

object PulseAudio {
    private var player: MediaPlayer? = null
    private val _level = MutableStateFlow(0.15f)
    val level: StateFlow<Float> = _level.asStateFlow()
    @Volatile private var active = false
    private val handler = Handler(Looper.getMainLooper())
    private var pulseRunnable: Runnable? = null
    private var t0 = 0L

    fun start(ctx: Context, fadeMs: Int = 1200) {
        if (active) return
        active = true
        t0 = System.currentTimeMillis()
        try {
            stopInternal(keepActive = true)
            val mp = MediaPlayer.create(ctx.applicationContext, R.raw.bgm_pulse)
            if (mp != null) {
                mp.isLooping = true
                mp.setVolume(1f, 1f)
                mp.setAudioAttributes(
                    AudioAttributes.Builder()
                        .setUsage(AudioAttributes.USAGE_MEDIA)
                        .setContentType(AudioAttributes.CONTENT_TYPE_MUSIC)
                        .build()
                )
                mp.start()
                player = mp
            }
        } catch (_: Exception) {
        }
        startSynthPulse()
    }

    private fun startSynthPulse() {
        pulseRunnable?.let { handler.removeCallbacks(it) }
        val r = object : Runnable {
            override fun run() {
                if (!active) return
                val t = (System.currentTimeMillis() - t0) / 1000.0
                val kick = ((sin(t * 2.2) + 1.0) * 0.5).toFloat()
                val hat = ((sin(t * 9.5) + 1.0) * 0.25).toFloat()
                _level.value = (0.12f + kick * 0.55f + hat * 0.25f).coerceIn(0.08f, 1f)
                handler.postDelayed(this, 33)
            }
        }
        pulseRunnable = r
        handler.post(r)
    }

    fun stop() {
        stopInternal(keepActive = false)
    }

    private fun stopInternal(keepActive: Boolean) {
        try {
            player?.stop()
            player?.release()
        } catch (_: Exception) {
        }
        player = null
        pulseRunnable?.let { handler.removeCallbacks(it) }
        pulseRunnable = null
        if (!keepActive) {
            active = false
            _level.value = 0.08f
        }
    }
}
