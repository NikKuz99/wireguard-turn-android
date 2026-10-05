package com.wireguard.android.diagnostics

import com.wireguard.android.backend.TurnBackend
import org.json.JSONObject
import kotlin.concurrent.thread

/**
 * Продакшн-движок: единственная точка входа в Go-диагностику.
 * Контракт DiagnosticsEngine: onResult вызывается ровно один раз, НА ФОНОВОМ
 * потоке (экран П3-3 сам постит в main); строка = Report JSON либо {"error":...}.
 * wgDiagnosticsRun блокирующий (до 150с бюджет) — вызывать ТОЛЬКО отсюда.
 */
object GoDiagnosticsEngine : DiagnosticsEngine {

    override fun run(mode: String, onResult: (String) -> Unit) {
        thread(name = "tg-diagnostics", isDaemon = true, priority = Thread.NORM_PRIORITY - 1) {
            val req = JSONObject().put("mode", mode).toString()
            val out = try {
                TurnBackend.wgDiagnosticsRun(req)
            } catch (t: Throwable) {
                JSONObject().put("error", "bind call failed: ${t.message}").toString()
            }
            onResult(out)
        }
    }
}
