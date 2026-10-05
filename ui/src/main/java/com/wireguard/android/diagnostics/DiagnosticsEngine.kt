package com.wireguard.android.diagnostics

/**
 * Движок диагностики. Реализация П3 (GoEngine) вызывает единственную
 * экспортированную Go-функцию RunDiagnostics(reqJSON) в фоновом потоке/корутине.
 * Контракт: колбэк вызывается ровно один раз; строка — либо отчёт
 * (schema_version=1), либо {"error":"..."}.
 */
interface DiagnosticsEngine {
    fun run(mode: String, onResult: (String) -> Unit)
}

class UnwiredDiagnosticsEngine : DiagnosticsEngine {
    override fun run(mode: String, onResult: (String) -> Unit) {
        onResult("{\"error\":\"diagnostics engine not wired\"}")
    }
}