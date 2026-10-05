package com.wireguard.android.diagnostics

object ReportRenderer {

    private val TITLES = mapOf(
        "device_net" to "Сеть устройства",
        "dns" to "Разрешение имён (DNS)",
        "vk_auth" to "Сессия VK",
        "turn_alloc" to "TURN-релей",
        "dtls" to "Канал DTLS",
        "wg_handshake" to "Рукопожатие WireGuard",
        "tun_state" to "Туннель и маршруты",
        "e2e_http" to "Интернет через туннель",
        "latency" to "Задержка и стабильность",
        "rehandshake" to "Повторное рукопожатие",
    )

    private val SKIP_REASONS = mapOf(
        "upstream_stage_failed" to "пропущено: предыдущая стадия не пройдена",
        "rehandshake_invasive_when_connected" to "пропущено: инвазивно при живом туннеле",
        "requires_active_tunnel" to "пропущено: требуется активное подключение",
        "diagnostics_does_not_start_vpn" to "пропущено: диагностика не поднимает VPN",
        "requires_ephemeral_session_v1_9" to "пропущено: эфемерная сессия — планируется в версии 1.9",
    )

    private val CLASSES = mapOf(
        "NETWORK" to "сеть",
        "DNS" to "DNS",
        "AUTH" to "аутентификация",
        "TURN_ALLOC" to "TURN",
        "PROTECT" to "защита сокета (BUG-016)",
        "DTLS" to "DTLS",
        "WG_HANDSHAKE" to "WireGuard",
        "TUN" to "туннель",
        "E2E" to "сквозной доступ",
        "TIMEOUT" to "таймаут",
        "INTERNAL" to "внутренняя ошибка",
    )

    fun verdict(r: DiagReport): String = when (r.overall) {
        DiagStatus.PASS -> "диагностика пройдена"
        DiagStatus.WARN -> "обнаружены замечания"
        DiagStatus.FAIL -> "обнаружены проблемы"
        DiagStatus.SKIP -> "неполная диагностика"
    }

    fun stageLine(n: Int, s: DiagStage): String =
        "$n. ${glyph(s.status)} ${TITLES[s.id] ?: s.id} — ${s.durationMs} мс${suffix(s)}"

    fun render(r: DiagReport, appVersion: String): String = buildString {
        appendLine("TurnGuard — отчёт диагностики")
        appendLine("Версия: $appVersion | Режим: ${if (r.mode == "passive") "пассивный" else "полный"} | ${r.generatedAt.replace('T', ' ')}")
        appendLine("Итог: ${verdict(r)} (PASS ${r.pass} / WARN ${r.warn} / FAIL ${r.fail} / SKIP ${r.skip})")
        appendLine()
        r.stages.forEachIndexed { i, s ->
            appendLine("${i + 1}. ${glyph(s.status)} ${TITLES[s.id] ?: s.id} — ${s.durationMs} мс${suffix(s)}")
        }
        appendLine()
        appendLine("Технические детали:")
        r.stages
            .filter { it.errorRaw != null || it.details.any { (k, _) -> k != "reason" } }
            .forEach { s ->
                val parts = mutableListOf<String>()
                s.errorRaw?.let { parts.add("error: $it") }
                s.details.filterKeys { it != "reason" }.forEach { (k, v) -> parts.add("$k=$v") }
                if (parts.isNotEmpty()) appendLine("  [${TITLES[s.id] ?: s.id}] ${parts.joinToString("; ")}")
            }
    }

    private fun glyph(s: DiagStatus): String = when (s) {
        DiagStatus.PASS -> "✔"
        DiagStatus.WARN -> "⚠"
        DiagStatus.FAIL -> "✖"
        DiagStatus.SKIP -> "—"
    }

    private fun suffix(s: DiagStage): String = when {
        s.status == DiagStatus.SKIP && s.reason != null -> " — ${SKIP_REASONS[s.reason] ?: s.reason}"
        s.status == DiagStatus.FAIL && s.errorClass != null -> " — ${CLASSES[s.errorClass] ?: s.errorClass}"
        else -> ""
    }
}