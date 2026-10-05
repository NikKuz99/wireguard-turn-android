package com.wireguard.android.diagnostics

import org.json.JSONArray
import org.json.JSONObject

enum class DiagStatus { PASS, WARN, FAIL, SKIP }

data class DiagStage(
    val id: String,
    val status: DiagStatus,
    val durationMs: Long,
    val errorClass: String?,
    val errorRaw: String?,
    val reason: String?,
    val details: Map<String, String>,
)

data class DiagReport(
    val schemaVersion: Int,
    val generatedAt: String,
    val mode: String,
    val stages: List<DiagStage>,
    val pass: Int,
    val warn: Int,
    val fail: Int,
    val skip: Int,
    val overall: DiagStatus,
) {
    companion object {
        @JvmStatic
        fun parse(raw: String): DiagReport? = try {
            val o = JSONObject(raw)
            if (o.has("error")) null
            else DiagReport(
                schemaVersion = o.optInt("schema_version"),
                generatedAt = o.optString("generated_at"),
                mode = o.optString("mode"),
                stages = run {
                    val arr = o.optJSONArray("stages") ?: JSONArray()
                    (0 until arr.length()).mapNotNull { i ->
                        val s = arr.getJSONObject(i)
                        val d = s.optJSONObject("details")
                        val details = mutableMapOf<String, String>()
                        if (d != null) for (k in d.keys()) details[k] = stringify(d.get(k))
                        DiagStage(
                            id = s.getString("id"),
                            status = runCatching { DiagStatus.valueOf(s.getString("status")) }.getOrDefault(DiagStatus.FAIL),
                            durationMs = s.optLong("duration_ms"),
                            errorClass = s.optString("error_class").ifEmpty { null },
                            errorRaw = s.optString("error_raw").ifEmpty { null },
                            reason = d?.optString("reason")?.ifEmpty { null },
                            details = details,
                        )
                    }
                },
                pass = o.optInt("pass"),
                warn = o.optInt("warn"),
                fail = o.optInt("fail"),
                skip = o.optInt("skip"),
                overall = runCatching { DiagStatus.valueOf(o.optString("overall")) }.getOrDefault(DiagStatus.FAIL),
            )
        } catch (_: Exception) {
            null
        }

        private fun stringify(v: Any): String = when (v) {
            is JSONArray -> (0 until v.length()).joinToString(", ") { v.optString(it) }
            else -> v.toString()
        }
    }
}