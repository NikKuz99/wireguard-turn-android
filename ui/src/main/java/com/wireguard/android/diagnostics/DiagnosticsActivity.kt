package com.wireguard.android.diagnostics

import android.app.Activity
import android.graphics.Color
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.os.SystemClock
import android.view.View
import android.widget.Button
import android.widget.LinearLayout
import android.widget.TextView
import android.widget.Toast
import com.wireguard.android.R
import java.io.File

class DiagnosticsActivity : Activity() {

    private enum class State { IDLE, RUNNING, DONE, FAILED }

    private var state = State.IDLE
    private var report: DiagReport? = null
    private var rawJson: String? = null
    private var jsonFile: File? = null
    private var textFile: File? = null

    private val main = Handler(Looper.getMainLooper())
    private var ticker: Runnable? = null

    private lateinit var rowRunning: View
    private lateinit var textRunning: TextView
    private lateinit var textVerdict: TextView
    private lateinit var textSummary: TextView
    private lateinit var textMode: TextView
    private lateinit var textError: TextView
    private lateinit var stageList: LinearLayout
    private lateinit var textDetailsCaption: TextView
    private lateinit var textDetails: TextView
    private lateinit var btnRun: Button
    private lateinit var btnShareText: Button
    private lateinit var btnShareJson: Button
    private lateinit var btnCopy: Button

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_diagnostics)
        rowRunning = findViewById(R.id.rowRunning)
        textRunning = findViewById(R.id.textRunning)
        textVerdict = findViewById(R.id.textVerdict)
        textSummary = findViewById(R.id.textSummary)
        textMode = findViewById(R.id.textMode)
        textError = findViewById(R.id.textError)
        stageList = findViewById(R.id.stageList)
        textDetailsCaption = findViewById(R.id.textDetailsCaption)
        textDetails = findViewById(R.id.textDetails)
        btnRun = findViewById(R.id.btnRun)
        btnShareText = findViewById(R.id.btnShareText)
        btnShareJson = findViewById(R.id.btnShareJson)
        btnCopy = findViewById(R.id.btnCopy)

        btnRun.setOnClickListener { start() }
        btnShareText.setOnClickListener {
            val r = report ?: return@setOnClickListener
            val f = textFile ?: return@setOnClickListener
            DiagnosticsShare.shareText(this, f, ReportRenderer.verdict(r))
        }
        btnShareJson.setOnClickListener {
            val r = report ?: return@setOnClickListener
            val f = jsonFile ?: return@setOnClickListener
            DiagnosticsShare.shareJson(this, f, ReportRenderer.verdict(r))
        }
        btnCopy.setOnClickListener {
            val r = report ?: return@setOnClickListener
            if (DiagnosticsShare.copyToClipboard(this, ReportRenderer.render(r, versionName()))) {
                Toast.makeText(this, R.string.diag_copied, Toast.LENGTH_SHORT).show()
            }
        }
        applyState()
    }

    override fun onDestroy() {
        stopTicker()
        super.onDestroy()
    }

    private fun versionName(): String = try {
        @Suppress("DEPRECATION")
        packageManager.getPackageInfo(packageName, 0).versionName ?: "?"
    } catch (_: Exception) {
        "?"
    }

    private fun start() {
        if (state == State.RUNNING) return
        state = State.RUNNING
        applyState()
        val startedAt = SystemClock.elapsedRealtime()
        startTicker(startedAt)
        GoDiagnosticsEngine.run("auto") { raw ->
            // Фоновый поток tg-diagnostics: запись на диск здесь допустима.
            val parsed = DiagReport.parse(raw)
            val files: Pair<File, File>? = if (parsed != null) {
                try {
                    DiagnosticsShare.write(this, raw, ReportRenderer.render(parsed, versionName()))
                } catch (_: Exception) {
                    null
                }
            } else {
                null
            }
            main.post {
                stopTicker()
                report = parsed
                rawJson = raw
                jsonFile = files?.first
                textFile = files?.second
                state = if (parsed != null) State.DONE else State.FAILED
                applyState()
            }
        }
    }

    private fun startTicker(startedAtMs: Long) {
        val r = object : Runnable {
            override fun run() {
                textRunning.text = getString(
                    R.string.diag_running,
                    (SystemClock.elapsedRealtime() - startedAtMs) / 1000
                )
                main.postDelayed(this, 500)
            }
        }
        ticker = r
        r.run()
    }

    private fun stopTicker() {
        ticker?.let { main.removeCallbacks(it) }
        ticker = null
    }

    private fun statusColor(s: DiagStatus): Int = when (s) {
        DiagStatus.PASS -> Color.rgb(0x2E, 0x7D, 0x32)
        DiagStatus.WARN -> Color.rgb(0x9A, 0x67, 0x00)
        DiagStatus.FAIL -> Color.rgb(0xB0, 0x00, 0x20)
        DiagStatus.SKIP -> Color.rgb(0x6E, 0x6E, 0x6E)
    }

    private fun statusGlyph(s: DiagStatus): String = when (s) {
        DiagStatus.PASS -> "✔"
        DiagStatus.WARN -> "⚠"
        DiagStatus.FAIL -> "✖"
        DiagStatus.SKIP -> "—"
    }

    private fun applyState() {
        val r = report
        val done = state == State.DONE && r != null

        rowRunning.visibility = if (state == State.RUNNING) View.VISIBLE else View.GONE
        btnRun.visibility = if (state == State.RUNNING) View.GONE else View.VISIBLE
        textError.visibility = if (state == State.FAILED) View.VISIBLE else View.GONE
        val showDetails = done || state == State.FAILED
        textDetailsCaption.visibility = if (showDetails) View.VISIBLE else View.GONE
        textDetails.visibility = if (showDetails) View.VISIBLE else View.GONE
        textVerdict.visibility = if (done) View.VISIBLE else View.GONE
        textSummary.visibility = if (done) View.VISIBLE else View.GONE
        textMode.visibility = if (done) View.VISIBLE else View.GONE
        stageList.visibility = if (done) View.VISIBLE else View.GONE
        btnShareText.visibility = if (done && textFile != null) View.VISIBLE else View.GONE
        btnShareJson.visibility = if (done && jsonFile != null) View.VISIBLE else View.GONE
        btnCopy.visibility = if (done) View.VISIBLE else View.GONE

        if (state == State.FAILED) {
            textDetails.text = rawJson
        }
        if (!done || r == null) return

        textVerdict.text = "${statusGlyph(r.overall)} ${ReportRenderer.verdict(r)}"
        textVerdict.setTextColor(statusColor(r.overall))
        textSummary.text = "PASS ${r.pass} / WARN ${r.warn} / FAIL ${r.fail} / SKIP ${r.skip}"
        textMode.text = getString(
            if (r.mode == "passive") R.string.diag_banner_passive
            else R.string.diag_banner_full
        )
        stageList.removeAllViews()
        r.stages.forEachIndexed { i, st ->
            val tv = TextView(this)
            tv.text = ReportRenderer.stageLine(i + 1, st)
            tv.setTextColor(statusColor(st.status))
            stageList.addView(tv)
        }
        textDetails.text = ReportRenderer.render(r, versionName())
    }
}
