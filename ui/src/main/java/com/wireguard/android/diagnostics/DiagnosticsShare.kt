package com.wireguard.android.diagnostics

import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.content.Intent
import androidx.core.content.FileProvider
import java.io.File
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

object DiagnosticsShare {

    private const val KEEP_RUNS = 5 // храним последние 5 прогонов (json+txt)

    fun dir(context: Context): File = File(context.cacheDir, "diagnostics").apply { mkdirs() }

    fun write(context: Context, json: String, text: String): Pair<File, File> {
        val d = dir(context)
        prune(d)
        val stamp = SimpleDateFormat("yyyyMMdd_HHmmss", Locale.US).format(Date())
        val jf = File(d, "turnguard_diagnostics_$stamp.json")
        val tf = File(d, "turnguard_diagnostics_$stamp.txt")
        jf.writeText(json, Charsets.UTF_8)
        tf.writeText(text, Charsets.UTF_8)
        return jf to tf
    }

    fun shareText(context: Context, file: File, summary: String) = share(context, file, summary)
    fun shareJson(context: Context, file: File, summary: String) = share(context, file, summary)

    fun copyToClipboard(context: Context, text: String): Boolean {
        val cm = context.getSystemService(Context.CLIPBOARD_SERVICE) as? ClipboardManager ?: return false
        cm.setPrimaryClip(ClipData.newPlainText("TurnGuard diagnostics", text))
        return true
    }

    private fun share(context: Context, file: File, summary: String) {
        val uri = FileProvider.getUriForFile(
            context, "${context.packageName}.diagnostics-fileprovider", file
        )
        val intent = Intent(Intent.ACTION_SEND).apply {
            type = if (file.extension == "json") "application/json" else "text/plain"
            putExtra(Intent.EXTRA_SUBJECT, "TurnGuard — отчёт диагностики")
            putExtra(Intent.EXTRA_TEXT, summary)
            putExtra(Intent.EXTRA_STREAM, uri)
            addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
        }
        // П3: если вызов не из Activity — добавить FLAG_ACTIVITY_NEW_TASK
        context.startActivity(Intent.createChooser(intent, "TurnGuard"))
    }

    private fun prune(d: File) {
        val files = d.listFiles { f -> f.isFile }?.sortedBy { it.name } ?: return
        val excess = files.size - 2 * KEEP_RUNS
        for (i in 0 until maxOf(0, excess)) files[i].delete()
    }
}