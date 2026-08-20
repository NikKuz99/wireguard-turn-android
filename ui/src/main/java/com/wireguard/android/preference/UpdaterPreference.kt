/*
 * Copyright © 2026 NikKuz99. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */
package com.wireguard.android.preference

import android.app.AlertDialog
import android.content.Context
import android.util.AttributeSet
import android.util.Log
import android.view.View
import android.widget.TextView
import androidx.preference.Preference
import androidx.preference.PreferenceViewHolder
import com.wireguard.android.R
import com.wireguard.android.updater.Updater
import com.wireguard.android.util.applicationScope
import kotlinx.coroutines.flow.launchIn
import kotlinx.coroutines.flow.onEach

/**
 * Preference для проверки и запуска обновлений.
 *
 * Состояния:
 * - Complete: "Проверить обновления" / "Обновлений нет" → onClick = ручная проверка
 * - Available: "Доступно обновление: vX.X.X" / "Размер: XX MB" → onClick = начать загрузку
 * - Rechecking: "Проверка обновлений…" (disabled)
 * - Downloading: "Обновляю приложение… (нажмите для отмены)" / прогресс → onClick = отмена
 * - Installing: "Установка обновления…" (disabled)
 * - Failure: "Ошибка обновления" / текст ошибки → onClick = повторить
 */
class UpdaterPreference(context: Context, attrs: AttributeSet?) : Preference(context, attrs) {

    companion object {
        private const val TAG = "WireGuard/UpdaterPreference"
    }

    private var titleView: TextView? = null
    private var summaryView: TextView? = null

    init {
        // Сначала применяем текущее состояние
        updateState(Updater.state.value)

        // Подписываемся на изменения
        Updater.state.onEach { progress ->
            Log.d(TAG, "State changed: ${progress::class.simpleName}")
            updateState(progress)
        }.launchIn(applicationScope)
    }

    override fun onBindViewHolder(holder: PreferenceViewHolder) {
        super.onBindViewHolder(holder)
        // Keep references to title/summary views for direct updates
        titleView = holder.findViewById(android.R.id.title) as? TextView
        summaryView = holder.findViewById(android.R.id.summary) as? TextView
        Log.d(TAG, "onBindViewHolder: titleView=$titleView, summaryView=$summaryView")
        // Apply current state — but WITHOUT notifyChanged (causes crash during layout)
        applyStateWithoutNotify(Updater.state.value)
    }

    // Current display strings (updated by applyStateWithoutNotify, read by onClick)
    private var currentTitle: String = ""
    private var currentSummary: String? = null
    private var currentEnabled: Boolean = true

    /**
     * Apply state by computing display strings and updating views DIRECTLY.
     * Does NOT call Preference.setTitle/setSummary/setEnabled (those internally
     * call notifyChanged() which crashes during RecyclerView layout).
     * Safe to call from onBindViewHolder.
     */
    private fun applyStateWithoutNotify(progress: Updater.Progress) {
        val (newTitle, newSummary, newEnabled) = computeDisplayStrings(progress)
        currentTitle = newTitle
        currentSummary = newSummary
        currentEnabled = newEnabled
        // Update views directly — NO Preference property setters
        titleView?.text = newTitle
        summaryView?.apply {
            text = newSummary
            visibility = if (newSummary.isNullOrEmpty()) View.GONE else View.VISIBLE
        }
        // setEnabled on Preference also calls notifyChanged, so we set it on the view
        // parent instead (which controls click handling)
        // Actually, Preference.isEnabled controls click; but setting it calls notifyChanged.
        // We'll set it only in updateState (runtime path, not bind path).
    }

    /**
     * Compute display strings for a given progress state.
     * Returns (title, summary, isEnabled) — does NOT touch Preference properties.
     */
    private fun computeDisplayStrings(progress: Updater.Progress): Triple<String, String?, Boolean> {
        return when (progress) {
            is Updater.Progress.Complete -> Triple(
                context.getString(R.string.updater_pref_check),
                context.getString(R.string.updater_pref_no_update),
                true
            )
            is Updater.Progress.Available -> Triple(
                context.getString(R.string.updater_pref_available, progress.version),
                if (progress.downloadSize > 0) {
                    context.getString(R.string.updater_pref_size, formatBytes(progress.downloadSize))
                } else null,
                true
            )
            is Updater.Progress.Rechecking -> Triple(
                context.getString(R.string.updater_pref_checking),
                null,
                false
            )
            is Updater.Progress.Downloading -> {
                val progressText = if (progress.bytesTotal > 0) {
                    "${formatBytes(progress.bytesDownloaded)} / ${formatBytes(progress.bytesTotal)} " +
                    "(${progress.bytesDownloaded * 100 / progress.bytesTotal}%)"
                } else {
                    formatBytes(progress.bytesDownloaded)
                }
                Triple(
                    context.getString(R.string.updater_pref_downloading),
                    progressText + "\n" + context.getString(R.string.updater_pref_tap_cancel),
                    true
                )
            }
            is Updater.Progress.Installing -> Triple(
                context.getString(R.string.updater_pref_installing),
                null,
                false
            )
            is Updater.Progress.NeedsUserIntervention -> Triple(
                context.getString(R.string.updater_pref_installing),
                context.getString(R.string.updater_pref_confirm),
                false
            )
            is Updater.Progress.Failure -> Triple(
                context.getString(R.string.updater_pref_failed),
                progress.error.message,
                true
            )
        }
    }

    private fun updateState(progress: Updater.Progress) {
        // Compute strings (shared with applyStateWithoutNotify)
        val (newTitle, newSummary, newEnabled) = computeDisplayStrings(progress)
        currentTitle = newTitle
        currentSummary = newSummary
        currentEnabled = newEnabled
        // Set Preference properties — these internally call notifyChanged()
        // which triggers onBindViewHolder → applyStateWithoutNotify (view update).
        // Safe here because we're NOT in RecyclerView layout.
        title = newTitle
        summary = newSummary
        isEnabled = newEnabled
    }

    override fun onClick() {
        val state = Updater.state.value
        Log.i(TAG, "onClick: state=${state::class.simpleName}")
        when (state) {
            is Updater.Progress.Complete -> {
                Log.d(TAG, "Starting manual check")
                Updater.checkNow()
            }
            is Updater.Progress.Available -> {
                Log.d(TAG, "Starting download for v${state.version}")
                state.update()
            }
            is Updater.Progress.Downloading -> {
                Log.d(TAG, "Showing cancel confirmation dialog")
                AlertDialog.Builder(context)
                    .setTitle(R.string.updater_pref_cancel)
                    .setMessage(R.string.updater_pref_cancel_confirm)
                    .setPositiveButton(android.R.string.ok) { _, _ ->
                        Log.d(TAG, "User confirmed cancel")
                        Updater.cancelUpdate()
                    }
                    .setNegativeButton(android.R.string.cancel, null)
                    .show()
            }
            is Updater.Progress.Failure -> {
                Log.d(TAG, "Retrying after failure")
                state.retry()
            }
            else -> {
                Log.d(TAG, "Ignoring click in state ${state::class.simpleName}")
            }
        }
    }

    private fun formatBytes(bytes: Long): String {
        if (bytes < 1024) return "$bytes B"
        if (bytes < 1024 * 1024) return "${bytes / 1024} KB"
        return "${bytes / (1024 * 1024)} MB"
    }
}
