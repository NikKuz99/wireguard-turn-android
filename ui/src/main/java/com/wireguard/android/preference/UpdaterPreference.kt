/*
 * Copyright © 2026 NikKuz99. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */
package com.wireguard.android.preference

import android.content.Context
import android.util.AttributeSet
import android.util.Log
import androidx.preference.Preference
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

    init {
        // Сначала применяем текущее состояние
        updateState(Updater.state.value)

        // Подписываемся на изменения
        Updater.state.onEach { progress ->
            Log.d(TAG, "State changed: ${progress::class.simpleName}")
            updateState(progress)
        }.launchIn(applicationScope)
    }

    private fun updateState(progress: Updater.Progress) {
        when (progress) {
            is Updater.Progress.Complete -> {
                title = context.getString(R.string.updater_pref_check)
                summary = context.getString(R.string.updater_pref_no_update)
                isEnabled = true
            }
            is Updater.Progress.Available -> {
                title = context.getString(R.string.updater_pref_available, progress.version)
                summary = if (progress.downloadSize > 0) {
                    context.getString(R.string.updater_pref_size, formatBytes(progress.downloadSize))
                } else null
                isEnabled = true
            }
            is Updater.Progress.Rechecking -> {
                title = context.getString(R.string.updater_pref_checking)
                summary = null
                isEnabled = false
            }
            is Updater.Progress.Downloading -> {
                title = context.getString(R.string.updater_pref_downloading)
                summary = if (progress.bytesTotal > 0) {
                    "${formatBytes(progress.bytesDownloaded)} / ${formatBytes(progress.bytesTotal)} " +
                    "(${progress.bytesDownloaded * 100 / progress.bytesTotal}%)"
                } else {
                    formatBytes(progress.bytesDownloaded)
                }
                isEnabled = true // нажатие = отмена
            }
            is Updater.Progress.Installing -> {
                title = context.getString(R.string.updater_pref_installing)
                summary = null
                isEnabled = false
            }
            is Updater.Progress.NeedsUserIntervention -> {
                title = context.getString(R.string.updater_pref_installing)
                summary = context.getString(R.string.updater_pref_confirm)
                isEnabled = false
            }
            is Updater.Progress.Failure -> {
                title = context.getString(R.string.updater_pref_failed)
                summary = progress.error.message
                isEnabled = true
            }
        }
        notifyChanged()
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
                Log.d(TAG, "Cancelling download")
                Updater.cancelUpdate()
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
