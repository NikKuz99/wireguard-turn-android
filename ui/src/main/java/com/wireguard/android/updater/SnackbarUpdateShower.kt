/*
 * Copyright © 2026 NikKuz99. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

package com.wireguard.android.updater

import android.content.Intent
import android.net.Uri
import android.view.View
import android.widget.Toast
import androidx.activity.result.contract.ActivityResultContracts
import androidx.fragment.app.Fragment
import androidx.lifecycle.lifecycleScope
import com.google.android.material.dialog.MaterialAlertDialogBuilder
import com.google.android.material.snackbar.BaseTransientBottomBar
import com.google.android.material.snackbar.Snackbar
import com.wireguard.android.R
import com.wireguard.android.util.ErrorMessages
import com.wireguard.android.util.QuantityFormatter
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.launchIn
import kotlinx.coroutines.flow.onEach
import kotlinx.coroutines.launch
import kotlin.time.Duration.Companion.seconds

/**
 * Ненавязчивая плашка обновлений через Snackbar LENGTH_INDEFINITE.
 *
 * Особенности:
 * - Snackbar LENGTH_INDEFINITE — висит пока юзер не нажмёт кнопку
 * - Свайп отключён — нельзя закрыть случайно
 * - При Available: текст + кнопка "Обновить" (✓)
 *   → открывается диалог с release notes, в нём "Обновить"/"Позже"
 *   → "Позже" откладывает на 24 часа
 * - При Downloading/Installing: текст с прогрессом, без кнопок
 * - При Failure: текст ошибки + кнопка "Повторить"
 * - При Complete: плашка скрывается
 */
class SnackbarUpdateShower(private val fragment: Fragment) {
    private var lastUserIntervention: Updater.Progress.NeedsUserIntervention? = null
    private val intentLauncher = fragment.registerForActivityResult(ActivityResultContracts.StartActivityForResult()) {
        lastUserIntervention?.markAsDone()
    }

    private var currentSnackbar: Snackbar? = null

    private fun showSnackbar(text: String, actionText: String? = null, actionListener: View.OnClickListener? = null) {
        currentSnackbar?.dismiss()
        val view = fragment.view ?: return
        val snackbar = Snackbar.make(fragment.requireContext(), view, text, Snackbar.LENGTH_INDEFINITE)
        snackbar.setTextMaxLines(4)
        // Запрещаем свайп — плашка не должна закрываться случайно
        snackbar.behavior = object : BaseTransientBottomBar.Behavior() {
            override fun canSwipeDismissView(child: View): Boolean {
                return false
            }
        }
        if (actionText != null && actionListener != null) {
            snackbar.setAction(actionText, actionListener)
        }
        snackbar.show()
        currentSnackbar = snackbar
    }

    private fun dismissSnackbar() {
        currentSnackbar?.dismiss()
        currentSnackbar = null
    }

    fun attach(view: View, anchor: View?) {
        val context = fragment.requireContext()

        Updater.state.onEach { progress ->
            when (progress) {
                is Updater.Progress.Complete ->
                    dismissSnackbar()

                is Updater.Progress.Available -> {
                    // Плашка "Доступно обновление" с кнопкой "Обновить"
                    val sizeText = if (progress.downloadSize > 0) {
                        " (" + QuantityFormatter.formatBytes(progress.downloadSize) + ")"
                    } else ""
                    showSnackbar(
                        context.getString(R.string.updater_avalable, progress.version) + sizeText,
                        context.getString(R.string.updater_details)
                    ) {
                        // Открываем диалог с release notes
                        showUpdateDialog(progress)
                    }
                }

                is Updater.Progress.NeedsUserIntervention -> {
                    lastUserIntervention = progress
                    intentLauncher.launch(progress.intent)
                }

                is Updater.Progress.Installing ->
                    showSnackbar(context.getString(R.string.updater_installing))

                is Updater.Progress.Rechecking ->
                    showSnackbar(context.getString(R.string.updater_rechecking))

                is Updater.Progress.Downloading -> {
                    if (progress.bytesTotal > 0) {
                        showSnackbar(
                            context.getString(
                                R.string.updater_download_progress,
                                QuantityFormatter.formatBytes(progress.bytesDownloaded),
                                QuantityFormatter.formatBytes(progress.bytesTotal),
                                progress.bytesDownloaded.toFloat() * 100.0 / progress.bytesTotal.toFloat()
                            )
                        )
                    } else {
                        showSnackbar(
                            context.getString(
                                R.string.updater_download_progress_nototal,
                                QuantityFormatter.formatBytes(progress.bytesDownloaded)
                            )
                        )
                    }
                }

                is Updater.Progress.Failure -> {
                    showSnackbar(
                        context.getString(R.string.updater_failure, ErrorMessages[progress.error]),
                        context.getString(R.string.updater_retry)
                    ) {
                        progress.retry()
                    }
                }
            }
        }.launchIn(fragment.lifecycleScope)
    }

    /**
     * Диалог с release notes и кнопками "Обновить" / "Позже".
     */
    private fun showUpdateDialog(progress: Updater.Progress.Available) {
        val context = fragment.requireContext()
        val sizeText = if (progress.downloadSize > 0) {
            "\n\nРазмер: ${QuantityFormatter.formatBytes(progress.downloadSize)}"
        } else ""

        val message = if (progress.releaseNotes.isNotBlank()) {
            progress.releaseNotes + sizeText
        } else {
            context.getString(R.string.updater_release_notes) + sizeText
        }

        MaterialAlertDialogBuilder(context)
            .setTitle(context.getString(R.string.updater_avalable, progress.version))
            .setMessage(message)
            .setPositiveButton(context.getString(R.string.updater_action)) { _, _ ->
                progress.update()
            }
            .setNegativeButton(context.getString(R.string.updater_postpone)) { _, _ ->
                progress.postpone()
            }
            .setCancelable(true)
            .show()
    }
}
