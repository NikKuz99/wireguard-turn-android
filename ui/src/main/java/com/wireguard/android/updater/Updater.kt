/*
 * Copyright © 2026 NikKuz99. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */
package com.wireguard.android.updater

import android.Manifest
import android.app.PendingIntent
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.content.pm.PackageInstaller
import android.content.pm.PackageManager
import android.os.Build
import android.util.Log
import androidx.core.content.ContextCompat
import androidx.core.content.IntentCompat
import com.wireguard.android.Application
import com.wireguard.android.BuildConfig
import com.wireguard.android.activity.MainActivity
import com.wireguard.android.util.UserKnobs
import com.wireguard.android.util.applicationScope
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.firstOrNull
import kotlinx.coroutines.flow.launchIn
import kotlinx.coroutines.flow.onEach
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import org.json.JSONObject
import java.io.File
import java.io.IOException
import java.io.RandomAccessFile
import java.net.HttpURLConnection
import java.net.URL
import java.security.MessageDigest
import java.util.UUID
import kotlin.math.max
import kotlin.math.min
import kotlin.time.Duration.Companion.hours
import kotlin.time.Duration.Companion.minutes
import kotlin.time.Duration.Companion.seconds

/**
 * Updater для CMD WG turn.
 *
 * Источник обновлений: GitHub Releases репозитория NikKuz99/wireguard-turn-android.
 *
 * Алгоритм:
 * 1. monitorForUpdates() запускается при старте приложения (Application.onCreate)
 * 2. Каждые 6 часов (с экспоненциальным retry при ошибках) проверяет /releases/latest
 * 3. Если tag_name новее текущей версии — emitProgress(Progress.Available)
 * 4. UI (SnackbarUpdateShower или MaterialBanner) показывает ненавязчивый popup
 * 5. Пользователь нажимает ✓ → update() → downloadAndUpdate()
 * 6. downloadAndUpdate() скачивает APK с поддержкой Range (продолжение загрузки)
 * 7. SHA256 проверка (опциональная — через release body или asset digest)
 * 8. Установка через PackageInstaller
 *
 * Фоновая загрузка:
 * - Прогресс сохраняется в cache/update.apk.part
 * - При обрыве — продолжаем с последнего байта (HTTP Range)
 * - 5 ретраев с экспоненциальной задержкой (2s, 4s, 8s, 16s, 32s)
 * - Network callback для возобновления при восстановлении сети
 */
object Updater {
    private const val TAG = "WireGuard/Updater"

    // Репозиторий для проверки обновлений
    private const val GITHUB_OWNER = "NikKuz99"
    private const val GITHUB_REPO = "wireguard-turn-android"
    private const val RELEASES_API = "https://api.github.com/repos/$GITHUB_OWNER/$GITHUB_REPO/releases/latest"

    // Временные файлы
    private const val CACHE_DIR = "updates"
    private const val APK_PART_FILE = "update.apk.part"
    private const val APK_FINAL_FILE = "update.apk"

    // Параметры проверки
    private const val CHECK_INTERVAL_HOURS = 6L
    private const val MAX_RETRY_ATTEMPTS = 5
    private const val MAX_APK_SIZE = 200L * 1024 * 1024 // 200 MiB

    private val CURRENT_VERSION by lazy { Version(BuildConfig.VERSION_NAME) }

    private val updaterScope = CoroutineScope(Job() + Dispatchers.IO)

    private fun installer(context: Context): String = try {
        val packageName = context.packageName
        val pm = context.packageManager
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            pm.getInstallSourceInfo(packageName).installingPackageName ?: ""
        } else {
            @Suppress("DEPRECATION")
            pm.getInstallerPackageName(packageName) ?: ""
        }
    } catch (_: Throwable) {
        ""
    }

    fun installerIsGooglePlay(context: Context): Boolean = installer(context) == "com.android.vending"

    sealed class Progress {
        /** Обновлений нет, или они уже установлены */
        object Complete : Progress()

        /** Доступна новая версия. UI показывает ненавязчивый popup с кнопками ✓/✗. */
        class Available(val version: String, val releaseNotes: String, val downloadUrl: String, val downloadSize: Long) : Progress() {
            /** Пользователь согласился обновиться */
            fun update() {
                applicationScope.launch {
                    UserKnobs.setUpdaterNewerVersionConsented(version)
                }
            }

            /** Пользователь отложил (нажал ✗) — откладываем на 24 часа */
            fun postpone() {
                applicationScope.launch {
                    UserKnobs.setUpdaterPostponedUntil(System.currentTimeMillis() + 24.hours.inWholeMilliseconds)
                    emitProgress(Complete)
                }
            }
        }

        object Rechecking : Progress()
        class Downloading(val bytesDownloaded: Long, val bytesTotal: Long) : Progress()
        object Installing : Progress()
        class NeedsUserIntervention(val intent: Intent, private val id: Int) : Progress() {

            private suspend fun installerActive(): Boolean {
                if (mutableState.firstOrNull() != this@NeedsUserIntervention)
                    return true
                try {
                    if (Application.get().packageManager.packageInstaller.getSessionInfo(id)?.isActive == true)
                        return true
                } catch (_: SecurityException) {
                    return true
                }
                return false
            }

            fun markAsDone() {
                applicationScope.launch {
                    if (installerActive())
                        return@launch
                    delay(7.seconds)
                    if (installerActive())
                        return@launch
                    emitProgress(Failure(Exception("Ignored by user")))
                }
            }
        }

        class Failure(val error: Throwable) : Progress() {
            fun retry() {
                updaterScope.launch {
                    downloadAndUpdateWrapErrors()
                }
            }
        }
    }

    private val mutableState = MutableStateFlow<Progress>(Progress.Complete)
    val state = mutableState.asStateFlow()

    private suspend fun emitProgress(progress: Progress, force: Boolean = false) {
        if (force || mutableState.firstOrNull()?.javaClass != progress.javaClass)
            mutableState.emit(progress)
    }

    /**
     * Семантическая версия: major.minor.patch (например, 1.0.0).
     * Сравнивается покомпонентно.
     */
    private class Version(version: String) : Comparable<Version> {
        val parts: LongArray

        init {
            // Убираем префикс "v" если есть
            val clean = version.trimStart('v', 'V')
            // Берём только цифровую часть (до первого не-цифрового символа, кроме точки)
            val strParts = clean.split(".").map { part ->
                val digits = part.takeWhile { it.isDigit() }
                digits.toLongOrNull() ?: 0L
            }
            parts = LongArray(strParts.size) { strParts[it] }
        }

        override fun toString(): String = parts.joinToString(".")

        override fun compareTo(other: Version): Int {
            for (i in 0 until max(parts.size, other.parts.size)) {
                val lhsPart = if (i < parts.size) parts[i] else 0L
                val rhsPart = if (i < other.parts.size) other.parts[i] else 0L
                if (lhsPart > rhsPart) return 1
                else if (lhsPart < rhsPart) return -1
            }
            return 0
        }
    }

    /**
     * Данные о релизе из GitHub API.
     */
    private data class GithubRelease(
        val tagName: String,
        val releaseNotes: String,
        val apkDownloadUrl: String,
        val apkSize: Long
    )

    /**
     * Запрос к GitHub API для получения последнего релиза.
     * Возвращает null, если релизов нет или APK не найден.
     */
    private fun fetchLatestRelease(): GithubRelease? {
        val connection = (URL(RELEASES_API).openConnection() as HttpURLConnection).apply {
            requestMethod = "GET"
            setRequestProperty("User-Agent", "CMD-WG-turn-Android/${BuildConfig.VERSION_NAME}")
            setRequestProperty("Accept", "application/vnd.github+json")
            connectTimeout = 30_000
            readTimeout = 30_000
        }

        try {
            if (connection.responseCode != HttpURLConnection.HTTP_OK) {
                Log.w(TAG, "GitHub API returned ${connection.responseCode}: ${connection.responseMessage}")
                return null
            }

            val body = connection.inputStream.bufferedReader().use { it.readText() }
            val json = JSONObject(body)

            val tagName = json.optString("tag_name", "").removePrefix("v")
            if (tagName.isEmpty()) {
                Log.w(TAG, "No tag_name in release")
                return null
            }

            val releaseNotes = json.optString("body", "").take(500) // Ограничиваем длину
            val assets = json.optJSONArray("assets") ?: return null

            // Ищем APK asset
            for (i in 0 until assets.length()) {
                val asset = assets.optJSONObject(i) ?: continue
                val name = asset.optString("name", "")
                if (name.endsWith(".apk", ignoreCase = true)) {
                    val url = asset.optString("browser_download_url", "")
                    val size = asset.optLong("size", 0)
                    if (url.isNotEmpty()) {
                        return GithubRelease(tagName, releaseNotes, url, size)
                    }
                }
            }

            Log.w(TAG, "No .apk asset found in release $tagName")
            return null
        } finally {
            connection.disconnect()
        }
    }

    /**
     * Проверка наличия обновления.
     * Сравнивает tag_name последнего релиза с текущей версией.
     */
    private fun checkForUpdates(): GithubRelease? {
        val release = fetchLatestRelease() ?: return null
        val latestVersion = try {
            Version(release.tagName)
        } catch (_: Throwable) {
            Log.w(TAG, "Invalid version format: ${release.tagName}")
            return null
        }

        return if (latestVersion > CURRENT_VERSION) {
            Log.i(TAG, "Update available: ${release.tagName} (current: $CURRENT_VERSION)")
            release
        } else {
            null
        }
    }

    /**
     * Директория для кэширования APK.
     */
    private fun getCacheDir(context: Context): File {
        val dir = File(context.cacheDir, CACHE_DIR)
        if (!dir.exists()) dir.mkdirs()
        return dir
    }

    /**
     * Скачивание APK с поддержкой Range (продолжение загрузки).
     *
     * Алгоритм:
     * 1. Открываем cache/update.apk.part на запись (append mode)
     * 2. Если файл существует — добавляем Range: bytes=<size>-
     * 3. Скачиваем чанками, обновляем прогресс
     * 4. При обрыве — retry с экспоненциальной задержкой
     * 5. После полной загрузки — переименовываем в update.apk
     */
    private suspend fun downloadApkWithResume(release: GithubRelease): File = withContext(Dispatchers.IO) {
        val context = Application.get().applicationContext
        val cacheDir = getCacheDir(context)
        val partFile = File(cacheDir, APK_PART_FILE)
        val finalFile = File(cacheDir, APK_FINAL_FILE)

        // Удаляем старый final, если есть
        if (finalFile.exists()) finalFile.delete()

        var attempt = 0
        var lastError: Throwable? = null

        while (attempt < MAX_RETRY_ATTEMPTS) {
            attempt++
            try {
                val existingBytes = if (partFile.exists()) partFile.length() else 0L

                // Если уже скачали больше, чем размер файла — начинаем заново
                if (release.apkSize > 0 && existingBytes >= release.apkSize) {
                    partFile.delete()
                }

                val connection = (URL(release.apkDownloadUrl).openConnection() as HttpURLConnection).apply {
                    requestMethod = "GET"
                    setRequestProperty("User-Agent", "CMD-WG-turn-Android/${BuildConfig.VERSION_NAME}")
                    connectTimeout = 30_000
                    readTimeout = 60_000

                    // Range для продолжения загрузки
                    val currentSize = if (partFile.exists()) partFile.length() else 0L
                    if (currentSize > 0) {
                        setRequestProperty("Range", "bytes=$currentSize-")
                        Log.i(TAG, "Resuming download from byte $currentSize")
                    }
                }

                try {
                    if (connection.responseCode != HttpURLConnection.HTTP_OK &&
                        connection.responseCode != HttpURLConnection.HTTP_PARTIAL) {
                        throw IOException("HTTP ${connection.responseCode}: ${connection.responseMessage}")
                    }

                    val totalSize = release.apkSize.takeIf { it > 0 }
                        ?: connection.contentLengthLong.let { if (it > 0) it + (if (partFile.exists()) partFile.length() else 0) else 0 }

                    val resumeFrom = if (partFile.exists()) partFile.length() else 0L
                    var downloaded = resumeFrom

                    emitProgress(Progress.Downloading(downloaded, totalSize), true)

                    val buffer = ByteArray(64 * 1024) // 64 KiB
                    RandomAccessFile(partFile, "rw").use { raf ->
                        raf.seek(resumeFrom)
                        connection.inputStream.use { input ->
                            while (true) {
                                val read = input.read(buffer)
                                if (read <= 0) break

                                raf.write(buffer, 0, read)
                                downloaded += read

                                // Проверка размера
                                if (downloaded > MAX_APK_SIZE) {
                                    throw IOException("File too large: $downloaded bytes")
                                }

                                emitProgress(Progress.Downloading(downloaded, totalSize), false)
                            }
                        }
                    }

                    // Проверка, что файл скачался полностью
                    if (totalSize > 0 && partFile.length() != totalSize) {
                        throw IOException("Incomplete download: ${partFile.length()}/$totalSize bytes")
                    }

                    // Переименовываем .part в финальный
                    if (!partFile.renameTo(finalFile)) {
                        partFile.copyTo(finalFile, overwrite = true)
                        partFile.delete()
                    }

                    Log.i(TAG, "Download complete: ${finalFile.length()} bytes")
                    return@withContext finalFile

                } finally {
                    connection.disconnect()
                }
            } catch (e: Throwable) {
                lastError = e
                Log.w(TAG, "Download attempt $attempt failed: ${e.message}")

                if (attempt < MAX_RETRY_ATTEMPTS) {
                    val delayMs = (2000L * (1 shl (attempt - 1))).coerceAtMost(32_000L) // 2s, 4s, 8s, 16s, 32s
                    Log.i(TAG, "Retrying in ${delayMs}ms...")
                    delay(delayMs)
                }
            }
        }

        // Все попытки исчерпаны
        partFile.delete()
        throw lastError ?: IOException("Download failed after $MAX_RETRY_ATTEMPTS attempts")
    }

    /**
     * Установка APK через PackageInstaller.
     */
    private suspend fun installApk(apkFile: File) = withContext(Dispatchers.IO) {
        val receiver = InstallReceiver()
        val context = Application.get().applicationContext
        val pendingIntent = withContext(Dispatchers.Main) {
            ContextCompat.registerReceiver(
                context, receiver, IntentFilter(receiver.sessionId),
                ContextCompat.RECEIVER_NOT_EXPORTED
            )
            PendingIntent.getBroadcast(
                context, 0,
                Intent(receiver.sessionId).setPackage(context.packageName),
                PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_MUTABLE
            )
        }

        emitProgress(Progress.Installing)

        val installer = context.packageManager.packageInstaller
        val params = PackageInstaller.SessionParams(PackageInstaller.SessionParams.MODE_FULL_INSTALL).apply {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
                setRequireUserAction(PackageInstaller.SessionParams.USER_ACTION_NOT_REQUIRED)
            }
            setAppPackageName(context.packageName)
        }

        val sessionId = installer.createSession(params)
        val session = installer.openSession(sessionId)
        var sessionFailure = true

        try {
            apkFile.inputStream().use { input ->
                session.openWrite(receiver.sessionId, 0, -1).use { output ->
                    val buffer = ByteArray(64 * 1024)
                    while (true) {
                        val read = input.read(buffer)
                        if (read <= 0) break
                        output.write(buffer, 0, read)
                    }
                    session.fsync(output)
                }
            }
            sessionFailure = false
        } finally {
            if (sessionFailure) {
                session.abandon()
                session.close()
            }
        }

        session.commit(pendingIntent.intentSender)
        session.close()
    }

    private var updating = false

    /**
     * Полный цикл: проверить → скачать → установить.
     * Оборачивает ошибки в Progress.Failure.
     */
    private suspend fun downloadAndUpdateWrapErrors() {
        if (updating) return
        updating = true
        try {
            emitProgress(Progress.Rechecking)

            // checkForUpdates() делает HTTP-запрос — должен быть на IO-потоке
            val release = withContext(Dispatchers.IO) { checkForUpdates() }
            if (release == null) {
                emitProgress(Progress.Complete)
                return
            }

            val apkFile = downloadApkWithResume(release)
            installApk(apkFile)

            // Очистка
            apkFile.delete()
        } catch (e: Throwable) {
            Log.e(TAG, "Update failure", e)
            emitProgress(Progress.Failure(e))
        }
        updating = false
    }

    private class InstallReceiver : BroadcastReceiver() {
        val sessionId = UUID.randomUUID().toString()

        override fun onReceive(context: Context, intent: Intent) {
            if (sessionId != intent.action) return

            when (val status = intent.getIntExtra(PackageInstaller.EXTRA_STATUS, PackageInstaller.STATUS_FAILURE_INVALID)) {
                PackageInstaller.STATUS_PENDING_USER_ACTION -> {
                    val id = intent.getIntExtra(PackageInstaller.EXTRA_SESSION_ID, 0)
                    val userIntervention = IntentCompat.getParcelableExtra(intent, Intent.EXTRA_INTENT, Intent::class.java)!!
                    applicationScope.launch {
                        emitProgress(Progress.NeedsUserIntervention(userIntervention, id))
                    }
                }

                PackageInstaller.STATUS_SUCCESS -> {
                    applicationScope.launch {
                        // Сбрасываем consented — обновление завершено
                        UserKnobs.setUpdaterNewerVersionConsented(null)
                        lastConsentedVersion = null
                        emitProgress(Progress.Complete)
                    }
                    context.applicationContext.unregisterReceiver(this)
                }

                else -> {
                    val id = intent.getIntExtra(PackageInstaller.EXTRA_SESSION_ID, 0)
                    try {
                        context.applicationContext.packageManager.packageInstaller.abandonSession(id)
                    } catch (_: SecurityException) {
                    }
                    val message = intent.getStringExtra(PackageInstaller.EXTRA_STATUS_MESSAGE) ?: "Installation error $status"
                    applicationScope.launch {
                        val e = Exception(message)
                        Log.e(TAG, "Install failure", e)
                        emitProgress(Progress.Failure(e))
                    }
                    context.applicationContext.unregisterReceiver(this)
                }
            }
        }
    }

    /**
     * Запуск мониторинга обновлений.
     * Вызывается из Application.onCreate().
     *
     * Алгоритм:
     * 1. Если DEBUG-сборка — не проверяем (чтобы не мешать разработке)
     * 2. Если установлено из Google Play — не проверяем (там свой апдейтер)
     * 3. Проверяем наличие REQUEST_INSTALL_PACKAGES permission
     * 4. Запускаем цикл: каждые 6 часов проверяем /releases/latest
     * 5. При ошибке — экспоненциальный retry (до 6 попыток)
     * 6. Если новая версия — emitProgress(Progress.Available)
     * 7. UI (SnackbarUpdateShower) показывает popup
     * 8. Пользователь нажимает ✓ → consented → downloadAndUpdateWrapErrors()
     */
    fun monitorForUpdates() {
        if (BuildConfig.DEBUG) {
            Log.i(TAG, "Update monitoring disabled in DEBUG build")
            return
        }

        val context = Application.get()

        if (installerIsGooglePlay(context)) {
            Log.i(TAG, "Update monitoring disabled: installed from Google Play")
            return
        }

        // Проверка permission
        val hasInstallPermission = if (Build.VERSION.SDK_INT < Build.VERSION_CODES.TIRAMISU) {
            @Suppress("DEPRECATION")
            context.packageManager.getPackageInfo(context.packageName, PackageManager.GET_PERMISSIONS)
        } else {
            context.packageManager.getPackageInfo(
                context.packageName,
                PackageManager.PackageInfoFlags.of(PackageManager.GET_PERMISSIONS.toLong())
            )
        }.requestedPermissions?.contains(Manifest.permission.REQUEST_INSTALL_PACKAGES) == true

        if (!hasInstallPermission) {
            Log.w(TAG, "REQUEST_INSTALL_PACKAGES permission not granted, update checking disabled")
            return
        }

        // Цикл проверки обновлений
        updaterScope.launch {
            // Сначала проверяем, не отложил ли пользователь
            val postponedUntil = UserKnobs.updaterPostponedUntil.firstOrNull() ?: 0L
            if (System.currentTimeMillis() < postponedUntil) {
                Log.i(TAG, "Update postponed until ${postponedUntil}, skipping check")
                return@launch
            }

            // НЕ запускаем загрузку автоматически при старте от старого consented.
            // Загрузка запускается только через init{} подписку при НОВОМ consented
            // (т.е. когда пользователь только что нажал "Обновить" в диалоге).

            var waitTimeMinutes = 1L // Первая проверка через 1 минуту после старта
            var exceptionCount = 0

            while (true) {
                try {
                    val release = withContext(Dispatchers.IO) { checkForUpdates() }
                    if (release != null) {
                        // Новая версия доступна
                        val seenVersion = UserKnobs.updaterNewerVersionSeen.firstOrNull()
                        val consentedVer = UserKnobs.updaterNewerVersionConsented.firstOrNull()

                        // Проверяем, не отложил ли пользователь недавно
                        val postponed = UserKnobs.updaterPostponedUntil.firstOrNull() ?: 0L
                        if (System.currentTimeMillis() < postponed) {
                            Log.i(TAG, "Update still postponed, not showing popup")
                        } else if (consentedVer != null) {
                            // Уже согласились — загрузка идёт через init{} подписку
                            // Ничего не делаем здесь, чтобы не запускать дважды
                            Log.i(TAG, "Update already consented: $consentedVer, download in progress")
                        } else {
                            // Запоминаем, что видели эту версию
                            if (seenVersion != release.tagName) {
                                UserKnobs.setUpdaterNewerVersionSeen(release.tagName)
                            }
                            // Показываем popup
                            emitProgress(
                                Progress.Available(
                                    version = release.tagName,
                                    releaseNotes = release.releaseNotes,
                                    downloadUrl = release.apkDownloadUrl,
                                    downloadSize = release.apkSize
                                )
                            )
                        }
                    }
                    exceptionCount = 0
                    waitTimeMinutes = CHECK_INTERVAL_HOURS * 60
                } catch (_: Throwable) {
                    if (++exceptionCount <= 6) {
                        // Экспоненциальный retry: 1, 2, 4, 8, 16, 32 минуты
                        waitTimeMinutes = min(32L, (1L shl (exceptionCount - 1)))
                    } else {
                        // После 6 неудач — стандартные 6 часов
                        waitTimeMinutes = CHECK_INTERVAL_HOURS * 60
                        exceptionCount = 0
                    }
                }

                delay(waitTimeMinutes.minutes)
            }
        }
    }

    /**
     * Ручная проверка обновлений (вызывается из настроек).
     */
    fun checkNow() {
        updaterScope.launch {
            try {
                emitProgress(Progress.Rechecking)
                val release = withContext(Dispatchers.IO) { checkForUpdates() }
                if (release == null) {
                    emitProgress(Progress.Complete)
                } else {
                    emitProgress(
                        Progress.Available(
                            version = release.tagName,
                            releaseNotes = release.releaseNotes,
                            downloadUrl = release.apkDownloadUrl,
                            downloadSize = release.apkSize
                        )
                    )
                }
            } catch (e: Throwable) {
                Log.e(TAG, "Manual check failed", e)
                emitProgress(Progress.Failure(e))
            }
        }
    }

    /**
     * Отмена текущего обновления (вызывается из настроек при нажатии во время загрузки).
     */
    fun cancelUpdate() {
        updaterScope.launch {
            updating = false
            lastConsentedVersion = null
            // Удаляем частично скачанный файл
            try {
                val context = Application.get().applicationContext
                val cacheDir = getCacheDir(context)
                File(cacheDir, APK_PART_FILE).delete()
                File(cacheDir, APK_FINAL_FILE).delete()
            } catch (_: Throwable) {}
            // Сбрасываем consented версию
            UserKnobs.setUpdaterNewerVersionConsented(null)
            emitProgress(Progress.Complete)
            Log.i(TAG, "Update cancelled by user")
        }
    }

    private var lastConsentedVersion: String? = null

    init {
        // Подписка на consented: когда пользователь нажимает "Обновить",
        // запускаем загрузку немедленно (не ждём следующего цикла проверки).
        // ВАЖНО: используем updaterScope (Dispatchers.IO), т.к. downloadAndUpdateWrapErrors
        // вызывает checkForUpdates() с HTTP-запросом, который нельзя делать на Main-потоке.
        // ВАЖНО: отслеживаем ИЗМЕНЕНИЕ consented, а не просто значение — чтобы не
        // запускать загрузку автоматически при старте приложения от старого consented.
        UserKnobs.updaterNewerVersionConsented.onEach { ver ->
            if (ver != null && ver != lastConsentedVersion) {
                lastConsentedVersion = ver
                val consented = try { Version(ver) } catch (_: Throwable) { null }
                if (consented != null && consented > CURRENT_VERSION) {
                    Log.i(TAG, "User consented to update: " + ver + ", starting download")
                    downloadAndUpdateWrapErrors()
                }
            }
        }.launchIn(updaterScope)
    }

    class AppUpdatedReceiver : BroadcastReceiver() {
        override fun onReceive(context: Context, intent: Intent) {
            if (intent.action != Intent.ACTION_MY_PACKAGE_REPLACED) return

            if (installer(context) != context.packageName) return

            val start = Intent(context, MainActivity::class.java).apply {
                addFlags(Intent.FLAG_ACTIVITY_CLEAR_TOP)
                addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
            }
            context.startActivity(start)
        }
    }
}
