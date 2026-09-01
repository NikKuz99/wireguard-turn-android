/*
 * Copyright © 2026 NikKuz99. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

package com.wireguard.android.turn

import android.util.Log
import com.wireguard.android.Application.Companion.getBackend
import com.wireguard.android.backend.Tunnel
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

/**
 * Watches WireGuard handshake freshness and triggers TURN restart when stale.
 *
 * Problem: When phone is idle (Doze mode, WiFi sleep), the DTLS tunnel to TURN
 * server dies silently. WireGuard keepalive (25s) can't reach the server because
 * the underlying DTLS connection is dead. Handshake becomes stale indefinitely.
 *
 * Solution: Poll last_handshake_time every 30s. If handshake is older than
 * STALE_THRESHOLD (90s = 3× keepalive interval), restart TURN proxy to force
 * new DTLS connection + WG handshake.
 *
 * @param tunnelName The active tunnel name
 * @param onStale Callback to trigger TURN restart (calls TurnProxyManager.performRestartSequence)
 */
class HandshakeWatchdog(
    private val tunnelName: String,
    private val onStale: suspend () -> Unit
) {
    companion object {
        private const val TAG = "WireGuard/HandshakeWatchdog"
        private const val POLL_INTERVAL_MS = 30_000L  // 30 seconds
        private const val STALE_THRESHOLD_MS = 90_000L  // 90 seconds (3× keepalive)
        private const val MIN_RESTART_INTERVAL_MS = 120_000L  // 2 minutes between restarts
        private const val MAX_CONSECUTIVE_RESTARTS = 3  // max restarts before giving up
    }

    private var job: Job? = null
    private var lastRestartTime = 0L
    private var consecutiveRestarts = 0

    /**
     * Start monitoring handshake freshness.
     * Should be called when tunnel is UP and TURN proxy is running.
     */
    fun start(scope: CoroutineScope) {
        stop()
        consecutiveRestarts = 0
        Log.i(TAG, "Started watching tunnel: $tunnelName (poll=${POLL_INTERVAL_MS}ms, stale=${STALE_THRESHOLD_MS}ms)")

        job = scope.launch(Dispatchers.IO) {
            // Wait initial period for first handshake to complete
            delay(10_000)

            while (isActive) {
                try {
                    if (isHandshakeStale()) {
                        val now = System.currentTimeMillis()
                        val sinceLastRestart = now - lastRestartTime

                        if (sinceLastRestart < MIN_RESTART_INTERVAL_MS) {
                            Log.d(TAG, "Handshake stale but restart cooldown active (${sinceLastRestart / 1000}s < ${MIN_RESTART_INTERVAL_MS / 1000}s)")
                        } else if (consecutiveRestarts >= MAX_CONSECUTIVE_RESTARTS) {
                            Log.w(TAG, "Handshake stale but max consecutive restarts ($MAX_CONSECUTIVE_RESTARTS) reached. Giving up.")
                            // Reset counter after 10 minutes to allow future restarts
                            if (sinceLastRestart > 600_000) {
                                consecutiveRestarts = 0
                                Log.i(TAG, "Reset restart counter after 10min cooldown")
                            }
                        } else {
                            Log.w(TAG, "Handshake stale! Restarting TURN (attempt ${consecutiveRestarts + 1}/$MAX_CONSECUTIVE_RESTARTS)")
                            lastRestartTime = now
                            consecutiveRestarts++
                            onStale()
                            // Wait longer after restart for new handshake to establish
                            delay(15_000)
                        }
                    } else {
                        // Handshake is fresh — reset restart counter
                        if (consecutiveRestarts > 0) {
                            Log.i(TAG, "Handshake recovered! Resetting restart counter")
                            consecutiveRestarts = 0
                        }
                    }
                } catch (e: Exception) {
                    Log.w(TAG, "Error checking handshake: ${e.message}")
                }

                delay(POLL_INTERVAL_MS)
            }
        }
    }

    /**
     * Stop monitoring.
     */
    fun stop() {
        job?.cancel()
        job = null
        Log.d(TAG, "Stopped watching tunnel: $tunnelName")
    }

    /**
     * Check if the WireGuard handshake is stale.
     * Returns true if last handshake was more than STALE_THRESHOLD_MS ago.
     */
    private suspend fun isHandshakeStale(): Boolean {
        return withContext(Dispatchers.IO) {
            try {
                val backend = getBackend()
                val isRunning = backend.runningTunnelNames.any { it == tunnelName }
                if (!isRunning) {
                    Log.d(TAG, "Tunnel not running, skipping check")
                    return@withContext false
                }

                // Get tunnel object by name, then get statistics
                val tm = com.wireguard.android.model.TunnelManager.getTunnelManager()
                val tunnels = tm.getTunnels()
                val tunnelObj = tunnels[tunnelName]
                if (tunnelObj == null) {
                    Log.d(TAG, "Tunnel object not found: $tunnelName")
                    return@withContext false
                }

                val stats: Statistics = try {
                    tm.getTunnelStatistics(tunnelObj)
                } catch (e: Exception) {
                    Log.d(TAG, "Failed to get statistics: ${e.message}")
                    return@withContext false
                }

                // Find the latest handshake time across all peers
                var latestHandshake = 0L
                for (key in stats.peers()) {
                    val hs = stats.peer(key).latestHandshakeEpochMillis
                    if (hs > latestHandshake) {
                        latestHandshake = hs
                    }
                }

                if (latestHandshake == 0L) {
                    // No handshake ever — check if tunnel has been up long enough
                    // If tunnel just started, give it time. If it's been 60s+, it's stale.
                    Log.d(TAG, "No handshake recorded yet")
                    return@withContext false  // Don't trigger on first connect
                }

                val now = System.currentTimeMillis()
                val age = now - latestHandshake
                val stale = age > STALE_THRESHOLD_MS

                if (stale) {
                    Log.w(TAG, "Handshake is ${age / 1000}s old (threshold: ${STALE_THRESHOLD_MS / 1000}s)")
                }

                stale
            } catch (e: Exception) {
                Log.w(TAG, "isHandshakeStale error: ${e.message}")
                false  // Don't trigger restart on errors
            }
        }
    }
}
