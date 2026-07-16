/*
 * Copyright © 2017-2025 WireGuard LLC. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */
package com.wireguard.android.model

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.os.Build
import android.util.Log
import android.widget.Toast
import androidx.databinding.BaseObservable
import androidx.databinding.Bindable
import com.wireguard.android.Application.Companion.get
import com.wireguard.android.Application.Companion.getBackend
import com.wireguard.android.Application.Companion.getTunnelManager
import com.wireguard.android.Application.Companion.getTurnProxyManager
import com.wireguard.android.BR
import com.wireguard.android.R
import com.wireguard.android.backend.GoBackend
import com.wireguard.android.backend.Statistics
import com.wireguard.android.backend.Tunnel
import com.wireguard.android.configStore.ConfigStore
import com.wireguard.android.databinding.ObservableSortedKeyedArrayList
import com.wireguard.android.turn.TurnConfigProcessor
import com.wireguard.android.turn.TurnProxyManager
import com.wireguard.android.turn.TurnSettings
import com.wireguard.android.turn.TurnSettingsStore
import com.wireguard.android.util.ErrorMessages
import com.wireguard.android.util.UserKnobs
import com.wireguard.android.util.applicationScope
import com.wireguard.config.Config
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

/**
 * Maintains and mediates changes to the set of available WireGuard tunnels,
 */
private const val TAG = "WireGuard/TunnelManager"

class TunnelManager(
    private val configStore: ConfigStore,
    private val turnSettingsStore: TurnSettingsStore,
) : BaseObservable() {
    private val tunnels = CompletableDeferred<ObservableSortedKeyedArrayList<String, ObservableTunnel>>()
    private val context: Context = get()
    private val tunnelMap: ObservableSortedKeyedArrayList<String, ObservableTunnel> = ObservableSortedKeyedArrayList(TunnelComparator)
    private var haveLoaded = false

    private fun addToList(name: String, config: Config?, state: Tunnel.State): ObservableTunnel {
        val tunnel = ObservableTunnel(this, name, config, state)
        var turnSettings = turnSettingsStore.load(name)
        if (turnSettings == null && config != null) {
            turnSettings = TurnConfigProcessor.extractTurnSettings(config)
            if (turnSettings != null) {
                turnSettingsStore.save(name, turnSettings)
            }
        }
        tunnel.onTurnSettingsChanged(turnSettings)
        tunnelMap.add(tunnel)
        return tunnel
    }

    suspend fun getTunnels(): ObservableSortedKeyedArrayList<String, ObservableTunnel> = tunnels.await()

    suspend fun create(
        name: String,
        config: Config?,
        turnSettings: TurnSettings? = null,
    ): ObservableTunnel = withContext(Dispatchers.Main.immediate) {
        if (Tunnel.isNameInvalid(name))
            throw IllegalArgumentException(context.getString(R.string.tunnel_error_invalid_name))
        if (tunnelMap.containsKey(name))
            throw IllegalArgumentException(context.getString(R.string.tunnel_error_already_exists, name))
        
        val configWithTurn = TurnConfigProcessor.injectTurnSettings(config!!, turnSettings)
        val savedConfig = withContext(Dispatchers.IO) { configStore.create(name, configWithTurn) }
        withContext(Dispatchers.IO) { turnSettingsStore.save(name, turnSettings) }
        addToList(name, savedConfig, Tunnel.State.DOWN)
    }

    suspend fun delete(tunnel: ObservableTunnel) = withContext(Dispatchers.Main.immediate) {
        val originalState = tunnel.state
        val wasLastUsed = tunnel == lastUsedTunnel
        // Make sure nothing touches the tunnel.
        if (wasLastUsed)
            lastUsedTunnel = null
        tunnelMap.remove(tunnel)
        try {
            if (originalState == Tunnel.State.UP)
                withContext(Dispatchers.IO) { getBackend().setState(tunnel, Tunnel.State.DOWN, null) }
            try {
                withContext(Dispatchers.IO) {
                    configStore.delete(tunnel.name)
                    turnSettingsStore.delete(tunnel.name)
                }
            } catch (e: Throwable) {
                if (originalState == Tunnel.State.UP)
                    withContext(Dispatchers.IO) { getBackend().setState(tunnel, Tunnel.State.UP, tunnel.config) }
                throw e
            }
        } catch (e: Throwable) {
            // Failure, put the tunnel back.
            tunnelMap.add(tunnel)
            if (wasLastUsed)
                lastUsedTunnel = tunnel
            throw e
        }
    }

    @get:Bindable
    var lastUsedTunnel: ObservableTunnel? = null
        private set(value) {
            if (value == field) return
            field = value
            notifyPropertyChanged(BR.lastUsedTunnel)
            applicationScope.launch { UserKnobs.setLastUsedTunnel(value?.name) }
        }

    suspend fun getTunnelConfig(tunnel: ObservableTunnel): Config = withContext(Dispatchers.Main.immediate) {
        val config = withContext(Dispatchers.IO) { configStore.load(tunnel.name) }
        val extractedTurn = TurnConfigProcessor.extractTurnSettings(config)
        if (extractedTurn != null) {
            withContext(Dispatchers.IO) {
                turnSettingsStore.save(tunnel.name, extractedTurn)
            }
            tunnel.onTurnSettingsChanged(extractedTurn)
        }
        tunnel.onConfigChanged(config)!!
    }

    fun onCreate() {
        applicationScope.launch {
            try {
                Log.d(TAG, "onCreate: enumerating tunnels...")
                val present = withContext(Dispatchers.IO) { configStore.enumerate() }
                Log.d(TAG, "onCreate: enumerate returned ${present.size} tunnels: $present")
                val running = withContext(Dispatchers.IO) { getBackend().runningTunnelNames }
                Log.d(TAG, "onCreate: running tunnel names: $running")
                onTunnelsLoaded(present, running)
            } catch (e: Throwable) {
                Log.e(TAG, Log.getStackTraceString(e))
            }
        }
    }

    private fun onTunnelsLoaded(present: Iterable<String>, running: Collection<String>) {
        Log.d(TAG, "onTunnelsLoaded: present=${present.toList()}, running=${running.toList()}")
        for (name in present) {
            Log.d(TAG, "onTunnelsLoaded: adding to list: $name")
            addToList(name, null, if (running.contains(name)) Tunnel.State.UP else Tunnel.State.DOWN)
        }
        Log.d(TAG, "onTunnelsLoaded: tunnelMap.size=" + tunnelMap.size)
        applicationScope.launch {
            val lastUsedName = UserKnobs.lastUsedTunnel.first()
            if (lastUsedName != null)
                lastUsedTunnel = tunnelMap[lastUsedName]
            haveLoaded = true
            // Complete tunnels deferred FIRST so UI shows the list immediately,
            // even if restoreState (which may trigger captcha + VK auth) takes time.
            // Previously restoreState was called before complete(), causing UI to
            // show empty list during the 15-30s captcha resolution window, which
            // made users think the tunnel was missing and try to re-add it.
            Log.d(TAG, "onTunnelsLoaded: completing tunnels deferred (before restoreState)")
            tunnels.complete(tunnelMap)
            Log.d(TAG, "onTunnelsLoaded: tunnels.complete() done, calling restoreState(true)")
            restoreState(true)
            Log.d(TAG, "onTunnelsLoaded: restoreState done")
        }
    }

    private fun refreshTunnelStates() {
        applicationScope.launch {
            try {
                val running = withContext(Dispatchers.IO) { getBackend().runningTunnelNames }
                for (tunnel in tunnelMap)
                    tunnel.onStateChanged(if (running.contains(tunnel.name)) Tunnel.State.UP else Tunnel.State.DOWN)
            } catch (e: Throwable) {
                Log.e(TAG, Log.getStackTraceString(e))
            }
        }
    }

    suspend fun restoreState(force: Boolean) {
        Log.d(TAG, "restoreState(force=$force): haveLoaded=$haveLoaded")
        if (!haveLoaded || (!force && !UserKnobs.restoreOnBoot.first())) {
            Log.d(TAG, "restoreState: early return (haveLoaded=$haveLoaded)")
            return
        }
        val previouslyRunning = UserKnobs.runningTunnels.first()
        Log.d(TAG, "restoreState: previouslyRunning=$previouslyRunning, tunnelMap.size=${tunnelMap.size}")
        if (previouslyRunning.isEmpty()) {
            Log.d(TAG, "restoreState: no previously running tunnels, returning")
            return
        }
        val toRestore = tunnelMap.filter { previouslyRunning.contains(it.name) }
        Log.d(TAG, "restoreState: toRestore=${toRestore.map { it.name }}")
        withContext(Dispatchers.IO) {
            try {
                toRestore.map { async(Dispatchers.IO + SupervisorJob()) { setTunnelState(it, Tunnel.State.UP) } }
                    .awaitAll()
                Log.d(TAG, "restoreState: all tunnels restored")
            } catch (e: Throwable) {
                Log.e(TAG, Log.getStackTraceString(e))
            }
        }
    }

    suspend fun saveState() {
        UserKnobs.setRunningTunnels(tunnelMap.filter { it.state == Tunnel.State.UP }.map { it.name }.toSet())
    }

    suspend fun setTunnelConfig(
        tunnel: ObservableTunnel,
        config: Config,
        turnSettings: TurnSettings? = null,
    ): Config = withContext(Dispatchers.Main.immediate) {
        val originalState = tunnel.state
        if (originalState == Tunnel.State.UP) {
            setTunnelState(tunnel, Tunnel.State.DOWN)
        }
        
        val configWithTurn = TurnConfigProcessor.injectTurnSettings(config, turnSettings)
        val result = tunnel.onConfigChanged(
            withContext(Dispatchers.IO) {
                configStore.save(tunnel.name, configWithTurn)
                configWithTurn
            },
        )!!
            .also {
                withContext(Dispatchers.IO) {
                    turnSettingsStore.save(tunnel.name, turnSettings)
                    tunnel.onTurnSettingsChanged(turnSettingsStore.load(tunnel.name))
                }
            }
        
        if (originalState == Tunnel.State.UP) {
            setTunnelState(tunnel, Tunnel.State.UP)
        }
        
        result
    }

    suspend fun setTunnelName(tunnel: ObservableTunnel, name: String): String = withContext(Dispatchers.Main.immediate) {
        if (Tunnel.isNameInvalid(name))
            throw IllegalArgumentException(context.getString(R.string.tunnel_error_invalid_name))
        if (tunnelMap.containsKey(name)) {
            throw IllegalArgumentException(context.getString(R.string.tunnel_error_already_exists, name))
        }
        val originalState = tunnel.state
        val wasLastUsed = tunnel == lastUsedTunnel
        // Make sure nothing touches the tunnel.
        if (wasLastUsed)
            lastUsedTunnel = null
        tunnelMap.remove(tunnel)
        var throwable: Throwable? = null
        var newName: String? = null
        try {
            if (originalState == Tunnel.State.UP)
                withContext(Dispatchers.IO) { getBackend().setState(tunnel, Tunnel.State.DOWN, null) }
            withContext(Dispatchers.IO) {
                configStore.rename(tunnel.name, name)
                turnSettingsStore.rename(tunnel.name, name)
            }
            newName = tunnel.onNameChanged(name)
            if (originalState == Tunnel.State.UP)
                withContext(Dispatchers.IO) { getBackend().setState(tunnel, Tunnel.State.UP, tunnel.config) }
        } catch (e: Throwable) {
            throwable = e
            // On failure, we don't know what state the tunnel might be in. Fix that.
            getTunnelState(tunnel)
        }
        // Add the tunnel back to the manager, under whatever name it thinks it has.
        tunnelMap.add(tunnel)
        if (wasLastUsed)
            lastUsedTunnel = tunnel
        if (throwable != null)
            throw throwable
        newName!!
    }

    suspend fun setTunnelState(tunnel: ObservableTunnel, state: Tunnel.State): Tunnel.State = withContext(Dispatchers.Main.immediate) {
        if (state == tunnel.state) return@withContext state
        
        // If we are already UP and someone (like AlwaysOnCallback) requests UP again,
        // double check with backend if it is really running.
        if (state == Tunnel.State.UP && tunnel.state == Tunnel.State.UP) {
            val runningNames = withContext(Dispatchers.IO) { getBackend().runningTunnelNames }
            if (runningNames.contains(tunnel.name)) {
                Log.d(TAG, "Skip redundant UP call for ${tunnel.name}, already running")
                return@withContext state
            }
        }

        var newState = tunnel.state
        var throwable: Throwable? = null
        val originalState = tunnel.state
        // Optimistically mark tunnel as UP *before* the long TURN startup (captcha + VK auth).
        // This makes the toggle switch reflect the "starting" state immediately, instead of
        // showing OFF for 15-30 seconds while restoreState() is in progress.
        // If startup fails, we roll back to originalState below.
        if (state == Tunnel.State.UP || (state == Tunnel.State.TOGGLE && tunnel.state == Tunnel.State.DOWN)) {
            tunnel.onStateChanged(Tunnel.State.UP)
        }
        try {
            val backend = getBackend()
            var configToUse = tunnel.getConfigAsync()
            val turn = tunnel.turnSettings
            val turnEnabled = turn != null && turn.enabled
            
            // Determine if TURN should be started before WireGuard activation.
            // This happens when explicitly requesting UP, or TOGGLE from DOWN state.
            // NOTE: use originalState here (not tunnel.state) because we may have
            // optimistically set tunnel.state to UP above, which would break TOGGLE logic.
            val shouldStartTurn = state == Tunnel.State.UP || (state == Tunnel.State.TOGGLE && originalState == Tunnel.State.DOWN)
            
            // Stop TURN when tunnel goes DOWN
            val shouldStopTurn = state == Tunnel.State.DOWN || (state == Tunnel.State.TOGGLE && originalState == Tunnel.State.UP)

            suspend fun cleanupFailedTurnStartup(goBackend: GoBackend) {
                withContext(Dispatchers.IO) {
                    getTurnProxyManager().stopForTunnel(tunnel.name)
                    goBackend.stopVpnServiceIfIdle()
                }
            }

            if (turnEnabled) {
                if (shouldStartTurn) {
                    tunnelMap
                        .filter { it !== tunnel && it.state == Tunnel.State.UP }
                        .forEach { activeTunnel -> setTunnelState(activeTunnel, Tunnel.State.DOWN) }
                    configToUse = TurnConfigProcessor.modifyConfigForActiveTurn(configToUse, turn)
                } else if (shouldStopTurn) {
                    withContext(Dispatchers.IO) {
                        getTurnProxyManager().stopForTunnel(tunnel.name)
                    }
                }
            }

            if (shouldStartTurn && turnEnabled) {
                val goBackend = backend as? GoBackend
                    ?: throw IllegalStateException("TURN startup requires the Go backend")

                withContext(Dispatchers.IO) { goBackend.ensureVpnServiceReady() }

                when (val turnResult = withContext(Dispatchers.IO) {
                    getTurnProxyManager().onTunnelEstablished(tunnel.name, turn)
                }) {
                    TurnProxyManager.TurnStartResult.Success -> {
                        try {
                            newState = withContext(Dispatchers.IO) {
                                backend.setState(tunnel, state, configToUse)
                            }
                        } catch (e: Throwable) {
                            cleanupFailedTurnStartup(goBackend)
                            throw e
                        }
                    }
                    is TurnProxyManager.TurnStartResult.Failure -> {
                        cleanupFailedTurnStartup(goBackend)
                        throw IllegalStateException(turnResult.message)
                    }
                }
            } else {
                newState = withContext(Dispatchers.IO) { backend.setState(tunnel, state, configToUse) }
            }

            if (newState == Tunnel.State.UP) {
                lastUsedTunnel = tunnel
            }
        } catch (e: Throwable) {
            throwable = e
            // Roll back optimistic state on failure so toggle switch returns to its
            // original position. Only do this if we actually changed state above
            // (i.e. originalState was DOWN/TOGGLE and we optimistically set UP).
            if (originalState != Tunnel.State.UP) {
                tunnel.onStateChanged(originalState)
            }
        }
        if (throwable == null) {
            tunnel.onStateChanged(newState)
        }
        saveState()
        if (throwable != null)
            throw throwable
        newState
    }

    class IntentReceiver : BroadcastReceiver() {
        override fun onReceive(context: Context, intent: Intent?) {
            applicationScope.launch {
                val manager = getTunnelManager()
                if (intent == null) return@launch
                val action = intent.action ?: return@launch
                if ("com.wireguard.android.action.REFRESH_TUNNEL_STATES" == action) {
                    manager.refreshTunnelStates()
                    return@launch
                }
                if (!UserKnobs.allowRemoteControlIntents.first())
                    return@launch
                val state = when (action) {
                    "com.wireguard.android.action.SET_TUNNEL_UP" -> Tunnel.State.UP
                    "com.wireguard.android.action.SET_TUNNEL_DOWN" -> Tunnel.State.DOWN
                    else -> return@launch
                }
                val tunnelName = intent.getStringExtra("tunnel") ?: return@launch
                val tunnels = manager.getTunnels()
                val tunnel = tunnels[tunnelName] ?: return@launch
                try {
                    manager.setTunnelState(tunnel, state)
                } catch (e: Throwable) {
                    Toast.makeText(context, ErrorMessages[e], Toast.LENGTH_LONG).show()
                }
            }
        }
    }

    suspend fun getTunnelState(tunnel: ObservableTunnel): Tunnel.State = withContext(Dispatchers.Main.immediate) {
        tunnel.onStateChanged(withContext(Dispatchers.IO) { getBackend().getState(tunnel) })
    }

    suspend fun getTunnelStatistics(tunnel: ObservableTunnel): Statistics = withContext(Dispatchers.Main.immediate) {
        tunnel.onStatisticsChanged(withContext(Dispatchers.IO) { getBackend().getStatistics(tunnel) })!!
    }

    companion object {
        private const val TAG = "WireGuard/TunnelManager"
    }
}
