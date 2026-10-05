package main

// diagnostics_bridge.go - production StateSource for the diagnostics engine
// (Task 25, v1.8.0).
//
// Blind-safe scope: read-only over symbols confirmed in the code review:
//   - session state: currentTurnCancel / turnMutex (turn-client.go)
//   - BUG-016 signal: diagEpermCount / diagProtectFailCount (isEPERM /
//     isProtectFailure, this commit)
//   - tun state: diagnostics.ProbeTunInterfaces + session cross-check
// v1.9 (after review of the turn-client session/stream registry):
//   - per-stream liveness (ready / lastRx age), socket_protected, budget_ms
//   - ephemeral TURN/DTLS probe in full mode
//   - WG peer stats via device UAPI (IpcGet)
//
// ASCII-only by design; RU texts live in the Kotlin layer.

import (
	"context"

	"golang.zx2c4.com/wireguard/android/diagnostics"
)

type appStateSource struct{}

func init() {
	diagnostics.SetStateSource(appStateSource{})
	// v1.8.0: the bridge emits no secrets into reports (details contain only
	// counters/booleans/notes authored here). Pattern-based redaction of
	// arbitrary error strings is a v1.9 candidate together with deep probes.
	diagnostics.SetProductionRedactions(nil)
}

func (appStateSource) TunnelUp() bool { return turnSessionActive() }

func turnSessionActive() bool {
	turnMutex.Lock()
	defer turnMutex.Unlock()
	return currentTurnCancel != nil
}

func (s appStateSource) VKAuth(ctx context.Context) diagnostics.ProbeResult {
	if turnSessionActive() {
		return diagnostics.ProbeResult{
			Status:  diagnostics.StatusPass,
			Details: map[string]any{"source": "active turn session implies valid vk credentials"},
		}
	}
	return diagnostics.ProbeResult{
		Status:   diagnostics.StatusWarn,
		ErrClass: diagnostics.ErrAuth,
		ErrRaw:   "no active turn session: vk credential probe requires v1.9 deep instrumentation",
		Details:  map[string]any{"note": "connect the tunnel, then rerun diagnostics in passive mode"},
	}
}

func (s appStateSource) TURNAllocState(ctx context.Context) diagnostics.ProbeResult {
	active := turnSessionActive()
	details := map[string]any{
		"session_active":         active,
		"eperm_classified_total": diagEpermCount.Load(),
		"protect_fail_total":     diagProtectFailCount.Load(),
		"socket_protected":       "unknown_v1_9",
	}
	if active {
		if diagEpermCount.Load() > 0 || diagProtectFailCount.Load() > 0 {
			return diagnostics.ProbeResult{
				Status:   diagnostics.StatusWarn,
				ErrClass: diagnostics.ErrProtect,
				ErrRaw:   "EPERM/protect failures observed since process start",
				Details:  details,
			}
		}
		return diagnostics.ProbeResult{Status: diagnostics.StatusPass, Details: details}
	}
	// No session. In passive mode this is the black-hole signature:
	// diagnostics ran because the tunnel looked alive.
	tun := diagnostics.ProbeTunInterfaces(ctx)
	details["tun_up_while_session_dead"] = tun.Status == diagnostics.StatusPass
	return diagnostics.ProbeResult{
		Status:   diagnostics.StatusFail,
		ErrClass: diagnostics.ErrTURNAlloc,
		ErrRaw:   "turn session is not running",
		Details:  details,
	}
}

func (s appStateSource) DTLSState(ctx context.Context) diagnostics.ProbeResult {
	if turnSessionActive() {
		return diagnostics.ProbeResult{
			Status: diagnostics.StatusPass,
			Details: map[string]any{
				"note": "per-stream dtls liveness (ready/lastRx) arrives in v1.9; " +
					"data-plane proof comes from e2e_http/latency stages",
			},
		}
	}
	return diagnostics.ProbeResult{
		Status:   diagnostics.StatusFail,
		ErrClass: diagnostics.ErrDTLS,
		ErrRaw:   "no active turn session",
	}
}

func (s appStateSource) WGState(ctx context.Context) diagnostics.ProbeResult {
	if turnSessionActive() {
		return diagnostics.ProbeResult{
			Status: diagnostics.StatusPass,
			Details: map[string]any{
				"note": "wg peer stats are not exposed by libwg-go in v1.8.0; " +
					"device UAPI is a v1.9 candidate; data-plane proof: e2e_http/latency",
			},
		}
	}
	return diagnostics.ProbeResult{
		Status:   diagnostics.StatusFail,
		ErrClass: diagnostics.ErrWG,
		ErrRaw:   "no active turn session",
	}
}

func (s appStateSource) TunState(ctx context.Context) diagnostics.ProbeResult {
	res := diagnostics.ProbeTunInterfaces(ctx)
	if res.Status == diagnostics.StatusPass && !turnSessionActive() {
		return diagnostics.ProbeResult{
			Status:   diagnostics.StatusFail,
			ErrClass: diagnostics.ErrTun,
			ErrRaw:   "tun interface is up but turn session is dead (black-hole signature)",
			Details:  res.Details,
		}
	}
	return res
}

func (s appStateSource) Rehandshake(ctx context.Context) diagnostics.ProbeResult {
	return diagnostics.ProbeResult{
		Status:  diagnostics.StatusSkip,
		Details: map[string]any{"reason": "requires_ephemeral_session_v1_9"},
	}
}

func (s appStateSource) TeardownEphemeral(ctx context.Context) {
	// v1.8.0: no ephemeral session is created; nothing to tear down.
	// Contract (safe to call when nothing was started) still holds.
}
