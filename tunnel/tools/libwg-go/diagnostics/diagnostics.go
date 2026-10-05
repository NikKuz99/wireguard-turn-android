// Package diagnostics: machine-readable diagnostics pipeline (Task 25).
// ASCII-only by design: human-readable RU texts live in the Kotlin layer.
// Invariants: I1 ctx-bounded stages, I2 skip-chain after blocking FAIL,
// I3 panic-safe teardown, I4 secret redaction, I5 captcha never solved here.
package diagnostics

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

type StageID string

const (
	StageDeviceNet StageID = "device_net"
	StageDNS       StageID = "dns"
	StageVKAuth    StageID = "vk_auth"
	StageTURNAlloc StageID = "turn_alloc"
	StageDTLS      StageID = "dtls"
	StageWG        StageID = "wg_handshake"
	StageTun       StageID = "tun_state"
	StageE2E       StageID = "e2e_http"
	StageLatency   StageID = "latency"
	StageReHS      StageID = "rehandshake"
)

const (
	ModePassive = "passive" // tunnel is up: read state + light probes only
	ModeFull    = "full"    // tunnel is down: ephemeral session + teardown
)

type Status string

const (
	StatusPass Status = "PASS"
	StatusWarn Status = "WARN"
	StatusFail Status = "FAIL"
	StatusSkip Status = "SKIP"
)

type ErrorClass string

const (
	ErrNone      ErrorClass = ""
	ErrNetwork   ErrorClass = "NETWORK"
	ErrDNS       ErrorClass = "DNS"
	ErrAuth      ErrorClass = "AUTH"
	ErrTURNAlloc ErrorClass = "TURN_ALLOC"
	ErrProtect   ErrorClass = "PROTECT" // BUG-016 marker
	ErrDTLS      ErrorClass = "DTLS"
	ErrWG        ErrorClass = "WG_HANDSHAKE"
	ErrTun       ErrorClass = "TUN"
	ErrE2E       ErrorClass = "E2E"
	ErrTimeout   ErrorClass = "TIMEOUT"
	ErrInternal  ErrorClass = "INTERNAL"
)

// BlockingStage: FAIL here makes downstream stages meaningless (I2).
func BlockingStage(id StageID) bool {
	switch id {
	case StageDNS, StageVKAuth, StageTURNAlloc, StageDTLS, StageWG, StageTun:
		return true
	}
	return false
}

type ProbeResult struct {
	Status   Status
	ErrClass ErrorClass
	ErrRaw   string // technical text, ASCII-safe, redacted on output
	Details  map[string]any
}

type Probe interface {
	ID() StageID
	Timeout() time.Duration
	Run(ctx context.Context) ProbeResult
}

type StageReport struct {
	ID         StageID        `json:"id"`
	Status     Status         `json:"status"`
	DurationMS int64          `json:"duration_ms"`
	ErrorClass ErrorClass     `json:"error_class,omitempty"`
	ErrorRaw   string         `json:"error_raw,omitempty"`
	Details    map[string]any `json:"details,omitempty"`
}

type Report struct {
	SchemaVersion int           `json:"schema_version"`
	GeneratedAt   time.Time     `json:"generated_at"`
	Mode          string        `json:"mode"`
	Stages        []StageReport `json:"stages"`
	Pass          int           `json:"pass"`
	Warn          int           `json:"warn"`
	Fail          int           `json:"fail"`
	Skip          int           `json:"skip"`
	Overall       Status        `json:"overall"`
}

func Run(ctx context.Context, mode string, probes []Probe, redact []string, teardown func(context.Context)) *Report {
	rep := &Report{SchemaVersion: 1, GeneratedAt: time.Now().UTC(), Mode: mode, Overall: StatusPass}
	if teardown != nil { // I3
		defer func() {
			tctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			teardown(tctx)
		}()
	}
	broken := false
	for _, p := range probes {
		sr := StageReport{ID: p.ID()}
		if broken { // I2
			sr.Status = StatusSkip
			rep.Stages = append(rep.Stages, sr)
			rep.Skip++
			continue
		}
		start := time.Now()
		pctx, cancel := context.WithTimeout(ctx, p.Timeout()) // I1
		func() {
			defer func() { // panic containment
				if r := recover(); r != nil {
					sr.Status, sr.ErrorClass = StatusFail, ErrInternal
					sr.ErrorRaw = fmt.Sprintf("panic: %v", r)
				}
			}()
			res := p.Run(pctx)
			sr.Status, sr.ErrorClass, sr.ErrorRaw, sr.Details = res.Status, res.ErrClass, res.ErrRaw, res.Details
			if sr.Status == StatusFail && sr.ErrorClass == ErrNone && errors.Is(pctx.Err(), context.DeadlineExceeded) {
				sr.ErrorClass = ErrTimeout
			}
		}()
		cancel()
		sr.DurationMS = time.Since(start).Milliseconds()
		redactStage(&sr, redact) // I4
		rep.Stages = append(rep.Stages, sr)
		switch sr.Status {
		case StatusPass:
			rep.Pass++
		case StatusWarn:
			rep.Warn++
		case StatusFail:
			rep.Fail++
		case StatusSkip:
			rep.Skip++
		}
		if sr.Status == StatusFail && BlockingStage(p.ID()) {
			broken = true
		}
	}
	switch {
	case rep.Fail > 0:
		rep.Overall = StatusFail
	case rep.Warn > 0:
		rep.Overall = StatusWarn
	default:
		rep.Overall = StatusPass
	}
	return rep
}

func redactStage(sr *StageReport, redact []string) {
	if len(redact) == 0 {
		return
	}
	sr.ErrorRaw = redactString(sr.ErrorRaw, redact)
	for k, v := range sr.Details {
		if s, ok := v.(string); ok {
			sr.Details[k] = redactString(s, redact)
		}
	}
}

func redactString(s string, redact []string) string {
	for _, r := range redact {
		if r == "" {
			continue
		}
		s = strings.ReplaceAll(s, r, "[REDACTED]")
	}
	return s
}

func (rep *Report) JSON() ([]byte, error) { return json.MarshalIndent(rep, "", "  ") }