package diagnostics

// facade.go: probe assembly per mode and the single bind entry point.
// All human-readable RU texts live in the Kotlin layer; ASCII codes here.

import (
	"context"
	"encoding/json"
	"net/http"
	"time"
)

// StateSource supplies app state and transport internals for stages 3-6, 10.
// VKAuth MUST NOT solve the captcha (I5): it reads the existing session only.
// TURNAllocState in passive mode reports the live allocation and MUST fill
// details: socket_protected (bool), eperm_retries (int), budget_ms (int) -
// the BUG-016 regression marker. In full mode it begins the ephemeral
// session and attempts a fresh allocation (unless the chain broke upstream).
type StateSource interface {
	VKAuth(ctx context.Context) ProbeResult
	TURNAllocState(ctx context.Context) ProbeResult
	DTLSState(ctx context.Context) ProbeResult
	WGState(ctx context.Context) ProbeResult
	TunState(ctx context.Context) ProbeResult
	Rehandshake(ctx context.Context) ProbeResult
}

// TunnelState is an optional StateSource extension for mode auto-selection.
type TunnelState interface {
	TunnelUp() bool
}

// EphemeralSource is an optional StateSource extension for full mode.
// The ephemeral session begins lazily inside TURNAllocState; TeardownEphemeral
// must be safe to call even if no session was ever started (I3).
type EphemeralSource interface {
	StateSource
	TeardownEphemeral(ctx context.Context)
}

type Options struct {
	E2EURL        string
	DNSHosts      []string
	LatencyN      int
	RouteProbeAddr string
	Resolve       ResolveFunc  // nil: system resolver (П3 wires the app resolver)
	HTTPClient    *http.Client // nil: default client (unprotected = through VPN)
	Redactions    []string
}

func DefaultOptions() Options {
	return Options{
		E2EURL:         "https://ya.ru",
		DNSHosts:       []string{"vk.com"},
		LatencyN:       5,
		RouteProbeAddr: "8.8.8.8:53",
	}
}

// ---- adapters ----

type srcProbe struct {
	src StateSource
	id  StageID
}

func (p srcProbe) ID() StageID { return p.id }

func (p srcProbe) Timeout() time.Duration {
	switch p.id {
	case StageVKAuth:
		return 10 * time.Second
	case StageTURNAlloc:
		return 25 * time.Second
	case StageDTLS, StageWG, StageReHS:
		return 15 * time.Second
	}
	return 10 * time.Second
}

func (p srcProbe) Run(ctx context.Context) ProbeResult {
	switch p.id {
	case StageVKAuth:
		return p.src.VKAuth(ctx)
	case StageTURNAlloc:
		return p.src.TURNAllocState(ctx)
	case StageDTLS:
		return p.src.DTLSState(ctx)
	case StageWG:
		return p.src.WGState(ctx)
	case StageTun:
		return p.src.TunState(ctx)
	case StageReHS:
		return p.src.Rehandshake(ctx)
	}
	return ProbeResult{Status: StatusFail, ErrClass: ErrInternal, ErrRaw: "unknown stage " + string(p.id)}
}

// ---- assembly ----

func BuildPassiveProbes(src StateSource, o Options) []Probe {
	return []Probe{
		&deviceNetProbe{routeAddr: o.RouteProbeAddr},
		&dnsProbe{hosts: o.DNSHosts, resolve: o.Resolve},
		srcProbe{src: src, id: StageVKAuth},
		srcProbe{src: src, id: StageTURNAlloc},
		srcProbe{src: src, id: StageDTLS},
		srcProbe{src: src, id: StageWG},
		srcProbe{src: src, id: StageTun},
		&e2eProbe{url: o.E2EURL, client: o.HTTPClient},
		&latencyProbe{url: o.E2EURL, n: o.LatencyN, client: o.HTTPClient},
		NewSkipProbe(StageReHS, ReasonInvasiveReHS),
	}
}

func BuildFullProbes(src StateSource, o Options) []Probe {
	return []Probe{
		&deviceNetProbe{routeAddr: o.RouteProbeAddr},
		&dnsProbe{hosts: o.DNSHosts, resolve: o.Resolve},
		srcProbe{src: src, id: StageVKAuth},
		srcProbe{src: src, id: StageTURNAlloc},
		srcProbe{src: src, id: StageDTLS},
		srcProbe{src: src, id: StageWG},
		NewSkipProbe(StageTun, ReasonNoVpnInDiagnostics),
		NewSkipProbe(StageE2E, ReasonNeedsLiveTunnel),
		NewSkipProbe(StageLatency, ReasonNeedsLiveTunnel),
		srcProbe{src: src, id: StageReHS},
	}
}

// ---- single bind entry point ----

type runRequest struct {
	Mode          string   `json:"mode"`                     // auto (default) | passive | full
	E2EURL        string   `json:"e2e_url,omitempty"`        // advanced/tests
	DNSHosts      []string `json:"dns_hosts,omitempty"`      // advanced/tests
	LatencyN      int      `json:"latency_n,omitempty"`      // advanced/tests
	RouteProbe    string   `json:"route_probe,omitempty"`    // advanced/tests
	Redactions    []string `json:"redactions,omitempty"`
}

var activeState StateSource

// SetStateSource wires the production StateSource; called once at bind setup.
func SetStateSource(s StateSource) { activeState = s }

// RunDiagnostics is the single entry point for the Kotlin layer.
// Returns the Report JSON or {"error":"..."}. Never panics; global budget 150s.
// MUST be called off the Android main thread (it blocks for the whole run).
func RunDiagnostics(reqJSON string) (out string) {
	defer func() {
		if r := recover(); r != nil {
			out = `{"error":"internal panic"}`
		}
	}()
	req := runRequest{Mode: "auto"}
	if reqJSON != "" {
		if err := json.Unmarshal([]byte(reqJSON), &req); err != nil {
			return `{"error":"bad request json"}`
		}
	}
	if req.Mode == "" {
		req.Mode = "auto"
	}
	if activeState == nil {
		return `{"error":"state source not wired"}`
	}
	o := DefaultOptions()
	if req.E2EURL != "" {
		o.E2EURL = req.E2EURL
	}
	if len(req.DNSHosts) > 0 {
		o.DNSHosts = req.DNSHosts
	}
	if req.LatencyN > 0 {
		o.LatencyN = req.LatencyN
	}
	if req.RouteProbe != "" {
		o.RouteProbeAddr = req.RouteProbe
	}
	o.Redactions = req.Redactions

	mode := req.Mode
	if mode == "auto" {
		if ts, ok := activeState.(TunnelState); ok && ts.TunnelUp() {
			mode = ModePassive
		} else {
			mode = ModeFull
		}
	}
	if mode != ModePassive && mode != ModeFull {
		return `{"error":"unknown mode"}`
	}

	var probes []Probe
	var teardown func(context.Context)
	if mode == ModePassive {
		probes = BuildPassiveProbes(activeState, o)
	} else {
		probes = BuildFullProbes(activeState, o)
		if es, ok := activeState.(EphemeralSource); ok {
			teardown = es.TeardownEphemeral
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Second)
	defer cancel()
	rep := Run(ctx, mode, probes, o.Redactions, teardown)
	b, err := rep.JSON()
	if err != nil {
		return `{"error":"marshal failed"}`
	}
	return string(b)
}