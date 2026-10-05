package diagnostics

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
)

type fakeState struct {
	vk, turn, dtls, wg, tun, rehs ProbeResult
}

func (f *fakeState) VKAuth(ctx context.Context) ProbeResult         { return f.vk }
func (f *fakeState) TURNAllocState(ctx context.Context) ProbeResult { return f.turn }
func (f *fakeState) DTLSState(ctx context.Context) ProbeResult      { return f.dtls }
func (f *fakeState) WGState(ctx context.Context) ProbeResult        { return f.wg }
func (f *fakeState) Rehandshake(ctx context.Context) ProbeResult    { return f.rehs }
func (f *fakeState) TunState(ctx context.Context) ProbeResult        { return f.tun }

type fakeUpState struct{ fakeState }

func (f *fakeUpState) TunnelUp() bool { return true }

type fakeEphemeral struct {
	fakeState
	torndown bool
}

func (f *fakeEphemeral) TeardownEphemeral(ctx context.Context) { f.torndown = true }

func okRes() ProbeResult { return ProbeResult{Status: StatusPass} }

func localUDPAddr(t *testing.T) string {
	t.Helper()
	c, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Skipf("no local udp: %v", err)
	}
	defer c.Close()
	return c.LocalAddr().String()
}

func parseStage(t *testing.T, raw, id string) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal([]byte(raw), &m); err != nil {
		t.Fatalf("bad json: %s", raw)
	}
	stages, _ := m["stages"].([]any)
	for _, s := range stages {
		sm, _ := s.(map[string]any)
		if sm["id"] == id {
			return sm
		}
	}
	t.Fatalf("stage %s not found", id)
	return nil
}

func TestPassiveProbesOrderAndTail(t *testing.T) {
	probes := BuildPassiveProbes(&fakeState{}, DefaultOptions())
	if len(probes) != 10 {
		t.Fatalf("want 10 stages, got %d", len(probes))
	}
	want := []StageID{StageDeviceNet, StageDNS, StageVKAuth, StageTURNAlloc, StageDTLS, StageWG, StageTun, StageE2E, StageLatency, StageReHS}
	for i, p := range probes {
		if p.ID() != want[i] {
			t.Fatalf("stage %d: got %s want %s", i+1, p.ID(), want[i])
		}
	}
	if _, ok := probes[9].(*fixedProbe); !ok {
		t.Fatal("rehandshake must be a fixed skip probe in passive mode")
	}
}

func TestFullProbesSkipTail(t *testing.T) {
	probes := BuildFullProbes(&fakeState{}, DefaultOptions())
	for _, i := range []int{6, 7, 8} { // tun, e2e, latency
		if res := probes[i].Run(context.Background()); res.Status != StatusSkip {
			t.Fatalf("stage %d must be SKIP in full mode, got %s", i+1, res.Status)
		}
	}
}

func TestRunDiagnosticsPassiveHermetic(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusFound)
	}))
	defer srv.Close()
	src := &fakeUpState{}
	src.vk, src.turn, src.dtls, src.wg, src.tun, src.rehs = okRes(), okRes(), okRes(), okRes(), okRes(), okRes()
	old := activeState
	defer SetStateSource(old)
	SetStateSource(src)
	req := `{"mode":"auto","dns_hosts":["localhost"],"e2e_url":"` + srv.URL + `","latency_n":3,"route_probe":"` + localUDPAddr(t) + `"}`
	out := RunDiagnostics(req)
	var m map[string]any
	if err := json.Unmarshal([]byte(out), &m); err != nil {
		t.Fatalf("bad json: %s", out)
	}
	if m["mode"] != "passive" {
		t.Fatalf("auto must pick passive when tunnel is up: %s", out)
	}
	for _, id := range []string{"dns", "e2e_http", "latency"} {
		if s := parseStage(t, out, id); s["status"] != "PASS" {
			t.Fatalf("stage %s: %v", id, s)
		}
	}
}

func TestRunDiagnosticsFullHermetic(t *testing.T) {
	src := &fakeEphemeral{}
	src.vk, src.turn, src.dtls, src.wg, src.tun, src.rehs = okRes(), okRes(), okRes(), okRes(), okRes(), okRes()
	old := activeState
	defer SetStateSource(old)
	SetStateSource(src)
	req := `{"mode":"full","dns_hosts":["localhost"],"route_probe":"` + localUDPAddr(t) + `"}`
	out := RunDiagnostics(req)
	var m map[string]any
	if err := json.Unmarshal([]byte(out), &m); err != nil {
		t.Fatalf("bad json: %s", out)
	}
	if m["mode"] != "full" || m["overall"] != "PASS" {
		t.Fatalf("mode=%v overall=%v", m["mode"], m["overall"])
	}
	if !src.torndown {
		t.Fatal("teardown must run in full mode")
	}
	for _, c := range []struct{ id, reason string }{
		{"tun_state", ReasonNoVpnInDiagnostics},
		{"e2e_http", ReasonNeedsLiveTunnel},
		{"latency", ReasonNeedsLiveTunnel},
	} {
		s := parseStage(t, out, c.id)
		if s["status"] != "SKIP" {
			t.Fatalf("stage %s must be SKIP, got %v", c.id, s["status"])
		}
		d, _ := s["details"].(map[string]any)
		if d["reason"] != c.reason {
			t.Fatalf("stage %s reason: %v", c.id, d["reason"])
		}
	}
}

func TestFullModeChainBreakStillTeardown(t *testing.T) {
	src := &fakeEphemeral{}
	src.vk = ProbeResult{Status: StatusFail, ErrClass: ErrAuth}
	old := activeState
	defer SetStateSource(old)
	SetStateSource(src)
	req := `{"mode":"full","dns_hosts":["localhost"],"route_probe":"` + localUDPAddr(t) + `"}`
	out := RunDiagnostics(req)
	if !src.torndown {
		t.Fatal("teardown must run even when the chain breaks")
	}
	s := parseStage(t, out, "turn_alloc")
	if s["status"] != "SKIP" {
		t.Fatalf("turn_alloc must be SKIP after auth FAIL: %v", s)
	}
	d, _ := s["details"].(map[string]any)
	if d["reason"] != ReasonChainBroken {
		t.Fatalf("reason: %v", d["reason"])
	}
}

func TestRunDiagnosticsWiringErrors(t *testing.T) {
	old := activeState
	defer SetStateSource(old)
	SetStateSource(nil)
	if out := RunDiagnostics(`{"mode":"auto"}`); out != `{"error":"state source not wired"}` {
		t.Fatalf(out)
	}
	if out := RunDiagnostics(`{bad json`); out != `{"error":"bad request json"}` {
		t.Fatalf(out)
	}
}

func TestE2EProbeOutcomes(t *testing.T) {
	srv302 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(302) }))
	defer srv302.Close()
	srv500 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(500) }))
	defer srv500.Close()
	if r := (&e2eProbe{url: srv302.URL}).Run(context.Background()); r.Status != StatusPass {
		t.Fatalf("302: %+v", r)
	}
	if r := (&e2eProbe{url: srv500.URL}).Run(context.Background()); r.Status != StatusFail || r.ErrClass != ErrE2E {
		t.Fatalf("500: %+v", r)
	}
	if r := (&e2eProbe{url: "http://127.0.0.1:1"}).Run(context.Background()); r.Status != StatusFail {
		t.Fatalf("unreachable: %+v", r)
	}
}

func TestLatencyProbeOutcomes(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer srv.Close()
	if r := (&latencyProbe{url: srv.URL, n: 3}).Run(context.Background()); r.Status != StatusPass || len(r.Details["samples_ms"].([]int64)) != 3 {
		t.Fatalf("%+v", r)
	}
	if r := (&latencyProbe{url: "http://127.0.0.1:1", n: 3}).Run(context.Background()); r.Status != StatusFail {
		t.Fatalf("%+v", r)
	}
}

func TestDNSProbeInjected(t *testing.T) {
	ok := func(ctx context.Context, h string) ([]string, error) { return []string{"127.0.0.1"}, nil }
	bad := func(ctx context.Context, h string) ([]string, error) { return nil, errors.New("nx") }
	if r := (&dnsProbe{hosts: []string{"a"}, resolve: ok}).Run(context.Background()); r.Status != StatusPass {
		t.Fatalf("%+v", r)
	}
	if r := (&dnsProbe{hosts: []string{"a", "b"}, resolve: func(ctx context.Context, h string) ([]string, error) {
		if h == "a" {
			return []string{"127.0.0.1"}, nil
		}
		return nil, errors.New("nx")
	}}).Run(context.Background()); r.Status != StatusWarn {
		t.Fatalf("%+v", r)
	}
	if r := (&dnsProbe{hosts: []string{"a"}, resolve: bad}).Run(context.Background()); r.Status != StatusFail || r.ErrClass != ErrDNS {
		t.Fatalf("%+v", r)
	}
}


func TestTunFailBreaksChainInPassive(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(302) }))
	defer srv.Close()
	src := &fakeUpState{}
	src.vk, src.turn, src.dtls, src.wg, src.rehs = okRes(), okRes(), okRes(), okRes(), okRes()
	src.tun = ProbeResult{Status: StatusFail, ErrClass: ErrTun, ErrRaw: "no tun interface is up"}
	old := activeState
	defer SetStateSource(old)
	SetStateSource(src)
	req := `{"mode":"passive","dns_hosts":["localhost"],"e2e_url":"` + srv.URL + `","route_probe":"` + localUDPAddr(t) + `"}`
	out := RunDiagnostics(req)
	if s := parseStage(t, out, "tun_state"); s["status"] != "FAIL" {
		t.Fatalf("tun must FAIL: %v", s)
	}
	s := parseStage(t, out, "e2e_http")
	if s["status"] != "SKIP" {
		t.Fatalf("e2e must be SKIP after tun FAIL: %v", s)
	}
	d, _ := s["details"].(map[string]any)
	if d["reason"] != ReasonChainBroken {
		t.Fatalf("reason: %v", d["reason"])
	}
	var m map[string]any
	_ = json.Unmarshal([]byte(out), &m)
	if m["overall"] != "FAIL" {
		t.Fatalf("overall: %v", m["overall"])
	}
}
