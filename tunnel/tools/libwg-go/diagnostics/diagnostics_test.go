package diagnostics

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

type fakeProbe struct {
	id      StageID
	timeout time.Duration
	res     ProbeResult
	block   time.Duration // >0: wait ctx.Done, return timeout-fail
	panic   bool
}

func (f *fakeProbe) ID() StageID            { return f.id }
func (f *fakeProbe) Timeout() time.Duration { return f.timeout }
func (f *fakeProbe) Run(ctx context.Context) ProbeResult {
	if f.panic {
		panic("boom")
	}
	if f.block > 0 {
		<-ctx.Done()
		return ProbeResult{Status: StatusFail, ErrRaw: "context deadline exceeded"}
	}
	return f.res
}

func TestFatalChainSkipsDownstream(t *testing.T) {
	probes := []Probe{
		&fakeProbe{id: StageDNS, timeout: time.Second, res: ProbeResult{Status: StatusFail, ErrClass: ErrDNS}},
		&fakeProbe{id: StageVKAuth, timeout: time.Second, res: ProbeResult{Status: StatusPass}},
		&fakeProbe{id: StageE2E, timeout: time.Second, res: ProbeResult{Status: StatusPass}},
	}
	rep := Run(context.Background(), ModeFull, probes, nil, nil)
	if rep.Stages[0].Status != StatusFail || rep.Stages[1].Status != StatusSkip || rep.Stages[2].Status != StatusSkip {
		t.Fatalf("chain: %+v", rep.Stages)
	}
	if rep.Overall != StatusFail || rep.Skip != 2 {
		t.Fatalf("overall=%s skip=%d", rep.Overall, rep.Skip)
	}
}

func TestWarnDoesNotBreakChain(t *testing.T) {
	probes := []Probe{
		&fakeProbe{id: StageVKAuth, timeout: time.Second, res: ProbeResult{Status: StatusWarn, ErrClass: ErrAuth}},
		&fakeProbe{id: StageTURNAlloc, timeout: time.Second, res: ProbeResult{Status: StatusPass}},
	}
	rep := Run(context.Background(), ModeFull, probes, nil, nil)
	if rep.Overall != StatusWarn || rep.Stages[1].Status != StatusPass {
		t.Fatalf("%+v", rep)
	}
}

func TestTimeoutClassification(t *testing.T) {
	probes := []Probe{&fakeProbe{id: StageDTLS, timeout: 50 * time.Millisecond, block: 2 * time.Second}}
	start := time.Now()
	rep := Run(context.Background(), ModeFull, probes, nil, nil)
	if time.Since(start) > time.Second {
		t.Fatal("run exceeded probe timeout")
	}
	if rep.Stages[0].Status != StatusFail || rep.Stages[0].ErrorClass != ErrTimeout {
		t.Fatalf("%+v", rep.Stages[0])
	}
}

func TestPanicContainmentTeardownAndChainBreak(t *testing.T) {
	called := false
	td := func(context.Context) { called = true }
	probes := []Probe{
		&fakeProbe{id: StageWG, timeout: time.Second, panic: true},
		&fakeProbe{id: StageE2E, timeout: time.Second, res: ProbeResult{Status: StatusPass}},
	}
	rep := Run(context.Background(), ModeFull, probes, nil, td)
	if !called {
		t.Fatal("teardown not called")
	}
	if rep.Stages[0].Status != StatusFail || rep.Stages[0].ErrorClass != ErrInternal {
		t.Fatalf("%+v", rep.Stages[0])
	}
	if rep.Stages[1].Status != StatusSkip {
		t.Fatalf("panic in blocking stage must break chain")
	}
}

func TestRedaction(t *testing.T) {
	probes := []Probe{
		&fakeProbe{id: StageE2E, timeout: time.Second, res: ProbeResult{
			Status:  StatusFail,
			ErrRaw:  "auth SECRET_TOKEN failed",
			Details: map[string]any{"url": "https://vk.com/a?token=SECRET_TOKEN", "attempts": 2},
		}},
	}
	rep := Run(context.Background(), ModeFull, probes, []string{"SECRET_TOKEN"}, nil)
	b, err := rep.JSON()
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), "SECRET_TOKEN") {
		t.Fatalf("secret leaked: %s", b)
	}
	if !strings.Contains(string(b), "[REDACTED]") {
		t.Fatalf("no redaction marker: %s", b)
	}
}

func TestJSONRoundtrip(t *testing.T) {
	probes := []Probe{&fakeProbe{id: StageE2E, timeout: time.Second,
		res: ProbeResult{Status: StatusPass, Details: map[string]any{"code": 302}}}}
	rep := Run(context.Background(), ModePassive, probes, nil, nil)
	if rep.Overall != StatusPass {
		t.Fatalf("overall: %s", rep.Overall)
	}
	b, _ := rep.JSON()
	var back Report
	if err := json.Unmarshal(b, &back); err != nil {
		t.Fatal(err)
	}
	if back.Stages[0].ID != StageE2E || back.Stages[0].Details["code"] != float64(302) {
		t.Fatalf("%+v", back)
	}
}