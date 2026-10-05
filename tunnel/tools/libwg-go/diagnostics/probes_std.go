package diagnostics

// probes_std.go: stage probes with no dependency on turn-client internals.
// Stages 3-6 and 10 are wired via StateSource (facade.go, П3).

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"sort"
	"strings"
	"time"
)

// ---- Stage 1: device network ----

type deviceNetProbe struct {
	routeAddr string // UDP probe target, used only when no tun is up
}

func (p *deviceNetProbe) ID() StageID            { return StageDeviceNet }
func (p *deviceNetProbe) Timeout() time.Duration { return 5 * time.Second }

func (p *deviceNetProbe) Run(ctx context.Context) ProbeResult {
	ifaces, err := net.Interfaces()
	if err != nil {
		return ProbeResult{Status: StatusFail, ErrClass: ErrInternal, ErrRaw: err.Error()}
	}
	var names []string
	usable, tunUp := 0, false
	for _, ifi := range ifaces {
		if ifi.Flags&net.FlagUp == 0 || ifi.Flags&net.FlagLoopback != 0 {
			continue
		}
		names = append(names, ifi.Name)
		if strings.HasPrefix(ifi.Name, "tun") {
			tunUp = true
		} else {
			usable++
		}
	}
	sort.Strings(names)
	details := map[string]any{"interfaces": names, "non_tun_up": usable, "tun_up": tunUp}
	if tunUp {
		// The VPN owns the default route: an unprotected socket would test the
		// tunnel, not the device. Interface inventory is the honest probe here.
		if usable > 0 {
			return ProbeResult{Status: StatusPass, Details: details}
		}
		return ProbeResult{Status: StatusWarn, ErrClass: ErrNetwork, ErrRaw: "only tunnel interface is up", Details: details}
	}
	addr := p.routeAddr
	if addr == "" {
		addr = "8.8.8.8:53"
	}
	d := net.Dialer{Timeout: 3 * time.Second}
	conn, err := d.DialContext(ctx, "udp", addr) // no payload: route check only
	if err != nil {
		details["route_probe"] = addr + ": " + err.Error()
		return ProbeResult{Status: StatusFail, ErrClass: ErrNetwork, ErrRaw: "no device-level UDP route", Details: details}
	}
	_ = conn.Close()
	details["route_probe"] = "udp " + addr + " ok"
	return ProbeResult{Status: StatusPass, Details: details}
}

// ---- Stage 2: DNS ----

type ResolveFunc func(ctx context.Context, host string) ([]string, error)

type dnsProbe struct {
	hosts   []string
	resolve ResolveFunc // nil: system resolver (П3 wires the app resolver on device)
}

func (p *dnsProbe) ID() StageID            { return StageDNS }
func (p *dnsProbe) Timeout() time.Duration { return 10 * time.Second }

func (p *dnsProbe) Run(ctx context.Context) ProbeResult {
	hosts := p.hosts
	if len(hosts) == 0 {
		hosts = []string{"vk.com"}
	}
	resolve := p.resolve
	if resolve == nil {
		resolve = func(ctx context.Context, host string) ([]string, error) {
			return net.DefaultResolver.LookupHost(ctx, host)
		}
	}
	perHost := map[string]any{}
	var failed []string
	for _, h := range hosts {
		addrs, err := resolve(ctx, h)
		if err != nil {
			failed = append(failed, h)
			perHost[h] = map[string]any{"error": err.Error()}
			continue
		}
		perHost[h] = addrs
	}
	details := map[string]any{"hosts": perHost}
	switch {
	case len(failed) == len(hosts):
		return ProbeResult{Status: StatusFail, ErrClass: ErrDNS, ErrRaw: "resolution failed for all hosts", Details: details}
	case len(failed) > 0:
		return ProbeResult{Status: StatusWarn, ErrClass: ErrDNS, ErrRaw: fmt.Sprintf("failed: %v", failed), Details: details}
	}
	return ProbeResult{Status: StatusPass, Details: details}
}

// ---- Stage 7: tun interface ----

// ProbeTunInterfaces: stdlib-часть стадии tun. Экспортирована для
// production-адаптера (П3); герметичные тесты фейкают TunState.
func ProbeTunInterfaces(ctx context.Context) ProbeResult {
	ifaces, err := net.Interfaces()
	if err != nil {
		return ProbeResult{Status: StatusFail, ErrClass: ErrInternal, ErrRaw: err.Error()}
	}
	for _, ifi := range ifaces {
		if strings.HasPrefix(ifi.Name, "tun") && ifi.Flags&net.FlagUp != 0 {
			addrs, addrErr := ifi.Addrs()
			var list []string
			for _, a := range addrs {
				list = append(list, a.String())
			}
			details := map[string]any{"interface": ifi.Name, "mtu": ifi.MTU, "addresses": list}
			switch {
			case addrErr != nil:
				return ProbeResult{Status: StatusWarn, ErrClass: ErrTun, ErrRaw: addrErr.Error(), Details: details}
			case len(list) == 0:
				return ProbeResult{Status: StatusWarn, ErrClass: ErrTun, ErrRaw: "tun interface has no address", Details: details}
			}
			return ProbeResult{Status: StatusPass, Details: details}
		}
	}
	return ProbeResult{Status: StatusFail, ErrClass: ErrTun, ErrRaw: "no tun interface is up"}
}

// ---- Stage 8: end-to-end HTTP through the tunnel ----

type e2eProbe struct {
	url    string
	client *http.Client // nil: default client (unprotected socket = through VPN)
}

func (p *e2eProbe) ID() StageID            { return StageE2E }
func (p *e2eProbe) Timeout() time.Duration { return 15 * time.Second }

func (p *e2eProbe) Run(ctx context.Context) ProbeResult {
	url := p.url
	if url == "" {
		url = "https://ya.ru"
	}
	client := p.client
	if client == nil {
		client = &http.Client{CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		}}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return ProbeResult{Status: StatusFail, ErrClass: ErrInternal, ErrRaw: err.Error()}
	}
	start := time.Now()
	resp, err := client.Do(req)
	elapsed := time.Since(start).Milliseconds()
	details := map[string]any{"url": url, "elapsed_ms": elapsed}
	if err != nil {
		details["error"] = err.Error()
		return ProbeResult{Status: StatusFail, ErrClass: ErrE2E, ErrRaw: err.Error(), Details: details}
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
	details["status_code"] = resp.StatusCode
	switch {
	case resp.StatusCode >= 200 && resp.StatusCode < 400:
		return ProbeResult{Status: StatusPass, Details: details}
	case resp.StatusCode < 500:
		return ProbeResult{Status: StatusWarn, ErrClass: ErrE2E, ErrRaw: fmt.Sprintf("HTTP %d", resp.StatusCode), Details: details}
	}
	return ProbeResult{Status: StatusFail, ErrClass: ErrE2E, ErrRaw: fmt.Sprintf("HTTP %d", resp.StatusCode), Details: details}
}

// ---- Stage 9: latency / stability ----

type latencyProbe struct {
	url    string
	n      int
	client *http.Client
}

func (p *latencyProbe) ID() StageID            { return StageLatency }
func (p *latencyProbe) Timeout() time.Duration { return 25 * time.Second }

func (p *latencyProbe) Run(ctx context.Context) ProbeResult {
	url := p.url
	if url == "" {
		url = "https://ya.ru"
	}
	n := p.n
	if n <= 0 {
		n = 5
	}
	client := p.client
	if client == nil {
		client = &http.Client{CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		}}
	}
	var samples []int64
	failures := 0
	for i := 0; i < n; i++ {
		req, err := http.NewRequestWithContext(ctx, http.MethodHead, url, nil)
		if err != nil {
			return ProbeResult{Status: StatusFail, ErrClass: ErrInternal, ErrRaw: err.Error()}
		}
		start := time.Now()
		resp, err := client.Do(req)
		elapsed := time.Since(start).Milliseconds()
		if err != nil {
			failures++
			continue
		}
		_ = resp.Body.Close()
		samples = append(samples, elapsed)
	}
	details := map[string]any{"samples_ms": samples, "failures": failures, "requested": n}
	if len(samples) == 0 {
		return ProbeResult{Status: StatusFail, ErrClass: ErrE2E, ErrRaw: "all probes failed", Details: details}
	}
	sort.Slice(samples, func(i, j int) bool { return samples[i] < samples[j] })
	min, max := samples[0], samples[len(samples)-1]
	median := samples[len(samples)/2]
	jitter := max - min
	details["min_ms"], details["max_ms"], details["median_ms"], details["jitter_ms"] = min, max, median, jitter
	res := ProbeResult{Status: StatusPass, Details: details}
	switch {
	case failures >= 3 || len(samples) < 2:
		res.Status, res.ErrClass, res.ErrRaw = StatusFail, ErrE2E, fmt.Sprintf("%d of %d probes failed", failures, n)
	case failures > 0 || median > 1500 || jitter > 1000:
		res.Status, res.ErrClass = StatusWarn, ErrE2E
		if failures > 0 {
			res.ErrRaw = fmt.Sprintf("%d of %d probes failed", failures, n)
		} else {
			res.ErrRaw = fmt.Sprintf("median %dms, jitter %dms", median, jitter)
		}
	}
	return res
}

// ---- Fixed-result probes ----

type fixedProbe struct {
	id  StageID
	res ProbeResult
}

func (p *fixedProbe) ID() StageID            { return p.id }
func (p *fixedProbe) Timeout() time.Duration { return time.Second }
func (p *fixedProbe) Run(ctx context.Context) ProbeResult {
	return p.res
}

func NewSkipProbe(id StageID, reason string) Probe {
	return &fixedProbe{id: id, res: ProbeResult{Status: StatusSkip, Details: map[string]any{"reason": reason}}}
}