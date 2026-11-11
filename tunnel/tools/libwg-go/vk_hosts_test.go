package main

import (
	"context"
	"testing"
	"time"
)

// newTestVkHosts — свежий экземпляр для изоляции тестов от глобального vkHosts.
func newTestVkHosts(dnsOK bool) *VkHosts {
	return &VkHosts{
		dynamic:         make(map[string][]string),
		metrics:         make(map[string]*HostMetric),
		pendingFailures: make(map[string][]string),
		pendingStarted:  make(map[string]time.Time),
		dnsOK:           dnsOK,
	}
}

// resetEndpointBaselineForTest очищает runtime-карту endpoint-адресов.
func resetEndpointBaselineForTest() {
	endpointBaseline.mu.Lock()
	endpointBaseline.ips = make(map[string]string)
	endpointBaseline.mu.Unlock()
}

// Задача 80: адрес endpoint-а приходит из настроек туннеля (аннотация
// #@wgt:EndpointIP выданного конфига), а не вшит в код. Регистрация валидна
// только для настоящего IP и доменного имени пира.
func TestSetEndpointBaseline(t *testing.T) {
	resetEndpointBaselineForTest()
	defer resetEndpointBaselineForTest()

	SetEndpointBaseline("vpn.example.net", "203.0.113.7")
	if got := getEndpointBaseline("vpn.example.net"); got != "203.0.113.7" {
		t.Fatalf("getEndpointBaseline = %q, want 203.0.113.7", got)
	}

	// Мусор игнорируется: не-IP, пустые значения
	SetEndpointBaseline("vpn.example.net", "not-an-ip")
	if got := getEndpointBaseline("vpn.example.net"); got != "203.0.113.7" {
		t.Fatalf("мусорный IP перезаписал карту: %q", got)
	}
	SetEndpointBaseline("", "203.0.113.1")
	SetEndpointBaseline("vpn.example.net", "")
	if got := getEndpointBaseline("vpn.example.net"); got != "203.0.113.7" {
		t.Fatalf("пустые значения изменили карту: %q", got)
	}
}

// Главный сценарий Задачи 79/80: DNS упал (dnsOK=false, cooldown активен),
// динамический кэш пуст, но адрес домена известен из конфига туннеля —
// Resolve обязан отдать его БЕЗ запуска DNS-каскада (мгновенно, не тратя
// ~10 секунд на таймауты при каждой попытке старта).
func TestResolveEndpointFallbackNoDNS(t *testing.T) {
	resetEndpointBaselineForTest()
	defer resetEndpointBaselineForTest()

	vh := newTestVkHosts(false)
	SetEndpointBaseline("vpn.example.net", "203.0.113.7")
	vh.MarkDNSFailed() // dnsOK=false + lastDNSFail=сейчас

	start := time.Now()
	ip, err := vh.Resolve(context.Background(), "vpn.example.net")
	elapsed := time.Since(start)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if ip != "203.0.113.7" {
		t.Fatalf("Resolve = %q, want 203.0.113.7 (адрес из конфига туннеля)", ip)
	}
	if elapsed > 500*time.Millisecond {
		t.Fatalf("Resolve took %v — DNS-каскад не должен был запускаться внутри cooldown", elapsed)
	}
	vh.mu.RLock()
	dnsOK := vh.dnsOK
	vh.mu.RUnlock()
	if dnsOK {
		t.Fatal("dnsOK стал true без успешного резолва — не должен")
	}
}

// Задача 79: dnsOK=false больше не защёлкивается навсегда — DNS перепробуется
// после cooldown (сеть могла вернуться) или сразу, если известных IP нет вовсе.
func TestDNSRetryAfterCooldown(t *testing.T) {
	resetEndpointBaselineForTest()
	defer resetEndpointBaselineForTest()

	vh := newTestVkHosts(false)
	SetEndpointBaseline("vpn.example.net", "203.0.113.7")
	now := time.Now()

	vh.mu.Lock()
	vh.lastDNSFail = now
	vh.mu.Unlock()

	if vh.shouldAttemptDNS("vpn.example.net", now) {
		t.Fatal("shouldAttemptDNS: внутри cooldown при известном адресе — не должен пробовать")
	}
	if !vh.shouldAttemptDNS("unknown.example.com", now) {
		t.Fatal("shouldAttemptDNS: домен без известных IP — должен пробовать DNS всегда")
	}
	later := now.Add(dnsRetryCooldown + time.Second)
	if !vh.shouldAttemptDNS("vpn.example.net", later) {
		t.Fatal("shouldAttemptDNS: cooldown истёк — должен пробовать DNS")
	}
}

// Кэш последнего успешного резолва приоритетнее адреса из конфига (свежее).
func TestResolveDynamicCachePriority(t *testing.T) {
	resetEndpointBaselineForTest()
	defer resetEndpointBaselineForTest()

	vh := newTestVkHosts(false)
	SetEndpointBaseline("vpn.example.net", "203.0.113.7")
	vh.mu.Lock()
	vh.dynamic["vpn.example.net"] = []string{"198.51.100.25"} // прошлый успешный резолв
	vh.lastDNSFail = time.Now()
	vh.mu.Unlock()

	ip, err := vh.Resolve(context.Background(), "vpn.example.net")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if ip != "198.51.100.25" {
		t.Fatalf("Resolve = %q, want 198.51.100.25 (динамический кэш приоритетнее)", ip)
	}
}

// Конфиг без аннотации (старые клиенты): никаких известных адресов нет —
// поведение как до задачи 79/80: единственный шанс это DNS, поэтому
// shouldAttemptDNS обязан вернуть true даже сразу после отказа.
func TestNoEndpointAnnotationStillRetriesDNS(t *testing.T) {
	resetEndpointBaselineForTest()
	defer resetEndpointBaselineForTest()

	vh := newTestVkHosts(false)
	vh.MarkDNSFailed()
	now := time.Now()
	if !vh.shouldAttemptDNS("vpn.example.net", now) {
		t.Fatal("без адреса из конфига DNS должен пробоваться всегда, даже внутри cooldown")
	}
}

// MarkDNSFailed фиксирует время отказа — от него отсчитывается cooldown.
func TestMarkDNSFailedRecordsTime(t *testing.T) {
	vh := newTestVkHosts(true)
	vh.MarkDNSFailed()
	vh.mu.RLock()
	defer vh.mu.RUnlock()
	if vh.dnsOK {
		t.Fatal("dnsOK должен быть false после MarkDNSFailed")
	}
	if time.Since(vh.lastDNSFail) > time.Second {
		t.Fatal("lastDNSFail не зафиксирован")
	}
}
