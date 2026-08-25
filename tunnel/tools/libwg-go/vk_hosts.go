/* SPDX-License-Identifier: Apache-2.0
 *
 * Copyright © 2026 NikKuz99. All Rights Reserved.
 */

package main

import (
	"context"
	"fmt"
	"net"
	"sync"
	"time"
)

// VK-домены, которые критичны для работы TURN:
// - login.vk.ru — получение anonymous_token
// - api.vk.ru — получение TURN credentials + captcha API
// - calls.okcdn.ru — получение session_key
// - id.vk.ru — captcha

// Baseline IP-адреса, собранные с разных DNS-серверов (Google, Cloudflare, Yandex, Quad9).
// Используются как fallback когда DNS недоступен (белые списки).
var vkHostsBaseline = map[string][]string{
	"login.vk.ru": {
		"93.186.237.1",
		"95.213.56.1",
	},
	"api.vk.ru": {
		"87.240.129.140",
		"87.240.137.130",
		"87.240.137.206",
		"87.240.137.207",
		"87.240.137.208",
		"87.240.139.193",
		"87.240.190.70",
		"87.240.190.75",
		"93.186.225.205",
	},
	"calls.okcdn.ru": {
		"155.212.204.12",
		"155.212.204.136",
		"155.212.204.195",
	},
	"id.vk.ru": {
		"93.186.237.1",
		"95.213.56.1",
	},
}

// HostMetric — метрики доступности одного IP
type HostMetric struct {
	IP          string
	RTT         time.Duration // средний RTT (TCP handshake до :443)
	SuccessRate float64       // 0.0 - 1.0, доля успешных подключений
	LastSeen    time.Time     // когда последний раз отвечал
	FailCount   int           // количество подряд неудач
	TotalTries  int           // всего попыток
	TotalOK     int           // всего успешных
}

// Score — комбинированная метрика качества IP
// Формула: successRate * (1000 / (RTT_ms + 1))
// - successRate важнее RTT (лучше медленный но работающий)
// - +1 в знаменателе — защита от деления на ноль
func (m *HostMetric) Score() float64 {
	if m.SuccessRate < 0.1 {
		return 0 // 90% неудач — исключаем
	}
	if m.FailCount > 5 && time.Since(m.LastSeen) > time.Hour {
		return 0 // давно не отвечал и много неудач — исключаем
	}
	rttMs := float64(m.RTT.Milliseconds())
	return m.SuccessRate * (1000.0 / (rttMs + 1.0))
}

// VkHosts — менеджер VK-доменов с baseline + dynamic + метриками
type VkHosts struct {
	mu              sync.RWMutex
	dynamic         map[string][]string    // домен → список IP из DNS
	metrics         map[string]*HostMetric // "domain:ip" → метрика
	dnsOK           bool                   // работает ли DNS сейчас
	lastDNS         time.Time              // когда последний раз DNS работал
	pendingFailures map[string][]string    // домен → буфер неудач
	pendingStarted  map[string]time.Time   // домен → когда начали буфер
}

var vkHosts = &VkHosts{
	dynamic:         make(map[string][]string),
	metrics:         make(map[string]*HostMetric),
	pendingFailures: make(map[string][]string),
	pendingStarted:  make(map[string]time.Time),
	dnsOK:           true,
}

func init() {
	// Background goroutine: discard stale pending failures every 10s
	go func() {
		ticker := time.NewTicker(10 * time.Second)
		defer ticker.Stop()
		for range ticker.C {
			vkHosts.discardStalePending()
		}
	}()
}

// metricKey возвращает ключ для map metrics
func metricKey(domain, ip string) string {
	return domain + ":" + ip
}

// allIPs возвращает все известные IP для домена (baseline + dynamic, без дубликатов)
func (vh *VkHosts) allIPs(domain string) []string {
	vh.mu.RLock()
	defer vh.mu.RUnlock()

	seen := make(map[string]bool)
	var ips []string

	// Сначала dynamic (более свежие)
	for _, ip := range vh.dynamic[domain] {
		if !seen[ip] {
			seen[ip] = true
			ips = append(ips, ip)
		}
	}

	// Затем baseline
	for _, ip := range vkHostsBaseline[domain] {
		if !seen[ip] {
			seen[ip] = true
			ips = append(ips, ip)
		}
	}

	return ips
}

// Resolve выбирает лучший IP для домена
//
// Логика:
// 1. Если DNS работает — попробовать резолвнуть через hostCache.ResolveAll
//    (cascading DNS: system → Yandex → Google, возвращает ВСЕ A-записи)
//    Если удалось — обновить dynamic всеми IP + вернуть лучший по метрикам
// 2. Если DNS не работает — выбрать лучший из baseline+dynamic по метрикам
func (vh *VkHosts) Resolve(ctx context.Context, domain string) (string, error) {
	// 1. Попытка через DNS (cascading resolver, все A-записи)
	if vh.dnsOK {
		ips, err := hostCache.ResolveAll(ctx, domain)
		if err == nil && len(ips) > 0 {
			// DNS сработал — обновляем dynamic всеми IP
			vh.mu.Lock()
			old := vh.dynamic[domain]
			vh.dynamic[domain] = mergeUnique(old, ips)
			wasDNSFailed := !vh.dnsOK
			vh.dnsOK = true
			vh.lastDNS = time.Now()
			addedCount := len(vh.dynamic[domain]) - len(old)
			if addedCount > 0 {
				turnLog("[VKHosts] DNS added %d new IPs for %s (total: %d): %v",
					addedCount, domain, len(vh.dynamic[domain]), vh.dynamic[domain])
				needTrim := len(vh.dynamic[domain]) > maxIPsPerDomain
				vh.mu.Unlock()
				if needTrim {
					trimDomainIPs(domain)
					turnLog("[VKHosts] Trimmed %s to max %d IPs", domain, maxIPsPerDomain)
				}
				persist.MarkDirty()
			} else {
				vh.mu.Unlock()
			}
			if wasDNSFailed {
				turnLog("[VKHosts] DNS recovered for %s — switching back from baseline to DNS mode", domain)
			}
			// Возвращаем лучший по метрикам из всех (dynamic + baseline)
			return vh.selectBestIP(domain)
		}
		// DNS не сработал
		vh.mu.Lock()
		vh.dnsOK = false
		vh.mu.Unlock()
		turnLog("[VKHosts] DNS failed for %s, falling back to baseline+dynamic", domain)
	}

	// 2. Выбор лучшего IP из baseline + dynamic
	return vh.selectBestIP(domain)
}

// selectBestIP выбирает лучший IP из baseline + dynamic по метрикам
func (vh *VkHosts) selectBestIP(domain string) (string, error) {
	ips := vh.allIPs(domain)
	if len(ips) == 0 {
		return "", fmt.Errorf("no IPs available for %s", domain)
	}

	bestIP := ""
	bestScore := -1.0

	vh.mu.RLock()
	for _, ip := range ips {
		key := metricKey(domain, ip)
		metric, exists := vh.metrics[key]
		if !exists {
			// Нет метрики — даём базовый score (приоритет ниже, чем у проверенных)
			score := 0.5 * (1000.0 / (200.0 + 1.0)) // предполагаем 200ms RTT, 50% success
			if score > bestScore {
				bestScore = score
				bestIP = ip
			}
		} else {
			score := metric.Score()
			if score > bestScore {
				bestScore = score
				bestIP = ip
			}
		}
	}
	vh.mu.RUnlock()

	if bestIP == "" {
		// Все IP забракованы метриками — берём первый из baseline
		if baseline := vkHostsBaseline[domain]; len(baseline) > 0 {
			bestIP = baseline[0]
			turnLog("[VKHosts] All IPs blacklisted for %s, using baseline: %s", domain, bestIP)
		} else {
			return "", fmt.Errorf("no usable IP for %s", domain)
		}
	}

	return bestIP, nil
}

// mergeUnique объединяет два слайса IP без дубликатов
func mergeUnique(a, b []string) []string {
	seen := make(map[string]bool)
	result := make([]string, 0, len(a)+len(b))
	for _, ip := range a {
		if !seen[ip] {
			seen[ip] = true
			result = append(result, ip)
		}
	}
	for _, ip := range b {
		if !seen[ip] {
			seen[ip] = true
			result = append(result, ip)
		}
	}
	return result
}

// UpdateDynamic обновляет dynamic IP-список для домена (из DNS ответа)
func (vh *VkHosts) UpdateDynamic(domain string, ips []string) {
	vh.mu.Lock()
	defer vh.mu.Unlock()
	if len(ips) > 0 {
		vh.dynamic[domain] = ips
		vh.dnsOK = true
		vh.lastDNS = time.Now()
		turnLog("[VKHosts] Updated dynamic IPs for %s: %v", domain, ips)
	}
}

// RecordSuccess обновляет метрику после успешного подключения.
// Успех означает что сеть работает — коммитим pending failures.
func (vh *VkHosts) RecordSuccess(domain, ip string, rtt time.Duration) {
	vh.mu.Lock()

	key := metricKey(domain, ip)
	m, exists := vh.metrics[key]
	if !exists {
		m = &HostMetric{IP: ip}
		vh.metrics[key] = m
	}

	m.TotalTries++
	m.TotalOK++
	m.FailCount = 0
	m.LastSeen = time.Now()

	if m.RTT == 0 {
		m.RTT = rtt
	} else {
		m.RTT = time.Duration(float64(m.RTT)*0.7 + float64(rtt)*0.3)
	}

	m.SuccessRate = float64(m.TotalOK) / float64(m.TotalTries)
	vh.mu.Unlock()

	vh.flushPendingFailures(domain)
	persist.MarkDirty()
}

// RecordFailure обновляет метрику после неудачного подключения.
// ВАЖНО: Не списываем TTL немедленно. Буферизуем неудачу в pendingFailures.
// TTL будет списан только когда хотя бы один IP в этой "сессии" ответил
// успешно (вызов RecordSuccess → flushPendingFailures).
func (vh *VkHosts) RecordFailure(domain, ip string) {
	vh.mu.Lock()
	defer vh.mu.Unlock()
	vh.pendingFailures[domain] = append(vh.pendingFailures[domain], ip)
	if _, ok := vh.pendingStarted[domain]; !ok {
		vh.pendingStarted[domain] = time.Now()
	}
	if len(vh.pendingFailures[domain]) > 200 {
		vh.pendingFailures[domain] = vh.pendingFailures[domain][len(vh.pendingFailures[domain])-100:]
	}
}

// flushPendingFailures коммитит буфер неудач в метрики.
func (vh *VkHosts) flushPendingFailures(domain string) {
	vh.mu.Lock()
	pending := vh.pendingFailures[domain]
	delete(vh.pendingFailures, domain)
	delete(vh.pendingStarted, domain)
	vh.mu.Unlock()

	if len(pending) == 0 {
		return
	}

	vh.mu.Lock()
	evicted := []string{}
	for _, ip := range pending {
		key := metricKey(domain, ip)
		m, exists := vh.metrics[key]
		if !exists {
			m = &HostMetric{IP: ip}
			vh.metrics[key] = m
		}
		m.TotalTries++
		m.FailCount++
		m.SuccessRate = float64(m.TotalOK) / float64(m.TotalTries)
		if m.FailCount >= failCountHardLimit {
			evicted = append(evicted, ip)
		}
	}
	vh.mu.Unlock()

	for _, ip := range evicted {
		evictHardFailedIP(domain, ip)
		turnLog("[VKHosts] Evicted IP %s for %s (FailCount >= %d)", ip, domain, failCountHardLimit)
	}
	persist.MarkDirty()
}

// discardStalePending сбрасывает pending-буферы старше pendingTimeout.
func (vh *VkHosts) discardStalePending() {
	vh.mu.Lock()
	defer vh.mu.Unlock()
	now := time.Now()
	for domain, started := range vh.pendingStarted {
		if now.Sub(started) > pendingTimeout {
			delete(vh.pendingFailures, domain)
			delete(vh.pendingStarted, domain)
		}
	}
}

// MarkDNSWorking помечает что DNS снова работает
func (vh *VkHosts) MarkDNSWorking() {
	vh.mu.Lock()
	defer vh.mu.Unlock()
	if !vh.dnsOK {
		vh.dnsOK = true
		vh.lastDNS = time.Now()
		turnLog("[VKHosts] DNS is working again")
	}
}

// MarkDNSFailed помечает что DNS не работает
func (vh *VkHosts) MarkDNSFailed() {
	vh.mu.Lock()
	defer vh.mu.Unlock()
	vh.dnsOK = false
}

// IsDNSWorking возвращает true если DNS работал за последние 5 минут
func (vh *VkHosts) IsDNSWorking() bool {
	vh.mu.RLock()
	defer vh.mu.RUnlock()
	return vh.dnsOK && time.Since(vh.lastDNS) < 5*time.Minute
}

// StartMetricsCollector запускает фоновый сборщик метрик
// Для каждого IP из baseline + dynamic — TCP connect к :443, замер RTT
func (vh *VkHosts) StartMetricsCollector(ctx context.Context) {
	go func() {
		ticker := time.NewTicker(5 * time.Minute)
		defer ticker.Stop()

		// Первая проверка через 10 секунд после старта
		time.Sleep(10 * time.Second)
		vh.collectMetrics(ctx)

		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				vh.collectMetrics(ctx)
			}
		}
	}()
}

// collectMetrics проверяет доступность всех известных IP
func (vh *VkHosts) collectMetrics(ctx context.Context) {
	// Собираем все домены и IP
	domains := make(map[string][]string)
	vh.mu.RLock()
	for domain := range vkHostsBaseline {
		domains[domain] = vh.allIPs(domain)
	}
	vh.mu.RUnlock()

	// Пытаемся обновить через DNS.
	// ВАЖНО: используем отдельный ctx с timeout для каждого домена,
	// чтобы отмена одного запроса не отменяла остальные.
	for domain := range domains {
		select {
		case <-ctx.Done():
			return
		default:
		}
		dnsCtx, dnsCancel := context.WithTimeout(context.Background(), 10*time.Second)
		ips, err := resolveAllViaDNS(dnsCtx, domain)
		dnsCancel()
		if err == nil && len(ips) > 0 {
			vh.UpdateDynamic(domain, ips)
			// Если DNS работает — помечаем что DNS снова доступен
			vh.MarkDNSWorking()
		}
	}

	// Проверяем каждый IP
	for domain, ips := range domains {
		for _, ip := range ips {
			select {
			case <-ctx.Done():
				return
			default:
			}
			vh.probeIP(domain, ip)
		}
	}
}

// probeIP проверяет доступность IP через TCP connect к :443
func (vh *VkHosts) probeIP(domain, ip string) {
	addr := ip + ":443"
	start := time.Now()

	dialer := &net.Dialer{
		Timeout: 3 * time.Second,
		Control: protectControl,
	}
	conn, err := dialer.Dial("tcp", addr)
	rtt := time.Since(start)

	if err != nil {
		vh.RecordFailure(domain, ip)
		turnLog("[VKHosts] Probe failed: %s (%s) — %v", domain, ip, err)
		return
	}
	conn.Close()
	vh.RecordSuccess(domain, ip, rtt)
	turnLog("[VKHosts] Probe OK: %s (%s) — RTT=%v", domain, ip, rtt)
}

// contains проверяет наличие элемента в слайсе
func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}

// resolveAllViaDNS резолвит домен через cascading DNS и возвращает ВСЕ A-записи
func resolveAllViaDNS(ctx context.Context, domain string) ([]string, error) {
	return hostCache.ResolveAll(ctx, domain)
}
