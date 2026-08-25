/* SPDX-License-Identifier: Apache-2.0
 *
 * Copyright © 2026 NikKuz99. All Rights Reserved.
 *
 * dns_cache_persist.go — Persistent DNS cache with metrics.
 *
 * Stores resolved IPs and per-IP metrics between application restarts.
 * Format: JSON file at path provided by Kotlin side via wgSetDnsCachePath.
 *
 * TTL semantics (implemented in vk_hosts.go RecordSuccess/RecordFailure):
 *   - RecordFailure buffers into vkHosts.pendingFailures (no immediate commit).
 *   - RecordSuccess commits the buffer (one IP succeeded → others were tried
 *     and genuinely failed).
 *   - A 60s inactivity timer discards the buffer (user offline / gave up).
 *   - When an IP's FailCount >= failCountHardLimit, it is evicted from both
 *     the in-memory cache and the persisted file.
 *
 * Limits:
 *   - maxIPsPerDomain: when exceeded, lowest-Score IPs are evicted on save.
 */

package main

/*
#include <stdlib.h>
*/
import "C"

import (
	"encoding/json"
	"os"
	"sort"
	"sync"
	"time"
)

// ─────────────────────────────────────────────────────────────────────────────
// Constants
// ─────────────────────────────────────────────────────────────────────────────

const (
	maxIPsPerDomain    = 30                 // hard cap on stored IPs per domain
	failCountHardLimit = 20                 // at this FailCount, IP is evicted
	saveDebounce       = 5 * time.Second   // debounce async saves
	saveInterval       = 60 * time.Second   // periodic save while tunnel is up
	pendingTimeout     = 60 * time.Second   // discard pending failures after this
)

// ─────────────────────────────────────────────────────────────────────────────
// On-disk format
// ─────────────────────────────────────────────────────────────────────────────

// diskMetric is the persisted form of HostMetric.
type diskMetric struct {
	IP          string  `json:"ip"`
	RTTms       int64   `json:"rtt_ms"`
	SuccessRate float64 `json:"success_rate"`
	LastSeen    string  `json:"last_seen"`
	FailCount   int     `json:"fail_count"`
	TotalTries  int     `json:"total_tries"`
	TotalOK     int     `json:"total_ok"`
}

type diskDomain struct {
	IPs     []string     `json:"ips"`
	Metrics []diskMetric `json:"metrics,omitempty"`
}

// cacheFileV1 is the top-level persisted structure.
type cacheFileV1 struct {
	Version int                   `json:"version"`
	SavedAt string                `json:"saved_at"`
	Domains map[string]diskDomain `json:"domains"`
}

// ─────────────────────────────────────────────────────────────────────────────
// PersistentCache
// ─────────────────────────────────────────────────────────────────────────────

// PersistentCache wraps DnsCache + VkHosts metrics with disk persistence.
// All state lives in the existing in-memory structures; PersistentCache only
// reads/writes them under their own locks.
type PersistentCache struct {
	mu      sync.Mutex
	path    string
	loaded  bool
	dirty   bool
	stopCh  chan struct{}
	stopped bool
	saveWG  sync.WaitGroup
}

var persist = &PersistentCache{
	stopCh: make(chan struct{}),
}

// SetCachePath is called from JNI (wgSetDnsCachePath).
// Loads cache from disk synchronously and starts background saver.
func (p *PersistentCache) SetCachePath(path string) {
	p.mu.Lock()
	// Stop any previous saver (e.g. on app restart within same process)
	if p.loaded && p.path != "" && p.path != path {
		p.stopSaverLocked()
	}
	p.path = path
	p.mu.Unlock()

	// Load outside the lock to avoid blocking SetCachePath for too long,
	// but it's typically fast (<10ms for our size).
	if err := p.loadFromDisk(); err != nil {
		turnLog("[DNSCache] load error: %v (starting with empty cache)", err)
	} else {
		p.mu.Lock()
		p.loaded = true
		p.mu.Unlock()
		turnLog("[DNSCache] loaded cache from %s", path)
	}

	// Start background saver
	p.mu.Lock()
	p.startSaverLocked()
	p.mu.Unlock()
}

// LoadForTest exposes load for tests.
func (p *PersistentCache) LoadForTest(path string) error {
	p.mu.Lock()
	p.path = path
	p.mu.Unlock()
	return p.loadFromDisk()
}

// loadFromDisk reads JSON file and merges into in-memory caches.
func (p *PersistentCache) loadFromDisk() error {
	p.mu.Lock()
	path := p.path
	p.mu.Unlock()
	if path == "" {
		return nil
	}

	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil // fresh install — nothing to load
		}
		return err
	}

	var cf cacheFileV1
	if err := json.Unmarshal(data, &cf); err != nil {
		return err
	}
	if cf.Version != 1 {
		turnLog("[DNSCache] unknown version %d, ignoring", cf.Version)
		return nil
	}

	// Merge into hostCache (allIps + ips for backward compat)
	hostCache.mu.Lock()
	for domain, dd := range cf.Domains {
		if len(dd.IPs) == 0 {
			continue
		}
		ips := dd.IPs
		if len(ips) > maxIPsPerDomain {
			ips = ips[:maxIPsPerDomain]
		}
		existing := hostCache.allIps[domain]
		merged := mergeUnique(existing, ips)
		if len(merged) > maxIPsPerDomain {
			merged = merged[:maxIPsPerDomain]
		}
		hostCache.allIps[domain] = merged
		if len(merged) > 0 {
			hostCache.ips[domain] = merged[0]
		}
	}
	hostCache.mu.Unlock()

	// Merge into vkHosts (dynamic + metrics)
	vkHosts.mu.Lock()
	for domain, dd := range cf.Domains {
		if len(dd.IPs) > 0 {
			old := vkHosts.dynamic[domain]
			merged := mergeUnique(old, dd.IPs)
			if len(merged) > maxIPsPerDomain {
				merged = merged[:maxIPsPerDomain]
			}
			vkHosts.dynamic[domain] = merged
		}
		for _, dm := range dd.Metrics {
			// Skip hard-failed IPs on load (they should have been evicted before save,
			// but be defensive)
			if dm.FailCount >= failCountHardLimit {
				continue
			}
			key := metricKey(domain, dm.IP)
			lastSeen, _ := time.Parse(time.RFC3339, dm.LastSeen)
			if lastSeen.IsZero() {
				lastSeen = time.Now()
			}
			rtt := time.Duration(dm.RTTms) * time.Millisecond
			vkHosts.metrics[key] = &HostMetric{
				IP:          dm.IP,
				RTT:         rtt,
				SuccessRate: dm.SuccessRate,
				LastSeen:    lastSeen,
				FailCount:   dm.FailCount,
				TotalTries:  dm.TotalTries,
				TotalOK:     dm.TotalOK,
			}
		}
	}
	vkHosts.mu.Unlock()

	turnLog("[DNSCache] loaded %d domains from disk", len(cf.Domains))
	return nil
}

// MarkDirty schedules an async save (debounced).
func (p *PersistentCache) MarkDirty() {
	p.mu.Lock()
	p.dirty = true
	p.mu.Unlock()
}

// SaveNow forces a synchronous save. Called on tunnel stop and on app exit.
func (p *PersistentCache) SaveNow() {
	if err := p.saveToDisk(); err != nil {
		turnLog("[DNSCache] save error: %v", err)
	}
}

// saveToDisk collects current state from hostCache + vkHosts and writes JSON.
func (p *PersistentCache) saveToDisk() error {
	p.mu.Lock()
	path := p.path
	p.dirty = false
	p.mu.Unlock()
	if path == "" {
		return nil
	}

	cf := cacheFileV1{
		Version: 1,
		SavedAt: time.Now().Format(time.RFC3339),
		Domains: make(map[string]diskDomain),
	}

	// Collect all known domains
	domains := make(map[string]struct{})
	hostCache.mu.RLock()
	for d := range hostCache.allIps {
		domains[d] = struct{}{}
	}
	for d := range hostCache.ips {
		domains[d] = struct{}{}
	}
	hostCache.mu.RUnlock()

	vkHosts.mu.RLock()
	for d := range vkHosts.dynamic {
		domains[d] = struct{}{}
	}
	for k := range vkHosts.metrics {
		// k = "domain:ip" — extract domain (last ':' separator)
		for i := len(k) - 1; i >= 0; i-- {
			if k[i] == ':' {
				domains[k[:i]] = struct{}{}
				break
			}
		}
	}
	// Snapshot metrics for trimByScore (read-locked)
	metricsSnapshot := make(map[string]*HostMetric, len(vkHosts.metrics))
	for k, v := range vkHosts.metrics {
		metricsSnapshot[k] = v
	}
	vkHosts.mu.RUnlock()

	for domain := range domains {
		// Collect IPs from hostCache + vkHosts.dynamic (NOT baseline — that's in code)
		hostCache.mu.RLock()
		allIps := append([]string(nil), hostCache.allIps[domain]...)
		hostCache.mu.RUnlock()

		vkHosts.mu.RLock()
		dynIps := vkHosts.dynamic[domain]
		vkHosts.mu.RUnlock()

		mergedIPs := mergeUnique(allIps, dynIps)
		// Also include any IPs that have metrics for this domain
		prefix := domain + ":"
		for k := range metricsSnapshot {
			if len(k) > len(prefix) && k[:len(prefix)] == prefix {
				ip := k[len(prefix):]
				mergedIPs = mergeUnique(mergedIPs, []string{ip})
			}
		}

		if len(mergedIPs) == 0 {
			continue
		}

		// Trim to maxIPsPerDomain by Score
		if len(mergedIPs) > maxIPsPerDomain {
			mergedIPs = trimByScore(domain, mergedIPs, metricsSnapshot, maxIPsPerDomain)
		}

		// Build metrics for kept IPs only (skip hard-failed)
		var dms []diskMetric
		vkHosts.mu.RLock()
		for _, ip := range mergedIPs {
			key := metricKey(domain, ip)
			m, ok := vkHosts.metrics[key]
			if !ok {
				continue
			}
			if m.FailCount >= failCountHardLimit {
				continue
			}
			dms = append(dms, diskMetric{
				IP:          m.IP,
				RTTms:       m.RTT.Milliseconds(),
				SuccessRate: m.SuccessRate,
				LastSeen:    m.LastSeen.Format(time.RFC3339),
				FailCount:   m.FailCount,
				TotalTries:  m.TotalTries,
				TotalOK:     m.TotalOK,
			})
		}
		vkHosts.mu.RUnlock()

		cf.Domains[domain] = diskDomain{
			IPs:     mergedIPs,
			Metrics: dms,
		}
	}

	data, err := json.MarshalIndent(cf, "", "  ")
	if err != nil {
		return err
	}

	// Atomic write: temp file + rename
	tmpPath := path + ".tmp"
	if err := os.WriteFile(tmpPath, data, 0600); err != nil {
		return err
	}
	return os.Rename(tmpPath, path)
}

// trimByScore keeps top N IPs by Score(), evicts the rest.
func trimByScore(domain string, ips []string, metrics map[string]*HostMetric, keep int) []string {
	type scored struct {
		ip    string
		score float64
	}
	scoredIPs := make([]scored, len(ips))
	for i, ip := range ips {
		key := metricKey(domain, ip)
		m, ok := metrics[key]
		if !ok {
			// Unknown IP — assume neutral score
			scoredIPs[i] = scored{ip: ip, score: 0.5 * (1000.0 / 201.0)}
			continue
		}
		scoredIPs[i] = scored{ip: ip, score: m.Score()}
	}
	sort.SliceStable(scoredIPs, func(i, j int) bool {
		return scoredIPs[i].score > scoredIPs[j].score
	})
	if keep > len(scoredIPs) {
		keep = len(scoredIPs)
	}
	result := make([]string, keep)
	for i := 0; i < keep; i++ {
		result[i] = scoredIPs[i].ip
	}
	return result
}

// ─────────────────────────────────────────────────────────────────────────────
// Background saver
// ─────────────────────────────────────────────────────────────────────────────

func (p *PersistentCache) startSaverLocked() {
	if !p.stopped {
		// Already running — replace stopCh to signal old one to exit
		close(p.stopCh)
	}
	p.stopCh = make(chan struct{})
	p.stopped = false

	p.saveWG.Add(1)
	go func(stopCh <-chan struct{}) {
		defer p.saveWG.Done()
		ticker := time.NewTicker(saveInterval)
		defer ticker.Stop()

		for {
			select {
			case <-stopCh:
				_ = p.saveToDisk()
				return
			case <-ticker.C:
				p.mu.Lock()
				dirty := p.dirty
				p.mu.Unlock()
				if dirty {
					_ = p.saveToDisk()
				}
			}
		}
	}(p.stopCh)
}

func (p *PersistentCache) stopSaverLocked() {
	if p.stopped {
		return
	}
	p.stopped = true
	close(p.stopCh)
	p.saveWG.Wait()
}

// Stop stops the background saver and does a final save.
func (p *PersistentCache) Stop() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.stopSaverLocked()
}

// ─────────────────────────────────────────────────────────────────────────────
// Eviction: hard-failed IPs are removed from cache when FailCount hits limit.
// Called from vkHosts.RecordFailure after commit.
// ─────────────────────────────────────────────────────────────────────────────

func evictHardFailedIP(domain, ip string) {
	vkHosts.mu.Lock()
	defer vkHosts.mu.Unlock()

	delete(vkHosts.metrics, metricKey(domain, ip))

	// Remove from dynamic
	dyn := vkHosts.dynamic[domain]
	for i, d := range dyn {
		if d == ip {
			vkHosts.dynamic[domain] = append(dyn[:i], dyn[i+1:]...)
			break
		}
	}

	// Remove from hostCache (under separate lock)
	hostCache.mu.Lock()
	defer hostCache.mu.Unlock()
	ai := hostCache.allIps[domain]
	for i, d := range ai {
		if d == ip {
			hostCache.allIps[domain] = append(ai[:i], ai[i+1:]...)
			break
		}
	}
	if hostCache.ips[domain] == ip {
		delete(hostCache.ips, domain)
		if len(hostCache.allIps[domain]) > 0 {
			hostCache.ips[domain] = hostCache.allIps[domain][0]
		}
	}
}

// trimDomainIPs enforces maxIPsPerDomain after a successful DNS resolution
// merges new IPs into the cache.
func trimDomainIPs(domain string) {
	vkHosts.mu.RLock()
	metricsSnapshot := make(map[string]*HostMetric, len(vkHosts.metrics))
	for k, v := range vkHosts.metrics {
		metricsSnapshot[k] = v
	}
	vkHosts.mu.RUnlock()

	vkHosts.mu.Lock()
	if dyn := vkHosts.dynamic[domain]; len(dyn) > maxIPsPerDomain {
		vkHosts.dynamic[domain] = trimByScore(domain, dyn, metricsSnapshot, maxIPsPerDomain)
	}
	vkHosts.mu.Unlock()

	hostCache.mu.Lock()
	if ai := hostCache.allIps[domain]; len(ai) > maxIPsPerDomain {
		hostCache.allIps[domain] = trimByScore(domain, ai, metricsSnapshot, maxIPsPerDomain)
	}
	hostCache.mu.Unlock()
}

// ─────────────────────────────────────────────────────────────────────────────
// JNI exports
// ─────────────────────────────────────────────────────────────────────────────

//export wgSetDnsCachePath
func wgSetDnsCachePath(pathC *C.char) {
	path := C.GoString(pathC)
	persist.SetCachePath(path)
}

//export wgSaveDnsCacheNow
func wgSaveDnsCacheNow() {
	persist.SaveNow()
}
