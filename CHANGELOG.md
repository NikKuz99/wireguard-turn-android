# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/).

## [1.7.0] - 2026-10-04

### Fixed

- **BUG-016**: TURN allocation socket was not protected by the VPN service — on
  Android 16 the system blocked it with EPERM, the transport lived ~30 seconds
  and died ("connected but no internet"). All transport sockets are now created
  through a single protected dial point, the protection result is checked
  (`wgProtectSocket` failures no longer pass silently), and an early failure
  retries with backoff until the tunnel is fully established.
- **BUG-017**: after three failed restarts the handshake watchdog left the
  tunnel UP with a dead TURN proxy, silently blackholing all device traffic
  behind a live VPN icon. Give-up now performs a full teardown (tunnel DOWN)
  so the failure is visible and a simple toggle restores the connection.

## [1.6.0] - 2026-10-02

### Changed

- Captcha architecture: tokenizer-based powInput extraction. A custom JS lexer
  (`jstoken`) plus structural classification of the IIFE call arguments
  (ladder L1a marker → L1b structural fingerprint → L1c whole-HTML pseudo-JS →
  L1d HTML-unescape retry) replaces the regex-first approach. Legacy regex
  patterns are kept as a safety net. Immune to VK obfuscation changes:
  single/double quotes, template literals, hex numbers, argument reordering,
  renamed markers, bare IIFE.

### Added

- 8 behavioral fixtures + negative tests for the extraction ladder
  (false-positive guard on settings pages).

## [1.5.3] - 2026-09-25

### Fixed

- BUG-013: VK changed the BFF obfuscation quotes (double → single) in powInput —
  added the 11th regex pattern (superseded architecturally in 1.6.0).

## [1.5.2] - 2026-09-11

### Fixed

- BUG-012: stdlib captcha client was unusable on Android — custom dialer
  (vkHosts cascading DNS + `protect()` for sockets) and bundled CA certificates.

## [1.5.1] - 2026-09-10

### Fixed

- BUG-011: VK captcha API overhaul — settings from initSession, stdlib HTTP for
  captcha calls, dynamic debug_info, adFp, telemetry PoW.

## [1.8.0] - 2026-10-06

### Added

- Diagnostics screen (Task 25): 10 channel-check stages — device network, DNS,
  VK session, TURN relay, DTLS, WireGuard, tunnel, internet through the tunnel,
  latency, re-handshake — each with timing and PASS/WARN/FAIL/SKIP status.
  Passive mode while connected (no disruption), full mode otherwise. One-button
  report sharing as text or JSON.
- Socket-protection error counters (BUG-016) in the diagnostics report:
  eperm_classified_total, protect_fail_total.

### Changed

- EPERM classification in the TURN client now recognizes the string form of
  errors from network libraries.
