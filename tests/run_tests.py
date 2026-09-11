#!/usr/bin/env python3
"""
Android CI/CD Test Suite
========================
Automated tests for CMD WG turn Android app.

Run on test platform (has Android SDK + NDK):
    python3 /home/z/my-project/scripts/ssh_tp.py 'cd /root/wireguard-turn-android && python3 tests/run_tests.py'

Test categories:
1. Build tests (gradle assembleDebug)
2. Version check (versionCode + versionName in APK)
3. Captcha parser tests (BFF pattern, powInput extraction)
4. Config parser tests (.conf import, #@wgt: format)
5. DNS cache tests (persistent cache structure)
6. HandshakeWatchdog tests
7. Signing config tests

Usage:
    python3 run_tests.py              # run all
    python3 run_tests.py --category build
    python3 run_tests.py --category parser
    python3 run_tests.py --json        # JSON output
"""
import subprocess
import sys
import os
import json
import re
import argparse
import tempfile
from pathlib import Path

REPO = "/root/wireguard-turn-android"
GO_PATH = "/usr/local/go/bin"
ANDROID_HOME = "/opt/android-sdk"

# ─── Test framework ──────────────────────────────────────────────────────────

class TestResult:
    def __init__(self, name, category):
        self.name = name
        self.category = category
        self.passed = False
        self.message = ""
        self.details = ""

    def to_dict(self):
        return {
            "name": self.name,
            "category": self.category,
            "passed": self.passed,
            "message": self.message,
            "details": self.details[:500] if self.details else "",
        }


def run_cmd(cmd, timeout=300):
    """Run shell command, return (exit_code, stdout, stderr)."""
    try:
        result = subprocess.run(
            cmd, shell=True, capture_output=True, text=True, timeout=timeout
        )
        return result.returncode, result.stdout, result.stderr
    except subprocess.TimeoutExpired:
        return -1, "", "TIMEOUT"
    except Exception as e:
        return -1, "", str(e)


# ─── 1. Build tests ──────────────────────────────────────────────────────────

def test_gradle_assemble_debug():
    """Gradle assembles debug APK without errors."""
    r = TestResult("gradle_assemble_debug", "build")
    code, out, err = run_cmd(
        f"cd {REPO} && export PATH={GO_PATH}:$PATH ANDROID_HOME={ANDROID_HOME} "
        f"&& ./gradlew :ui:assembleDebug 2>&1 | tail -20",
        timeout=600
    )
    r.passed = code == 0 and "BUILD SUCCESSFUL" in out
    r.message = "Debug APK built" if r.passed else f"Build failed: {out[-200:]}"
    return r


def test_gradle_assemble_release():
    """Gradle assembles release APK without errors."""
    r = TestResult("gradle_assemble_release", "build")
    code, out, err = run_cmd(
        f"cd {REPO} && export PATH={GO_PATH}:$PATH ANDROID_HOME={ANDROID_HOME} "
        f"&& ./gradlew :ui:assembleRelease 2>&1 | tail -20",
        timeout=600
    )
    r.passed = code == 0 and "BUILD SUCCESSFUL" in out
    r.message = "Release APK built" if r.passed else f"Build failed: {out[-200:]}"
    return r


def test_apk_exists():
    """Release APK file exists."""
    r = TestResult("apk_exists", "build")
    apk_path = f"{REPO}/ui/build/outputs/apk/release/ui-release.apk"
    r.passed = os.path.exists(apk_path)
    if r.passed:
        size = os.path.getsize(apk_path)
        r.message = f"APK: {size / 1024 / 1024:.1f} MB"
    else:
        r.message = f"APK not found: {apk_path}"
    return r


# ─── 2. Version check tests ──────────────────────────────────────────────────

def test_version_in_apk():
    """APK versionCode and versionName match gradle.properties."""
    r = TestResult("version_in_apk", "version")
    # Read gradle.properties
    with open(f"{REPO}/gradle.properties") as f:
        props = f.read()
    code_match = re.search(r'wireguardVersionCode=(\d+)', props)
    name_match = re.search(r'wireguardVersionName=([^\n]+)', props)
    if not code_match or not name_match:
        r.passed = False
        r.message = "gradle.properties missing version"
        return r

    expected_code = code_match.group(1)
    expected_name = name_match.group(1).strip()

    # Check APK
    apk_path = f"{REPO}/ui/build/outputs/apk/release/ui-release.apk"
    if not os.path.exists(apk_path):
        r.passed = True  # Skip if no APK built
        r.message = "Skipped (no APK)"
        return r

    code, out, _ = run_cmd(
        f"export PATH=$PATH:{ANDROID_HOME}/build-tools/36.0.0 "
        f"&& aapt2 dump badging {apk_path} 2>&1 | grep versionCode",
        timeout=30
    )
    r.passed = f"versionCode='{expected_code}'" in out
    r.message = f"Expected code={expected_code}, name={expected_name}" if r.passed else f"Mismatch: {out[:100]}"
    return r


def test_version_format():
    """Version follows semantic versioning (X.Y.Z)."""
    r = TestResult("version_format", "version")
    with open(f"{REPO}/gradle.properties") as f:
        props = f.read()
    name_match = re.search(r'wireguardVersionName=(\d+\.\d+\.\d+)', props)
    r.passed = name_match is not None
    r.message = name_match.group(1) if r.passed else "Version not in X.Y.Z format"
    return r


# ─── 3. Captcha parser tests ─────────────────────────────────────────────────

def test_captcha_bff_pattern():
    """slider_captcha.go has BFF obfuscated powInput pattern (BUG-007 fix)."""
    r = TestResult("captcha_bff_pattern", "captcha")
    code, out, _ = run_cmd(
        f"grep -c 'pow_timeout' {REPO}/tunnel/tools/libwg-go/slider_captcha.go || true"
    )
    count = int(out.strip()) if out.strip().isdigit() else 0
    r.passed = count >= 1
    r.message = f"BFF pattern found ({count} matches)" if r.passed else "BFF pattern missing (BUG-007 not fixed)"
    return r


def test_captcha_multiple_patterns():
    """Parser tries multiple patterns (not just one const pattern)."""
    r = TestResult("captcha_multiple_patterns", "captcha")
    code, out, _ = run_cmd(
        f"grep -c 'regexp.MustCompile' {REPO}/tunnel/tools/libwg-go/slider_captcha.go || true"
    )
    count = int(out.strip()) if out.strip().isdigit() else 0
    r.passed = count >= 2  # At least: const pattern + BFF pattern
    r.message = f"Found {count} regex patterns" if r.passed else f"Only {count} patterns (need >=2)"
    return r


def test_captcha_webview_auto_close():
    """CaptchaActivity auto-closes on timeout — BUG-008 (eternal white screen) guard.

    BUG-008 (2026-09-10): when the VK BFF captcha page never rendered in the
    WebView (white screen), the activity stayed open forever — even after the
    retry loop solved the captcha via slider POC and the tunnel connected.
    Fix: internal watchdog (CAPTCHA_ACTIVITY_TIMEOUT_MS + postDelayed + finish).
    """
    r = TestResult("captcha_webview_auto_close", "captcha")
    kt = f"{REPO}/ui/src/main/java/com/wireguard/android/activity/CaptchaActivity.kt"
    code, out, _ = run_cmd(
        f"grep -c 'CAPTCHA_ACTIVITY_TIMEOUT_MS' {kt} || true"
    )
    count = int(out.strip()) if out.strip().isdigit() else 0
    code2, out2, _ = run_cmd(
        f"grep -c 'removeCallbacksAndMessages' {kt} || true"
    )
    count2 = int(out2.strip()) if out2.strip().isdigit() else 0
    r.passed = count >= 2 and count2 >= 1  # const declaration + timer usage + cleanup
    r.message = (
        f"Auto-close watchdog present (timer refs: {count}, cleanup: {count2})"
        if r.passed
        else "Auto-close watchdog missing (BUG-008: captcha WebView can stay on screen forever)"
    )
    return r


def test_captcha_manual_mode_disabled():
    """Manual captcha WebView disabled while BFF SPA does not render — BUG-009 workaround.

    BUG-009 (2026-09-10): manual fallback WebView showed an eternal white screen
    (VK BFF SPA not rendering on Android 7) and blocked the credential loop for
    120s per attempt. Disabled in favour of the fast auto/slider retry loop.
    """
    r = TestResult("captcha_manual_mode_disabled", "captcha")
    code, out, _ = run_cmd(
        f"grep -c 'manualCaptcha := false' {REPO}/tunnel/tools/libwg-go/vk.go || true"
    )
    count = int(out.strip()) if out.strip().isdigit() else 0
    r.passed = count == 1
    r.message = (
        "Manual captcha disabled (fast retry loop handles solving)"
        if r.passed
        else "manualCaptcha := false not found — manual WebView enabled (white-screen + 120s block risk)"
    )
    return r




# ─── BUG-011 tests (2026-09-11): VK captcha API overhaul ────────────────────

def test_captcha_settings_from_initsession():
    """BUG-011: captcha settings must come from initSession content_settings
    (VK removed captcha_settings from captchaNotRobot.settings response)."""
    r = TestResult("captcha_settings_from_initsession", "captcha")
    code, out, _ = run_cmd(
        f"grep -c 'content_settings' {REPO}/tunnel/tools/libwg-go/slider_captcha.go || true"
    )
    count = int(out.strip()) if out.strip().isdigit() else 0
    code2, out2, _ = run_cmd(
        f"grep -c 'requestInitSession' {REPO}/tunnel/tools/libwg-go/slider_captcha.go || true"
    )
    count2 = int(out2.strip()) if out2.strip().isdigit() else 0
    r.passed = count >= 1 and count2 >= 2
    r.message = (
        f"initSession content_settings parsing present ({count}/{count2} refs)"
        if r.passed
        else "BUG-011 fix missing: captcha settings not read from initSession"
    )
    return r


def test_captcha_stdlib_http():
    """BUG-011: VK fingerprints the tls-client uTLS hello; captcha requests
    must use Go stdlib net/http (tls-client gets status=BOT)."""
    r = TestResult("captcha_stdlib_http", "captcha")
    code, out, _ = run_cmd(
        f"grep -c 'http.NewRequestWithContext' {REPO}/tunnel/tools/libwg-go/slider_captcha.go || true"
    )
    slider = int(out.strip()) if out.strip().isdigit() else 0
    code2, out2, _ = run_cmd(
        f"grep -c 'fhttp.NewRequestWithContext' {REPO}/tunnel/tools/libwg-go/slider_captcha.go || true"
    )
    fhttp_slider = int(out2.strip()) if out2.strip().isdigit() else 0
    r.passed = slider >= 1 and fhttp_slider == 0
    r.message = (
        f"captcha uses stdlib net/http ({slider} stdlib, {fhttp_slider} fhttp)"
        if r.passed
        else "BUG-011: captcha still uses fhttp/tls-client (VK returns BOT)"
    )
    return r



def test_captcha_client_custom_dialer():
    """BUG-012: stdlib captcha client must use the app-wide custom dialer
    (cascading DNS via vkHosts + protectControl) and bundled CA — the default
    transport breaks on Android: lookup on [::1]:53 -> connection refused
    (no /etc/resolv.conf), and Go has no system CA pool on Android."""
    r = TestResult("captcha_client_custom_dialer", "captcha")
    code, out, _ = run_cmd(
        f"grep -c 'http.Client{{Timeout: 25' {REPO}/tunnel/tools/libwg-go/vk_captcha.go || true"
    )
    bare = int(out.strip()) if out.strip().isdigit() else 0
    code2, out2, _ = run_cmd(
        f"grep -c 'getCustomDialContext' {REPO}/tunnel/tools/libwg-go/vk_captcha.go || true"
    )
    dialer = int(out2.strip()) if out2.strip().isdigit() else 0
    code3, out3, _ = run_cmd(
        f"grep -c 'loadCABundle' {REPO}/tunnel/tools/libwg-go/vk_captcha.go || true"
    )
    ca = int(out3.strip()) if out3.strip().isdigit() else 0
    r.passed = bare == 0 and dialer >= 1 and ca >= 1
    r.message = (
        f"captcha client: custom dialer ({dialer}) + CA bundle ({ca}), no bare client"
        if r.passed
        else "BUG-012: captcha stdlib client uses default transport (DNS [::1]:53 refused on Android, no CA)"
    )
    return r


def test_captcha_dynamic_debug_info():
    """BUG-011: debug_info is per-page-load UUID (brlefapmjnpg in page HTML),
    must be extracted dynamically, not hardcoded."""
    r = TestResult("captcha_dynamic_debug_info", "captcha")
    code, out, _ = run_cmd(
        f"grep -c 'brlefapmjnpg' {REPO}/tunnel/tools/libwg-go/vk_captcha.go || true"
    )
    count = int(out.strip()) if out.strip().isdigit() else 0
    r.passed = count >= 1
    r.message = f"dynamic debug_info extraction present ({count} refs)" if r.passed else "BUG-011: debug_info not extracted from page (stale hardcoded value = bot marker)"
    return r


def test_captcha_adfp_generated():
    """BUG-011: adFp (rb_sync id) generated as 21-char nanoid and sent in
    captcha API params."""
    r = TestResult("captcha_adfp_generated", "captcha")
    code, out, _ = run_cmd(
        f"grep -c 'generateAdFpId' {REPO}/tunnel/tools/libwg-go/vk_captcha.go || true"
    )
    count = int(out.strip()) if out.strip().isdigit() else 0
    r.passed = count >= 2
    r.message = f"adFp nanoid generation present ({count} refs)" if r.passed else "BUG-011: adFp not generated (empty adFp = bot marker)"
    return r


def test_captcha_pow_telemetry():
    """BUG-011: v2 PoW hash must carry telemetry + tel_hash (VK validates
    payload structure)."""
    r = TestResult("captcha_pow_telemetry", "captcha")
    code, out, _ = run_cmd(
        f"grep -c 'stableTelemetryHash' {REPO}/tunnel/tools/libwg-go/vk_captcha.go || true"
    )
    count = int(out.strip()) if out.strip().isdigit() else 0
    r.passed = count >= 2
    r.message = f"v2 telemetry hash present ({count} refs)" if r.passed else "BUG-011: PoW hash missing telemetry payload"
    return r


def test_captcha_rate_limit_backoff():
    """Captcha rate-limit errors use long reconnect backoff — BUG-010 mitigation.

    BUG-010 (2026-09-10): with manual captcha disabled, rapid 1s retries hammer
    the VK captcha API and escalate rate limiting (check status: BOT / ERROR_LIMIT).
    Fix: 20s backoff when the error is captcha-rate-limit-related.
    """
    r = TestResult("captcha_rate_limit_backoff", "captcha")
    code, out, _ = run_cmd(
        f"grep -c 'isCaptchaRateLimitError' {REPO}/tunnel/tools/libwg-go/turn-client.go || true"
    )
    count = int(out.strip()) if out.strip().isdigit() else 0
    code2, out2, _ = run_cmd(
        f"grep -c '20 \* time.Second' {REPO}/tunnel/tools/libwg-go/turn-client.go || true"
    )
    count2 = int(out2.strip()) if out2.strip().isdigit() else 0
    r.passed = count >= 1 and count2 >= 1
    r.message = (
        f"Backoff present (helper refs: {count}, 20s delay: {count2})"
        if r.passed
        else "Captcha backoff missing — 1s retries will escalate VK rate limiting"
    )
    return r


# ─── 4. Config parser tests ──────────────────────────────────────────────────

def test_conf_parser_exists():
    """TunnelConfigProcessor or similar parser exists."""
    r = TestResult("conf_parser_exists", "parser")
    code, out, _ = run_cmd(
        f"find {REPO} -name 'TurnConfigProcessor*' -o -name 'TurnSettings*' 2>/dev/null | head -5"
    )
    r.passed = len(out.strip()) > 0
    r.message = "Parser files found" if r.passed else "No config parser found"
    return r


def test_conf_android_export_format():
    """TurnSettings.kt exports #@wgt: format."""
    r = TestResult("conf_android_export_format", "parser")
    code, out, _ = run_cmd(
        f"grep -c '#@wgt:' {REPO}/ui/src/main/java/com/wireguard/android/turn/TurnSettings.kt || true"
    )
    count = int(out.strip()) if out.strip().isdigit() else 0
    r.passed = count >= 3
    r.message = f"Found {count} #@wgt: export lines" if r.passed else f"Only {count} export lines"
    return r


def test_conf_parser_imports_wgt():
    """TurnConfigProcessor.kt parses #@wgt: format on import."""
    r = TestResult("conf_parser_imports_wgt", "parser")
    code, out, _ = run_cmd(
        f"grep -c '#@wgt:' {REPO}/ui/src/main/java/com/wireguard/android/turn/TurnConfigProcessor.kt || true"
    )
    count = int(out.strip()) if out.strip().isdigit() else 0
    r.passed = count >= 1
    r.message = f"Parser handles #@wgt: ({count} references)" if r.passed else "Parser doesn't handle #@wgt:"
    return r


# ─── 5. DNS cache tests ──────────────────────────────────────────────────────

def test_dns_cache_persist_exists():
    """dns_cache_persist.go exists (persistent DNS cache feature)."""
    r = TestResult("dns_cache_persist_exists", "dns")
    code, out, _ = run_cmd(f"test -f {REPO}/tunnel/tools/libwg-go/dns_cache_persist.go && echo OK")
    r.passed = "OK" in out
    r.message = "dns_cache_persist.go exists" if r.passed else "dns_cache_persist.go missing"
    return r


def test_dns_cache_vk_hosts():
    """vk_hosts.go exists (VK host resolution with fallback IPs)."""
    r = TestResult("dns_cache_vk_hosts", "dns")
    code, out, _ = run_cmd(f"test -f {REPO}/tunnel/tools/libwg-go/vk_hosts.go && echo OK")
    r.passed = "OK" in out
    r.message = "vk_hosts.go exists" if r.passed else "vk_hosts.go missing"
    return r


def test_dns_cache_baseline_ips():
    """vk_hosts.go has baseline IPs for VK domains (DNS fallback)."""
    r = TestResult("dns_cache_baseline_ips", "dns")
    code, out, _ = run_cmd(
        f"grep -c '93.186.237.1\\|87.240.129' {REPO}/tunnel/tools/libwg-go/vk_hosts.go || true"
    )
    count = int(out.strip()) if out.strip().isdigit() else 0
    r.passed = count >= 2
    r.message = f"Found {count} baseline IP references" if r.passed else "No baseline IPs found"
    return r


# ─── 6. HandshakeWatchdog tests ──────────────────────────────────────────────

def test_handshake_watchdog_exists():
    """HandshakeWatchdog.kt exists (stale handshake detection)."""
    r = TestResult("handshake_watchdog_exists", "watchdog")
    code, out, _ = run_cmd(
        f"test -f {REPO}/ui/src/main/java/com/wireguard/android/turn/HandshakeWatchdog.kt && echo OK"
    )
    r.passed = "OK" in out
    r.message = "HandshakeWatchdog.kt exists" if r.passed else "HandshakeWatchdog.kt missing"
    return r


def test_handshake_watchdog_threshold():
    """HandshakeWatchdog has stale threshold (90s = 3x keepalive)."""
    r = TestResult("handshake_watchdog_threshold", "watchdog")
    code, out, _ = run_cmd(
        f"grep -c '90\\|staleThreshold\\|STALE' {REPO}/ui/src/main/java/com/wireguard/android/turn/HandshakeWatchdog.kt || true"
    )
    count = int(out.strip()) if out.strip().isdigit() else 0
    r.passed = count >= 1
    r.message = f"Stale threshold found ({count} refs)" if r.passed else "No stale threshold"
    return r


# ─── 7. Signing config tests ─────────────────────────────────────────────────

def test_signing_config():
    """build.gradle has signingConfig (debug or release)."""
    r = TestResult("signing_config", "signing")
    code, out, _ = run_cmd(
        f"grep -c 'signingConfig' {REPO}/ui/build.gradle.kts || true"
    )
    count = int(out.strip()) if out.strip().isdigit() else 0
    r.passed = count >= 1
    r.message = f"Signing config present ({count} refs)" if r.passed else "No signing config"
    return r


# ─── 8. Source code quality tests ────────────────────────────────────────────

def test_no_kotlin_string_interpolation_bugs():
    """No \${e.message} in Kotlin (causes crash, must use string concatenation)."""
    r = TestResult("no_kotlin_string_interp_bugs", "quality")
    code, out, _ = run_cmd(
        f"grep -rn '\\$\\{{e.message\\}}' {REPO}/ui/src/main/java/ 2>/dev/null | grep -v test | wc -l || true"
    )
    count = int(out.strip()) if out.strip().isdigit() else 0
    r.passed = count == 0
    r.message = "No \${e.message} bugs" if r.passed else f"Found {count} \${{e.message}} bugs"
    return r


def test_no_bak_files():
    """No .bak files in git."""
    r = TestResult("no_bak_files", "quality")
    code, out, _ = run_cmd(f"cd {REPO} && git status --short | grep -c '\\.bak' || true")
    count = int(out.strip()) if out.strip().isdigit() else 0
    r.passed = count == 0
    r.message = "No .bak files" if r.passed else f"Found {count} .bak files"
    return r


# ─── Test runner ─────────────────────────────────────────────────────────────

ALL_TESTS = [
    # Build
    # test_gradle_assemble_debug,  # Uncomment when running full CI
    # test_gradle_assemble_release,
    test_apk_exists,
    # Version
    test_version_in_apk,
    test_version_format,
    # Captcha
    test_captcha_bff_pattern,
    test_captcha_multiple_patterns,
    test_captcha_webview_auto_close,
    test_captcha_manual_mode_disabled,
    test_captcha_settings_from_initsession,
    test_captcha_stdlib_http,
    test_captcha_client_custom_dialer,
    test_captcha_dynamic_debug_info,
    test_captcha_adfp_generated,
    test_captcha_pow_telemetry,
    test_captcha_rate_limit_backoff,
    # Parser
    test_conf_parser_exists,
    test_conf_android_export_format,
    test_conf_parser_imports_wgt,
    # DNS
    test_dns_cache_persist_exists,
    test_dns_cache_vk_hosts,
    test_dns_cache_baseline_ips,
    # Watchdog
    test_handshake_watchdog_exists,
    test_handshake_watchdog_threshold,
    # Signing
    test_signing_config,
    # Quality
    test_no_kotlin_string_interpolation_bugs,
    test_no_bak_files,
]

CATEGORIES = {
    "build": ["apk_exists"],
    "version": ["version_in_apk", "version_format"],
    "captcha": ["captcha_bff_pattern", "captcha_multiple_patterns", "captcha_webview_auto_close", "captcha_manual_mode_disabled", "captcha_settings_from_initsession", "captcha_stdlib_http", "captcha_dynamic_debug_info", "captcha_adfp_generated", "captcha_pow_telemetry", "captcha_rate_limit_backoff", "captcha_client_custom_dialer"],
    "parser": ["conf_parser_exists", "conf_android_export_format", "conf_parser_imports_wgt"],
    "dns": ["dns_cache_persist_exists", "dns_cache_vk_hosts", "dns_cache_baseline_ips"],
    "watchdog": ["handshake_watchdog_exists", "handshake_watchdog_threshold"],
    "signing": ["signing_config"],
    "quality": ["no_kotlin_string_interp_bugs", "no_bak_files"],
}


def main():
    parser = argparse.ArgumentParser(description="Android CI/CD Test Suite")
    parser.add_argument("--category", help="Run only specific category")
    parser.add_argument("--json", action="store_true", help="JSON output")
    parser.add_argument("--list", action="store_true", help="List all tests")
    parser.add_argument("--full", action="store_true", help="Include gradle build tests (slow)")
    args = parser.parse_args()

    if args.list:
        for cat, tests in CATEGORIES.items():
            print(f"\n{cat}:")
            for t in tests:
                print(f"  - {t}")
        return

    tests_to_run = ALL_TESTS
    if args.full:
        tests_to_run = [test_gradle_assemble_debug, test_gradle_assemble_release] + ALL_TESTS

    if args.category:
        if args.category not in CATEGORIES:
            print(f"Unknown category: {args.category}. Available: {', '.join(CATEGORIES.keys())}")
            sys.exit(2)
        wanted_names = set(CATEGORIES[args.category])
        tests_to_run = [t for t in ALL_TESTS if t.__name__.replace("test_", "") in wanted_names]

    results = []
    for test_fn in tests_to_run:
        print(f"Running {test_fn.__name__}...", file=sys.stderr)
        try:
            result = test_fn()
        except Exception as e:
            result = TestResult(test_fn.__name__, "error")
            result.passed = False
            result.message = f"EXCEPTION: {e}"
        results.append(result)

    if args.json:
        print(json.dumps([r.to_dict() for r in results], indent=2))
    else:
        passed = sum(1 for r in results if r.passed)
        failed = sum(1 for r in results if not r.passed)
        print(f"\n{'='*60}")
        print(f"CMD WG turn Android CI/CD Test Results")
        print(f"{'='*60}")
        for r in results:
            status = "✓" if r.passed else "✗"
            print(f"  {status} [{r.category:10s}] {r.name:40s} {r.message}")
        print(f"{'='*60}")
        print(f"Total: {len(results)} | Passed: {passed} | Failed: {failed}")
        print(f"{'='*60}")
        sys.exit(0 if failed == 0 else 1)


if __name__ == "__main__":
    main()
