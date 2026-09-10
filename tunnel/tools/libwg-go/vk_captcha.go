/* SPDX-License-Identifier: Apache-2.0
 *
 * Copyright © 2026 WireGuard LLC. All Rights Reserved.
 */

package main

/*
#include <stdlib.h>
extern const char* requestCaptcha(const char* redirect_uri);
*/
import "C"

import (
	"context"
	"crypto/md5"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"bytes"
	crand "crypto/rand"
	"math/rand"
	"net/http"
	"regexp"
	neturl "net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	fhttp "github.com/bogdanfinn/fhttp"
	tlsclient "github.com/kiper292/tls-client"
)

type VkCaptchaError struct {
	ErrorCode               int
	ErrorMsg                string
	CaptchaSid              string
	CaptchaImg              string
	RedirectURI             string
	IsSoundCaptchaAvailable bool
	SessionToken            string
	CaptchaTs               string
	CaptchaAttempt          string
}

func ParseVkCaptchaError(errData map[string]interface{}) *VkCaptchaError {
	// Extract error_code
	codeFloat, ok := errData["error_code"].(float64)
	if !ok {
		turnLog("missing error_code in captcha error data")
		return nil
	}
	code := int(codeFloat)

	// Extract redirect_uri (optional in new VK captcha flow)
	RedirectURI, _ := errData["redirect_uri"].(string)

	// Extract captcha_sid (optional in new flow)
	captchaSid, ok := errData["captcha_sid"].(string)
	if !ok {
		if sidNum, ok2 := errData["captcha_sid"].(float64); ok2 {
			captchaSid = fmt.Sprintf("%.0f", sidNum)
		}
	}

	// Extract captcha_img (optional in new flow)
	captchaImg, _ := errData["captcha_img"].(string)

	// Extract error_msg (optional)
	errorMsg, _ := errData["error_msg"].(string)

	// Extract session token if redirect_uri present
	var sessionToken string
	if RedirectURI != "" {
		parsed, err := neturl.Parse(RedirectURI)
		if err != nil {
			turnLog("failed to parse redirect_uri: %v", err)
			return nil
		}
		sessionToken = parsed.Query().Get("session_token")
	}

	// Require at least one solvable path
	if RedirectURI == "" && sessionToken == "" && captchaImg == "" && captchaSid == "" {
		turnLog("no solvable captcha path in error data")
		return nil
	}

	// Extract is_sound_captcha_available
	isSound, ok := errData["is_sound_captcha_available"].(bool)
	if !ok {
		isSound = false
	}

	// Extract captcha_ts
	var captchaTs string
	if tsFloat, ok := errData["captcha_ts"].(float64); ok {
		captchaTs = fmt.Sprintf("%.0f", tsFloat)
	} else if tsStr, ok := errData["captcha_ts"].(string); ok {
		captchaTs = tsStr
	}

	// Extract captcha_attempt
	var captchaAttempt string
	if attFloat, ok := errData["captcha_attempt"].(float64); ok {
		captchaAttempt = fmt.Sprintf("%.0f", attFloat)
	} else if attStr, ok := errData["captcha_attempt"].(string); ok {
		captchaAttempt = attStr
	}

	// Build VkCaptchaError
	return &VkCaptchaError{
		ErrorCode:               code,
		ErrorMsg:                errorMsg,
		CaptchaSid:              captchaSid,
		CaptchaImg:              captchaImg,
		RedirectURI:             RedirectURI,
		IsSoundCaptchaAvailable: isSound,
		SessionToken:            sessionToken,
		CaptchaTs:               captchaTs,
		CaptchaAttempt:          captchaAttempt,
	}
}

func (e *VkCaptchaError) IsCaptchaError() bool {
	return e.ErrorCode == 14 && e.RedirectURI != "" && e.SessionToken != ""
}

// captchaMutex serializes captcha solving to avoid multiple concurrent attempts
var captchaMutex sync.Mutex

/*
// solveVkCaptcha solves the VK Not Robot Captcha and returns success_token
// First tries automatic solution, falls back to WebView if it fails
func solveVkCaptcha(ctx context.Context, streamID int, client tlsclient.HttpClient, profile Profile, captchaErr *VkCaptchaError) (string, error) {
	// Serialize captcha solving to avoid multiple concurrent attempts
	captchaMutex.Lock()
	defer captchaMutex.Unlock()

	turnLog("[Captcha] Solving Not Robot Captcha...")

	// Step 1: Try automatic solution
	turnLog("[Captcha] Attempting automatic solution...")
	successToken, err := solveVkCaptchaAutomatic(ctx, streamID, client, profile, captchaErr)
	if err == nil && successToken != "" {
		turnLog("[Captcha] Automatic solution SUCCESS!")
		return successToken, nil
	}

	turnLog("[Captcha] Automatic solution FAILED: %v", err)
	turnLog("[Captcha] Falling back to WebView...")

	// Step 2: Fall back to WebView
	turnLog("[Captcha] Opening WebView for manual solving...")
	redirectURICStr := C.CString(captchaErr.RedirectUri)
	defer C.free(unsafe.Pointer(redirectURICStr))

	cToken := C.requestCaptcha(redirectURICStr)
	if cToken == nil {
		return "", fmt.Errorf("WebView captcha solving failed: returned nil token")
	}
	defer C.free(unsafe.Pointer(cToken))

	successToken = C.GoString(cToken)
	if successToken == "" {
		return "", fmt.Errorf("WebView captcha solving failed: returned empty token")
	}

	turnLog("[Captcha] WebView solution SUCCESS! Got success_token")
	return successToken, nil
}

// solveVkCaptchaAutomatic performs the automatic captcha solving without UI
func solveVkCaptchaAutomatic(ctx context.Context, streamID int, client tlsclient.HttpClient, profile Profile, captchaErr *VkCaptchaError) (string, error) {
	sessionToken := captchaErr.SessionToken
	if sessionToken == "" {
		return "", fmt.Errorf("no session_token in redirect_uri")
	}

	// Step 1: Fetch the captcha HTML page to get powInput
	bootstrap, err := fetchCaptchaBootstrap(ctx, captchaErr.RedirectUri, client, profile)
	if err != nil {
		return "", fmt.Errorf("failed to fetch captcha bootstrap: %w", err)
	}

	turnLog("[Captcha] PoW input: %s, difficulty: %d", bootstrap.PowInput, bootstrap.Difficulty)

	// Step 2: Solve PoW
	hash := solvePoW(bootstrap.PowInput, bootstrap.Difficulty)
	turnLog("[Captcha] PoW solved: hash=%s", hash)

	// Step 3: Call captchaNotRobot API with slider POC support
	successToken, err := callCaptchaNotRobotWithSliderPOC(
		ctx,
		captchaErr.SessionToken,
		hash,
		streamID,
		client,
		profile,
		bootstrap.Settings,
	)

	if err != nil {
		return "", fmt.Errorf("callCaptchaNotRobotWithSliderPOC API failed: %w", err)
	}

	turnLog("[Captcha] Success! Got success_token")
	return successToken, nil
}
*/

func solveVkCaptcha(ctx context.Context, captchaErr *VkCaptchaError, streamID int, client tlsclient.HttpClient, profile Profile, useSliderPOC bool) (string, error) {
	// BUG-011: VK fingerprints the tls-client uTLS hello; captcha calls use stdlib
	httpClient := &http.Client{Timeout: 25 * time.Second}
	adFp := generateAdFpId()
	registerAdFpFingerprint(ctx, adFp, profile, httpClient)
	if useSliderPOC {
		turnLog("[STREAM %d] [Captcha] Solving captcha with slider POC...", streamID)
	} else {
		turnLog("[STREAM %d] [Captcha] Solving captcha...", streamID)
	}

	if captchaErr.SessionToken == "" {
		return "", fmt.Errorf("no session_token in redirect_uri for auto-solve")
	}
	if captchaErr.RedirectURI == "" {
		return "", fmt.Errorf("no redirect_uri for auto-solve")
	}

	bootstrap, err := fetchCaptchaBootstrap(ctx, captchaErr.RedirectURI, httpClient, profile)
	if err != nil {
		return "", fmt.Errorf("failed to fetch captcha bootstrap: %w", err)
	}

	turnLog("[STREAM %d] [Captcha] PoW input: %s, difficulty: %d", streamID, bootstrap.PowInput, bootstrap.Difficulty)

	hexHash, nonce, ok := solvePoW(bootstrap.PowInput, bootstrap.Difficulty)
	if !ok {
		return "", fmt.Errorf("PoW solve exhausted")
	}
	hash := formatPoWResult(hexHash, nonce, buildCaptchaTelemetry(profile))
	turnLog("[STREAM %d] [Captcha] PoW solved: nonce=%d (v2-wrapped)", streamID, nonce)

	var successToken string
	if useSliderPOC {
		successToken, err = callCaptchaNotRobotWithSliderPOC(
			ctx,
			captchaErr.SessionToken,
			hash,
			streamID,
			client,
			profile,
			bootstrap.Settings,
			bootstrap.DebugInfo,
			adFp,
			httpClient,
		)
	} else {
		successToken, err = callCaptchaNotRobot(ctx, captchaErr.SessionToken, hash, bootstrap.DebugInfo, adFp, streamID, client, profile, httpClient)
	}
	if err != nil {
		return "", fmt.Errorf("captchaNotRobot API failed: %w", err)
	}

	turnLog("[STREAM %d] [Captcha] Success! Got success_token", streamID)
	return successToken, nil
}


// applyCaptchaHeadersHTTP sets Chrome-style headers on net/http captcha requests.
func applyCaptchaHeadersHTTP(req *http.Request, profile Profile) {
        req.Header.Set("Accept", "*/*")
        req.Header.Set("Accept-Language", "en-US,en;q=0.9")
        req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
        req.Header.Set("Origin", "https://id.vk.ru")
        req.Header.Set("Referer", "https://id.vk.ru/")
        req.Header.Set("sec-ch-ua", profile.SecChUa)
        req.Header.Set("sec-ch-ua-mobile", profile.SecChUaMobile)
        req.Header.Set("sec-ch-ua-platform", profile.SecChUaPlatform)
        req.Header.Set("Sec-Fetch-Dest", "empty")
        req.Header.Set("Sec-Fetch-Mode", "cors")
        req.Header.Set("Sec-Fetch-Site", "same-site")
        req.Header.Set("User-Agent", profile.UserAgent)
}

// applyBrowserProfileHTTP mirrors applyBrowserProfileFhttp for net/http.
func applyBrowserProfileHTTP(req *http.Request, profile Profile) {
        req.Header.Set("User-Agent", profile.UserAgent)
        req.Header.Set("sec-ch-ua", profile.SecChUa)
        req.Header.Set("sec-ch-ua-mobile", profile.SecChUaMobile)
        req.Header.Set("sec-ch-ua-platform", profile.SecChUaPlatform)
        req.Header.Set("Accept-Language", "en-US,en;q=0.9")
}


// buildCaptchaTelemetry replicates the browser telemetry payload embedded by
// the captcha page PoW solver (30 probes, Chrome/Win10 desktop profile).
func buildCaptchaTelemetry(profile Profile) map[string]interface{} {
        probe := func(result interface{}, d float64) map[string]interface{} {
                return map[string]interface{}{"ok": true, "result": result, "duration_ms": d}
        }
        return map[string]interface{}{
                "globals": probe(map[string]interface{}{
                        "doc": true, "win": true, "nav": true, "webdriver": false,
                        "subtle": true, "secure": true, "gcs": true, "raf": true, "wasm": true,
                        "plugins_len": 5, "languages_len": 1, "hw": 8, "mem": 8,
                }, 0.2),
                "ua": probe(map[string]interface{}{
                        "userAgent": profile.UserAgent,
                        "userAgentData": map[string]interface{}{
                                "brands": []map[string]interface{}{
                                        {"brand": "Chromium", "version": "146.0.0.0"},
                                        {"brand": "Google Chrome", "version": "146.0.0.0"},
                                        {"brand": "Not=A?Brand", "version": "24.0.0.0"},
                                },
                                "platform":     "Windows",
                                "mobile":       false,
                                "architecture": "x86",
                        },
                }, 0.3),
                "frame": probe(map[string]interface{}{
                        "frameElement": "set", "ancestorOriginsLen": 1, "parentAccessible": false,
                }, 0.1),
                "match_media": probe(map[string]interface{}{
                        "prefersDark": false, "prefersLight": true, "reducedMotion": false, "pointerFine": true,
                }, 0.1),
                "plugins": probe(map[string]interface{}{
                        "length":       5,
                        "names":        []string{"PDF Viewer", "Chrome PDF Viewer", "Chromium PDF Viewer", "Microsoft Edge PDF Viewer", "WebKit built-in PDF"},
                        "descriptions": []string{"Portable Document Format", "Portable Document Format", "Portable Document Format", "Portable Document Format", "Portable Document Format"},
                        "mimeTypes": []map[string]interface{}{
                                {"type": "application/pdf", "suffixes": "pdf", "description": "Portable Document Format"},
                                {"type": "text/pdf", "suffixes": "pdf", "description": "Portable Document Format"},
                        },
                        "isChrome": true,
                }, 0.2),
                "nav_tamper": probe(map[string]interface{}{
                        "tampered": false, "el_ctor": "HTMLDivElement", "style_ctor": "CSSStyleDeclaration",
                        "nav_ctor": "Navigator", "alert_native": true, "to_string_native": true,
                }, 0.1),
                "referrer": probe(map[string]interface{}{
                        "referrer": "", "inIframe": true, "domain": "id.vk.ru",
                }, 0.1),
                "devtools": probe(map[string]interface{}{
                        "open": false, "delay_ms": 0,
                }, 0.1),
                "css": probe(map[string]interface{}{
                        "expectedMissing": 0,
                }, 0.1),
                "native_integrity": probe(map[string]interface{}{
                        "protoMatch": true, "xhrNative": true, "xhrSendNative": true,
                        "addEventListenerNative": true, "alertNative": true, "toStringNative": true,
                }, 0.1),
                "cookie_test": probe(map[string]interface{}{
                        "write": true,
                }, 0.1),
                "ancestor_origins": probe(map[string]interface{}{
                        "ancestorOrigin": "https://id.vk.ru",
                }, 0.1),
                "sandbox_behavior": probe(map[string]interface{}{
                        "originIsNull": false, "localStorage": true, "sessionStorage": true,
                }, 0.1),
                "max_touch_points": probe(map[string]interface{}{
                        "maxTouchPoints": 0,
                }, 0.1),
                "timezone_locale": probe(map[string]interface{}{
                        "timezone": "Europe/Moscow", "languages": []string{"en-US", "ru"}, "tz_offset": -180,
                }, 0.1),
                "device_pixel_ratio": probe(map[string]interface{}{
                        "dpr": 1, "orientation": "landscape-primary", "orientationAngle": 0,
                }, 0.1),
                "webgl": probe(map[string]interface{}{
                        "vendor": "Google Inc. (NVIDIA)", "renderer": "ANGLE (NVIDIA, NVIDIA GeForce GTX 1650 (0x00001F82) Direct3D11 vs_5_0 ps_5_0, D3D11)",
                        "available": true, "glsl_version": "WebGL GLSL ES 1.0 (OpenGL ES GLSL ES 1.0 Chromium)",
                        "max_texture_size": 16384, "extensions": []string{"ANGLE_instanced_arrays", "EXT_blend_minmax", "EXT_color_buffer_half_float", "EXT_disjoint_timer_query", "EXT_float_blend", "EXT_texture_compression_bptc", "OES_element_index_uint", "OES_standard_derivatives", "OES_texture_float", "OES_texture_half_float", "WEBGL_debug_renderer_info"},
                        "timedOut": false,
                }, 8.4),
                "chrome_runtime": probe(map[string]interface{}{
                        "present": true,
                }, 0.1),
                "audio_sig": probe(map[string]interface{}{
                        "hash": 258.0685760895704, "timedOut": false,
                }, 12.7),
                "reflow_timing": probe(map[string]interface{}{
                        "timings": []float64{0.156, 0.201, 0.178}, "timedOut": false,
                }, 1.2),
                "dom_chain": probe(map[string]interface{}{
                        "hash": 482193042, "iterations": 4,
                }, 0.9),
                "wasm": probe(map[string]interface{}{
                        "instantiated": true, "result": 7, "duration_ms": 3.1, "loop_ms": 0.4,
                }, 3.6),
                "subpixel_font": probe(map[string]interface{}{
                        "widths": []int{72, 78, 66}, "timedOut": false,
                }, 0.8),
                "timing_baseline": probe(map[string]interface{}{
                        "cpu": []float64{0.104, 0.101, 0.105}, "res": []float64{1.047, 1.039, 1.042, 1.051, 1.044}, "timedOut": false,
                }, 2.9),
                "canvas_fingerprint": probe(map[string]interface{}{
                        "hash": "a1f3c2e9d4b5", "timedOut": false,
                }, 1.8),
                "font_enumeration": probe(map[string]interface{}{
                        "available": []string{"Arial", "Verdana", "Times New Roman", "Courier New", "Georgia", "Trebuchet MS", "Tahoma", "Segoe UI", "Consolas", "Roboto"},
                        "timedOut": false,
                }, 1.1),
                "shadow_dom_check": probe(map[string]interface{}{
                        "customElements": true, "shadowDom": true,
                }, 0.1),
                "ua_high_entropy": probe(map[string]interface{}{
                        "platform": "Windows", "platformVersion": "15.0.0", "architecture": "x86",
                        "model": "", "uaFullVersion": "146.0.7410.0",
                        "fullVersionList": []map[string]interface{}{
                                {"brand": "Chromium", "version": "146.0.7410.0"},
                                {"brand": "Google Chrome", "version": "146.0.7410.0"},
                                {"brand": "Not=A?Brand", "version": "24.0.0.0"},
                        },
                        "bitness": "64", "formFactors": []string{"Desktop"}, "wow64": false,
                }, 1.4),
                "visibility_raf": probe(map[string]interface{}{
                        "visibilityState": "visible", "frames": 17, "fps": 57, "durationMs": 300.128, "hiddenMs": 0,
                }, 305.2),
        }
}

// marshalStableJSON mirrors JS stableStringify: sorted keys, compact, no HTML escaping.
func marshalStableJSON(v interface{}) ([]byte, error) {
        var buf bytes.Buffer
        enc := json.NewEncoder(&buf)
        enc.SetEscapeHTML(false)
        if err := enc.Encode(v); err != nil {
                return nil, err
        }
        return bytes.TrimRight(buf.Bytes(), "\n"), nil
}

func stableTelemetryHash(telemetry map[string]interface{}) string {
        if telemetry == nil {
                return ""
        }
        data, err := marshalStableJSON(telemetry)
        if err != nil {
                return ""
        }
        sum := sha256.Sum256(data)
        return hex.EncodeToString(sum[:])
}

// generateAdFpId replicates VK sync-loader nanoid: 21 chars, charset [0-9a-zA-Z_-].
func generateAdFpId() string {
        const charset = "0123456789abcdefghijklmnopqrstuvwxyz"
        var raw [21]byte
        if _, err := crand.Read(raw[:]); err != nil {
                for i := range raw {
                        raw[i] = byte(rand.Intn(256))
                }
        }
        out := make([]byte, len(raw))
        for i, v := range raw {
                v &= 63
                switch {
                case v < 36:
                        out[i] = charset[v]
                case v < 62:
                        out[i] = charset[v-26] - 32
                case v == 62:
                        out[i] = '_'
                default:
                        out[i] = '-'
                }
        }
        return string(out)
}

// registerAdFpFingerprint mirrors sync-loader.js POST to privacy-cs.mail.ru/fp/
// (registers the adFp id server-side, as a real browser does).
func registerAdFpFingerprint(ctx context.Context, adFp string, profile Profile, httpClient *http.Client) {
        pluginsHash := fmt.Sprintf("%032x", md5.Sum([]byte(adFp+"plugins")))
        propsHash := fmt.Sprintf("%032x", md5.Sum([]byte(adFp+"props")))
        payload := fmt.Sprintf(
                `{"script":{"v":"v4.0.3","b_id":"152552442"},"navigator":{"language":"en-US (en-US)","plugins_hash":"%s","properties_hash":"%s","userAgent":"%s"},"screen":{"availableScreenResolution":"1920;1040","screenResolution":"1920;1080"},"sendReason":1}`,
                pluginsHash, propsHash, profile.UserAgent,
        )
        reqURL := "https://privacy-cs.mail.ru/fp/?id=" + adFp
        req, err := http.NewRequestWithContext(ctx, "POST", reqURL, strings.NewReader(payload))
        if err != nil {
                turnLog("[Captcha] adFp registration: request build failed: %v", err)
                return
        }
        applyBrowserProfileHTTP(req, profile)
        req.Header.Set("Content-Type", "application/json")
        req.Header.Set("Accept", "*/*")
        req.Header.Set("Origin", "https://id.vk.ru")
        req.Header.Set("Referer", "https://id.vk.ru/")
        req.Header.Set("Sec-Fetch-Site", "cross-site")
        req.Header.Set("Sec-Fetch-Mode", "cors")
        req.Header.Set("Sec-Fetch-Dest", "empty")
        resp, err := httpClient.Do(req)
        if err != nil {
                turnLog("[Captcha] adFp registration failed (continuing): %v", err)
                return
        }
        defer func(Body io.ReadCloser) { _ = Body.Close() }(resp.Body)
        _, _ = io.Copy(io.Discard, resp.Body)
        turnLog("[Captcha] adFp registered: %s (fp HTTP %d)", adFp, resp.StatusCode)
}

func applyBrowserProfileFhttp(req *fhttp.Request, profile Profile) {
	req.Header.Set("User-Agent", profile.UserAgent)
	req.Header.Set("sec-ch-ua", profile.SecChUa)
	req.Header.Set("sec-ch-ua-mobile", profile.SecChUaMobile)
	req.Header.Set("sec-ch-ua-platform", profile.SecChUaPlatform)
	req.Header.Set("Accept-Language", "en-US,en;q=0.9")
	req.Header.Set("DNT", "1")
}

func generateBrowserFp(profile Profile) string {
	data := profile.UserAgent + profile.SecChUa + "1920x1080x24" + strconv.FormatInt(time.Now().UnixNano(), 10)
	h := md5.Sum([]byte(data))
	return fmt.Sprintf("%x", h)
}

func generateFakeCursor() string {
	startX := 600 + rand.Intn(400)
	startY := 300 + rand.Intn(200)
	startTime := time.Now().UnixMilli() - int64(rand.Intn(2000)+1000)
	var points []string
	for i := 0; i < 15+rand.Intn(10); i++ {
		startX += rand.Intn(15) - 5
		startY += rand.Intn(15) + 2
		startTime += int64(rand.Intn(40) + 10)
		points = append(points, fmt.Sprintf(`{"x":%d,"y":%d,"t":%d}`, startX, startY, startTime))
	}
	return "[" + strings.Join(points, ",") + "]"
}

func fetchCaptchaBootstrap(ctx context.Context, redirectURI string, httpClient *http.Client, profile Profile) (*captchaBootstrap, error) {
	parsedURL, err := neturl.Parse(redirectURI)
	if err != nil {
		return nil, err
	}
	domain := parsedURL.Hostname()

	_ = domain
	req, err := http.NewRequestWithContext(ctx, "GET", redirectURI, nil)
	if err != nil {
		return nil, err
	}

	applyBrowserProfileHTTP(req, profile)
	req.Header.Set("Sec-Fetch-Site", "none")
	req.Header.Set("Sec-Fetch-Mode", "navigate")
	req.Header.Set("Sec-Fetch-Dest", "document")
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")

	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer func(Body io.ReadCloser) {
		_ = Body.Close()
	}(resp.Body)

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	// BUG-011: debug_info (brlefapmjnpg) is per-page-load, must be sent fresh
	debugInfo := ""
	if m := regexp.MustCompile(`brlefapmjnpg:\s*"([^"]+)"`).FindStringSubmatch(string(body)); len(m) >= 2 {
		debugInfo = m[1]
	}
	// Debug: log HTML length and check for pow_timeout pattern
	log.Printf("[Captcha] Bootstrap HTML length: %d, contains pow_timeout: %v", len(body), strings.Contains(string(body), "pow_timeout"))
	// Log last 300 chars to see if BFF JS is present
	htmlStr := string(body)
	if len(htmlStr) > 300 {
		log.Printf("[Captcha] HTML tail: ...%s", htmlStr[len(htmlStr)-300:])
	}
	result, perr := parseCaptchaBootstrapHTML(htmlStr)
	if perr != nil {
		return nil, perr
	}
	result.DebugInfo = debugInfo
	return result, nil
}

func solvePoW(powInput string, difficulty int) (string, int, bool) {
	target := strings.Repeat("0", difficulty)
	for nonce := 1; nonce <= 10000000; nonce++ {
		data := powInput + strconv.Itoa(nonce)
		hash := sha256.Sum256([]byte(data))
		hexHash := hex.EncodeToString(hash[:])
		if strings.HasPrefix(hexHash, target) {
			return hexHash, nonce, true
		}
	}
	return "", 0, false
}

func formatPoWResult(hexHash string, nonce int, telemetry map[string]interface{}) string {
	durationMs := 90 + rand.Intn(260)
	payload := map[string]interface{}{
		"hash":        hexHash,
		"nonce":       nonce,
		"error":       "",
		"duration_ms": durationMs,
		"telemetry":   telemetry,
		"tel_hash":    stableTelemetryHash(telemetry),
	}
	data, err := marshalStableJSON(payload)
	if err != nil {
		data = []byte(fmt.Sprintf(`{"hash":%q,"nonce":%d}`, hexHash, nonce))
	}
	return "v2." + base64.StdEncoding.EncodeToString(data)
}

const captchaDebugInfoHardcoded = "4045edac1cb2c18eff209dc09cd5e2e56475a13ed4615413a87618b3c6813f9a"

func generateConnectionRtt(n int) string {
	if n <= 0 { n = 10 }
	base := 45 + rand.Intn(40)
	parts := make([]string, 0, n)
	for i := 0; i < n; i++ {
		jitter := rand.Intn(41) - 10
		if rand.Intn(8) == 0 { jitter += 30 + rand.Intn(60) }
		val := base + jitter
		if val < 5 { val = 5 }
		parts = append(parts, strconv.Itoa(val))
	}
	return "[" + strings.Join(parts, ",") + "]"
}

func generateConnectionDownlink(n int) string {
	if n <= 0 { n = 16 }
	baseTenths := 50 + rand.Intn(100)
	parts := make([]string, 0, n)
	for i := 0; i < n; i++ {
		jitter := rand.Intn(7) - 3
		t := baseTenths + jitter
		if t < 10 { t = 10 }
		parts = append(parts, fmt.Sprintf("%.1f", float64(t)/10.0))
	}
	return "[" + strings.Join(parts, ",") + "]"
}

func callCaptchaNotRobot(ctx context.Context, sessionToken, hash, debugInfo, adFp string, streamID int, _client tlsclient.HttpClient, profile Profile, httpClient *http.Client) (string, error) {
	vkReq := func(method string, postData string) (map[string]interface{}, error) {
		reqURL := "https://api.vk.ru/method/" + method + "?v=5.131"

		req, err := http.NewRequestWithContext(ctx, "POST", reqURL, strings.NewReader(postData))
		if err != nil {
			return nil, err
		}

		applyCaptchaHeadersHTTP(req, profile)

		httpResp, err := httpClient.Do(req)
		if err != nil {
			return nil, err
		}
		defer func(Body io.ReadCloser) {
			_ = Body.Close()
		}(httpResp.Body)

		body, err := io.ReadAll(httpResp.Body)
		if err != nil {
			return nil, err
		}
		var resp map[string]interface{}
		if err := json.Unmarshal(body, &resp); err != nil {
			return nil, err
		}
		return resp, nil
	}

	baseParams := fmt.Sprintf("session_token=%s&domain=vk.com&adFp=%s&access_token=", neturl.QueryEscape(sessionToken), neturl.QueryEscape(adFp))
	initParams := baseParams + "&lang=3"

	// Step 0: initSession — VK's JS always calls this before settings
	turnLog("[STREAM %d] [Captcha] Step 0/4: initSession", streamID)
	if initResp, err := vkReq("captchaNotRobot.initSession", initParams); err != nil {
		turnLog("[STREAM %d] [Captcha] Warning: initSession failed: %v", streamID, err)
	} else if respObj, ok := initResp["response"].(map[string]interface{}); ok {
		if showType, _ := respObj["show_captcha_type"].(string); showType != "" {
			turnLog("[STREAM %d] [Captcha] initSession: show_captcha_type=%s", streamID, showType)
		}
	}
	time.Sleep(200 * time.Millisecond)

	turnLog("[STREAM %d] [Captcha] Step 1/4: settings", streamID)
	if _, err := vkReq("captchaNotRobot.settings", baseParams); err != nil {
		return "", fmt.Errorf("settings failed: %w", err)
	}

	time.Sleep(200 * time.Millisecond)

	turnLog("[STREAM %d] [Captcha] Step 2/4: componentDone", streamID)
	browserFp := generateBrowserFp(profile)
	deviceJSON := buildCaptchaDeviceJSON(profile)
	componentDoneData := baseParams + fmt.Sprintf("&browser_fp=%s&device=%s", browserFp, neturl.QueryEscape(deviceJSON))

	if _, err := vkReq("captchaNotRobot.componentDone", componentDoneData); err != nil {
		return "", fmt.Errorf("componentDone failed: %w", err)
	}

	time.Sleep(200 * time.Millisecond)

	// BUG-011: human interaction pause (cursor sampling time)
	humanPause := time.Duration(4200+rand.Intn(1300)) * time.Millisecond
	turnLog("[STREAM %d] [Captcha] Emulating interaction (%v)...", streamID, humanPause)
	time.Sleep(humanPause)

	turnLog("[STREAM %d] [Captcha] Step 3/4: check", streamID)
	cursorJSON := "[]"
	answer := base64.StdEncoding.EncodeToString([]byte("{}"))

	if debugInfo == "" {
		debugInfo = captchaDebugInfoHardcoded
	}

	checkData := baseParams + fmt.Sprintf(
		"&accelerometer=%s&gyroscope=%s&motion=%s&cursor=%s&taps=%s&browser_fp=%s&hash=%s&answer=%s&debug_info=%s",
		neturl.QueryEscape("[]"), neturl.QueryEscape("[]"), neturl.QueryEscape("[]"),
		neturl.QueryEscape(cursorJSON), neturl.QueryEscape("[]"),
		browserFp, hash, answer, debugInfo,
	)

	checkResp, err := vkReq("captchaNotRobot.check", checkData)
	if err != nil {
		return "", fmt.Errorf("check failed: %w", err)
	}

	respObj, ok := checkResp["response"].(map[string]interface{})
	if !ok {
		return "", fmt.Errorf("invalid check response: %v", checkResp)
	}
	status, ok := respObj["status"].(string)
	if !ok || status != "OK" {
		return "", fmt.Errorf("check status: %s", status)
	}
	successToken, ok := respObj["success_token"].(string)
	if !ok || successToken == "" {
		return "", fmt.Errorf("success_token not found")
	}

	time.Sleep(200 * time.Millisecond)

	turnLog("[STREAM %d] [Captcha] Step 4/4: endSession", streamID)
	_, err = vkReq("captchaNotRobot.endSession", baseParams)
	if err != nil {
		turnLog("[STREAM %d] [Captcha] Warning: endSession failed: %v", streamID, err)
	}

	return successToken, nil
}