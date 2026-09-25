/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (C) 2026 NikKuz99. All Rights Reserved.
 *
 * pow_extract.go — structure-based PoW seed extraction (v0.7.0 architecture).
 *
 * Layered design (first match wins):
 *
 *   L1a  Tokenizer + marker:  lex inline <script> blocks, find the string
 *        literal "pow_timeout", recover the enclosing call's argument list,
 *        classify arguments by TYPE (string/number/array).  Immune to quote
 *        style, spacing and 0x-hex numbers — the failure modes of BUG-007
 *        and BUG-013.
 *
 *   L1b  Tokenizer + structure:  same walk, but WITHOUT depending on the
 *        "pow_timeout" literal.  A call qualifies when it carries an array
 *        of known telemetry component names, exactly one plausible seed
 *        string and a small difficulty number.  Survives marker renames
 *        ("pow_timeout" -> anything).
 *
 *   L1c  Same two passes over the raw HTML (the seed has always lived in
 *        an inline script, but this costs nothing).
 *
 *   L1d  HTML-unescape (&quot; &#34; &#x27; &#39; &amp;) then retry L1a-L1c.
 *
 * Legacy regex patterns (captcha_bootstrap.go) remain as the final safety
 * net for non-obfuscated variants (const powInput = "...", JSON blobs, …).
 *
 * Rejected alternatives (see memory decisions 2026-09-25):
 *   - executing the obfuscated script in an embedded JS engine: feasible in
 *     node (verified: window.captchaPowResult produced in ~390 ms with a
 *     15-line shim), but goja lacks async/await and quickjs needs CGO+NDK —
 *     revisit only if VK changes PoW *semantics*, not representation.
 *   - headless Chrome: not embeddable in an Android app.
 */
package main

import (
        "regexp"
        "strconv"
        "strings"
)

// powSeed is the classified argument list of the PoW seed call.
type powSeed struct {
        PowInput   string
        Difficulty int // 0 = not present in the call; caller falls back to legacy
        Marker     string
        Source     string // "raw/inline/tokenizer-marker", "…/tokenizer-structure", …
}

// knownPowComponents are telemetry component names observed in VK's pow
// obfuscator output ("frame", "cookie_test", …).  The list is a heuristic
// fingerprint: L1b requires several known names to fire, so additions and
// renames of individual components do not break extraction.
var knownPowComponents = map[string]bool{
        "frame": true, "cookie_test": true, "referrer": true, "nav_tamper": true,
        "timezone_locale": true, "plugins": true, "devtools": true, "ua": true,
        "shadow_dom_check": true, "env_viewport": true, "device_pixel_ratio": true,
        "native_integrity": true, "match_media": true, "env_ua": true,
        "max_touch_points": true, "chrome_runtime": true, "media_codecs": true,
        "ancestor_origins": true, "globals": true, "css": true,
        "sandbox_behavior": true, "origin_via_self": true, "font": true,
        "webgl": true, "canvas": true, "audio": true, "battery": true,
        "speech": true, "notification": true, "permissions": true,
}

// powInputShape matches what VK has used as a seed: short base62-ish token.
var powInputShape = regexp.MustCompile(`^[A-Za-z0-9_\-]{6,64}$`)

// inlineScriptRe extracts inline script bodies (src= scripts have empty bodies).
var inlineScriptRe = regexp.MustCompile(`(?is)<script[^>]*>(.*?)</script>`)

// extractPowSeed runs the tokenizer layers over the captcha HTML.
func extractPowSeed(html string) (*powSeed, bool) {
        // L1d preparation: precompute the unescaped variant once.
        unescaped := htmlUnescapeForPow(html)

        for _, pass := range []struct {
                name  string
                input string
        }{
                {"raw", html},
                {"unescaped", unescaped},
        } {
                bodies := []string{}
                for _, m := range inlineScriptRe.FindAllStringSubmatch(pass.input, -1) {
                        if strings.TrimSpace(m[1]) != "" {
                                bodies = append(bodies, m[1])
                        }
                }
                // L1a/L1b over inline scripts
                if seed, ok := extractPowFromBodies(bodies, pass.name+"/inline"); ok {
                        return seed, true
                }
                // L1c: whole HTML as one pseudo-script
                if seed, ok := extractPowFromBodies([]string{pass.input}, pass.name+"/full"); ok {
                        return seed, true
                }
        }
        return nil, false
}

// extractPowFromBodies lexes each body and looks for a qualifying call.
func extractPowFromBodies(bodies []string, label string) (*powSeed, bool) {
        for _, body := range bodies {
                toks := lexJS(body)
                // L1a: every occurrence of the exact marker string.
                for k, t := range toks {
                        if (t.Kind == jsTString || (t.Kind == jsTTemplate && t.Val != "")) && t.Val == "pow_timeout" {
                                if seed, ok := classifyCallAround(toks, k, label+"/tokenizer-marker", true); ok {
                                        return seed, true
                                }
                        }
                }
                // L1b: structure-only scan over every call opener.
                for k, t := range toks {
                        if t.Kind == jsTPunct && t.Val == "(" {
                                if seed, ok := classifyCallAround(toks, k, label+"/tokenizer-structure", false); ok {
                                        return seed, true
                                }
                        }
                }
        }
        return nil, false
}

// classifyCallAround inspects the argument list related to token index k.
//
// markerMode=true: k points at a "pow_timeout" string token; the enclosing
// call opener is located by walking backward.  Acceptance requires the
// marker plus at least one corroborating signal (components array or a
// small difficulty number) and exactly one seed-shaped string argument.
//
// markerMode=false: k points at a "(" token and the whole argument list is
// classified purely structurally (components fingerprint required).
func classifyCallAround(toks []jsToken, k int, source string, markerMode bool) (*powSeed, bool) {
        open := k
        if markerMode {
                open = findEnclosingCallOpen(toks, k)
                if open < 0 {
                        return nil, false
                }
        }

        args, closed := parseCallArgs(toks, open)
        if !closed || len(args) < 3 || len(args) > 6 {
                return nil, false
        }

        seed := &powSeed{Source: source}

        var strArgs []string
        var arrayArg []string
        hasArray := false
        difficulty := 0

        for _, arg := range args {
                switch {
                case len(arg) == 1 && arg[0].Kind == jsTString:
                        strArgs = append(strArgs, arg[0].Val)
                case len(arg) == 1 && arg[0].Kind == jsTTemplate && arg[0].Val != "":
                        // template literal without substitutions behaves like a string
                        strArgs = append(strArgs, arg[0].Val)
                case len(arg) == 1 && arg[0].Kind == jsTNumber:
                        if v, err := parseJSNumber(arg[0].Val); err == nil && v >= 1 && v <= 16 {
                                if difficulty == 0 {
                                        difficulty = v
                                }
                        }
                case len(arg) >= 2 && arg[0].Kind == jsTPunct && arg[0].Val == "[" &&
                        arg[len(arg)-1].Kind == jsTPunct && arg[len(arg)-1].Val == "]":
                        if hasArray {
                                return nil, false // two array args — not our call
                        }
                        hasArray = true
                        for _, t := range arg[1 : len(arg)-1] {
                                if t.Kind == jsTString || (t.Kind == jsTTemplate && t.Val != "") {
                                        arrayArg = append(arrayArg, t.Val)
                                }
                                // non-literal elements (numbers, spread) are ignored
                        }
                default:
                        // complex expression argument (function, object, …) — not our call
                        return nil, false
                }
        }

        // Split string args into marker / seed candidates.
        var seedCandidates []string
        for _, s := range strArgs {
                low := strings.ToLower(s)
                if strings.Contains(low, "pow") || strings.Contains(low, "timeout") || strings.Contains(low, "seed") {
                        if seed.Marker == "" {
                                seed.Marker = s
                        }
                        continue
                }
                if powInputShape.MatchString(s) {
                        seedCandidates = append(seedCandidates, s)
                }
        }

        // Component-name fingerprint.
        known := 0
        for _, c := range arrayArg {
                if knownPowComponents[c] {
                        known++
                }
        }

        if markerMode {
                // The exact "pow_timeout" marker is a strong signal, but require at
                // least one corroborating feature to avoid single-purpose calls like
                // f('pow_timeout') that merely mention the marker.
                if !hasArray && difficulty == 0 {
                        return nil, false
                }
        } else {
                // No marker dependency: the components fingerprint must be strong.
                if !hasArray || known < 4 {
                        return nil, false
                }
        }

        if len(seedCandidates) != 1 {
                return nil, false
        }
        seed.PowInput = seedCandidates[0]
        seed.Difficulty = difficulty
        return seed, true
}

// findEnclosingCallOpen walks backward from the token at index k to the
// "(" that directly opens the argument list containing it.  Returns -1 if
// the token is not a direct argument of a call (e.g. it lives inside an
// array/object literal, or in a function body).
func findEnclosingCallOpen(toks []jsToken, k int) int {
        depth := 0
        for j := k - 1; j >= 0; j-- {
                t := toks[j]
                if t.Kind != jsTPunct {
                        continue
                }
                switch t.Val {
                case ")", "]", "}":
                        depth++
                case "(", "[", "{":
                        if depth == 0 {
                                if t.Val == "(" {
                                        // The token before "(" decides call vs grouping paren:
                                        // `)` (wrapped function expression), `}` (bare IIFE,
                                        // e.g. !function(){}(...)) or an identifier fn(...).
                                        if j > 0 {
                                                p := toks[j-1]
                                                if (p.Kind == jsTPunct && (p.Val == ")" || p.Val == "}")) || p.Kind == jsTIdent {
                                                        return j
                                                }
                                        }
                                }
                                return -1
                        }
                        depth--
                }
        }
        return -1
}

// parseCallArgs splits the top-level comma groups of the argument list that
// starts at toks[open] == "(".  Returns the token slices per argument and
// whether the list was properly closed with a matching ")".
func parseCallArgs(toks []jsToken, open int) ([][]jsToken, bool) {
        if open >= len(toks) || toks[open].Kind != jsTPunct || toks[open].Val != "(" {
                return nil, false
        }
        var args [][]jsToken
        var cur []jsToken
        depth := 0
        for i := open + 1; i < len(toks); i++ {
                t := toks[i]
                if t.Kind == jsTPunct {
                        switch t.Val {
                        case "(", "[", "{":
                                depth++
                        case ")", "]", "}":
                                if depth == 0 {
                                        if t.Val == ")" {
                                                if len(cur) > 0 || len(args) > 0 {
                                                        args = append(args, cur)
                                                }
                                                return args, true
                                        }
                                        return nil, false // ] or } closing at depth 0 — malformed
                                }
                                depth--
                        case ",":
                                if depth == 0 {
                                        args = append(args, cur)
                                        cur = nil
                                        continue
                                }
                        case ";":
                                if depth == 0 {
                                        return nil, false // statement separator — not an arg list
                                }
                        }
                } else if t.Kind == jsTIdent && depth == 0 && len(cur) == 0 {
                        switch t.Val {
                        case "function":
                                // allowed — wrapped function expression (IIFE head)
                        case "return", "var", "let", "const", "if", "for", "while", "do",
                                "switch", "try", "typeof", "new", "delete", "void", "class",
                                "import", "export", "yield", "await", "throw", "else", "case":
                                return nil, false // statement keyword — not a literal arg list
                        }
                }
                cur = append(cur, t)
        }
        return nil, false // unterminated
}

// parseJSNumber understands 0x/0o/0b prefixes, underscores, floats and
// exponents — returning an int when the value is integral.
func parseJSNumber(s string) (int, error) {
        s = strings.ReplaceAll(s, "_", "")
        if strings.HasSuffix(s, "n") || strings.HasSuffix(s, "N") {
                s = s[:len(s)-1]
        }
        neg := false
        if strings.HasPrefix(s, "-") {
                neg = true
                s = s[1:]
        }
        var v int64
        switch {
        case strings.HasPrefix(s, "0x"), strings.HasPrefix(s, "0X"):
                v64, err := strconv.ParseInt(s[2:], 16, 64)
                if err != nil {
                        return 0, err
                }
                v = v64
        case strings.HasPrefix(s, "0o"), strings.HasPrefix(s, "0O"):
                v64, err := strconv.ParseInt(s[2:], 8, 64)
                if err != nil {
                        return 0, err
                }
                v = v64
        case strings.HasPrefix(s, "0b"), strings.HasPrefix(s, "0B"):
                v64, err := strconv.ParseInt(s[2:], 2, 64)
                if err != nil {
                        return 0, err
                }
                v = v64
        case strings.ContainsAny(s, ".eE"):
                f, err := strconv.ParseFloat(s, 64)
                if err != nil {
                        return 0, err
                }
                v = int64(f)
        default:
                v64, err := strconv.ParseInt(s, 10, 64)
                if err != nil {
                        return 0, err
                }
                v = v64
        }
        if neg {
                v = -v
        }
        return int(v), nil
}

// htmlUnescapeForPow decodes the handful of entities that can appear in
// inline scripts inside XHTML-ish captcha pages.
func htmlUnescapeForPow(s string) string {
        r := strings.NewReplacer(
                "&quot;", `"`,
                "&#34;", `"`,
                "&#x22;", `"`,
                "&amp;", "&",
                "&#x27;", "'",
                "&#39;", "'",
        )
        return r.Replace(s)
}
