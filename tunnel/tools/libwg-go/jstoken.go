/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (C) 2026 NikKuz99. All Rights Reserved.
 *
 * jstoken.go — minimal JavaScript lexer for the captcha bootstrap parser.
 *
 * VK serves the PoW seed inside an obfuscated self-invoking function call
 * embedded as an inline <script> in the captcha HTML page.  The obfuscator
 * (VK build step "tools/pow-obfuscate/obfuscate.mjs") periodically changes
 * the REPRESENTATION of that call — quote style ('...' vs "..."), spacing,
 * hex vs decimal numbers (2 vs 0x2) — while keeping the STRUCTURE stable:
 *
 *   (function(_0xa,_0xb,_0xc,_0xd){ ... })(
 *       "<powInput>", <difficulty>, "pow_timeout", ["frame","cookie_test",...]
 *   );
 *
 * History: BUG-007 (2026-09-07, powInput moved into the call args),
 * BUG-013 (2026-09-25, quotes flipped from double to single).  Both broke
 * regex-based extraction because regexes encode representation.
 *
 * This lexer encodes structure instead: it turns script text into a token
 * stream that is immune to quote style, spacing and number-base changes.
 * pow_extract.go walks the stream to recover the call argument list.
 *
 * The lexer is deliberately best-effort: it never fails, it just stops at
 * the end of input.  Callers that need perfect JS parsing should use a real
 * parser; here we only need strings, numbers and punctuation to be right,
 * which keeps the whole thing dependency-free (stdlib only, no CGO —
 * required for the Android gomobile build and the static desktop build).
 */
package main

// jsTokenKind classifies tokens produced by lexJS.
type jsTokenKind int

const (
        jsTString   jsTokenKind = iota // '...' or "..." with escapes resolved
        jsTNumber                      // 12, 0x2, 3.5, 1e3, 0n
        jsTIdent                       // identifier or keyword
        jsTPunct                       // operator / punctuation
        jsTTemplate                    // `...` kept raw (values not needed here)
        jsTRegex                       // /.../ flags — skipped by extractors
)

// jsToken is one lexical token.  Pos is the byte offset of the token start
// in the source (diagnostics only).  For strings, Val holds the escape-
// resolved value; for everything else Val is the literal source text.
type jsToken struct {
        Kind jsTokenKind
        Val  string
        Pos  int
}

// jsPunctOps lists multi-character operators, longest first, so that the
// lexer prefers the longest match.  Order within the same length does not
// matter because the lookup uses the sorted-by-length list below.
var jsPunctOps = []string{
        ">>>=", "...", "===", "!==", "**=", "<<=", ">>=", ">>>", "&&=", "||=", "??=",
        "=>", "==", "!=", "<=", ">=", "&&", "||", "??", "?.", "++", "--",
        "+=", "-=", "*=", "/=", "%=", "&=", "|=", "^=", "<<", ">>",
}

// jsRegexPrecKw are keywords after which a '/' starts a regex literal
// rather than a division.  This is the standard lexer heuristic.
var jsRegexPrecKw = map[string]bool{
        "return": true, "typeof": true, "instanceof": true, "in": true, "of": true,
        "new": true, "delete": true, "void": true, "case": true, "do": true,
        "else": true, "throw": true, "yield": true, "await": true,
}

// lexJS tokenizes src.  Comments and whitespace are skipped.  The function
// is tolerant: on anything unexpected it emits a single-character punct
// token and continues, so a malformed region degrades into junk tokens
// instead of aborting the whole stream.
func lexJS(src string) []jsToken {
        var toks []jsToken
        i, n := 0, len(src)

        prevIsRegexPos := func() bool {
                if len(toks) == 0 {
                        return true // start of input
                }
                last := toks[len(toks)-1]
                switch last.Kind {
                case jsTIdent:
                        return jsRegexPrecKw[last.Val]
                case jsTNumber, jsTString, jsTTemplate, jsTRegex:
                        return false
                case jsTPunct:
                        switch last.Val {
                        case ")", "]", "}", "++", "--":
                                return false
                        default:
                                return true
                        }
                }
                return true
        }

        for i < n {
                c := src[i]

                // Whitespace
                if c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '\v' || c == '\f' {
                        i++
                        continue
                }

                // Comments
                if c == '/' && i+1 < n {
                        if src[i+1] == '/' {
                                for i < n && src[i] != '\n' {
                                        i++
                                }
                                continue
                        }
                        if src[i+1] == '*' {
                                i += 2
                                for i+1 < n && !(src[i] == '*' && src[i+1] == '/') {
                                        i++
                                }
                                if i+1 < n {
                                        i += 2
                                } else {
                                        i = n
                                }
                                continue
                        }
                }

                start := i

                // Strings
                if c == '\'' || c == '"' {
                        quote := c
                        i++
                        var b []byte
                        closed := false
                        for i < n {
                                ch := src[i]
                                if ch == quote {
                                        i++
                                        closed = true
                                        break
                                }
                                if ch == '\\' && i+1 < n {
                                        i++
                                        esc := src[i]
                                        switch esc {
                                        case 'n':
                                                b = append(b, '\n')
                                        case 't':
                                                b = append(b, '\t')
                                        case 'r':
                                                b = append(b, '\r')
                                        case 'b':
                                                b = append(b, '\b')
                                        case 'f':
                                                b = append(b, '\f')
                                        case 'v':
                                                b = append(b, '\v')
                                        case '0':
                                                b = append(b, 0)
                                        case 'x':
                                                if i+2 < n {
                                                        if v, ok := parseHexPair(src[i+1], src[i+2]); ok {
                                                                b = append(b, v)
                                                                i += 2
                                                        } else {
                                                                b = append(b, 'x')
                                                        }
                                                } else {
                                                        b = append(b, 'x')
                                                }
                                        case 'u':
                                                if i+4 < n && isHexDigit(src[i+1]) && isHexDigit(src[i+2]) &&
                                                        isHexDigit(src[i+3]) && isHexDigit(src[i+4]) {
                                                        v := 0
                                                        for _, d := range []byte{src[i+1], src[i+2], src[i+3], src[i+4]} {
                                                                v = v*16 + hexVal(d)
                                                        }
                                                        b = append(b, []byte(string(rune(v)))...)
                                                        i += 4
                                                } else if i+1 < n && src[i+1] == '{' {
                                                        // \u{NNNN}
                                                        j := i + 2
                                                        v := 0
                                                        for j < n && isHexDigit(src[j]) {
                                                                v = v*16 + hexVal(src[j])
                                                                j++
                                                        }
                                                        if j < n && src[j] == '}' && v < 0x110000 {
                                                                b = append(b, []byte(string(rune(v)))...)
                                                                i = j
                                                        } else {
                                                                b = append(b, 'u')
                                                        }
                                                } else {
                                                        b = append(b, 'u')
                                                }
                                        case '\n':
                                                // line continuation — produce nothing
                                        default:
                                                b = append(b, esc)
                                        }
                                        i++
                                        continue
                                }
                                if ch == '\n' {
                                        // unterminated string at newline — stop here, tolerate
                                        break
                                }
                                b = append(b, ch)
                                i++
                        }
                        _ = closed
                        toks = append(toks, jsToken{Kind: jsTString, Val: string(b), Pos: start})
                        continue
                }

                // Template literal — skip raw, tracking ${ } nesting and inner strings.
                // When the literal has no ${...} substitution, Val carries the text
                // (escapes resolved lightly) so callers can classify it like a string.
                if c == '`' {
                        i++
                        depth := 0
                        var b []byte
                        for i < n {
                                ch := src[i]
                                if ch == '\\' && i+1 < n {
                                        if depth == 0 && src[i+1] != '`' {
                                                b = append(b, src[i+1])
                                        }
                                        i += 2
                                        continue
                                }
                                if depth == 0 && ch == '`' {
                                        i++
                                        break
                                }
                                if ch == '$' && i+1 < n && src[i+1] == '{' {
                                        depth++
                                        i += 2
                                        continue
                                }
                                if depth > 0 && ch == '{' {
                                        depth++
                                }
                                if depth > 0 && ch == '}' {
                                        depth--
                                }
                                if depth == 0 {
                                        b = append(b, ch)
                                }
                                i++
                        }
                        toks = append(toks, jsToken{Kind: jsTTemplate, Val: string(b), Pos: start})
                        continue
                }

                // Numbers (hex/oct/bin/decimal/float/exponent/BigInt)
                if isDecDigit(c) || (c == '.' && i+1 < n && isDecDigit(src[i+1])) {
                        j := i
                        if c == '0' && i+1 < n {
                                switch src[i+1] {
                                case 'x', 'X':
                                        j = i + 2
                                        for j < n && (isHexDigit(src[j]) || src[j] == '_') {
                                                j++
                                        }
                                case 'o', 'O':
                                        j = i + 2
                                        for j < n && (isOctDigit(src[j]) || src[j] == '_') {
                                                j++
                                        }
                                case 'b', 'B':
                                        j = i + 2
                                        for j < n && (src[j] == '0' || src[j] == '1' || src[j] == '_') {
                                                j++
                                        }
                                }
                        }
                        if j == i { // decimal path
                                for j < n && (isDecDigit(src[j]) || src[j] == '_') {
                                        j++
                                }
                                if j < n && src[j] == '.' {
                                        j++
                                        for j < n && (isDecDigit(src[j]) || src[j] == '_') {
                                                j++
                                        }
                                }
                                if j < n && (src[j] == 'e' || src[j] == 'E') {
                                        k := j + 1
                                        if k < n && (src[k] == '+' || src[k] == '-') {
                                                k++
                                        }
                                        if k < n && isDecDigit(src[k]) {
                                                j = k
                                                for j < n && isDecDigit(src[j]) {
                                                        j++
                                                }
                                        }
                                }
                        }
                        if j < n && (src[j] == 'n' || src[j] == 'N') { // BigInt suffix
                                j++
                        }
                        toks = append(toks, jsToken{Kind: jsTNumber, Val: src[i:j], Pos: start})
                        i = j
                        continue
                }

                // Identifiers / keywords
                if isIdentStart(rune(c)) || c >= 0x80 {
                        j := i
                        for j < n && (src[j] >= 0x80 || isIdentPart(rune(src[j]))) {
                                j++
                        }
                        toks = append(toks, jsToken{Kind: jsTIdent, Val: src[i:j], Pos: start})
                        i = j
                        continue
                }

                // '/' — regex literal or division
                if c == '/' {
                        if prevIsRegexPos() {
                                j := i + 1
                                inClass := false
                                okRegex := false
                                for j < n {
                                        ch := src[j]
                                        if ch == '\\' && j+1 < n {
                                                j += 2
                                                continue
                                        }
                                        if ch == '\n' {
                                                break // regexes cannot span lines — treat as division
                                        }
                                        if inClass {
                                                if ch == ']' {
                                                        inClass = false
                                                }
                                        } else if ch == '[' {
                                                inClass = true
                                        } else if ch == '/' {
                                                j++
                                                // flags
                                                for j < n && isIdentPart(rune(src[j])) {
                                                        j++
                                                }
                                                okRegex = true
                                                break
                                        }
                                        j++
                                }
                                if okRegex {
                                        toks = append(toks, jsToken{Kind: jsTRegex, Val: src[i:j], Pos: start})
                                        i = j
                                        continue
                                }
                        }
                        toks = append(toks, jsToken{Kind: jsTPunct, Val: "/", Pos: start})
                        i++
                        continue
                }

                // Multi-char punctuation
                matched := false
                for _, op := range jsPunctOps {
                        if i+len(op) <= n && src[i:i+len(op)] == op {
                                toks = append(toks, jsToken{Kind: jsTPunct, Val: op, Pos: start})
                                i += len(op)
                                matched = true
                                break
                        }
                }
                if matched {
                        continue
                }

                // Single-char punctuation (includes '#')
                toks = append(toks, jsToken{Kind: jsTPunct, Val: string(c), Pos: start})
                i++
        }

        return toks
}

func isDecDigit(b byte) bool { return b >= '0' && b <= '9' }
func isOctDigit(b byte) bool { return b >= '0' && b <= '7' }
func isHexDigit(b byte) bool {
        return (b >= '0' && b <= '9') || (b >= 'a' && b <= 'f') || (b >= 'A' && b <= 'F')
}
func hexVal(b byte) int {
        switch {
        case b >= '0' && b <= '9':
                return int(b - '0')
        case b >= 'a' && b <= 'f':
                return int(b-'a') + 10
        default:
                return int(b-'A') + 10
        }
}
func parseHexPair(a, b byte) (byte, bool) {
        if !isHexDigit(a) || !isHexDigit(b) {
                return 0, false
        }
        return byte(hexVal(a)*16 + hexVal(b)), true
}

func isIdentStart(r rune) bool {
        return (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || r == '_' || r == '$'
}
func isIdentPart(r rune) bool {
        return isIdentStart(r) || (r >= '0' && r <= '9')
}
