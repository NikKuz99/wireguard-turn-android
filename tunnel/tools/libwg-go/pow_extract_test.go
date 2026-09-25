/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (C) 2026 NikKuz99. All Rights Reserved.
 *
 * pow_extract_test.go — behavioral tests for the v0.7.0 powInput architecture.
 *
 * Fixtures in testdata/ are derived from the REAL captcha page captured on
 * 2026-09-25 (BUG-013 era) plus synthetic obfuscator-drift variants: quote
 * flips (BUG-007 vs BUG-013), hex difficulty, argument reordering, template
 * literals, a renamed marker (structural layer) and a bare IIFE.
 */
package main

import (
	"os"
	"path/filepath"
	"testing"
)

func loadFixture(t *testing.T, name string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatalf("read fixture %s: %v", name, err)
	}
	return string(b)
}

func TestExtractPowSeedFixtures(t *testing.T) {
	cases := []struct {
		file     string
		wantPow  string
		wantDiff int
	}{
		{"pow_bug013_single.html", "bC2NroTIH2mShJWH", 2},   // real page, single quotes (BUG-013)
		{"pow_bug007_double.html", "bC2NroTIH2mShJWH", 2},   // double quotes (BUG-007 era)
		{"pow_variant_hexnum.html", "bC2NroTIH2mShJWH", 2},  // 0x2 + odd spacing
		{"pow_variant_reordered.html", "bC2NroTIH2mShJWH", 2}, // marker first
		{"pow_variant_backtick.html", "bC2NroTIH2mShJWH", 2}, // template literals
		{"pow_variant_renamed.html", "bC2NroTIH2mShJWH", 2},  // marker renamed -> structural layer
		{"pow_variant_bare_iife.html", "bC2NroTIH2mShJWH", 2}, // !function(){}(...)
		{"real_page.html", "bC2NroTIH2mShJWH", 2},            // the full captured page
	}
	for _, tc := range cases {
		t.Run(tc.file, func(t *testing.T) {
			html := loadFixture(t, tc.file)
			seed, ok := extractPowSeed(html)
			if !ok {
				t.Fatalf("extractPowSeed failed for %s", tc.file)
			}
			if seed.PowInput != tc.wantPow {
				t.Errorf("powInput = %q, want %q (source %s)", seed.PowInput, tc.wantPow, seed.Source)
			}
			if seed.Difficulty != tc.wantDiff {
				t.Errorf("difficulty = %d, want %d (source %s)", seed.Difficulty, tc.wantDiff, seed.Source)
			}
			t.Logf("source: %s, marker: %q", seed.Source, seed.Marker)
		})
	}
}

func TestExtractPowSeedNegative(t *testing.T) {
	html := loadFixture(t, "pow_none.html")
	if seed, ok := extractPowSeed(html); ok {
		t.Fatalf("expected failure on plain page, got %+v", seed)
	}
}

func TestLexJSStrings(t *testing.T) {
	toks := lexJS(`var a = 'it\'s'; var b = "x\"y"; var c = '\x41\u0042'; var d = "line\
cont"; // comment "with quotes"
/* block // comment */ var e = 'pow_timeout';`)
	strs := []string{}
	for _, tok := range toks {
		if tok.Kind == jsTString {
			strs = append(strs, tok.Val)
		}
	}
	want := []string{"it's", `x"y`, "AB", "linecont", "pow_timeout"}
	if len(strs) != len(want) {
		t.Fatalf("strings = %q (len %d), want %q", strs, len(strs), want)
	}
	for i := range want {
		if strs[i] != want[i] {
			t.Errorf("str[%d] = %q, want %q", i, strs[i], want[i])
		}
	}
}

func TestLexJSTemplatesAndRegex(t *testing.T) {
	// Template with nested ${...} and a string inside; regex vs division.
	src := "var s = `a ${'inner'} b`; var r = /a\\/b/g; var q = s / 2 / 1;"
	toks := lexJS(src)
	var kinds []jsTokenKind
	var vals []string
	for _, tok := range toks {
		if tok.Kind == jsTPunct || tok.Kind == jsTTemplate || tok.Kind == jsTRegex {
			kinds = append(kinds, tok.Kind)
			vals = append(vals, tok.Val)
		}
	}
	// must contain exactly one template and one regex; divisions stay punct "/"
	tpl, rgx, div := 0, 0, 0
	for _, k := range kinds {
		switch k {
		case jsTTemplate:
			tpl++
		case jsTRegex:
			rgx++
		}
	}
	for _, v := range vals {
		if v == "/" && toks != nil {
			div++
		}
	}
	if tpl != 1 || rgx != 1 {
		t.Fatalf("templates=%d regex=%d, want 1 and 1 (kinds %v)", tpl, rgx, kinds)
	}
	if div != 2 {
		t.Fatalf("division puncts = %d, want 2", div)
	}
}

func TestParseJSNumber(t *testing.T) {
	cases := map[string]int{
		"2": 2, "0x2": 2, "0X10": 16, "0o7": 7, "0b101": 5,
		"1_0": 10, "3": 3, "2.0": 2, "1e1": 10, "-4": -4,
	}
	for in, want := range cases {
		got, err := parseJSNumber(in)
		if err != nil || got != want {
			t.Errorf("parseJSNumber(%q) = %d, %v; want %d", in, got, err, want)
		}
	}
}

func TestExtractPowSeedNoFalsePositiveOnSettings(t *testing.T) {
	// A settings object mentioning pow_timeout inside an object literal must
	// NOT be classified as a seed call.
	src := `<html><body><script>
	var settings = {"pow_timeout": 30000, "difficulty": 3, "powInput": "notaseed"};
	window.init(settings);
	</script></body></html>`
	if seed, ok := extractPowSeed(src); ok {
		t.Fatalf("false positive: %+v", seed)
	}
}
