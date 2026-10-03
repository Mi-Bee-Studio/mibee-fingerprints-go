// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Copyright (c) 2026 Mi-Bee Studio. All rights reserved.
//
// This file is part of mibee-fingerprints-go, distributed under the GNU Affero General
// Public License v3.0 or later. You can use, modify, and redistribute it under
// those terms; see LICENSE for the full text. A commercial license is available
// for use cases the AGPL does not accommodate; see the main repository's LICENSE-COMMERCIAL.md.

package fingerprint

import (
	"strings"
	"testing"
)

// TestMandatoryLiterals exercises the conservative regex→literal extractor on
// pattern shapes that appear across the corpus (and a few adversarial ones).
// Every expectation doubles as a soundness anchor: the returned literal MUST
// occur in every string the pattern matches.
func TestMandatoryLiterals(t *testing.T) {
	cases := []struct {
		pat  string
		want string // "" ⇒ no gate extractable
		ci   bool
	}{
		// Recog-style anchored banner pattern: one long literal run.
		{`^([^ ]{1,512}) Microsoft FTP Service \(Version 5\.0\)\.$`, "Microsoft FTP Service (Version 5.0).", false},
		// Literal head with optional separator + class tail.
		{`OpenSSH[-_ ]?([\d.]{1,32})`, "OpenSSH", false},
		// Case-folded pattern ⇒ CI gate, lowercased.
		{`(?i)huawei`, "huawei", true},
		// Alternation over versions: regexp/syntax itself factors the common
		// prefix, so the AST yields the full case-sensitive literal "Version 5."
		// (more precise than a CI common-prefix gate — either is sound).
		{`(?:Version 5\.0|Version 5\.1)`, "Version 5.", false},
		// Alternation sharing nothing ⇒ no gate.
		{`(?:foo|bar)server`, "server", false},
		// Case-variant branches fold to the same literal ⇒ CI gate.
		{`(?i)(cisco|CISCO)`, "cisco", true},
		// Optional middle: both sides mandatory, longest wins.
		{`foobar(baz)?quux`, "foobar", false},
		// Dynamic-only patterns ⇒ no gate.
		{`^[\d.]{1,64}$`, "", false},
		{`[a-z0-9]+`, "", false},
		// Plus of a literal keeps it mandatory.
		{`Apache[ /]?(\d[\w.]*)`, "Apache", false},
		// Non-ASCII literal ⇒ gate refused (ASCII-only invariant).
		{`München`, "", false},
	}
	for _, tc := range cases {
		lits, ci, ok := mandatoryLiterals(tc.pat)
		if tc.want == "" {
			if ok {
				t.Errorf("pattern %q: expected no gate, got %q ci=%v", tc.pat, lits, ci)
			}
			continue
		}
		if !ok {
			t.Errorf("pattern %q: expected gate %q, got none", tc.pat, tc.want)
			continue
		}
		if len(lits) != 1 {
			t.Errorf("pattern %q: expected 1 literal, got %v", tc.pat, lits)
			continue
		}
		if ci != tc.ci {
			t.Errorf("pattern %q: ci=%v, want %v", tc.pat, ci, tc.ci)
		}
		got := lits[0]
		if ci {
			got = strings.ToLower(got)
		}
		if !strings.Contains(got, tc.want) {
			t.Errorf("pattern %q: got literal %q, want it to contain %q", tc.pat, got, tc.want)
		}
	}
}

// TestGateASCIIGuard: a CI gate must never skip non-ASCII text (Unicode case
// orbits like ſ/s can lower to a string lacking the literal while a folded
// matcher still matches).
func TestGateASCIIGuard(t *testing.T) {
	g := extractGate(matchSpec{Op: "contains", Field: "banner", Value: "switch", CI: true})
	if g == nil {
		t.Fatal("expected gate for contains rule")
	}
	// ASCII text without the literal ⇒ skipped.
	texts := map[gateKey]string{}
	if g.passes(Evidence{RawData: map[string]string{"banner": "plain hub"}}, texts) {
		t.Error("ASCII text without literal should be gated out")
	}
	// Non-ASCII text without the literal ⇒ passed through (matcher decides).
	texts = map[gateKey]string{}
	if !g.passes(Evidence{RawData: map[string]string{"banner": "ſtraño"}}, texts) {
		t.Error("non-ASCII text must never be gated out")
	}
}

// TestExtractGateCompound: compound rules gate on their strongest sub-literal.
func TestExtractGateCompound(t *testing.T) {
	spec := matchSpec{
		Op: "compound",
		And: []matchSpec{
			{Op: "contains", Field: "sys_descr", Value: "Cisco"},
			{Op: "port_eq", Value: 22},
		},
	}
	g := extractGate(spec)
	if g == nil {
		t.Fatal("expected gate from compound")
	}
	if g.field != "sys_descr" || len(g.literals) != 1 || g.literals[0] != "Cisco" {
		t.Errorf("unexpected gate: %+v", g)
	}
	// or-rules must NOT gate on one branch's literal.
	spec = matchSpec{
		Op: "or",
		Any: []matchSpec{
			{Op: "contains", Field: "banner", Value: "Apache"},
			{Op: "contains", Field: "banner", Value: "nginx"},
		},
	}
	if g := extractGate(spec); g != nil {
		t.Errorf("or-rule must not be gated, got %+v", g)
	}
}

// TestRegexCacheLRU: bounded size, MRU retention, eviction drops oldest.
func TestRegexCacheLRU(t *testing.T) {
	c := newRegexCache(2)
	if _, err := c.get("a+"); err != nil {
		t.Fatal(err)
	}
	if _, err := c.get("b+"); err != nil {
		t.Fatal(err)
	}
	if _, err := c.get("a+"); err != nil { // a is now MRU
		t.Fatal(err)
	}
	if _, err := c.get("c+"); err != nil { // evicts b
		t.Fatal(err)
	}
	if got := c.size(); got != 2 {
		t.Fatalf("size = %d, want 2", got)
	}
	c.mu.Lock()
	_, hasB := c.byPat["b+"]
	c.mu.Unlock()
	if hasB {
		t.Error("oldest entry (b+) should have been evicted")
	}
	// Compile errors are returned, never cached.
	if _, err := c.get("("); err == nil {
		t.Error("malformed pattern must error")
	}
}
