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
	"regexp/syntax"
	"strings"
)

// ruleGate is a provably-required literal for a rule: if none of `literals`
// occurs in the rule's (possibly transformed) field text, the rule cannot
// match that evidence piece and is skipped before its regexes are touched.
//
// Soundness contract: a gate may only skip a rule when the full matcher is
// GUARANTEED to return false. Skipping is always conservative-safe; passing
// through merely costs a normal evaluation. Case-insensitive gates only skip
// pure-ASCII texts (Unicode case orbits such as ſ/s or ß/SS can otherwise
// lower to a string that lacks the literal while the folded matcher still
// matches — see gates_test.go).
type ruleGate struct {
	field     string
	transform string
	trim      bool
	ci        bool
	literals  []string // ASCII, non-blank; lowercase when ci
}

// gateKey identifies the derived text a gate tests, so per-evidence texts are
// computed once and shared by all rules with the same field/transform/case.
type gateKey struct {
	field, transform string
	trim, ci         bool
}

// passes reports whether the gate lets the rule through for this evidence.
// texts caches derived field texts per evidence piece (caller-owned).
func (g *ruleGate) passes(e Evidence, texts map[gateKey]string) bool {
	if g == nil || len(g.literals) == 0 {
		return true
	}
	k := gateKey{field: g.field, transform: g.transform, trim: g.trim, ci: g.ci}
	t, ok := texts[k]
	if !ok {
		t = fieldOf(e, g.field, g.trim)
		if g.transform != "" {
			t = applyTransform(t, g.transform)
		}
		if g.ci {
			t = strings.ToLower(t)
		}
		texts[k] = t
	}
	if g.ci && !isASCII(t) {
		// Non-ASCII text: Unicode case folding can disagree with ToLower
		// (ſ vs s, ß vs SS). Never skip — let the real matcher decide.
		return true
	}
	for _, lit := range g.literals {
		if strings.Contains(t, lit) {
			return true
		}
	}
	return false
}

func isASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] >= 0x80 {
			return false
		}
	}
	return true
}

// extractGate derives the strongest sound gate from a match spec tree.
// Returns nil when no provably-required literal exists (or/alternation
// branches that share nothing, fully dynamic patterns, …) — the rule is then
// always evaluated, exactly as before.
func extractGate(s matchSpec) *ruleGate {
	g, ok := extractGateFrom(s)
	if !ok {
		return nil
	}
	if g.field == "" {
		g.field = "banner"
	}
	if g.ci {
		for i, l := range g.literals {
			g.literals[i] = strings.ToLower(l)
		}
	}
	return &g
}

func extractGateFrom(s matchSpec) (ruleGate, bool) {
	switch s.Op {
	case "contains", "contains_any":
		// OR over values: the text must contain at least ONE of them.
		vals := toStrings(s.Value)
		lits := make([]string, 0, len(vals))
		for _, v := range vals {
			if gateLiteralOK(v) {
				lits = append(lits, v)
			}
		}
		if len(lits) == 0 {
			return ruleGate{}, false
		}
		return ruleGate{field: s.Field, trim: s.Trim, ci: s.CI, literals: lits}, true
	case "equals":
		val, _ := s.Value.(string)
		if !gateLiteralOK(val) {
			return ruleGate{}, false
		}
		return ruleGate{field: s.Field, trim: s.Trim, ci: s.CI, literals: []string{val}}, true
	case "prefix", "prefix_ci":
		// Both ops compare case-insensitively today (prefix upper-cases both
		// sides, prefix_ci uses the fold-comparing hasPrefix helper), so a CI
		// gate is sound for either.
		vals := toStrings(s.Value)
		lits := make([]string, 0, len(vals))
		for _, v := range vals {
			if gateLiteralOK(v) {
				lits = append(lits, v)
			}
		}
		if len(lits) == 0 {
			return ruleGate{}, false
		}
		return ruleGate{field: s.Field, trim: s.Trim, ci: true, literals: lits}, true
	case "regex":
		pat, _ := s.Value.(string)
		lits, ci, ok := mandatoryLiterals(pat)
		if !ok {
			return ruleGate{}, false
		}
		return ruleGate{field: s.Field, transform: s.Transform, ci: ci, literals: lits}, true
	case "compound":
		// AND: if ANY sub-condition's required literal is absent the whole
		// rule fails, so the strongest (longest) sub-gate gates the rule.
		var best ruleGate
		found := false
		for _, c := range s.And {
			if g, ok := extractGateFrom(c); ok && gateLen(g) > gateLen(best) {
				best, found = g, true
			}
		}
		return best, found
	}
	// or / port / port_eq / kind_presence / unknown: no single text literal is
	// provably required.
	return ruleGate{}, false
}

func gateLen(g ruleGate) int {
	n := 0
	for _, l := range g.literals {
		if len(l) > n {
			n = len(l)
		}
	}
	return n
}

// gateLiteralOK: gates are restricted to printable ASCII (the folded-match
// guarantee is only needed for, and only holds for, ASCII needles) and must
// carry real signal (non-blank).
func gateLiteralOK(s string) bool {
	if s == "" || strings.TrimSpace(s) == "" {
		return false
	}
	return isASCII(s)
}

// ── regex → mandatory literals ────────────────────────────────────────────

// mandatoryLiterals returns literals that must occur in ANY string the
// pattern matches (unanchored: a match anywhere implies containment).
//
// It walks the regexp/syntax AST conservatively:
//   - OpLiteral            → the literal itself (lowercased+CI when folded)
//   - OpConcat             → any sub-expression's mandatory literal (all of
//     them occur; the longest is returned)
//   - OpAlternate          → longest common prefix of the branches' literals
//     (case-insensitively compared; every branch
//     contains it, so any match does)
//   - OpCapture/OpPlus/
//     OpRepeat(min≥1)      → recurse (the sub-expression must match ≥1 time)
//   - anything optional
//     (star/quest/repeat0) → no mandatory literal
//
// Multiline flags don't affect containment. Case-sensitivity of the RESULT is
// reported so callers can gate case-insensitively exactly when the pattern
// folds.
func mandatoryLiterals(pat string) (lits []string, ci bool, ok bool) {
	p, err := syntax.Parse(pat, syntax.Perl)
	if err != nil {
		return nil, false, false // malformed: no gate (load-time validation reports it)
	}
	lit, fold, found := astMandatory(p)
	if !found || !gateLiteralOK(lit) {
		return nil, false, false
	}
	if fold {
		lit = strings.ToLower(lit)
	}
	return []string{lit}, fold, true
}

// astMandatory finds one mandatory literal in the AST. Returns ci=true when
// the literal is only guaranteed case-insensitively (pattern folded).
func astMandatory(re *syntax.Regexp) (lit string, ci bool, ok bool) {
	if re == nil {
		return "", false, false
	}
	switch re.Op {
	case syntax.OpLiteral:
		s := string(re.Rune)
		fold := re.Flags&syntax.FoldCase != 0
		if fold {
			s = strings.ToLower(s)
		}
		return s, fold, s != ""
	case syntax.OpConcat:
		best, bestCi, found := "", false, false
		for _, sub := range re.Sub {
			if l, c, o := astMandatory(sub); o && len(l) > len(best) {
				best, bestCi, found = l, c, true
			}
		}
		return best, bestCi, found
	case syntax.OpAlternate:
		// Longest common prefix over the branches' mandatory literals,
		// compared case-insensitively (every branch contains the branch
		// literal, hence its lowercased prefix, in the folded sense).
		prefix := ""
		for i, sub := range re.Sub {
			l, _, o := astMandatory(sub)
			if !o || l == "" {
				return "", false, false
			}
			l = strings.ToLower(l)
			if i == 0 {
				prefix = l
				continue
			}
			prefix = commonPrefix(prefix, l)
			if prefix == "" {
				return "", false, false
			}
		}
		if prefix == "" {
			return "", false, false
		}
		return prefix, true, true
	case syntax.OpCapture:
		if len(re.Sub) == 0 {
			return "", false, false
		}
		return astMandatory(re.Sub[0])
	case syntax.OpPlus:
		if len(re.Sub) == 0 {
			return "", false, false
		}
		return astMandatory(re.Sub[0])
	case syntax.OpRepeat:
		if re.Min < 1 || len(re.Sub) == 0 {
			return "", false, false
		}
		return astMandatory(re.Sub[0])
	}
	return "", false, false
}

func commonPrefix(a, b string) string {
	n := 0
	for n < len(a) && n < len(b) && a[n] == b[n] {
		n++
	}
	return a[:n]
}
