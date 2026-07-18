// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Copyright (c) 2026 Mi-Bee Studio. All rights reserved.
//
// This file is part of mibee-fingerprints-go, distributed under the GNU Affero General
// Public License v3.0 or later. You may use, modify, and redistribute it under
// those terms; see LICENSE for the full text. A commercial license is available
// for use cases the AGPL does not accommodate; see the main repository's LICENSE-COMMERCIAL.md.

package fingerprint

import "testing"

// TestLoadAllRules verifies the full embedded corpus (builtin + Recog) loads
// without error — all regex patterns compile under RE2, all YAML parses.
func TestLoadAllRules(t *testing.T) {
	rc := &RuleClassifier{}
	if err := rc.LoadEmbeddedDefaults(); err != nil {
		t.Fatalf("LoadEmbeddedDefaults: %v", err)
	}
	if rc.RuleCount() < 2000 {
		t.Errorf("expected ≥2000 rules, got %d", rc.RuleCount())
	}
	t.Logf("loaded %d rules", rc.RuleCount())
}

// TestMissingDir verifies silent degradation on a missing directory.
func TestMissingDir(t *testing.T) {
	rc := &RuleClassifier{}
	if err := rc.LoadFromDir("/nonexistent/fingerprints"); err != nil {
		t.Errorf("missing dir should be silent, got error: %v", err)
	}
	if rc.Loaded() {
		t.Error("missing dir should leave classifier unloaded")
	}
}
