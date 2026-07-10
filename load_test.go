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
