// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Copyright (c) 2026 Mi-Bee Studio. All rights reserved.
//
// This file is part of mibee-fingerprints-go, distributed under the GNU Affero General
// Public License v3.0 or later. You may use, modify, and redistribute it under
// those terms; see LICENSE for the full text. A commercial license is available
// for use cases the AGPL does not accommodate; see the main repository's LICENSE-COMMERCIAL.md.

package fingerprint

import (
	"os"
	"testing"

)

// TestKindScoping verifies that a rule with `kind: snmp` does NOT fire on
// banner evidence, even when the banner content would match the regex. This is
// the guard that lets Recog's snmp.sys_description rules (matching product
// strings like "Linux", "Cisco IOS") coexist with banner rules without
// cross-contamination.
func TestKindScoping(t *testing.T) {
	dir := t.TempDir()
	// A snmp rule that matches "Linux" in sysDescr. Without kind-scoping this
	// would also match a TCP banner containing "Linux".
	yaml := `version: 1
rules:
  - id: snmp-linux
    match: { kind: snmp, field: sys_descr, op: regex, value: "Linux" }
    service: snmp
    protocol: udp
    confidence: 0.9
    extract:
      metadata:
        inferred_brand: { const: "Linux" }
`
	if err := os.WriteFile(dir+"/test.yaml", []byte(yaml), 0o644); err != nil {
		t.Fatal(err)
	}
	rc := &RuleClassifier{}
	if err := rc.LoadFromDir(dir); err != nil {
		t.Fatalf("LoadFromDir: %v", err)
	}

	// 1. SNMP evidence with sysDescr="Linux 5.15" → should match.
	snmpEv := []Evidence{
		{Kind: "snmp", Port: 161, Protocol: "udp", Confidence: 0.9,
			RawData: map[string]string{"sys_descr": "Linux 5.15.0 kernel"}},
	}
	out := rc.Classify(snmpEv)
	if len(out) != 1 || out[0].Service != "snmp" {
		t.Errorf("snmp evidence should match the snmp rule, got %+v", out)
	}

	// 2. Banner evidence containing "Linux" → should NOT match (kind-scoped).
	bannerEv := []Evidence{
		{Kind: "banner", Port: 22, Confidence: 0.9,
			RawData: map[string]string{"banner": "SSH-2.0-OpenSSH Linux-based"}},
	}
	out2 := rc.Classify(bannerEv)
	for _, s := range out2 {
		if s.Service == "snmp" {
			t.Errorf("snmp rule fired on banner evidence — kind-scoping guard failed: %+v", s)
		}
	}
}
