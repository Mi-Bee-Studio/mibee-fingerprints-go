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
	"fmt"
	"math/rand"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"strings"
	"testing"
)

// smokeEvidence builds a realistic battery spanning every kind/field the
// corpus rules on (banner/http/snmp/smb/rtsp/cdp/tls/metric), plus noise.
func smokeEvidence() []Evidence {
	mk := func(kind string, port int, rd map[string]string) Evidence {
		return Evidence{Source: "smoke", Kind: kind, IP: "192.0.2.10", Port: port,
			Protocol: "tcp", RawData: rd, Confidence: 0.9}
	}
	return []Evidence{
		// SSH banner (strip_ssh_prefix transforms).
		mk("banner", 22, map[string]string{"banner": "SSH-2.0-OpenSSH_9.6p1 Debian-3+deb12u1"}),
		mk("banner", 22, map[string]string{"banner": "SSH-2.0-libssh_0.10.6"}),
		// FTP / SMTP-style banners (strip_resp_code transforms).
		mk("banner", 21, map[string]string{"banner": "220 testhost Microsoft FTP Service (Version 5.0)."}),
		mk("banner", 25, map[string]string{"banner": "220 mail.example.com ESMTP Postfix (Debian/GNU)"}),
		mk("banner", 110, map[string]string{"banner": "+OK Dovecot ready."}),
		// HTTP server headers + titles (Recog http rules).
		mk("http", 80, map[string]string{"server": "Apache/2.4.57 (Unix)", "title": "It works!"}),
		mk("http", 80, map[string]string{"server": "nginx/1.24.0", "title": "Welcome to nginx!"}),
		mk("http", 8080, map[string]string{"server": "lighttpd/1.4.71", "title": ""}),
		mk("http", 443, map[string]string{"server": "Boa/0.94.14rc21", "title": "IPCamera"}),
		// SNMP sysDescr / sysObjectID (kind snmp).
		mk("snmp", 161, map[string]string{"sys_descr": "Linux server 5.15.0-91-generic #1 SMP x86_64", "sys_object_id": "1.3.6.1.4.1.8072.3.2.10", "os": "Linux 5.15.0"}),
		mk("snmp", 161, map[string]string{"sys_descr": "Cisco IOS Software, C2960 Software (C2960-LANBASEK9-M), Version 15.2(4)E5", "sys_object_id": "1.3.6.1.4.1.9.1.694", "os": "Cisco IOS"}),
		mk("snmp", 161, map[string]string{"sys_descr": "Huawei Versatile Routing Platform Software VRP (R) software V200R010C00SPC600", "sys_object_id": "1.3.6.1.4.1.2011.2.23"}),
		mk("snmp", 161, map[string]string{"sys_descr": "Synology DiskStation DS920+", "sys_object_id": "1.3.6.1.4.1.6574.1"}),
		// SMB (field os, kind smb).
		mk("smb", 445, map[string]string{"os": "Windows 10 Pro 10.0.19045", "banner": ""}),
		// RTSP / ONVIF (kind presence + server keyword maps).
		mk("rtsp_banner", 554, map[string]string{"server": "Hikvision Rtsp 1.0", "status": "200 OK"}),
		mk("onvif_response", 8000, map[string]string{"server": "Dahua ONVIF"}),
		// TLS.
		mk("tls", 443, map[string]string{"subject_cn": "NAS-6F2C4D"}),
		// LLDP/CDP platform strings.
		mk("cdp", 0, map[string]string{"platform": "cisco WS-C2960X-24TS-L", "sys_desc": "Cisco IOS Software, C2960X Software"}),
		// Prometheus-style metrics endpoint.
		mk("metric", 9100, map[string]string{"banner": "node_exporter", "content_sample": "# HELP node_cpu_seconds_total Cumulative"}),
		// Noise: junk that should match nothing (gates must skip, not fire).
		mk("banner", 12345, map[string]string{"banner": "zzzz unrelated stuff 0000"}),
		mk("banner", 23, map[string]string{"banner": "SSH-1.99-olympus ISAMS/4.0.6.0"}),
		mk("http", 81, map[string]string{"server": "Whoknows/9.9 (build 42)", "title": "Untitled"}),
	}
}

// TestGateEquivalenceOnFullCorpus is the core soundness contract: over the
// whole embedded corpus, gating every rule must not change classification
// output — byte for byte — compared to evaluating every rule ungated.
func TestGateEquivalenceOnFullCorpus(t *testing.T) {
	gated := &RuleClassifier{}
	if err := gated.LoadEmbeddedDefaults(); err != nil {
		t.Fatalf("load: %v", err)
	}
	ungated := &RuleClassifier{}
	if err := ungated.LoadEmbeddedDefaults(); err != nil {
		t.Fatalf("load: %v", err)
	}
	for i := range ungated.rules {
		ungated.rules[i].gate = nil
	}
	ungated.regexes = gated.regexes // share compiled programs; irrelevant to output

	ev := smokeEvidence()
	outGated := gated.Classify(ev)
	outUngated := ungated.Classify(ev)

	if len(outUngated) < 20 {
		t.Fatalf("battery too weak: only %d identities fired — test would be vacuous", len(outUngated))
	}
	if !reflect.DeepEqual(outGated, outUngated) {
		t.Fatalf("gated and ungated outputs differ: %d vs %d identities",
			len(outGated), len(outUngated))
	}
	// Sanity: known-good classifications actually appear (SSH, Apache, Cisco).
	joined := identitySummary(outGated)
	for _, want := range []string{"ssh", "http", "snmp"} {
		if !strings.Contains(joined, want) {
			t.Errorf("expected service %q in output, got: %s", want, joined)
		}
	}
}

// identitySummary renders identities compactly for failure messages.
func identitySummary(ids []ServiceIdentity) string {
	var sb strings.Builder
	for i, id := range ids {
		if i > 0 {
			sb.WriteByte(';')
		}
		fmt.Fprintf(&sb, "%s/%d/%.3f", id.Service, id.Port, id.Confidence)
	}
	return sb.String()
}

// TestLazyCompilationStaysLazy: after a load NOTHING is compiled (the memory
// guarantee), and realistic traffic compiles only a small fraction of the
// corpus instead of all of it.
func TestLazyCompilationStaysLazy(t *testing.T) {
	rc := &RuleClassifier{}
	if err := rc.LoadEmbeddedDefaults(); err != nil {
		t.Fatalf("load: %v", err)
	}
	if got := rc.CompiledRegexCount(); got != 0 {
		t.Fatalf("after load, %d regexes compiled — load must not compile", got)
	}
	_ = rc.Classify(smokeEvidence())
	compiled := rc.CompiledRegexCount()
	// Realistic traffic passes gates for rules gated on common literals
	// ("Linux", "Version ", …), so a few hundred programs is expected; the LRU
	// caps residency regardless. The eager design compiled ALL ~2574 at load
	// on every startup, even with no traffic at all.
	if compiled > 300 {
		t.Errorf("compiled %d regexes on smoke battery — gates are not filtering", compiled)
	}
	if compiled == 0 {
		t.Error("battery matched nothing — smoke evidence too weak")
	}
	t.Logf("compiled %d/%d regex programs on smoke battery", compiled, rc.RuleCount())
}

// TestGateNeverSkipsAMatch is the adversarial soundness check over real
// corpus patterns: for random strings, whenever the gate would skip a rule,
// the rule's regex must not match. A violation means an unsound gate (a real
// fingerprint would be lost in production).
func TestGateNeverSkipsAMatch(t *testing.T) {
	rc := &RuleClassifier{}
	if err := rc.LoadEmbeddedDefaults(); err != nil {
		t.Fatalf("load: %v", err)
	}
	rng := rand.New(rand.NewSource(20261003)) // deterministic
	alphabet := []byte("abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ0123456789 ._/-()")
	// Seed the generator with fragments of the corpus literals so strings
	// sometimes come close to matching (pure random never would).
	fragments := []string{"Microsoft FTP", "OpenSSH", "Apache", "Cisco IOS", "nginx/",
		"Version ", "Windows", "Huawei", "Dovecot", "Postfix", "node_exporter", "SSHD"}

	skip, evaluated := 0, 0
	for _, rl := range rc.rules {
		if rl.hostScoped || rl.matchPat == "" || rl.gate == nil {
			continue
		}
		re, err := regexp.Compile(rl.matchPat)
		if err != nil {
			continue
		}
		field := rl.matchField
		if field == "" {
			field = "banner"
		}
		for i := 0; i < 300; i++ {
			var s string
			if i%4 == 0 && len(fragments) > 0 {
				// literal-seeded mutation: fragment + random noise around it
				f := fragments[rng.Intn(len(fragments))]
				pos := rng.Intn(len(f) + 1)
				s = f[:pos] + randString(rng, 1+rng.Intn(8), alphabet) + f[pos:] + randString(rng, 0+rng.Intn(6), alphabet)
			} else {
				s = randString(rng, 1+rng.Intn(30), alphabet)
			}
			e := Evidence{Kind: "banner", RawData: map[string]string{field: s}}
			texts := map[gateKey]string{}
			if rl.gate.passes(e, texts) {
				evaluated++
				continue
			}
			// Gate says skip ⇒ prove the regex cannot match the same derived text.
			v := fieldOf(e, field, false)
			if rl.gate.transform != "" {
				v = applyTransform(v, rl.gate.transform)
			}
			if re.MatchString(v) {
				t.Fatalf("unsound gate: rule %q pattern %q gate %v skipped text %q that MATCHES",
					rl.id, rl.matchPat, rl.gate.literals, v)
			}
			skip++
		}
	}
	if skip == 0 || evaluated == 0 {
		t.Fatalf("test too weak: %d skips, %d passes — generator must exercise both sides", skip, evaluated)
	}
	t.Logf("soundness sweep: %d gate-skips all provably non-matching, %d pass-throughs", skip, evaluated)
}

func randString(rng *rand.Rand, n int, alphabet []byte) string {
	b := make([]byte, n)
	for i := range b {
		b[i] = alphabet[rng.Intn(len(alphabet))]
	}
	return string(b)
}

// TestLoadRejectsMalformedRegexPreserved: the load-time validation contract
// (bad pattern ⇒ hard error, engine falls back) must survive lazy compilation.
func TestLoadRejectsMalformedRegexPreserved(t *testing.T) {
	dir := t.TempDir()
	yaml := "version: 1\nrules:\n  - id: bad\n    match:\n      op: regex\n      value: \"(unclosed[\"\n    service: x\n"
	if err := os.WriteFile(filepath.Join(dir, "bad.yaml"), []byte(yaml), 0o644); err != nil {
		t.Fatal(err)
	}
	rc := &RuleClassifier{}
	if err := rc.LoadFromDir(dir); err == nil {
		t.Fatal("malformed regex must fail the load")
	}
}
