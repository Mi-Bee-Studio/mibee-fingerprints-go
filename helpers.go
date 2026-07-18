// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Copyright (c) 2026 Mi-Bee Studio. All rights reserved.
//
// This file is part of mibee-fingerprints-go, distributed under the GNU Affero General
// Public License v3.0 or later. You may use, modify, and redistribute it under
// those terms; see LICENSE for the full text. A commercial license is available
// for use cases the AGPL does not accommodate; see the main repository's LICENSE-COMMERCIAL.md.

package fingerprint

import "strings"

// fuseConfidence combines several confidence values into one by taking the
// complement of the product of (1-c) — i.e. independent evidence reinforces.
// A single source keeps its confidence; two 0.9 sources yield ~0.99.
func fuseConfidence(cs ...float64) float64 {
	prod := 1.0
	for _, c := range cs {
		if c < 0 {
			c = 0
		}
		if c > 1 {
			c = 1
		}
		prod *= (1 - c)
	}
	r := 1 - prod
	if r > 1 {
		r = 1
	}
	return r
}

// evidenceIndex indexes evidence by kind and port for quick lookup.
type evidenceIndex struct {
	byKind map[string][]Evidence
	byPort map[int][]Evidence
}

func indexEvidence(ev []Evidence) evidenceIndex {
	idx := evidenceIndex{
		byKind: make(map[string][]Evidence),
		byPort: make(map[int][]Evidence),
	}
	for _, e := range ev {
		idx.byKind[e.Kind] = append(idx.byKind[e.Kind], e)
		if e.Port != 0 {
			idx.byPort[e.Port] = append(idx.byPort[e.Port], e)
		}
	}
	return idx
}

// portHasOpen reports whether any port_open evidence exists for the port.
func portHasOpen(idx evidenceIndex, port int) bool {
	for _, e := range idx.byPort[port] {
		if e.Kind == "port_open" {
			return true
		}
	}
	return false
}

// hasPrefix tests whether s starts with any of the prefixes (case-insensitive).
func hasPrefix(s string, prefixes ...string) bool {
	up := strings.ToUpper(s)
	for _, p := range prefixes {
		if strings.HasPrefix(up, strings.ToUpper(p)) {
			return true
		}
	}
	return false
}
