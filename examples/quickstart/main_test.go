// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Copyright (c) 2026 Mi-Bee Studio. All rights reserved.
//
// This file is part of mibee-fingerprints-go, distributed under the GNU Affero General
// Public License v3.0 or later; see LICENSE for the full text.

package main

import (
	"testing"
	"time"
)

func TestQuickstart(t *testing.T) {
	observedAt := time.Date(2026, time.November, 27, 12, 0, 0, 0, time.UTC)
	result, err := collectEvidence(observedAt)
	if err != nil {
		t.Fatalf("collectEvidence: %v", err)
	}

	if len(result.input) != 1 {
		t.Fatalf("evidence count = %d, want 1", len(result.input))
	}
	ev := result.input[0]
	if ev.Source == "" || ev.IP == "" || ev.ObservedAt.IsZero() {
		t.Errorf("required evidence fields are empty: %+v", ev)
	}
	if !ev.ObservedAt.Equal(observedAt) {
		t.Errorf("ObservedAt = %v, want %v", ev.ObservedAt, observedAt)
	}

	var found bool
	for _, id := range result.identities {
		if id.Service == "http" && id.Port == 8080 && id.Metadata["inferred_brand"] == "OpenWrt" {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("Classify did not return the expected OpenWrt HTTP identity: %+v", result.identities)
	}
}
