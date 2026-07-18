// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Copyright (c) 2026 Mi-Bee Studio. All rights reserved.
//
// This file is part of mibee-fingerprints-go, distributed under the GNU Affero General
// Public License v3.0 or later. You may use, modify, and redistribute it under
// those terms; see LICENSE for the full text. A commercial license is available
// for use cases the AGPL does not accommodate; see the main repository's LICENSE-COMMERCIAL.md.

// Package fingerprint provides the data-driven identification rule engine.
//
// This package defines the core types (Evidence, ServiceIdentity) and the
// RuleClassifier that loads YAML rule files and evaluates them against
// evidence to emit service identities. It is the reference Go implementation
// of the MiBee fingerprint adapter spec (see the mibee-fingerprints data repo,
// docs/fingerprint-spec.md).
//
// The types here are pure data shapes with JSON tags, designed to be
// language-agnostic: any runtime (Go, Rust, Zig) that produces/consumes these
// JSON structures produces identical classification output.
package fingerprint

import "time"

// Evidence is the universal unit produced by every probe — active or passive.
// It is deliberately domain-agnostic: it carries raw observed data and a
// confidence score, nothing about devices or services. Classifiers interpret it.
type Evidence struct {
	Source     string            `json:"source"`
	Kind       string            `json:"kind"`
	IP         string            `json:"ip"`
	Port       int               `json:"port,omitempty"`
	Protocol   string            `json:"protocol,omitempty"`
	RawData    map[string]string `json:"raw_data,omitempty"`
	Confidence float64           `json:"confidence"`
	ObservedAt time.Time         `json:"observed_at"`
}

// ServiceIdentity is a classified assertion: "this IP:Port is running <Service>,
// with confidence X, backed by these evidence pieces".
type ServiceIdentity struct {
	Service    string            `json:"service"`
	Port       int               `json:"port,omitempty"`
	Protocol   string            `json:"protocol,omitempty"`
	Confidence float64           `json:"confidence"`
	Evidence   []Evidence        `json:"evidence,omitempty"`
	Metadata   map[string]string `json:"metadata,omitempty"`
}

// ServiceClassifier is the interface a classifier implements. The RuleClassifier
// is the data-driven implementation; host applications may also register
// hand-written logic classifiers alongside it.
type ServiceClassifier interface {
	Service() string
	Classify(evidence []Evidence) []ServiceIdentity
}
