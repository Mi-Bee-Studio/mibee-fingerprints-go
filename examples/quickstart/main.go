// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Copyright (c) 2026 Mi-Bee Studio. All rights reserved.
//
// This file is part of mibee-fingerprints-go, distributed under the GNU Affero General
// Public License v3.0 or later; see LICENSE for the full text.

package main

import (
	"fmt"
	"log"
	"time"

	fp "github.com/Mi-Bee-Studio/mibee-fingerprints-go"
)

func main() {
	evidence, err := collectEvidence(time.Now())
	if err != nil {
		log.Fatal(err)
	}

	for _, id := range evidence.identities {
		fmt.Printf("%s:%d -> %s (conf=%.2f brand=%s)\n",
			evidence.input[0].IP, id.Port, id.Service, id.Confidence, id.Metadata["inferred_brand"])
	}
}

type result struct {
	input      []fp.Evidence
	identities []fp.ServiceIdentity
}

func collectEvidence(now time.Time) (result, error) {
	rc := &fp.RuleClassifier{}
	if err := rc.LoadEmbeddedDefaults(); err != nil {
		return result{}, err
	}

	// Classify the complete evidence slice collected for one host.
	input := []fp.Evidence{
		{
			Source:     "active:tcp",
			Kind:       "http",
			IP:         "192.0.2.10",
			Port:       8080,
			Protocol:   "tcp",
			RawData:    map[string]string{"server": "uhttpd/2023.12"},
			Confidence: 0.9,
			ObservedAt: now,
		},
	}
	return result{input: input, identities: rc.Classify(input)}, nil
}
