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
	"container/list"
	"regexp"
	"sync"
)

// defaultRegexCacheSize bounds the lazily compiled regex programs kept
// resident per RuleClassifier. Patterns are only compiled when a rule's gate
// (see gates.go) lets real evidence through; in practice a scan touches a few
// dozen patterns, so 512 covers busy hosts with room to spare while capping
// worst-case resident memory (a compiled RE2 program is ~10-40 KB).
const defaultRegexCacheSize = 512

type cacheEntry struct {
	pat string
	re  *regexp.Regexp
}

// regexCache lazily compiles and LRU-caches compiled regexes, shared by all
// rules of one RuleClassifier. Safe for concurrent use: Classify may be
// called from multiple host workers.
type regexCache struct {
	mu    sync.Mutex
	max   int
	ll    *list.List // front = most recently used; *cacheEntry values
	byPat map[string]*list.Element
}

func newRegexCache(max int) *regexCache {
	if max <= 0 {
		max = defaultRegexCacheSize
	}
	return &regexCache{
		max:   max,
		ll:    list.New(),
		byPat: make(map[string]*list.Element),
	}
}

// get returns the compiled regex for pat, compiling it on first use. Patterns
// are validated at load time (LoadFromDir compiles every pattern once and
// discards the program), so an error here means the pattern went stale
// between load and use — callers treat it as a non-match.
func (c *regexCache) get(pat string) (*regexp.Regexp, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if el, ok := c.byPat[pat]; ok {
		c.ll.MoveToFront(el)
		return el.Value.(*cacheEntry).re, nil
	}
	re, err := regexp.Compile(pat)
	if err != nil {
		return nil, err
	}
	c.byPat[pat] = c.ll.PushFront(&cacheEntry{pat: pat, re: re})
	for c.ll.Len() > c.max {
		oldest := c.ll.Back()
		if oldest == nil {
			break
		}
		c.ll.Remove(oldest)
		delete(c.byPat, oldest.Value.(*cacheEntry).pat)
	}
	return re, nil
}

func (c *regexCache) size() int {
	if c == nil {
		return 0
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.ll.Len()
}
