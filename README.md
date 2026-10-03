# mibee-fingerprints-go

Reference Go engine for the MiBee fingerprint corpus.

Loads YAML rule files and evaluates them against `Evidence` to emit
`ServiceIdentity` assertions. Implements the adapter spec
([fingerprint-spec.md](https://github.com/Mi-Bee-Studio/MiBeeSteward/blob/main/docs/fingerprint-spec.md)).

## Usage

```go
import fp "github.com/Mi-Bee-Studio/mibee-fingerprints-go"

// Load embedded rules (compiled into the binary — zero config).
rc := &fp.RuleClassifier{}
if err := rc.LoadEmbeddedDefaults(); err != nil {
    log.Fatal(err)
}

// Classify evidence.
identities := rc.Classify(evidence)
for _, id := range identities {
    fmt.Printf("%s:%d → %s (conf=%.2f brand=%s)\n",
        ip, id.Port, id.Service, id.Confidence, id.Metadata["inferred_brand"])
}
```

## Types

```go
type Evidence struct {
    Kind       string            // "banner", "snmp", "http", "tls", ...
    Port       int
    RawData    map[string]string // protocol-specific payload
    Confidence float64           // [0,1]
    // ... (see fingerprint.go)
}

type ServiceIdentity struct {
    Service    string            // "ssh", "http", "camera", ...
    Port       int
    Confidence float64
    Metadata   map[string]string // brand, version, os_type, ...
    // ...
}
```

## Rule format

See the [MiBee Steward repo](https://github.com/Mi-Bee-Studio/MiBeeSteward) for
the rule YAML files and `docs/fingerprint-spec.md` for the normative format spec.

## Memory model: lazy regexes + literal gates

A ~2600-rule corpus compiled eagerly costs ~50 MB of live Go heap (dominated
by compiled RE2 programs) — too much for low-memory routers. The engine
therefore compiles **lazily**:

- **Load** validates every regex pattern (a malformed corpus still fails the
  load) but keeps no compiled program resident.
- Each rule gets a **gate**: a provably-required ASCII literal extracted from
  its match tree (directly for `contains`/`equals`/`prefix`; from the
  `regexp/syntax` AST for `regex` rules — concat ⇒ any mandatory literal,
  alternation ⇒ common prefix of the branches' literals, fold-case ⇒ CI
  gate, non-ASCII text is never gated). A rule whose gate literal is absent
  from the evidence text is skipped before any regex is touched.
- Patterns that pass gates compile on demand into a shared, mutex-protected
  **LRU** (`RegexCacheSize`, default 512 ≈ a few MB worst case).

Gates are conservative by construction: they may only skip a rule when the
full matcher is *guaranteed* false. `TestGateEquivalenceOnFullCorpus`
asserts byte-identical `Classify` output with gates on vs off across the
whole corpus, and `TestGateNeverSkipsAMatch` fuzzes corpus patterns for
soundness. Measured: full corpus load drops from ~50 MB to ~4 MB live heap
with zero regexes compiled at startup.

This also decouples corpus updates from binaries: rule YAMLs loaded via
`LoadFromDir` (e.g. the agent's `scanner.fingerprint_path`) apply on restart
without any recompile of center or agent.

## Testing

```bash
go test ./...     # all tests including full-corpus load + gate soundness
go test -race ./...
```

## License

This module is **dual-licensed by layer**, mirroring the
[main MiBee Steward repository](https://github.com/Mi-Bee-Studio/MiBeeSteward):

| Layer | License |
|---|---|
| Source code (`*.go`) | [GNU AGPLv3](https://www.gnu.org/licenses/agpl-3.0) (or later) |
| Fingerprint corpus (`fingerprint-assets/*.yaml`) | [CC-BY-SA 4.0](https://creativecommons.org/licenses/by-sa/4.0/) |

Both layers are copyleft. Derivative Go code must be released under AGPLv3
(or later), and derivative fingerprint corpora must be released under
CC-BY-SA 4.0. A commercial license is available for source-code use cases the
AGPLv3 does not accommodate (closed-source derivatives, SaaS without
open-sourcing modifications) — see the main repository's
[LICENSE-COMMERCIAL.md](https://github.com/Mi-Bee-Studio/MiBeeSteward/blob/main/LICENSE-COMMERCIAL.md).

See [LICENSE](LICENSE) for the AGPLv3 full text and [NOTICE](NOTICE) for
third-party attributions. The corpus provenance (Rapid7 Recog Apache-2.0,
IEEE OUI, IANA PEN, and the nmap NPSL exclusion) is documented in NOTICE.
