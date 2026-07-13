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

## Testing

```bash
go test ./...     # all tests including full 2554-rule corpus load
go test -race ./...
```

## License

Apache-2.0. Rule data includes Rapid7 Recog (Apache-2.0) — see the data repo's
NOTICE/THIRD-PARTY files.
