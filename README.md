# juno-txsign

Offline signer for `TxPlan` (v0) packages.

Intended for hot/warm/cold key tiering and HSM/airgapped workflows.

Supports multi-output plans and produces a raw transaction hex blob suitable for broadcast.

## API stability

- Input `TxPlan` is versioned via `txplan.version` (currently `"v0"`). Unsupported versions are rejected.
- For automation/integrations, treat JSON as the stable API surface (`--json` and `--out`). Human-oriented output may change.
- Schema: `api/txplan.v0.schema.json`

## CLI

Sign a plan from a file and print raw tx hex:

- `juno-txsign sign --txplan ./txplan.json --seed-file ./seed.b64`

Sign a plan from stdin and write raw tx hex to a file (mode `0600`):

- `cat ./txplan.json | juno-txsign sign --txplan - --seed-base64 <b64> --out ./rawtx.hex`

Machine-readable output:

- add `--json`

Run `juno-txsign --help` for the complete flag reference.

## Build

- `make build` (outputs `bin/juno-txsign`)

## Dynamic library path (Linux)

`juno-txsign` uses CGO and links against Rust shared libraries built under:

- `rust/juno-tx/target/release`
- `rust/witness/target/release`

If you see an error like `libjuno_tx.so: cannot open shared object file`, export `LD_LIBRARY_PATH`:

```sh
export LD_LIBRARY_PATH="$PWD/rust/juno-tx/target/release:$PWD/rust/witness/target/release${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
```

## Output formats

- Default stdout: raw transaction hex (one line)
- `--out <path>` writes the raw tx hex with a trailing newline (mode `0600`)
- `--json` envelope:
  - success: `{"version":"v1","status":"ok","data":{"txid":"...","raw_tx_hex":"...","fee_zat":"..."}}`
  - error: `{"version":"v1","status":"err","error":{"code":"...","message":"..."}}`

## Testing

`make test` runs unit + integration + e2e suites (Dockerized `junocashd` regtest).
