# juno-txsign

Offline signer for `TxPlan` (v0) packages.

Intended for hot/warm/cold key tiering and HSM/airgapped workflows.

Supports multi-output plans and produces a raw transaction hex blob suitable for broadcast.

## API stability

- Input `TxPlan` is versioned via `txplan.version` (currently `"v0"`). Unsupported versions are rejected.
- For automation/integrations, treat JSON as the stable API surface (`--json` and `--out`). Human-oriented output may change.
- Schemas:
  - `api/txplan.v0.schema.json`
  - External signing mode:
    - `api/prepared_tx.v0.schema.json`
    - `api/signing_requests.v0.schema.json`
    - `api/spend_auth_sigs.v0.schema.json`

## CLI

Sign a plan from a file and print raw tx hex:

- `juno-txsign sign --txplan ./txplan.json --seed-file ./seed.b64`

Sign a plan from stdin and write raw tx hex to a file (mode `0600`):

- `cat ./txplan.json | juno-txsign sign --txplan - --seed-base64 <b64> --out ./rawtx.hex`

Machine-readable output:

- add `--json`

### Digest signing mode (Bridge / EIP-712 digest)

Sign a final 32-byte EIP-712 digest (no prefixing/re-hashing):

- `JUNO_TXSIGN_SIGNER_KEYS=<hex1>,<hex2> juno-txsign sign-digest --digest 0x<64-hex> --json`

`sign-digest` reads signer keys from `JUNO_TXSIGN_SIGNER_KEYS` as a comma-separated list of secp256k1 private keys (32-byte hex, optional `0x` prefixes).

### External signing mode (Orchard spend-auth TSS)

This mode does not require a seed/spending key. It builds a proven Orchard transaction using a UFVK (`jview...`) and returns per-action signing inputs for external spend-auth signing.

Two-phase flow:

1. Prepare a transaction and get signing requests:
   - `juno-txsign ext-prepare --txplan ./txplan.json --ufvk <jview...> --out-prepared ./prepared.json --out-requests ./requests.json`
2. Finalize with externally-produced spend-auth signatures:
   - `juno-txsign ext-finalize --prepared-tx ./prepared.json --sigs ./sigs.json --out ./rawtx.hex`

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
    - with `--action-indices`, `data` also includes:
      - `orchard_output_action_indices`: array of Orchard action indices aligned to `txplan.outputs` order
      - `orchard_change_action_index`: Orchard action index for the change output, or `null` if no change output was created
  - error: `{"version":"v1","status":"err","error":{"code":"...","message":"..."}}`

### External signing mode JSON

- `ext-prepare` output (always JSON):
  - success: `{"version":"v1","status":"ok","data":{"prepared_tx":<PreparedTx>,"signing_requests":<SigningRequests>}}`
- `ext-finalize` output:
  - default stdout: raw tx hex (one line)
  - with `--json`: same envelope as `sign` (includes `txid`, `raw_tx_hex`, `fee_zat`, and optional Orchard action indices)

### sign-digest JSON

- success: `{"version":"v1","status":"ok","data":{"signatures":["0x<65-byte-sig>", "..."]}}`
- error: `{"version":"v1","status":"err","error":{"code":"<machine_code>","message":"<human_message>"}}`

For `sign-digest`, each signature is `r || s || v` (65 bytes), with `v` in `{27,28}` and canonical low-`s`. Output signatures are sorted by recovered signer address ascending and guaranteed unique.

## Fees

`juno-txsign` validates that `txplan.fee_zat` is **at least** the ZIP-317 conventional fee for the plan (based on note and output counts). Higher fees are allowed (they reduce the change output).

## Testing

`make test` runs unit + integration + e2e suites (Dockerized `junocashd` regtest).
