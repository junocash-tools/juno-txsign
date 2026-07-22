# juno-txsign

Offline signer for `TxPlan` (v0) packages.

Intended for hot/warm/cold key tiering and HSM/airgapped workflows.

Supports multi-output plans and produces a raw transaction hex blob suitable for broadcast.

## API stability

- Input `TxPlan` is versioned via `txplan.version` (currently `"v0"`). Unsupported versions are rejected.
- For automation/integrations, treat JSON as the stable API surface (`--json` and `--out-result`). Human-oriented output may change.
- Schemas:
  - `api/txplan.v0.schema.json`
  - External signing mode:
    - `api/prepared_tx.v0.schema.json`
    - `api/signing_requests.v0.schema.json`
    - `api/spend_auth_sigs.v0.schema.json`

## CLI

Sign a plan from a file and print raw tx hex:

- `juno-txsign sign --txplan ./txplan.json --seed-file ./seed.b64`

Sign a plan from stdin and write the raw transaction and complete JSON result to owner-only files:

- `cat ./txplan.json | juno-txsign sign --txplan - --seed-base64 <b64> --out ./rawtx.hex --out-result ./signed.json --json`

Machine-readable output:

- add `--json` for stdout; add `--out-result <path>` for a durable JSON result

### Digest signing mode (Bridge / EIP-712 digest)

Sign a final 32-byte EIP-712 digest (no prefixing/re-hashing):

- `JUNO_TXSIGN_SIGNER_KEYS=<hex1>,<hex2> juno-txsign sign-digest --digest 0x<64-hex> --json`
- `JUNO_TXSIGN_SIGNER_KEYS=<hex1> juno-txsign sign-digest --digest 0x<64-hex> --operator-endpoint https://op1.example.com --operator-endpoint https://op2.example.com --json`

`sign-digest` always reads local signer keys from `JUNO_TXSIGN_SIGNER_KEYS` as a comma-separated list of secp256k1 private keys (32-byte hex, optional `0x` prefixes). When `--operator-endpoint` is repeated, `juno-txsign` also queries each remote operator at `POST /v1/sign-digest` and returns the merged signature set.

### Operator service mode

Expose a digest-signing HTTP API for remote callers:

- `JUNO_TXSIGN_SIGNER_KEYS=<hex1>,<hex2> juno-txsign serve --listen 127.0.0.1:8080`

Endpoints:

- `GET /healthz`
- `POST /v1/sign-digest` with `{"version":"v1","digest":"0x<64-hex>"}`

### External signing mode (Orchard spend-auth TSS)

This mode does not require a seed/spending key. It builds a proven Orchard transaction using a UFVK (`jview...`) and returns per-action signing inputs for external spend-auth signing.

Two-phase flow:

1. Prepare a transaction and get signing requests:
   - `juno-txsign ext-prepare --txplan ./txplan.json --ufvk <jview...> --out-prepared ./prepared.json --out-requests ./requests.json --out-result ./prepare-result.json`
2. Persist the exact `prepared.json` bytes and record their SHA-256 digest in a trusted, integrity-protected system before distributing signing requests. Rehash and compare those exact bytes before using the output/change action mappings. These mappings are coordination metadata and are not authenticated by Orchard spend-auth signatures.
3. Finalize with externally-produced spend-auth signatures:
   - `juno-txsign ext-finalize --prepared-tx ./prepared.json --sigs ./sigs.json --out ./rawtx.hex --out-result ./signed.json --json`

Only use action mappings from the digest-bound `ext-prepare` artifact. `ext-finalize` deliberately does not return them because it cannot authenticate their semantic roles.

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
- `--out-result <path>` writes the complete versioned JSON result (mode `0600`)
- `--json` envelope:
  - success: `{"version":"v1","status":"ok","data":{"txid":"...","raw_tx_hex":"...","fee_zat":"..."}}`
    - for direct `sign`, `--action-indices` also includes:
      - `orchard_output_action_indices`: array of Orchard action indices aligned to `txplan.outputs` order
      - `orchard_change_action_index`: Orchard action index for the change output, or `null` if no change output was created
  - error: `{"version":"v1","status":"err","error":{"code":"...","message":"..."}}`

Every transaction-artifact output is one-shot: the CLI reserves all requested paths before preparing or signing, refuses an existing path or reservation, writes through an owner-only temporary file, syncs it, and publishes without replacement. Never reuse an attempt directory or output path. A post-result commit failure returns `io_error` and intentionally leaves a `<path>.juno-txsign-pending` reservation and any recoverable temporary artifact. Quarantine them and do not rerun the signing command until an audited review proves that no valid bytes escaped; otherwise keep every selected note reserved and reconcile every known signed variant through finality or strict expiry.

Stdout remains supported for compatibility, and write failures now return nonzero. Stdout is not crash-durable: for a transaction command, if its consumer fails after any bytes escape and no complete `--out-result` exists, treat the signing outcome as unknown. Preserve the partial capture, keep reservations, and do not blindly sign again. Production transaction workflows should use all applicable file-output flags and validate the complete JSON result before transferring raw bytes.

### External signing mode JSON

- `ext-prepare` output (always JSON):
  - success: `{"version":"v1","status":"ok","data":{"prepared_tx":<PreparedTx>,"signing_requests":<SigningRequests>}}`
- `ext-finalize` output:
  - default stdout: raw tx hex (one line)
  - with `--json`: includes only `txid`, `raw_tx_hex`, and `fee_zat`
  - `--action-indices` is rejected; use the integrity-bound `ext-prepare` artifact

### sign-digest JSON

- success: `{"version":"v1","status":"ok","data":{"signatures":["0x<65-byte-sig>", "..."]}}`
- error: `{"version":"v1","status":"err","error":{"code":"<machine_code>","message":"<human_message>"}}`

For `sign-digest`, each signature is `r || s || v` (65 bytes), with `v` in `{27,28}` and canonical low-`s`. Output signatures are sorted by recovered signer address ascending and guaranteed unique across local plus remote operators.

## Network and change safety

- TxPlan `chain` and `coin_type` must match: mainnet `8133`, testnet `8134`, or regtest `8135`.
- Every recipient, change address, and external-signing UFVK must use that network's exact HRP.
- Any actual change output must belong to the direct signer's seed-derived FVK or the UFVK supplied to `ext-prepare`. External and internal Orchard scopes are accepted. A no-change sweep may send its full value to another wallet.
- `ext-prepare` requires the NU6.2 transaction branch. Earlier branches are rejected with `external_signing_branch_unsupported` because the current Orchard PCZT prover constructs NU6.2 circuits. Direct `sign` remains branch-aware for supported earlier branches. The Docker regtest fixture activates NU6.2 at height 1.
- A transaction may contain at most 200 Orchard spends and 200 Orchard outputs, including change. External-signing action indices are therefore limited to `0..199`.

## Fees

`juno-txsign` validates that `txplan.fee_zat` is **at least** the ZIP-317 conventional fee for the plan (based on note and output counts). Higher fees are allowed (they reduce the change output).

## Testing

`make test` runs unit + integration + e2e suites (Dockerized `junocashd` regtest).
