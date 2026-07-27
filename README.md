# juno-txsign

Offline signer for `TxPlan` (v0) packages.

Intended for hot/warm/cold key tiering and HSM/airgapped workflows.

Supports multi-output plans and produces a raw transaction hex blob suitable for broadcast.

## API stability

- Input `TxPlan` is versioned via `txplan.version` (currently `"v0"`). Unsupported versions are rejected.
- For automation/integrations, treat JSON as the stable API surface (`--json` and `--out-result`). Human-oriented output may change.
- Schemas:
  - `api/txplan.v0.schema.json`
  - Private TxPlan service: `api/txplan_sign_service.v1.schema.json`
  - Signer wallet bindings: `api/txplan_signer_bindings.v1.schema.json`
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

This existing TCP service signs only bridge/EIP-712 digests. It does not accept
TxPlans or use the Juno wallet seed.

### Private TxPlan service (Unix socket)

`serve-txplan` is the automation interface for a private transaction
coordinator. It signs complete approved `TxPlan` v0 bytes and returns durable,
ready-to-broadcast raw transaction hex. It cannot listen on TCP and makes no
network calls. In a container, also set `network_mode: none` as defense in
depth. Only the private coordinator runtime identity may mount the socket. The
seed and journal remain signer-only.

Start one signer for the allowed wallet/account/network set:

```sh
install -d -m 0700 /run/juno-txsign /run/juno-txsign-secrets /var/lib/juno-txsign/results
install -m 0600 ./seed.b64 /run/juno-txsign-secrets/seed.b64
install -m 0600 ./bindings.json /run/juno-txsign-secrets/bindings.json

juno-txsign serve-txplan \
  --socket /run/juno-txsign/txplan.sock \
  --journal-dir /var/lib/juno-txsign/results \
  --seed-file /run/juno-txsign-secrets/seed.b64 \
  --bindings-file /run/juno-txsign-secrets/bindings.json
```

`bindings.json` is copied from the coordinator's registered watch-only wallet
configuration:

```json
{
  "version": "v1",
  "bindings": [
    { "wallet_id": "hot", "account": 0, "network": "mainnet", "ufvk": "jview1..." }
  ]
}
```

At startup, the signer derives the Orchard UFVK from its seed for every unique
network/account and compares it to every configured UFVK before opening the
socket. A mismatch fails startup, so a wrong seed cannot pass health and poison
the first live attempt. Authorization then matches the exact
`wallet_id`/`account`/normalized-network tuple; bindings are not combined as
independent allowlists.

`JUNO_TXSIGN_SEED_BASE64` may replace `--seed-file`, but exactly one source is
required. The file must be a non-symlink regular file owned by the service user
with no group/other permissions. The seed is never accepted by the API,
written to the journal, or logged.

The socket and its directory are owner-only (`0600` and `0700`). Possession of
socket access is the caller authentication boundary. The private coordinator
may run as a second listener in the gateway process/container; that runtime
identity mounts only the socket directory, never the signer-only seed or
journal mounts. The public HTTP handler must never route, call, proxy, or expose
the signer API. Never bind it to TCP, a container network, or public ingress.

#### Sign request

Send HTTP/1.1 with `Content-Type: application/json` over the Unix socket:

```json
{
  "version": "v1",
  "attempt_id": "withdrawal-1842-attempt-1",
  "plan_digest": "sha256:<64 lowercase hex>",
  "txplan_base64": "<canonical standard-base64>"
}
```

`plan_digest` is SHA-256 of the exact bytes decoded from `txplan_base64`.
Whitespace and every metadata byte are therefore approval-bound. The decoded
value must be one strict TxPlan JSON object; unknown fields and trailing values
are rejected. `attempt_id` is the coordinator's immutable signing-attempt ID,
not a withdrawal ID that can be reused across rebuilds.

A minimal Node.js caller for an already-built plan is:

```js
import crypto from "node:crypto";
import fs from "node:fs";
import http from "node:http";

const plan = fs.readFileSync("./txplan.json");
const body = JSON.stringify({
  version: "v1",
  attempt_id: "withdrawal-1842-attempt-1",
  plan_digest: `sha256:${crypto.createHash("sha256").update(plan).digest("hex")}`,
  txplan_base64: plan.toString("base64"),
});

const req = http.request({
  socketPath: "/run/juno-txsign/txplan.sock",
  path: "/v1/sign",
  method: "POST",
  headers: { "content-type": "application/json", "content-length": Buffer.byteLength(body) },
}, (res) => res.pipe(process.stdout));
req.end(body);
```

Success is returned only after the immutable result journal is fsynced:

```json
{
  "version": "v1",
  "status": "ok",
  "data": {
    "attempt_id": "withdrawal-1842-attempt-1",
    "plan_digest": "sha256:<64 lowercase hex>",
    "replayed": false,
    "txid": "<64 lowercase hex>",
    "raw_tx_hex": "<ready-to-broadcast transaction hex>",
    "fee_zat": "10000",
    "orchard_output_action_indices": [0],
    "orchard_change_action_index": 1
  }
}
```

Retry the exact same `attempt_id`, `plan_digest`, and plan bytes after a lost
response. It returns the same `txid` and `raw_tx_hex` with `replayed: true`
without using the key again. The service never broadcasts automatically.

#### Attempt and recovery rules

Before key use, the signer writes and fsyncs an immutable pending record. It
then writes and fsyncs the complete signed result before responding. This makes
the recovery rules fail closed:

- Same attempt and digest with a complete result: replay identical signed bytes.
- Same attempt with another digest: `409 attempt_digest_conflict`; create a new
  attempt only after the coordinator has safely reconciled the old one.
- Pending record without a complete result: `409 attempt_outcome_unknown`.
  Keep every selected note reserved and require operator recovery.
- Invalid, corrupt, insecure, or unexplained journal artifacts: startup or the
  request fails with `journal_unsafe`. Never delete them to make a retry pass.
- A signing or durable-write failure after the pending record returns
  `signing_outcome_unknown`. Raw bytes may exist even when the caller received
  no success response.

The journal is not reproducible scanner data. Put it on durable storage and
back it up together with coordinator attempts and note reservations. After a
restore, reconcile all attempts created after the backup before enabling the
signer; never restore an older journal and blindly retry an ID.

`GET /healthz` over the same socket returns the journal readiness, number of
verified bindings, configured concurrency limit, and current in-flight count. `429 signer_busy` means another
attempt is using the configured signing capacity; retry the unchanged request.
The default concurrency is one.

Configuration:

| Flag / environment | Default | Meaning |
| --- | --- | --- |
| `--socket` | required | Absolute Unix socket path; parent must be owner-only |
| `--journal-dir` | required | Owner-only durable immutable-result directory |
| `--seed-file` / `JUNO_TXSIGN_SEED_BASE64` | exactly one required | Base64 seed source |
| `--bindings-file` | required | Owner-only v1 JSON with 1–256 exact wallet/account/network/UFVK bindings |
| `--max-concurrency` | `1` | Active signings, maximum `16` |
| `--max-body-bytes` | `5242880` | HTTP request body limit |
| `--max-plan-bytes` | `3145728` | Decoded exact TxPlan byte limit |
| `--shutdown-timeout` | `10m` | Time allowed for in-flight durable completion |

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
