# juno-txsign

Offline signer for `TxPlan` (v0) packages.

Intended for hot/warm/cold key tiering and HSM/airgapped workflows.

Supports multi-output plans and produces a raw transaction hex blob suitable for broadcast.

## Testing

`make test` runs unit + integration + e2e suites (Dockerized `junocashd` regtest).
