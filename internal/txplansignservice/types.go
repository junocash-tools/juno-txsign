package txplansignservice

import (
	"context"

	"github.com/Abdullah1738/juno-sdk-go/types"
	"github.com/Abdullah1738/juno-txsign/pkg/txsign"
)

const (
	JSONVersionV1 = "v1"
	SignPath      = "/v1/sign"
)

// Signer signs a complete, already-approved TxPlan. Implementations must not
// log or persist seed material.
type Signer func(context.Context, types.TxPlan) (txsign.Result, error)

type SignRequest struct {
	Version      string `json:"version"`
	AttemptID    string `json:"attempt_id"`
	PlanDigest   string `json:"plan_digest"`
	TxPlanBase64 string `json:"txplan_base64"`
}

type SignData struct {
	AttemptID                  string   `json:"attempt_id"`
	PlanDigest                 string   `json:"plan_digest"`
	Replayed                   bool     `json:"replayed"`
	TxID                       string   `json:"txid"`
	RawTxHex                   string   `json:"raw_tx_hex"`
	FeeZat                     string   `json:"fee_zat"`
	OrchardOutputActionIndices []uint32 `json:"orchard_output_action_indices"`
	OrchardChangeActionIndex   *uint32  `json:"orchard_change_action_index"`
}

type ErrorData struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

type SignResponse struct {
	Version string     `json:"version"`
	Status  string     `json:"status"`
	Data    *SignData  `json:"data,omitempty"`
	Error   *ErrorData `json:"error,omitempty"`
}

type HealthData struct {
	Service        string `json:"service"`
	Journal        string `json:"journal"`
	BindingCount   int    `json:"binding_count"`
	MaxConcurrency int    `json:"max_concurrency"`
	InFlight       int64  `json:"in_flight"`
}

type HealthResponse struct {
	Version string     `json:"version"`
	Status  string     `json:"status"`
	Data    HealthData `json:"data"`
}
