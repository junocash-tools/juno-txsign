package witness

import (
	"encoding/json"
	"errors"

	"github.com/Abdullah1738/juno-txsign/internal/ffi"
)

type Path struct {
	Position uint32   `json:"position"`
	AuthPath []string `json:"auth_path"`
}

type Result struct {
	Root  string
	Paths []Path
}

func OrchardWitness(cmxHex []string, positions []uint32) (Result, error) {
	req := struct {
		CMXHex    []string `json:"cmx_hex"`
		Positions []uint32 `json:"positions"`
	}{
		CMXHex:    cmxHex,
		Positions: positions,
	}
	b, err := json.Marshal(req)
	if err != nil {
		return Result{}, errors.New("witness: marshal request")
	}

	raw, err := ffi.OrchardWitnessJSON(string(b))
	if err != nil {
		return Result{}, err
	}

	var resp struct {
		Status string `json:"status"`
		Root   string `json:"root,omitempty"`
		Paths  []Path `json:"paths,omitempty"`
		Error  string `json:"error,omitempty"`
	}
	if err := json.Unmarshal([]byte(raw), &resp); err != nil {
		return Result{}, errors.New("witness: invalid response")
	}
	switch resp.Status {
	case "ok":
		return Result{Root: resp.Root, Paths: resp.Paths}, nil
	case "err":
		if resp.Error == "" {
			return Result{}, errors.New("witness: failed")
		}
		return Result{}, errors.New("witness: " + resp.Error)
	default:
		return Result{}, errors.New("witness: invalid response")
	}
}
