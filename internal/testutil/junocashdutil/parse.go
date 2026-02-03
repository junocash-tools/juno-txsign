package junocashdutil

import (
	"errors"
	"strconv"
	"strings"
)

func parseZECToZat(s string) (uint64, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, errors.New("empty amount")
	}

	if strings.HasPrefix(s, "-") {
		return 0, errors.New("negative amount")
	}

	whole, frac, _ := strings.Cut(s, ".")
	if whole == "" {
		whole = "0"
	}
	if len(frac) > 8 {
		return 0, errors.New("too many decimals")
	}
	frac = frac + strings.Repeat("0", 8-len(frac))

	w, err := strconv.ParseUint(whole, 10, 64)
	if err != nil {
		return 0, err
	}
	f, err := strconv.ParseUint(frac, 10, 64)
	if err != nil {
		return 0, err
	}

	if w > (^uint64(0))/100_000_000 {
		return 0, errors.New("overflow")
	}
	return w*100_000_000 + f, nil
}
