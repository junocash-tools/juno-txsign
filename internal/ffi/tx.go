package ffi

/*
#cgo CFLAGS: -I${SRCDIR}/../../rust/juno-tx/include
#cgo LDFLAGS: -L${SRCDIR}/../../rust/juno-tx/target/release -ljuno_tx

#include "juno_tx.h"
#include <stdlib.h>
*/
import "C"

import (
	"errors"
	"unsafe"
)

var errNull = errors.New("ffi: null response")

func BuildTxJSON(reqJSON string) (string, error) {
	cReq := C.CString(reqJSON)
	defer C.free(unsafe.Pointer(cReq))

	out := C.juno_tx_build_tx_json(cReq)
	if out == nil {
		return "", errNull
	}
	defer C.juno_tx_string_free(out)

	return C.GoString(out), nil
}
