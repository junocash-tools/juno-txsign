package ffi

/*
#cgo CFLAGS: -I${SRCDIR}/../../rust/witness/include
#cgo LDFLAGS: -L${SRCDIR}/../../rust/witness/target/release -ljuno_tx_witness

#include "juno_tx_witness.h"
#include <stdlib.h>
*/
import "C"

import (
	"unsafe"
)

func OrchardWitnessJSON(reqJSON string) (string, error) {
	cReq := C.CString(reqJSON)
	defer C.free(unsafe.Pointer(cReq))

	out := C.juno_tx_witness_orchard_witness_json(cReq)
	if out == nil {
		return "", errNull
	}
	defer C.juno_tx_witness_string_free(out)

	return C.GoString(out), nil
}
