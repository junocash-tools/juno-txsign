#pragma once

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

// Builds and signs a Juno transaction described by a JSON request.
//
// Returns a newly-allocated UTF-8 JSON string with one of:
//   - {"status":"ok","txid":"...","raw_tx_hex":"...","fee_zat":"..."}
//   - {"status":"err","error":"..."}
//
// The returned pointer must be freed with `juno_tx_string_free`.
//
// Privacy/safety: request JSON may contain seeds and other sensitive material. Do not log.
char *juno_tx_build_tx_json(const char *req_json);

// Frees a string returned by `juno_tx_build_tx_json`.
void juno_tx_string_free(char *s);

#ifdef __cplusplus
} // extern "C"
#endif

