/** @file se050_tls.h
 * @brief Mbed TLS identity/CSR bridge. Host owns certificate policy and returned handles.
 */
#ifndef SSWL_SE050_TLS_H
#define SSWL_SE050_TLS_H
#include "se050_psa.h"
#include "mbedtls/pk.h"

/** Public C API; identical calling convention when included from C++. */
#ifdef __cplusplus
extern "C"
{
#endif
    int se050_tls_load(mbedtls_pk_context *pk, const mbedtls_pk_context *certificate_key,
                       const uint8_t *stored_key, size_t stored_length, int iso20,
                       mbedtls_svc_key_id_t *handle);
    int se050_csr_key(mbedtls_pk_context *pk, mbedtls_svc_key_id_t *handle, uint8_t *reference,
                      size_t *length);
    int se050_parse_key(mbedtls_pk_context *pk, const uint8_t *stored, size_t length,
                        mbedtls_svc_key_id_t *handle);

#ifdef __cplusplus
}
#endif

#endif
