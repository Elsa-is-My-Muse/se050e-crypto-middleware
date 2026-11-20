/** @file se050_crypto.h
 * @brief Persistent identity references and owned transient EC object lifecycle.
 */
#ifndef SSWL_SE050_CRYPTO_H
#define SSWL_SE050_CRYPTO_H
#include "se050.h"

/** Public C API; identical calling convention when included from C++. */
#ifdef __cplusplus
extern "C"
{
#endif

/* Application-owned object namespace. Existing objects are never overwritten. */
#define SE050_TLS_ISO2_OBJECT 0x53050001UL
#define SE050_TLS_ISO20_OBJECT 0x53050002UL
#define SE050_CSR_OBJECT_BASE 0x53050100UL
#define SE050_CSR_OBJECT_COUNT 16U
#define SE050_KEY_REFERENCE_SIZE 12U
/* Reserved RAM objects. Never adopt or delete objects already present here. */
#define SE050_TRANSIENT_OBJECT_BASE 0x53050200UL
#define SE050_TRANSIENT_OBJECT_COUNT 16U

    se050_status_t se050_key_exists(uint32_t id, int *exists);
    se050_status_t se050_key_create(uint32_t id, size_t bits, const uint8_t *private_value,
                                    size_t private_length, const uint8_t *public_value,
                                    size_t public_length);
    se050_status_t se050_key_public(uint32_t id, uint8_t *output, size_t capacity, size_t *length);
    se050_status_t se050_key_sign(uint32_t id, size_t bits, unsigned hash_bits, const uint8_t *hash,
                                  size_t hash_length, uint8_t *signature, size_t capacity,
                                  size_t *length);
    se050_status_t se050_key_ecdh(uint32_t id, size_t bits, const uint8_t *peer, size_t peer_length,
                                  uint8_t *output, size_t capacity, size_t *length);
    se050_status_t se050_transient_create(size_t bits, const uint8_t *public_value,
                                          size_t public_length, uint32_t *object_id);
    se050_status_t se050_transient_delete(uint32_t object_id);
    /* Optional thread-owned batch; only public verification objects permit updates.
     * Begin/end must bracket one synchronous TLS call, including WANT_READ/errors.
     * End deletes the retained slot before the caller reports handshake completion. */
    se050_status_t se050_verify_reuse_set(int enabled);
    int se050_verify_reuse_enabled(void);
    se050_status_t se050_verify_scope_begin(void);
    se050_status_t se050_verify_scope_end(void);
    se050_status_t se050_verify_prepare(size_t bits, const uint8_t *public_value,
                                        size_t public_length, uint32_t *object_id, int *retained);
    void se050_transient_status(unsigned *active, unsigned *pending);
    se050_status_t se050_key_verify(uint32_t id, size_t bits, unsigned hash_bits,
                                    const uint8_t *hash, size_t hash_length,
                                    const uint8_t *signature, size_t signature_length, int *valid);
    se050_status_t se050_raw_to_der(const uint8_t *raw, size_t raw_length, size_t scalar_length,
                                    uint8_t *der, size_t capacity, size_t *length);
    se050_status_t se050_der_to_raw(const uint8_t *der, size_t der_length, size_t scalar_length,
                                    uint8_t *raw, size_t capacity);
    void se050_key_reference(uint8_t output[SE050_KEY_REFERENCE_SIZE], uint32_t id, size_t bits);
    int se050_key_reference_parse(const uint8_t *input, size_t length, uint32_t *id, size_t *bits);

#ifdef __cplusplus
}
#endif

#endif
