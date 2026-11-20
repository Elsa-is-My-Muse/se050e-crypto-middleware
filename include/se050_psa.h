/** @file se050_psa.h
 * @brief Version-specific PSA dispatch for borrowed identities and owned transient keys.
 */
#ifndef SSWL_SE050_PSA_H
#define SSWL_SE050_PSA_H
#include "se050_config.h"
#include "psa/crypto.h"

/** Public C API; identical calling convention when included from C++. */
#ifdef __cplusplus
extern "C"
{
#endif
#define SE050_PSA_LOCATION ((psa_key_location_t)0x005e05)

    /* Imported 4-byte references borrow identity objects. Generated 5-byte
     * references own transient ECDHE objects; their PSA cleanup deletes the object. */
    psa_status_t se050_psa_verify_scope_end(void);
    int se050_offload_verify_enabled(void);
    int se050_offload_ecdh_enabled(void);
    psa_status_t se050_offload_set(int verify, int ecdh);
    psa_status_t se050_psa_generate(const psa_key_attributes_t *attributes, uint8_t *buffer,
                                    size_t capacity, size_t *length);
    psa_status_t se050_psa_destroy(const psa_key_attributes_t *attributes, const uint8_t *buffer,
                                   size_t length);
    psa_status_t se050_psa_verify(const psa_key_attributes_t *attributes, const uint8_t *buffer,
                                  size_t buffer_length, psa_algorithm_t algorithm,
                                  const uint8_t *hash, size_t hash_length, const uint8_t *signature,
                                  size_t signature_length);
    psa_status_t se050_psa_buffer_size(const psa_key_attributes_t *attributes, size_t *size);
    psa_status_t se050_psa_import(const psa_key_attributes_t *attributes, const uint8_t *data,
                                  size_t data_length, uint8_t *buffer, size_t capacity,
                                  size_t *length, size_t *bits);
    psa_status_t se050_psa_public(const psa_key_attributes_t *attributes, const uint8_t *buffer,
                                  size_t buffer_length, uint8_t *data, size_t capacity,
                                  size_t *length);
    psa_status_t se050_psa_sign(const psa_key_attributes_t *attributes, const uint8_t *buffer,
                                size_t buffer_length, psa_algorithm_t algorithm,
                                const uint8_t *hash, size_t hash_length, uint8_t *signature,
                                size_t capacity, size_t *length);
    psa_status_t se050_psa_agreement(const psa_key_attributes_t *attributes, const uint8_t *buffer,
                                     size_t buffer_length, psa_algorithm_t algorithm,
                                     const uint8_t *peer, size_t peer_length, uint8_t *output,
                                     size_t capacity, size_t *length);
    psa_status_t se050_psa_open(uint32_t object_id, size_t bits, mbedtls_svc_key_id_t *key);
    struct se050_stats
    {
        uint32_t entropy_calls;
        uint32_t entropy_bytes;
        uint32_t entropy_failures;
        uint32_t entropy_ms;
        uint32_t sign_calls;
        uint32_t sign_failures;
        uint32_t sign_ms;
        uint32_t verify_calls;
        uint32_t verify_failures;
        uint32_t verify_ms;
        uint32_t verify_create_ms;
        uint32_t verify_execute_ms;
        uint32_t verify_delete_ms;
        uint32_t keygen_calls;
        uint32_t keygen_failures;
        uint32_t keygen_ms;
        uint32_t ecdh_calls;
        uint32_t ecdh_failures;
        uint32_t ecdh_ms;
        uint32_t cleanup_failures;
    };
    void se050_stats_get(struct se050_stats *stats);
    void se050_stats_entropy(size_t bytes, int success, uint32_t elapsed_ms);

#ifdef __cplusplus
}
#endif

#endif
