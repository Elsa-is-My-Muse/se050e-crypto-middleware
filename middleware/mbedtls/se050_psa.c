#include "se050_psa.h"
#include "se050_crypto.h"
#include <string.h>
static struct se050_stats counters;
static int verify_enabled = SE050_TLS_VERIFY;
static int ecdh_enabled = SE050_TLS_ECDHE;
static unsigned active_operations;
#define OWNED_MARKER 0xa5
static int transient_id(uint32_t id)
{
    return id >= SE050_TRANSIENT_OBJECT_BASE &&
           id < SE050_TRANSIENT_OBJECT_BASE + SE050_TRANSIENT_OBJECT_COUNT;
}
static uint32_t elapsed_ms(se050_tick_t start)
{
    return (uint32_t)(((uint64_t)(se050_tick_t)(se050_port_tick_get() - start) * 1000) /
                      SE050_TICKS_PER_SECOND);
}
int se050_offload_verify_enabled(void)
{
    return verify_enabled;
}
int se050_offload_ecdh_enabled(void)
{
    return ecdh_enabled;
}
psa_status_t se050_offload_set(int verify, int ecdh)
{
    if ((verify != 0 && verify != 1) || (ecdh != 0 && ecdh != 1))
        return PSA_ERROR_INVALID_ARGUMENT;
    se050_port_critical_enter();
    if (active_operations)
    {
        se050_port_critical_exit();
        return PSA_ERROR_BAD_STATE;
    }
    verify_enabled = verify;
    ecdh_enabled = ecdh;
    se050_port_critical_exit();
    return PSA_SUCCESS;
}
static void operation_start(void)
{
    se050_port_critical_enter();
    ++active_operations;
    se050_port_critical_exit();
}
static void operation_done(uint32_t *calls, uint32_t *failures, uint32_t *ms, se050_tick_t start,
                           psa_status_t status)
{
    uint32_t elapsed = elapsed_ms(start);
    se050_port_critical_enter();
    ++*calls;
    *ms += elapsed;
    if (status != PSA_SUCCESS)
        ++*failures;
    --active_operations;
    se050_port_critical_exit();
}
static void put_id(uint8_t *p, uint32_t id)
{
    p[0] = (uint8_t)(id >> 24);
    p[1] = (uint8_t)(id >> 16);
    p[2] = (uint8_t)(id >> 8);
    p[3] = (uint8_t)id;
}
static int valid_type(const psa_key_attributes_t *a)
{
    size_t bits = psa_get_key_bits(a);
    return psa_get_key_type(a) == PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1) &&
           (bits == 256 || bits == 384 || bits == 521);
}
static uint32_t object_id(const uint8_t *p, size_t n)
{
    uint32_t id;
    if (!p || (n != 4 && (n != 5 || p[4] != OWNED_MARKER)))
        return 0;
    id = ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) | ((uint32_t)p[2] << 8) | p[3];
    return (id & 0xffff0000UL) == 0x53050000UL ? id : 0;
}
static psa_status_t result(se050_status_t status)
{
    return status == SE050_OK        ? PSA_SUCCESS
           : status == -SE050_EFULL  ? PSA_ERROR_BUFFER_TOO_SMALL
           : status == -SE050_EINVAL ? PSA_ERROR_INVALID_ARGUMENT
                                     : PSA_ERROR_HARDWARE_FAILURE;
}
psa_status_t se050_psa_buffer_size(const psa_key_attributes_t *a, size_t *size)
{
    *size = 0;
    if (!valid_type(a))
        return PSA_ERROR_NOT_SUPPORTED;
    *size = 5;
    return PSA_SUCCESS;
}
psa_status_t se050_psa_import(const psa_key_attributes_t *a, const uint8_t *data, size_t data_len,
                              uint8_t *buffer, size_t cap, size_t *length, size_t *bits)
{
    uint8_t public_key[133];
    size_t n = 0, expected;
    uint32_t id = object_id(data, data_len);
    if (!length || !bits || !buffer)
        return PSA_ERROR_INVALID_ARGUMENT;
    *length = 0;
    *bits = 0;
    if (!valid_type(a))
        return PSA_ERROR_NOT_SUPPORTED;
    if (!id || data_len != 4 || transient_id(id))
        return PSA_ERROR_INVALID_ARGUMENT;
    if (cap < 4)
        return PSA_ERROR_BUFFER_TOO_SMALL;
    if (psa_get_key_usage_flags(a) & (PSA_KEY_USAGE_EXPORT | PSA_KEY_USAGE_COPY))
        return PSA_ERROR_NOT_PERMITTED;
    if (se050_key_public(id, public_key, sizeof(public_key), &n) != SE050_OK)
        return PSA_ERROR_HARDWARE_FAILURE;
    expected = 1 + 2 * ((psa_get_key_bits(a) + 7) / 8);
    if (n != expected || public_key[0] != 4)
        return PSA_ERROR_INVALID_ARGUMENT;
    memcpy(buffer, data, 4);
    *length = 4;
    *bits = psa_get_key_bits(a);
    return PSA_SUCCESS;
}
psa_status_t se050_psa_public(const psa_key_attributes_t *a, const uint8_t *buffer, size_t n,
                              uint8_t *output, size_t cap, size_t *length)
{
    uint32_t id = object_id(buffer, n);
    psa_status_t status;
    *length = 0;
    if (!id || !valid_type(a))
        return PSA_ERROR_INVALID_ARGUMENT;
    status = result(se050_key_public(id, output, cap, length));
    if (status == PSA_SUCCESS &&
        (*length != 1 + 2 * ((psa_get_key_bits(a) + 7) / 8) || output[0] != 4))
    {
        memset(output, 0, cap);
        *length = 0;
        return PSA_ERROR_CORRUPTION_DETECTED;
    }
    return status;
}
psa_status_t se050_psa_sign(const psa_key_attributes_t *a, const uint8_t *buffer, size_t n,
                            psa_algorithm_t alg, const uint8_t *hash, size_t hash_len,
                            uint8_t *signature, size_t cap, size_t *length)
{
    uint32_t id = object_id(buffer, n);
    unsigned hash_bits;
    psa_status_t status;
    psa_algorithm_t hash_alg = PSA_ALG_GET_HASH(alg);
    se050_tick_t start;
    *length = 0;
    if (!id || !valid_type(a))
        return PSA_ERROR_INVALID_ARGUMENT;
    if (!PSA_ALG_IS_RANDOMIZED_ECDSA(alg))
        return PSA_ERROR_NOT_SUPPORTED;
    hash_bits = hash_alg == PSA_ALG_SHA_256   ? 256
                : hash_alg == PSA_ALG_SHA_384 ? 384
                : hash_alg == PSA_ALG_SHA_512 ? 512
                                              : 0;
    if (!hash_bits)
        return PSA_ERROR_NOT_SUPPORTED;
    operation_start();
    start = se050_port_tick_get();
    status = result(
        se050_key_sign(id, psa_get_key_bits(a), hash_bits, hash, hash_len, signature, cap, length));
    operation_done(&counters.sign_calls, &counters.sign_failures, &counters.sign_ms, start, status);
    return status;
}
psa_status_t se050_psa_agreement(const psa_key_attributes_t *a, const uint8_t *buffer, size_t n,
                                 psa_algorithm_t alg, const uint8_t *peer, size_t peer_len,
                                 uint8_t *output, size_t cap, size_t *length)
{
    uint32_t id = object_id(buffer, n);
    psa_status_t status;
    se050_tick_t start;
    *length = 0;
    if (alg != PSA_ALG_ECDH)
        return PSA_ERROR_NOT_SUPPORTED;
    if (!id || !valid_type(a))
        return PSA_ERROR_INVALID_ARGUMENT;
    operation_start();
    start = se050_port_tick_get();
    status = result(se050_key_ecdh(id, psa_get_key_bits(a), peer, peer_len, output, cap, length));
    operation_done(&counters.ecdh_calls, &counters.ecdh_failures, &counters.ecdh_ms, start, status);
    return status;
}

psa_status_t se050_psa_generate(const psa_key_attributes_t *a, uint8_t *buffer, size_t cap,
                                size_t *length)
{
    uint32_t id = 0;
    psa_status_t status;
    se050_status_t ret;
    se050_tick_t start;
    if (!buffer || !length)
        return PSA_ERROR_INVALID_ARGUMENT;
    *length = 0;
    if (!valid_type(a) || psa_get_key_algorithm(a) != PSA_ALG_ECDH)
        return PSA_ERROR_NOT_SUPPORTED;
    if (psa_get_key_usage_flags(a) & ~(psa_key_usage_t)PSA_KEY_USAGE_DERIVE)
        return PSA_ERROR_NOT_PERMITTED;
    if (!PSA_KEY_LIFETIME_IS_VOLATILE(psa_get_key_lifetime(a)))
        return PSA_ERROR_NOT_SUPPORTED;
    if (cap < 5)
        return PSA_ERROR_BUFFER_TOO_SMALL;
    operation_start();
    start = se050_port_tick_get();
    ret = se050_transient_create(psa_get_key_bits(a), NULL, 0, &id);
    status = ret == -SE050_EFULL ? PSA_ERROR_INSUFFICIENT_MEMORY : result(ret);
    if (status == PSA_SUCCESS)
    {
        put_id(buffer, id);
        buffer[4] = OWNED_MARKER;
        *length = 5;
    }
    operation_done(&counters.keygen_calls, &counters.keygen_failures, &counters.keygen_ms, start,
                   status);
    return status;
}
psa_status_t se050_psa_destroy(const psa_key_attributes_t *a, const uint8_t *buffer, size_t n)
{
    uint32_t id;
    psa_status_t status;
    (void)a;
    /* Imported identity references are borrowed, and are never deleted. */
    if (n != 5)
        return PSA_SUCCESS;
    id = object_id(buffer, n);
    if (!id || !transient_id(id))
        return PSA_ERROR_CORRUPTION_DETECTED;
    status = result(se050_transient_delete(id));
    if (status != PSA_SUCCESS)
    {
        se050_port_critical_enter();
        ++counters.cleanup_failures;
        se050_port_critical_exit();
    }
    return status;
}
psa_status_t se050_psa_verify(const psa_key_attributes_t *a, const uint8_t *pub, size_t pub_len,
                              psa_algorithm_t alg, const uint8_t *hash, size_t hash_len,
                              const uint8_t *sig, size_t sig_len)
{
    uint32_t id = 0;
    size_t bits = psa_get_key_bits(a), scalar = (bits + 7) / 8;
    unsigned hash_bits;
    size_t i;
    int nonzero, valid = 0, retained = 0;
    se050_status_t ret;
    psa_status_t status, cleanup;
    se050_tick_t start;
    psa_algorithm_t hash_alg = PSA_ALG_GET_HASH(alg);
    /* Transparent public keys only: keep private software keys on the MCU. */
    if (!verify_enabled ||
        psa_get_key_type(a) != PSA_KEY_TYPE_ECC_PUBLIC_KEY(PSA_ECC_FAMILY_SECP_R1) ||
        (bits != 256 && bits != 384 && bits != 521) || !PSA_ALG_IS_ECDSA(alg))
        return PSA_ERROR_NOT_SUPPORTED;
    /* Mbed TLS X509 uses ECDSA_ANY with an already computed digest. */
    if (alg == PSA_ALG_ECDSA_ANY)
        hash_bits = hash_len == 32 ? 256 : hash_len == 48 ? 384 : hash_len == 64 ? 512 : 0;
    else
        hash_bits = hash_alg == PSA_ALG_SHA_256   ? 256
                    : hash_alg == PSA_ALG_SHA_384 ? 384
                    : hash_alg == PSA_ALG_SHA_512 ? 512
                                                  : 0;
    if (!hash_bits)
        return PSA_ERROR_NOT_SUPPORTED;
    if (!pub || pub_len != 1 + 2 * scalar || pub[0] != 4 || !hash || hash_len != hash_bits / 8)
        return PSA_ERROR_INVALID_ARGUMENT;
    if (!sig || sig_len != 2 * scalar)
        return PSA_ERROR_INVALID_SIGNATURE;
    for (i = 0, nonzero = 0; i < scalar; ++i)
        nonzero |= sig[i];
    if (!nonzero)
        return PSA_ERROR_INVALID_SIGNATURE;
    for (i = scalar, nonzero = 0; i < 2 * scalar; ++i)
        nonzero |= sig[i];
    if (!nonzero)
        return PSA_ERROR_INVALID_SIGNATURE;
    operation_start();
    start = se050_port_tick_get();
    ret = se050_verify_prepare(bits, pub, pub_len, &id, &retained);
    {
        uint32_t ms = elapsed_ms(start);
        se050_port_critical_enter();
        counters.verify_create_ms += ms;
        se050_port_critical_exit();
    }
    status = ret == -SE050_EFULL ? PSA_ERROR_INSUFFICIENT_MEMORY : result(ret);
    if (status == PSA_SUCCESS)
    {
        se050_tick_t phase = se050_port_tick_get();
        uint32_t ms;
        ret = se050_key_verify(id, bits, hash_bits, hash, hash_len, sig, sig_len, &valid);
        ms = elapsed_ms(phase);
        se050_port_critical_enter();
        counters.verify_execute_ms += ms;
        se050_port_critical_exit();
        status =
            ret == SE050_OK ? (valid ? PSA_SUCCESS : PSA_ERROR_INVALID_SIGNATURE) : result(ret);
        phase = se050_port_tick_get();
        cleanup = retained ? PSA_SUCCESS : result(se050_transient_delete(id));
        ms = elapsed_ms(phase);
        se050_port_critical_enter();
        counters.verify_delete_ms += ms;
        se050_port_critical_exit();
        if (cleanup != PSA_SUCCESS)
        {
            se050_port_critical_enter();
            ++counters.cleanup_failures;
            se050_port_critical_exit();
            status = cleanup;
        }
    }
    operation_done(&counters.verify_calls, &counters.verify_failures, &counters.verify_ms, start,
                   status);
    return status;
}

psa_status_t se050_psa_verify_scope_end(void)
{
    se050_tick_t start = se050_port_tick_get();
    psa_status_t status = result(se050_verify_scope_end());
    uint32_t ms = elapsed_ms(start);
    se050_port_critical_enter();
    counters.verify_delete_ms += ms;
    counters.verify_ms += ms;
    if (status != PSA_SUCCESS)
        ++counters.cleanup_failures;
    se050_port_critical_exit();
    return status;
}

psa_status_t se050_psa_open(uint32_t id, size_t bits, mbedtls_svc_key_id_t *key)
{
    psa_key_attributes_t attr = PSA_KEY_ATTRIBUTES_INIT;
    uint8_t reference[4];
    psa_status_t status;
    reference[0] = (uint8_t)(id >> 24);
    reference[1] = (uint8_t)(id >> 16);
    reference[2] = (uint8_t)(id >> 8);
    reference[3] = (uint8_t)id;
    *key = MBEDTLS_SVC_KEY_ID_INIT;
    psa_set_key_type(&attr, PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1));
    psa_set_key_bits(&attr, bits);
    psa_set_key_usage_flags(&attr, PSA_KEY_USAGE_SIGN_HASH);
    psa_set_key_algorithm(&attr, PSA_ALG_ECDSA(PSA_ALG_ANY_HASH));
    psa_set_key_lifetime(&attr, PSA_KEY_LIFETIME_FROM_PERSISTENCE_AND_LOCATION(
                                    PSA_KEY_PERSISTENCE_VOLATILE, SE050_PSA_LOCATION));
    status = psa_import_key(&attr, reference, sizeof(reference), key);
    psa_reset_key_attributes(&attr);
    return status;
}
void se050_stats_entropy(size_t bytes, int success, uint32_t ms)
{
    se050_port_critical_enter();
    ++counters.entropy_calls;
    counters.entropy_ms += ms;
    if (success)
        counters.entropy_bytes += (uint32_t)bytes;
    else
        ++counters.entropy_failures;
    se050_port_critical_exit();
}
void se050_stats_get(struct se050_stats *stats)
{
    se050_port_critical_enter();
    *stats = counters;
    se050_port_critical_exit();
}
