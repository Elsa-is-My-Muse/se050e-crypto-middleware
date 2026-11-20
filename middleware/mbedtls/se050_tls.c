#include "se050_tls.h"
#include "se050_crypto.h"
#include <string.h>

static int wrap(mbedtls_pk_context *pk, uint32_t id, size_t bits, mbedtls_svc_key_id_t *handle)
{
    int ret = (int)se050_psa_open(id, bits, handle);
    if (!ret)
        ret = mbedtls_pk_wrap_psa(pk, *handle);
    if (ret && !mbedtls_svc_key_id_is_null(*handle))
    {
        (void)psa_destroy_key(*handle);
        *handle = MBEDTLS_SVC_KEY_ID_INIT;
    }
    return ret;
}
int se050_parse_key(mbedtls_pk_context *pk, const uint8_t *stored, size_t n,
                    mbedtls_svc_key_id_t *handle)
{
    uint32_t id;
    size_t bits;
    *handle = MBEDTLS_SVC_KEY_ID_INIT;
    if (se050_key_reference_parse(stored, n, &id, &bits))
        return wrap(pk, id, bits, handle);
    /* A corrupt reference must not be interpreted as a software private key. */
    if (n >= 4 && !memcmp(stored, "SE05", 4))
        return MBEDTLS_ERR_PK_BAD_INPUT_DATA;
    return mbedtls_pk_parse_key(pk, stored, n, NULL, 0);
}
int se050_tls_load(mbedtls_pk_context *pk, const mbedtls_pk_context *certificate_key,
                   const uint8_t *stored, size_t n, int iso20, mbedtls_svc_key_id_t *handle)
{
#if !SE050_TLS_PRIVATE_KEY
    (void)certificate_key;
    (void)iso20;
    return se050_parse_key(pk, stored, n, handle);
#else
    uint32_t id = iso20 ? SE050_TLS_ISO20_OBJECT : SE050_TLS_ISO2_OBJECT;
    size_t bits = mbedtls_pk_get_bitlen(certificate_key);
    int ret;
    *handle = MBEDTLS_SVC_KEY_ID_INIT;
    if (stored && n >= 4 && !memcmp(stored, "SE05", 4))
    {
        size_t ref_bits;
        if (!se050_key_reference_parse(stored, n, &id, &ref_bits) || ref_bits != bits)
            return MBEDTLS_ERR_PK_BAD_INPUT_DATA;
    }
    ret = wrap(pk, id, bits, handle);
    if (!ret)
        ret = mbedtls_pk_check_pair(certificate_key, pk);
    if (ret)
    {
        se050_port_printf("SE050 TLS key unavailable/mismatch object=0x%08x ret=%d\n", (unsigned)id,
                          ret);
        mbedtls_pk_free(pk);
        if (!mbedtls_svc_key_id_is_null(*handle))
            (void)psa_destroy_key(*handle);
        *handle = MBEDTLS_SVC_KEY_ID_INIT;
        return ret;
    }
    se050_port_printf("SE050 TLS private key object=0x%08x bits=%u\n", (unsigned)id,
                      (unsigned)bits);
    return 0;
#endif
}
int se050_csr_key(mbedtls_pk_context *pk, mbedtls_svc_key_id_t *handle, uint8_t *reference,
                  size_t *length)
{
    unsigned i;
    int exists;
    uint32_t id;
    se050_status_t status;
    *length = 0;
    for (i = 0; i < SE050_CSR_OBJECT_COUNT; ++i)
    {
        id = SE050_CSR_OBJECT_BASE + i;
        status = se050_key_exists(id, &exists);
        if (status != SE050_OK)
            return status;
        if (exists)
            continue;
        status = se050_key_create(id, 256, NULL, 0, NULL, 0);
        if (status == -SE050_EBUSY)
            continue;
        if (status != SE050_OK)
            return status;
        if (wrap(pk, id, 256, handle))
            return -1;
        se050_key_reference(reference, id, 256);
        *length = SE050_KEY_REFERENCE_SIZE;
        se050_port_printf("SE050 CSR generated in chip object=0x%08x bits=256\n", (unsigned)id);
        return 0;
    }
    se050_port_printf(
        "SE050 CSR slots full; retain existing identities and provision a new application slot\n");
    return -1;
}
