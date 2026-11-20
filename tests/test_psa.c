/* Real vendored PSA core + Mbed TLS PK; mock only the SE050 EC backend. */
#include <assert.h>
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <windows.h>
#include <wincrypt.h>
#include "se050_psa.h"
#include "se050_crypto.h"
#include "mbedtls/pk.h"
#include "mbedtls/x509_csr.h"
#include "psa/crypto_extra.h"
#include "psa_crypto_core.h"

static mbedtls_svc_key_id_t device;
static int offline, device_signs, verify_invalid, delete_fail, generate_fail, public_fail;
static mbedtls_svc_key_id_t temporary[SE050_TRANSIENT_OBJECT_COUNT];
static unsigned created, deleted;
static uint8_t verify_pub[133];
static size_t verify_pub_length;
rt_tick_t rt_tick_get(void)
{
    static rt_tick_t tick;
    return ++tick;
}
static int temp_slot(uint32_t id)
{
    return id >= SE050_TRANSIENT_OBJECT_BASE &&
                   id < SE050_TRANSIENT_OBJECT_BASE + SE050_TRANSIENT_OBJECT_COUNT
               ? (int)(id - SE050_TRANSIENT_OBJECT_BASE)
               : -1;
}
rt_err_t se050_transient_create(size_t bits, const uint8_t *pub, size_t pub_len, uint32_t *id)
{
    unsigned i;
    psa_key_attributes_t a = PSA_KEY_ATTRIBUTES_INIT;
    *id = 0;
    assert(se050_offload_set(0, 0) == PSA_ERROR_BAD_STATE);
    if (offline || generate_fail)
        return -RT_EIO;
    for (i = 0; i < SE050_TRANSIENT_OBJECT_COUNT; ++i)
        if (mbedtls_svc_key_id_is_null(temporary[i]))
            break;
    if (i == SE050_TRANSIENT_OBJECT_COUNT)
        return -RT_EFULL;
    if (pub)
    {
        assert(pub_len <= sizeof(verify_pub));
        memcpy(verify_pub, pub, pub_len);
        verify_pub_length = pub_len;
        /* Mock public object needs no PSA slot; marker is never used as a key. */
        temporary[i] = 0x7ffffffe;
    }
    else
    {
        psa_set_key_type(&a, PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1));
        psa_set_key_bits(&a, bits);
        psa_set_key_algorithm(&a, PSA_ALG_ECDH);
        psa_set_key_usage_flags(&a, PSA_KEY_USAGE_DERIVE);
        assert(psa_generate_key(&a, &temporary[i]) == PSA_SUCCESS);
    }
    *id = SE050_TRANSIENT_OBJECT_BASE + i;
    ++created;
    return 0;
}
rt_err_t se050_verify_prepare(size_t bits, const uint8_t *pub, size_t n, uint32_t *id,
                              int *retained)
{
    *retained = 0;
    return se050_transient_create(bits, pub, n, id);
}
rt_err_t se050_verify_scope_end(void)
{
    return 0;
}
rt_err_t se050_transient_delete(uint32_t id)
{
    int i = temp_slot(id);
    assert(i >= 0 && !mbedtls_svc_key_id_is_null(temporary[i]));
    if (offline || delete_fail)
        return -RT_EIO;
    if (temporary[i] != 0x7ffffffe)
        assert(psa_destroy_key(temporary[i]) == PSA_SUCCESS);
    temporary[i] = MBEDTLS_SVC_KEY_ID_INIT;
    ++deleted;
    return 0;
}
void se050_transient_status(unsigned *active, unsigned *pending)
{
    unsigned i;
    *active = *pending = 0;
    for (i = 0; i < SE050_TRANSIENT_OBJECT_COUNT; ++i)
        if (temporary[i])
            ++*active;
}
rt_err_t se050_key_verify(uint32_t id, size_t bits, unsigned hashbits, const uint8_t *hash,
                          size_t hashlen, const uint8_t *sig, size_t siglen, int *valid)
{
    psa_key_attributes_t a = PSA_KEY_ATTRIBUTES_INIT;
    psa_status_t status;
    assert(temp_slot(id) >= 0);
    (void)hashbits;
    *valid = 0;
    if (offline)
        return -RT_EIO;
    if (verify_invalid)
        return 0;
    psa_set_key_type(&a, PSA_KEY_TYPE_ECC_PUBLIC_KEY(PSA_ECC_FAMILY_SECP_R1));
    psa_set_key_bits(&a, bits);
    /* Bypass driver dispatch inside the mocked chip, preventing recursion. */
    status = psa_verify_hash_builtin(&a, verify_pub, verify_pub_length, PSA_ALG_ECDSA_ANY, hash,
                                     hashlen, sig, siglen);
    *valid = status == PSA_SUCCESS;
    return status == PSA_SUCCESS || status == PSA_ERROR_INVALID_SIGNATURE ? 0 : -RT_EIO;
}
void mbedtls_platform_zeroize(void *buffer, size_t n)
{
    volatile uint8_t *p = buffer;
    while (n--)
        *p++ = 0;
}
void rt_enter_critical(void)
{
}
void rt_exit_critical(void)
{
}
void rt_kprintf(const char *fmt, ...)
{
    (void)fmt;
}
psa_status_t mbedtls_psa_external_get_random(mbedtls_psa_external_random_context_t *ctx,
                                             unsigned char *output, size_t len, size_t *actual)
{
    HCRYPTPROV provider;
    BOOL ok;
    (void)ctx;
    *actual = 0;
    if (!CryptAcquireContext(&provider, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT))
        return PSA_ERROR_INSUFFICIENT_ENTROPY;
    ok = CryptGenRandom(provider, (DWORD)len, output);
    CryptReleaseContext(provider, 0);
    if (!ok)
        return PSA_ERROR_INSUFFICIENT_ENTROPY;
    *actual = len;
    return PSA_SUCCESS;
}
rt_err_t se050_key_public(uint32_t id, uint8_t *output, size_t cap, size_t *length)
{
    *length = 0;
    if (offline || public_fail)
        return -RT_EIO;
    if (temp_slot(id) >= 0)
        return psa_export_public_key(temporary[temp_slot(id)], output, cap, length) == PSA_SUCCESS
                   ? 0
                   : -RT_EIO;
    if (id != SE050_TLS_ISO2_OBJECT)
        return -RT_EIO;
    return psa_export_public_key(device, output, cap, length) == PSA_SUCCESS ? 0 : -RT_EIO;
}
rt_err_t se050_key_sign(uint32_t id, size_t bits, unsigned hashbits, const uint8_t *hash,
                        size_t hashlen, uint8_t *sig, size_t cap, size_t *length)
{
    *length = 0;
    assert(id == SE050_TLS_ISO2_OBJECT && bits == 256 && hashbits == 256);
    ++device_signs;
    if (offline)
        return -RT_EIO;
    return psa_sign_hash(device, PSA_ALG_ECDSA(PSA_ALG_SHA_256), hash, hashlen, sig, cap, length) ==
                   PSA_SUCCESS
               ? 0
               : -RT_EIO;
}
rt_err_t se050_key_ecdh(uint32_t id, size_t bits, const uint8_t *peer, size_t peerlen, uint8_t *out,
                        size_t cap, size_t *length)
{
    (void)bits;
    *length = 0;
    if (offline || temp_slot(id) < 0)
        return -RT_EIO;
    return psa_raw_key_agreement(PSA_ALG_ECDH, temporary[temp_slot(id)], peer, peerlen, out, cap,
                                 length) == PSA_SUCCESS
               ? 0
               : -RT_EIO;
}
static void local_key(void)
{
    psa_key_attributes_t attr = PSA_KEY_ATTRIBUTES_INIT;
    const uint8_t scalar[32] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1};
    psa_set_key_type(&attr, PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1));
    psa_set_key_bits(&attr, 256);
    psa_set_key_usage_flags(&attr, PSA_KEY_USAGE_SIGN_HASH | PSA_KEY_USAGE_VERIFY_HASH);
    psa_set_key_algorithm(&attr, PSA_ALG_ECDSA(PSA_ALG_SHA_256));
    assert(psa_import_key(&attr, scalar, sizeof(scalar), &device) == PSA_SUCCESS);
    psa_reset_key_attributes(&attr);
}
static void driver_test(void)
{
    mbedtls_svc_key_id_t handle = MBEDTLS_SVC_KEY_ID_INIT, copy = MBEDTLS_SVC_KEY_ID_INIT;
    psa_key_attributes_t attr = PSA_KEY_ATTRIBUTES_INIT;
    uint8_t sig[80], hash[32] = {1}, pub[65], original[65], secret[100];
    size_t n, pubn, originaln;
    int i;
    struct se050_stats stats;
    assert(se050_psa_open(SE050_TLS_ISO2_OBJECT, 256, &handle) == PSA_SUCCESS);
    assert(psa_export_public_key(handle, pub, sizeof(pub), &pubn) == PSA_SUCCESS && pubn == 65);
    assert(psa_export_public_key(device, original, sizeof(original), &originaln) == PSA_SUCCESS);
    assert(originaln == pubn && memcmp(original, pub, pubn) == 0);
    assert(psa_export_key(handle, secret, sizeof(secret), &n) == PSA_ERROR_NOT_PERMITTED);
    assert(psa_get_key_attributes(handle, &attr) == PSA_SUCCESS);
    assert(psa_copy_key(handle, &attr, &copy) == PSA_ERROR_NOT_PERMITTED);
    psa_reset_key_attributes(&attr);
    assert(psa_sign_hash(handle, PSA_ALG_ECDSA(PSA_ALG_SHA_256), hash, sizeof(hash), sig,
                         sizeof(sig), &n) == PSA_SUCCESS &&
           n == 64);
    assert(device_signs == 1);
    assert(psa_verify_hash(device, PSA_ALG_ECDSA(PSA_ALG_SHA_256), hash, sizeof(hash), sig, n) ==
           PSA_SUCCESS);
    offline = 1;
    assert(psa_sign_hash(handle, PSA_ALG_ECDSA(PSA_ALG_SHA_256), hash, sizeof(hash), sig,
                         sizeof(sig), &n) == PSA_ERROR_HARDWARE_FAILURE &&
           n == 0);
    assert(device_signs == 2);
    offline = 0;
    se050_stats_get(&stats);
    assert(stats.sign_calls == 2 && stats.sign_failures == 1);
    assert(psa_destroy_key(handle) == PSA_SUCCESS);
    /* Repeated TLS context lifetimes must not leak slots or delete chip keys. */
    for (i = 0; i < 80; ++i)
    {
        assert(se050_psa_open(SE050_TLS_ISO2_OBJECT, 256, &handle) == PSA_SUCCESS);
        assert(psa_destroy_key(handle) == PSA_SUCCESS);
    }
    offline = 1;
    assert(se050_psa_open(SE050_TLS_ISO2_OBJECT, 256, &handle) == PSA_ERROR_HARDWARE_FAILURE);
    offline = 0;
    assert(se050_psa_open(0x12345678, 256, &handle) == PSA_ERROR_INVALID_ARGUMENT);
}
static void pk_test(void)
{
    /* RFC 5480 P-256 SPKI header followed by the device's public point. */
    uint8_t der[91] = {0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01,
                       0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0};
    uint8_t hash[32] = {2}, sig[80];
    size_t n, pubn;
    mbedtls_pk_context pub, opaque;
    mbedtls_svc_key_id_t handle = MBEDTLS_SVC_KEY_ID_INIT;
    mbedtls_pk_init(&pub);
    mbedtls_pk_init(&opaque);
    assert(psa_export_public_key(device, der + 26, 65, &pubn) == PSA_SUCCESS);
    assert(mbedtls_pk_parse_public_key(&pub, der, sizeof(der)) == 0);
    assert(se050_psa_open(SE050_TLS_ISO2_OBJECT, 256, &handle) == PSA_SUCCESS);
    assert(mbedtls_pk_wrap_psa(&opaque, handle) == 0);
    assert(mbedtls_pk_check_pair(&pub, &opaque) == 0);
    assert(mbedtls_pk_sign(&opaque, MBEDTLS_MD_SHA256, hash, sizeof(hash), sig, sizeof(sig), &n) ==
           0);
    assert(mbedtls_pk_verify(&pub, MBEDTLS_MD_SHA256, hash, sizeof(hash), sig, n) == 0);
    /* A different certificate/public key must fail before a TLS handshake. */
    {
        psa_key_attributes_t attrs = PSA_KEY_ATTRIBUTES_INIT;
        mbedtls_svc_key_id_t other = MBEDTLS_SVC_KEY_ID_INIT;
        psa_set_key_type(&attrs, PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1));
        psa_set_key_bits(&attrs, 256);
        psa_set_key_usage_flags(&attrs, PSA_KEY_USAGE_SIGN_HASH);
        psa_set_key_algorithm(&attrs, PSA_ALG_ECDSA(PSA_ALG_SHA_256));
        assert(psa_generate_key(&attrs, &other) == PSA_SUCCESS);
        assert(psa_export_public_key(other, der + 26, 65, &pubn) == PSA_SUCCESS);
        mbedtls_pk_free(&pub);
        assert(mbedtls_pk_parse_public_key(&pub, der, sizeof(der)) == 0);
        assert(mbedtls_pk_check_pair(&pub, &opaque) != 0);
        assert(psa_destroy_key(other) == PSA_SUCCESS);
        psa_reset_key_attributes(&attrs);
    }
    mbedtls_pk_free(&opaque);
    /* PK wrapper borrows the key: the caller releases the volatile handle. */
    assert(psa_get_key_attributes(handle, &(psa_key_attributes_t)PSA_KEY_ATTRIBUTES_INIT) ==
           PSA_SUCCESS);
    assert(psa_destroy_key(handle) == PSA_SUCCESS);
    mbedtls_pk_free(&pub);
}
static void bench_identity_test(void)
{
    /* Parse the existing bench identity and exercise the same explicit scalar
     * extraction as provision(). No private bytes are logged or written. */
    psa_key_attributes_t attr = PSA_KEY_ATTRIBUTES_INIT;
    mbedtls_pk_context pk;
    mbedtls_svc_key_id_t copy = MBEDTLS_SVC_KEY_ID_INIT;
    unsigned char sec1[121] = {0x30, 0x77, 0x02, 0x01, 0x01, 0x04, 0x20};
    static const unsigned char suffix[] = {0xa0, 0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d,
                                           0x03, 0x01, 0x07, 0xa1, 0x44, 0x03, 0x42, 0};
    unsigned char scalar[32];
    size_t n;
    sec1[38] = 1;
    memcpy(sec1 + 39, suffix, sizeof(suffix));
    assert(psa_export_public_key(device, sec1 + 56, 65, &n) == PSA_SUCCESS);
    mbedtls_pk_init(&pk);
    assert(mbedtls_pk_parse_key(&pk, sec1, sizeof(sec1), NULL, 0) == 0);
    assert(mbedtls_pk_get_psa_attributes(&pk, PSA_KEY_USAGE_SIGN_HASH, &attr) == 0);
    psa_set_key_usage_flags(&attr, PSA_KEY_USAGE_EXPORT | PSA_KEY_USAGE_SIGN_HASH);
    assert(mbedtls_pk_import_into_psa(&pk, &attr, &copy) == 0);
    assert(psa_export_key(copy, scalar, sizeof(scalar), &n) == PSA_SUCCESS && n == 32 &&
           scalar[31] == 1);
    mbedtls_platform_zeroize(scalar, sizeof(scalar));
    mbedtls_platform_zeroize(sec1, sizeof(sec1));
    mbedtls_pk_free(&pk);
    psa_reset_key_attributes(&attr);
    assert(psa_destroy_key(copy) == PSA_SUCCESS);
}
static void csr_test(void)
{
    mbedtls_pk_context pk;
    mbedtls_svc_key_id_t handle = MBEDTLS_SVC_KEY_ID_INIT;
    mbedtls_x509write_csr writer;
    mbedtls_x509_csr parsed;
    uint8_t der[1024], hash[32];
    size_t hashlen;
    int n, before = device_signs;
    mbedtls_pk_init(&pk);
    mbedtls_x509write_csr_init(&writer);
    mbedtls_x509_csr_init(&parsed);
    assert(se050_psa_open(SE050_TLS_ISO2_OBJECT, 256, &handle) == PSA_SUCCESS);
    assert(mbedtls_pk_wrap_psa(&pk, handle) == 0);
    mbedtls_x509write_csr_set_key(&writer, &pk);
    mbedtls_x509write_csr_set_md_alg(&writer, MBEDTLS_MD_SHA256);
    assert(mbedtls_x509write_csr_set_subject_name(&writer,
                                                  "CN=SE050 native CSR test,O=Test,C=CN") == 0);
    n = mbedtls_x509write_csr_der(&writer, der, sizeof(der));
    assert(n > 0 && device_signs == before + 1);
    assert(mbedtls_x509_csr_parse_der(&parsed, der + sizeof(der) - n, (size_t)n) == 0);
    assert(psa_hash_compute(PSA_ALG_SHA_256, parsed.cri.p, parsed.cri.len, hash, sizeof(hash),
                            &hashlen) == PSA_SUCCESS);
    assert(mbedtls_pk_verify(&parsed.pk, MBEDTLS_MD_SHA256, hash, hashlen,
                             parsed.MBEDTLS_PRIVATE(sig).p, parsed.MBEDTLS_PRIVATE(sig).len) == 0);
    mbedtls_x509_csr_free(&parsed);
    mbedtls_x509write_csr_free(&writer);
    mbedtls_pk_free(&pk);
    assert(psa_destroy_key(handle) == PSA_SUCCESS);
}

static void verify_test(void)
{
    psa_key_attributes_t a = PSA_KEY_ATTRIBUTES_INIT;
    mbedtls_svc_key_id_t pubkey = MBEDTLS_SVC_KEY_ID_INIT;
    uint8_t pub[65], sig[80], hash[32] = {3}, zero_sig[64] = {0};
    size_t pn, sn;
    unsigned before;
    struct se050_stats stats;
    assert(psa_export_public_key(device, pub, sizeof(pub), &pn) == PSA_SUCCESS);
    assert(psa_sign_hash(device, PSA_ALG_ECDSA(PSA_ALG_SHA_256), hash, sizeof(hash), sig,
                         sizeof(sig), &sn) == PSA_SUCCESS);
    psa_set_key_type(&a, PSA_KEY_TYPE_ECC_PUBLIC_KEY(PSA_ECC_FAMILY_SECP_R1));
    psa_set_key_usage_flags(&a, PSA_KEY_USAGE_VERIFY_HASH);
    psa_set_key_algorithm(&a, PSA_ALG_ECDSA_ANY);
    assert(psa_import_key(&a, pub, pn, &pubkey) == PSA_SUCCESS);
    assert(se050_offload_set(1, 1) == PSA_SUCCESS);
    before = created;
    assert(psa_verify_hash(pubkey, PSA_ALG_ECDSA_ANY, hash, sizeof(hash), sig, sn) == PSA_SUCCESS);
    assert(created == before + 1 && deleted == created);
    sig[0] ^= 1;
    assert(psa_verify_hash(pubkey, PSA_ALG_ECDSA_ANY, hash, sizeof(hash), sig, sn) ==
           PSA_ERROR_INVALID_SIGNATURE);
    sig[0] ^= 1;
    verify_invalid = 1; /* Hardware rejection must not be retried in software. */
    assert(psa_verify_hash(pubkey, PSA_ALG_ECDSA_ANY, hash, sizeof(hash), sig, sn) ==
           PSA_ERROR_INVALID_SIGNATURE);
    verify_invalid = 0;
    offline = 1;
    assert(psa_verify_hash(pubkey, PSA_ALG_ECDSA_ANY, hash, sizeof(hash), sig, sn) ==
           PSA_ERROR_HARDWARE_FAILURE);
    offline = 0;
    assert(psa_verify_hash(pubkey, PSA_ALG_ECDSA_ANY, hash, sizeof(hash), zero_sig,
                           sizeof(zero_sig)) == PSA_ERROR_INVALID_SIGNATURE);
    assert(psa_verify_hash(pubkey, PSA_ALG_ECDSA_ANY, hash, sizeof(hash), sig, sn - 1) ==
           PSA_ERROR_INVALID_SIGNATURE);
    assert(deleted == created);
    before = created;
    assert(se050_offload_set(0, 0) == PSA_SUCCESS);
    assert(psa_verify_hash(pubkey, PSA_ALG_ECDSA_ANY, hash, sizeof(hash), sig, sn) == PSA_SUCCESS);
    assert(created == before);
    assert(se050_offload_set(2, 0) == PSA_ERROR_INVALID_ARGUMENT);
    assert(psa_destroy_key(pubkey) == PSA_SUCCESS);
    se050_stats_get(&stats);
    assert(stats.verify_calls >= 4 && stats.verify_failures >= 3 && stats.verify_ms > 0);
}
static void ecdh_test(void)
{
    psa_key_attributes_t a = PSA_KEY_ATTRIBUTES_INIT;
    mbedtls_svc_key_id_t local = MBEDTLS_SVC_KEY_ID_INIT, chip = MBEDTLS_SVC_KEY_ID_INIT;
    uint8_t cp[65], lp[65], s1[32], s2[32], secret[40], reference[4];
    size_t cpn, lpn, n1, n2, n;
    unsigned before = created, i;
    struct se050_stats stats;
    psa_set_key_type(&a, PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1));
    psa_set_key_bits(&a, 256);
    psa_set_key_usage_flags(&a, PSA_KEY_USAGE_DERIVE);
    psa_set_key_algorithm(&a, PSA_ALG_ECDH);
    assert(psa_generate_key(&a, &local) == PSA_SUCCESS);
    psa_set_key_lifetime(&a, PSA_KEY_LIFETIME_FROM_PERSISTENCE_AND_LOCATION(
                                 PSA_KEY_PERSISTENCE_VOLATILE, SE050_PSA_LOCATION));
    assert(psa_generate_key(&a, &chip) == PSA_SUCCESS && created == before + 1);
    assert(psa_export_key(chip, secret, sizeof(secret), &n) == PSA_ERROR_NOT_PERMITTED);
    assert(psa_export_public_key(chip, cp, sizeof(cp), &cpn) == PSA_SUCCESS);
    assert(psa_export_public_key(local, lp, sizeof(lp), &lpn) == PSA_SUCCESS);
    {
        psa_status_t status =
            psa_raw_key_agreement(PSA_ALG_ECDH, chip, lp, lpn, s1, sizeof(s1), &n1);
        if (status)
            fprintf(stderr, "ECDH mock status=%ld\n", (long)status);
        assert(status == PSA_SUCCESS);
    }
    assert(psa_raw_key_agreement(PSA_ALG_ECDH, local, cp, cpn, s2, sizeof(s2), &n2) == PSA_SUCCESS);
    assert(n1 == 32 && n1 == n2 && memcmp(s1, s2, n1) == 0);
    offline = 1;
    assert(psa_raw_key_agreement(PSA_ALG_ECDH, chip, lp, lpn, s1, sizeof(s1), &n1) ==
           PSA_ERROR_HARDWARE_FAILURE);
    offline = 0;
    assert(psa_destroy_key(chip) == PSA_SUCCESS && deleted == created);
    for (i = 0; i < 80; ++i)
    {
        assert(psa_generate_key(&a, &chip) == PSA_SUCCESS);
        assert(psa_destroy_key(chip) == PSA_SUCCESS);
    }
    generate_fail = 1;
    chip = MBEDTLS_SVC_KEY_ID_INIT;
    assert(psa_generate_key(&a, &chip) == PSA_ERROR_HARDWARE_FAILURE &&
           mbedtls_svc_key_id_is_null(chip));
    generate_fail = 0;
    psa_set_key_usage_flags(&a, PSA_KEY_USAGE_DERIVE | PSA_KEY_USAGE_EXPORT);
    assert(psa_generate_key(&a, &chip) == PSA_ERROR_NOT_PERMITTED);
    psa_set_key_usage_flags(&a, PSA_KEY_USAGE_DERIVE);
    reference[0] = 0x53;
    reference[1] = 5;
    reference[2] = 2;
    reference[3] = 0;
    assert(psa_import_key(&a, reference, sizeof(reference), &chip) == PSA_ERROR_INVALID_ARGUMENT);
    assert(psa_generate_key(&a, &chip) == PSA_SUCCESS);
    public_fail = 1;
    assert(psa_export_public_key(chip, cp, sizeof(cp), &cpn) == PSA_ERROR_HARDWARE_FAILURE);
    public_fail = 0;
    assert(psa_destroy_key(chip) == PSA_SUCCESS && created == deleted);
    {
        mbedtls_svc_key_id_t occupied[SE050_TRANSIENT_OBJECT_COUNT];
        for (i = 0; i < SE050_TRANSIENT_OBJECT_COUNT; ++i)
            assert(psa_generate_key(&a, &occupied[i]) == PSA_SUCCESS);
        assert(psa_generate_key(&a, &chip) == PSA_ERROR_INSUFFICIENT_MEMORY);
        for (i = 0; i < SE050_TRANSIENT_OBJECT_COUNT; ++i)
            assert(psa_destroy_key(occupied[i]) == PSA_SUCCESS);
        assert(created == deleted);
    }
    assert(psa_generate_key(&a, &chip) == PSA_SUCCESS);
    delete_fail = 1;
    assert(psa_destroy_key(chip) == PSA_ERROR_HARDWARE_FAILURE);
    delete_fail = 0;
    /* The APDU suite checks quarantined-object retry. Release mock device now. */
    assert(se050_transient_delete(SE050_TRANSIENT_OBJECT_BASE) == 0);
    assert(psa_destroy_key(local) == PSA_SUCCESS && created == deleted);
    /* Whole PSA shutdown must also release an unfinished ephemeral exchange. */
    assert(psa_generate_key(&a, &chip) == PSA_SUCCESS);
    mbedtls_psa_crypto_free();
    assert(created == deleted);
    assert(psa_crypto_init() == PSA_SUCCESS);
    se050_stats_get(&stats);
    assert(stats.keygen_calls >= 83 && stats.keygen_failures == 2 && stats.ecdh_calls == 2 &&
           stats.ecdh_failures == 1 && stats.cleanup_failures == 1);
}

int main(void)
{
    assert(psa_crypto_init() == PSA_SUCCESS);
    local_key();
    driver_test();
    pk_test();
    bench_identity_test();
    csr_test();
    verify_test();
    assert(psa_destroy_key(device) == PSA_SUCCESS);
    ecdh_test();
    mbedtls_psa_crypto_free();
    puts("SE050 PSA/PK/CSR integration tests passed (real crypto core, mock device)");
    return 0;
}
