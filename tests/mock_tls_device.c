/* Host-only APDU emulator. Never included by the firmware project. */
#include <assert.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include "se050_crypto.h"
#include "se050_psa.h"
#include "psa_crypto_core.h"
/* This host emulator has one connection and no transport reconnects. */
uint32_t se050_session_generation(void)
{
    return 1;
}
static mbedtls_svc_key_id_t keys[SE050_TRANSIENT_OBJECT_COUNT];
static uint8_t points[SE050_TRANSIENT_OBJECT_COUNT][133];
static size_t point_lengths[SE050_TRANSIENT_OBJECT_COUNT], key_bits[SE050_TRANSIENT_OBJECT_COUNT];
static const uint8_t *field(const uint8_t *p, size_t n, uint8_t tag, size_t *length)
{
    size_t k;
    while (n >= 2)
    {
        uint8_t t = *p++;
        --n;
        k = *p++;
        --n;
        if (k == 0x81)
        {
            if (!n)
                break;
            k = *p++;
            --n;
        }
        if (k > n)
            break;
        if (t == tag)
        {
            *length = k;
            return p;
        }
        p += k;
        n -= k;
    }
    *length = 0;
    return NULL;
}
static int answer(uint8_t *out, size_t cap, size_t *length, const uint8_t *p, size_t n)
{
    size_t head = n < 128 ? 2 : 3;
    assert(cap >= head + n + 2);
    out[0] = 0x41;
    out[1] = n < 128 ? (uint8_t)n : 0x81;
    if (head == 3)
        out[2] = (uint8_t)n;
    memcpy(out + head, p, n);
    out[head + n] = 0x90;
    out[head + n + 1] = 0;
    *length = head + n + 2;
    return 0;
}
int se050_transceive(const uint8_t *tx, size_t txlen, uint8_t *rx, size_t cap, size_t *length)
{
    const uint8_t *data, *p, *hash, *der;
    size_t n, k, hn, dn, pn, sn;
    int slot;
    uint32_t id;
    uint8_t value, point[133], raw[132];
    psa_key_attributes_t a = PSA_KEY_ATTRIBUTES_INIT;
    psa_status_t status;
    *length = 0;
    assert(txlen >= 7 && tx[0] == 0x80);
    n = ((size_t)tx[5] << 8) | tx[6];
    data = tx + 7;
    assert(n <= txlen - 7);
    if (tx[1] == 2 && tx[2] == 0x0b && tx[3] == 0x25)
    {
        const uint8_t ready[] = {2, 2, 2, 2, 2};
        return answer(rx, cap, length, ready, sizeof(ready));
    }
    p = field(data, n, 0x41, &k);
    assert(p && k == 4);
    id = ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) | ((uint32_t)p[2] << 8) | p[3];
    assert(id >= SE050_TRANSIENT_OBJECT_BASE &&
           id < SE050_TRANSIENT_OBJECT_BASE + SE050_TRANSIENT_OBJECT_COUNT);
    slot = (int)(id - SE050_TRANSIENT_OBJECT_BASE);
    if (tx[1] == 4 && tx[3] == 0x27)
    {
        value = keys[slot] || point_lengths[slot] ? 1 : 2;
        return answer(rx, cap, length, &value, 1);
    }
    if (tx[1] == 0x81 && tx[2] == 1)
    {
        assert(!keys[slot] && point_lengths[slot]);
        assert(!field(data, n, 0x11, &k) && !field(data, n, 0x42, &k));
        p = field(data, n, 0x44, &k);
        assert(p && k == point_lengths[slot]);
        memcpy(points[slot], p, k);
    }
    else if (tx[1] == 0x81)
    {
        assert(!keys[slot] && !point_lengths[slot]);
        p = field(data, n, 0x42, &k);
        assert(p && k == 1);
        key_bits[slot] = *p == 3 ? 256 : *p == 4 ? 384 : *p == 5 ? 521 : 0;
        assert(key_bits[slot]);
        if (tx[2] == 0x21)
        {
            p = field(data, n, 0x44, &k);
            assert(p && k <= 133);
            memcpy(points[slot], p, k);
            point_lengths[slot] = k;
        }
        else
        {
            assert(tx[2] == 0x61);
            psa_set_key_type(&a, PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1));
            psa_set_key_bits(&a, key_bits[slot]);
            psa_set_key_algorithm(&a, PSA_ALG_ECDH);
            psa_set_key_usage_flags(&a, PSA_KEY_USAGE_DERIVE);
            assert(psa_generate_key(&a, &keys[slot]) == PSA_SUCCESS);
        }
    }
    else if (tx[1] == 2 && tx[2] == 0 && tx[3] == 0)
    {
        if (getenv("HOST_SE050_FAULT") && !strcmp(getenv("HOST_SE050_FAULT"), "public_export"))
        {
            assert(cap >= 2);
            rx[0] = 0x69;
            rx[1] = 0x85;
            *length = 2;
            return 0;
        }
        assert(keys[slot]);
        assert(psa_export_public_key(keys[slot], point, sizeof(point), &pn) == PSA_SUCCESS);
        return answer(rx, cap, length, point, pn);
    }
    else if (tx[1] == 3 && tx[2] == 0x0c && tx[3] == 0x0a)
    {
        assert(point_lengths[slot]);
        hash = field(data, n, 0x43, &hn);
        der = field(data, n, 0x45, &dn);
        assert(hash && der);
        assert(se050_der_to_raw(der, dn, (key_bits[slot] + 7) / 8, raw, sizeof(raw)) == 0);
        psa_set_key_type(&a, PSA_KEY_TYPE_ECC_PUBLIC_KEY(PSA_ECC_FAMILY_SECP_R1));
        psa_set_key_bits(&a, key_bits[slot]);
        status = psa_verify_hash_builtin(&a, points[slot], point_lengths[slot], PSA_ALG_ECDSA_ANY,
                                         hash, hn, raw, 2 * ((key_bits[slot] + 7) / 8));
        assert(status == PSA_SUCCESS || status == PSA_ERROR_INVALID_SIGNATURE);
        value = status == PSA_SUCCESS ? 1 : 2;
        if (getenv("HOST_SE050_FAULT") && !strcmp(getenv("HOST_SE050_FAULT"), "verify"))
            value = 2;
        return answer(rx, cap, length, &value, 1);
    }
    else if (tx[1] == 3 && tx[2] == 1 && tx[3] == 0x0f)
    {
        uint8_t shared[66];
        int ret;
        p = field(data, n, 0x42, &k);
        assert(p && keys[slot]);
        assert(psa_raw_key_agreement(PSA_ALG_ECDH, keys[slot], p, k, shared, sizeof(shared), &sn) ==
               PSA_SUCCESS);
        ret = answer(rx, cap, length, shared, sn);
        memset(shared, 0, sizeof(shared));
        return ret;
    }
    else if (tx[1] == 4 && tx[3] == 0x28)
    {
        assert(keys[slot] || point_lengths[slot]);
        if (keys[slot])
            assert(psa_destroy_key(keys[slot]) == PSA_SUCCESS);
        keys[slot] = MBEDTLS_SVC_KEY_ID_INIT;
        point_lengths[slot] = 0;
    }
    else
        assert(0 && "unhandled mock APDU");
    assert(cap >= 2);
    rx[0] = 0x90;
    rx[1] = 0;
    *length = 2;
    return 0;
}
