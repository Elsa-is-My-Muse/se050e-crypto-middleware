/* APDUs follow NXP Plug & Trust Se05x_API_WriteECKey, ReadObject,
 * CheckObjectExists, ECDSASign and ECDHGenerateSharedSecret. The existing
 * session layer owns the T=1 connection and serializes every exchange. */
#include "se050_crypto.h"
#include "se050_curves.h"
#include <string.h>

static se050_mutex_t create_mutex;
static int create_mutex_ready;
/* 0: free; 1: live owned object; 2: deletion pending after an I/O failure. */
static uint8_t transient_state[SE050_TRANSIENT_OBJECT_COUNT];
static uint32_t transient_generation[SE050_TRANSIENT_OBJECT_COUNT];
/* Protected by create_mutex; only cache confirmed initialized curves. */
static uint32_t curve_generation;
static uint8_t curves_ready_mask;
/* Public keys only. A batch cannot span tasks, handshakes or SE sessions. */
static int verify_reuse_enabled;
static void *verify_owner;
static uint32_t verify_object;
static size_t verify_bits;
static se050_status_t create_lock(void)
{
    se050_port_critical_enter();
    if (!create_mutex_ready &&
        se050_port_mutex_init(&create_mutex, "se_key", SE050_MUTEX_PRIO) == SE050_OK)
        create_mutex_ready = 1;
    se050_port_critical_exit();
    return create_mutex_ready ? se050_port_mutex_take(&create_mutex, SE050_WAIT_FOREVER)
                              : -SE050_ERROR;
}

static void put32(uint8_t *p, uint32_t value)
{
    p[0] = (uint8_t)(value >> 24);
    p[1] = (uint8_t)(value >> 16);
    p[2] = (uint8_t)(value >> 8);
    p[3] = (uint8_t)value;
}
static uint32_t get32(const uint8_t *p)
{
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) | ((uint32_t)p[2] << 8) | p[3];
}
static int object_valid(uint32_t id)
{
    return (id & 0xFFFF0000UL) == 0x53050000UL;
}
static int curve(size_t bits)
{
    return bits == 256 ? 3 : bits == 384 ? 4 : bits == 521 ? 5 : 0;
}
static size_t tlv(uint8_t *p, uint8_t tag, const uint8_t *data, size_t n)
{
    size_t h = n < 128 ? 2 : 3;
    p[0] = tag;
    if (h == 2)
        p[1] = (uint8_t)n;
    else
    {
        p[1] = 0x81;
        p[2] = (uint8_t)n;
    }
    if (n)
        memcpy(p + h, data, n);
    return h + n;
}
static size_t object_tlv(uint8_t *p, uint32_t id)
{
    p[0] = 0x41;
    p[1] = 4;
    put32(p + 2, id);
    return 6;
}
static void clear_bytes(void *buffer, size_t n)
{
    volatile uint8_t *p = buffer;
    while (n--)
        *p++ = 0;
}
static se050_status_t command(uint8_t ins, uint8_t p1, uint8_t p2, const uint8_t *data, size_t n,
                              uint8_t *output, size_t capacity, size_t *length)
{
    uint8_t apdu[384], response[180];
    size_t received = 0, pos = 2, count;
    se050_status_t status;
    if (length)
        *length = 0;
    if (n > sizeof(apdu) - 9 || (!data && n))
        return -SE050_EINVAL;
    apdu[0] = 0x80;
    apdu[1] = ins;
    apdu[2] = p1;
    apdu[3] = p2;
    apdu[4] = 0;
    apdu[5] = (uint8_t)(n >> 8);
    apdu[6] = (uint8_t)n;
    if (n)
        memcpy(apdu + 7, data, n);
    apdu[7 + n] = 0;
    apdu[8 + n] = 0;
    status = se050_transceive(apdu, n ? n + (output ? 9 : 7) : (output ? 7 : 4), response,
                              sizeof(response), &received);
    if (status != SE050_OK)
        goto exit;
    status = -SE050_EIO;
    if (received > sizeof(response) || received < 2)
        goto exit;
    if (response[received - 2] != 0x90 || response[received - 1] != 0)
    {
        se050_port_printf("SE050 APDU ins=%02x p1=%02x p2=%02x sw=%02x%02x\n", ins, p1, p2,
                          response[received - 2], response[received - 1]);
        goto exit;
    }
    if (!output)
    {
        status = received == 2 ? SE050_OK : -SE050_EIO;
        goto exit;
    }
    if (!length || received < 4 || response[0] != 0x41)
        goto exit;
    count = response[1];
    if (count == 0x81)
    {
        if (received < 5)
            goto exit;
        count = response[pos++];
    }
    else if (count == 0x82)
    {
        if (received < 6)
            goto exit;
        count = ((size_t)response[pos] << 8) | response[pos + 1];
        pos += 2;
    }
    else if (count > 0x7f)
        goto exit;
    if (count != received - pos - 2)
        goto exit;
    if (count > capacity)
    {
        status = -SE050_EFULL;
        goto exit;
    }
    memcpy(output, response + pos, count);
    *length = count;
    status = SE050_OK;
exit:
    /* Requests may contain an imported scalar, responses an ECDH secret. */
    clear_bytes(apdu, sizeof(apdu));
    clear_bytes(response, sizeof(response));
    return status;
}
/* Follow NXP CreateCurve: never rewrite an initialized curve. */
#define CURVE_VALUES(NAME)                                                                         \
    static const uint8_t NAME##_a[] = {EC_PARAM_##NAME##_a};                                       \
    static const uint8_t NAME##_b[] = {EC_PARAM_##NAME##_b};                                       \
    static const uint8_t NAME##_g[] = {4, EC_PARAM_##NAME##_x, EC_PARAM_##NAME##_y};               \
    static const uint8_t NAME##_n[] = {EC_PARAM_##NAME##_order};                                   \
    static const uint8_t NAME##_p[] = {EC_PARAM_##NAME##_prime}
CURVE_VALUES(prime256v1);
CURVE_VALUES(secp384r1);
CURVE_VALUES(secp521r1);
struct curve_value
{
    const uint8_t *data;
    size_t length;
};
#define CURVE_ROW(NAME)                                                                            \
    {                                                                                              \
        {NAME##_a, sizeof(NAME##_a)}, {NAME##_b, sizeof(NAME##_b)}, {NAME##_g, sizeof(NAME##_g)},  \
            {NAME##_n, sizeof(NAME##_n)},                                                          \
        {                                                                                          \
            NAME##_p, sizeof(NAME##_p)                                                             \
        }                                                                                          \
    }
static se050_status_t ensure_curve(uint8_t c)
{
    static const struct curve_value values[3][5] = {CURVE_ROW(prime256v1), CURVE_ROW(secp384r1),
                                                    CURVE_ROW(secp521r1)};
    static const uint8_t parameter[] = {1, 2, 4, 8, 0x10};
    uint8_t list[64], data[144];
    size_t length = 0, n;
    unsigned i;
    se050_status_t status;
    uint32_t generation = se050_session_generation();
    if (c < 3 || c > 5)
        return -SE050_EINVAL;
    if (generation != curve_generation)
    {
        curves_ready_mask = 0;
        curve_generation = generation;
    }
    if (curves_ready_mask & (1u << (c - 3)))
        return SE050_OK;
    status = command(2, 0x0b, 0x25, NULL, 0, list, sizeof(list), &length);
    if (status != SE050_OK)
        return status;
    if (length < c)
        return -SE050_EIO;
    /* One list reply describes all supported curves. Do not publish results
     * if the transport reconnected while obtaining this reply. */
    if (generation == se050_session_generation())
    {
        for (i = 3; i <= 5 && i <= length; ++i)
            if (list[i - 1] == 2)
                curves_ready_mask |= (uint8_t)(1u << (i - 3));
    }
    if (list[c - 1] == 2)
        return SE050_OK;
    if (list[c - 1] != 1)
        return -SE050_EIO;
    n = tlv(data, 0x41, &c, 1);
    status = command(1, 0x0b, 4, data, n, NULL, 0, NULL);
    for (i = 0; status == SE050_OK && i < 5; ++i)
    {
        n = tlv(data, 0x41, &c, 1);
        n += tlv(data + n, 0x42, &parameter[i], 1);
        n += tlv(data + n, 0x43, values[c - 3][i].data, values[c - 3][i].length);
        status = command(1, 0x0b, 0x40, data, n, NULL, 0, NULL);
    }
    if (status == SE050_OK)
    {
        if (generation == se050_session_generation())
            curves_ready_mask |= (uint8_t)(1u << (c - 3));
        se050_port_printf("SE050 curve initialized id=%u\n", c);
    }
    return status;
}
se050_status_t se050_key_exists(uint32_t id, int *exists)
{
    uint8_t data[6], result = 0;
    size_t n = 0;
    se050_status_t status;
    if (!object_valid(id) || !exists)
        return -SE050_EINVAL;
    *exists = 0;
    object_tlv(data, id);
    status = command(4, 0, 0x27, data, sizeof(data), &result, 1, &n);
    if (status != SE050_OK)
        return status;
    if (n != 1 || (result != 1 && result != 2))
        return -SE050_EIO;
    *exists = result == 1;
    return SE050_OK;
}
se050_status_t se050_key_create(uint32_t id, size_t bits, const uint8_t *priv, size_t priv_len,
                                const uint8_t *pub, size_t pub_len)
{
    /* Anonymous access policy: sign, verify, ECDH, public read and delete.
     * No private-key export/wrap or key overwrite permission is granted.
     * Transport remains plain T=1 until a device-specific SCP03 is provisioned. */
    static const uint8_t policy[] = {8, 0, 0, 0, 0, 0x1c, 0x24, 0, 0};
    uint8_t data[256], c = (uint8_t)curve(bits);
    size_t n = 0, scalar = (bits + 7) / 8;
    int exists = 0;
    se050_status_t status;
    if (!object_valid(id) || !c || ((!priv || !pub) && (priv_len || pub_len)) ||
        ((priv || pub) && (priv_len != scalar || pub_len != 1 + 2 * scalar || pub[0] != 4)))
        return -SE050_EINVAL;
    status = create_lock();
    if (status != SE050_OK)
        return status;
    status = se050_key_exists(id, &exists);
    if (status == SE050_OK && exists)
        status = -SE050_EBUSY;
    if (status == SE050_OK)
        status = ensure_curve(c);
    if (status == SE050_OK)
    {
        n += tlv(data + n, 0x11, policy, sizeof(policy));
        n += object_tlv(data + n, id);
        n += tlv(data + n, 0x42, &c, 1);
        if (priv_len)
            n += tlv(data + n, 0x43, priv, priv_len);
        if (pub_len)
            n += tlv(data + n, 0x44, pub, pub_len);
        status = command(1, 0x61, 0, data, n, NULL, 0, NULL);
    }
    {
        volatile uint8_t *p = data;
        size_t i;
        for (i = 0; i < sizeof(data); ++i)
            p[i] = 0;
    }
    se050_port_mutex_release(&create_mutex);
    return status;
}
se050_status_t se050_key_public(uint32_t id, uint8_t *output, size_t capacity, size_t *length)
{
    uint8_t data[6];
    if (!object_valid(id) || !output || !length)
        return -SE050_EINVAL;
    *length = 0;
    object_tlv(data, id);
    return command(2, 0, 0, data, sizeof(data), output, capacity, length);
}
/* Strict DER parser: reject negative, zero, padded, truncated or trailing data. */
se050_status_t se050_der_to_raw(const uint8_t *der, size_t n, size_t scalar, uint8_t *raw,
                                size_t cap)
{
    size_t pos = 2, seq, i, len, j;
    int nonzero;
    if (!raw || !der || !scalar || scalar > 66 || cap < 2 * scalar || n < 8 || der[0] != 0x30)
        return -SE050_EINVAL;
    memset(raw, 0, 2 * scalar);
    seq = der[1];
    if (seq == 0x81)
    {
        if (n < 9 || der[2] < 128)
            return -SE050_EINVAL;
        seq = der[pos++];
    }
    else if (seq > 127)
        return -SE050_EINVAL;
    if (seq != n - pos)
        return -SE050_EINVAL;
    for (i = 0; i < 2; ++i)
    {
        if (pos + 2 > n || der[pos++] != 2)
            return -SE050_EINVAL;
        len = der[pos++];
        if (!len || len > n - pos || (der[pos] & 0x80))
            return -SE050_EINVAL;
        if (der[pos] == 0 && len > 1)
        {
            if (!(der[pos + 1] & 0x80))
                return -SE050_EINVAL;
            ++pos;
            --len;
        }
        if (len > scalar)
            return -SE050_EINVAL;
        nonzero = 0;
        for (j = 0; j < len; ++j)
            nonzero |= der[pos + j];
        if (!nonzero)
            return -SE050_EINVAL;
        memcpy(raw + i * scalar + scalar - len, der + pos, len);
        pos += len;
    }
    return pos == n ? SE050_OK : -SE050_EINVAL;
}
se050_status_t se050_key_sign(uint32_t id, size_t bits, unsigned hash_bits, const uint8_t *hash,
                              size_t hash_len, uint8_t *signature, size_t cap, size_t *length)
{
    uint8_t data[80], der[144], alg;
    size_t n = 0, der_len = 0, scalar = (bits + 7) / 8;
    se050_status_t status;
    if (length)
        *length = 0;
    alg = hash_bits == 256 ? 0x21 : hash_bits == 384 ? 0x22 : hash_bits == 512 ? 0x26 : 0;
    if (!object_valid(id) || !curve(bits) || !alg || !hash || hash_len != hash_bits / 8 ||
        !signature || !length)
        return -SE050_EINVAL;
    if (cap < 2 * scalar)
        return -SE050_EFULL;
    n += object_tlv(data + n, id);
    n += tlv(data + n, 0x42, &alg, 1);
    n += tlv(data + n, 0x43, hash, hash_len);
    status = command(3, 0x0c, 9, data, n, der, sizeof(der), &der_len);
    if (status == SE050_OK)
        status = se050_der_to_raw(der, der_len, scalar, signature, cap);
    if (status == SE050_OK)
        *length = 2 * scalar;
    else
        memset(signature, 0, 2 * scalar);
    return status;
}
se050_status_t se050_key_ecdh(uint32_t id, size_t bits, const uint8_t *peer, size_t peer_len,
                              uint8_t *output, size_t capacity, size_t *length)
{
    uint8_t data[144];
    size_t n = 0, scalar = (bits + 7) / 8;
    se050_status_t status;
    if (length)
        *length = 0;
    if (!object_valid(id) || !curve(bits) || !peer || peer_len != 1 + 2 * scalar || peer[0] != 4 ||
        !output || !length)
        return -SE050_EINVAL;
    if (capacity < scalar)
        return -SE050_EFULL;
    n += object_tlv(data + n, id);
    n += tlv(data + n, 0x42, peer, peer_len);
    status = command(3, 1, 0x0f, data, n, output, capacity, length);
    if (status == SE050_OK && *length != scalar)
        status = -SE050_EIO;
    if (status != SE050_OK)
    {
        memset(output, 0, capacity);
        *length = 0;
    }
    return status;
}

/* Called with create_mutex held, only for objects this boot created. A lost
 * write/delete response leaves the ID quarantined until deletion is confirmed. */
static se050_status_t transient_delete_locked(unsigned slot)
{
    uint32_t id = SE050_TRANSIENT_OBJECT_BASE + slot;
    uint8_t data[6];
    int exists = 0;
    se050_status_t status = SE050_OK;
    int live =
        transient_state[slot] == 1 && transient_generation[slot] == se050_session_generation();
    transient_state[slot] = 2;
    /* A confirmed live object needs only DELETE. An uncertain create/delete
     * still needs EXISTS, so a lost response never frees an unconfirmed ID. */
    if (!live)
        status = se050_key_exists(id, &exists);
    if (status == SE050_OK && (live || exists))
    {
        object_tlv(data, id);
        status = command(4, 0, 0x28, data, sizeof(data), NULL, 0, NULL);
    }
    if (status == SE050_OK)
        transient_state[slot] = 0;
    else
        se050_port_printf("SE050 transient cleanup object=0x%08x status=%d pending=1\n",
                          (unsigned)id, status);
    return status;
}
static se050_status_t transient_create(size_t bits, const uint8_t *pub, size_t pub_len,
                                       uint32_t *id, int update_public)
{
    /* Verify-only public key, or chip-generated DERIVE key. No overwrite/export. */
    uint8_t policy[] = {8, 0, 0, 0, 0, 0x04, 0x24, 0, 0};
    uint8_t data[168], c = (uint8_t)curve(bits);
    size_t n = 0, scalar = (bits + 7) / 8;
    unsigned i;
    int exists;
    se050_status_t status;
    if (!id)
        return -SE050_EINVAL;
    *id = 0;
    if (!c || (!pub && pub_len) || (pub && (pub_len != 1 + 2 * scalar || pub[0] != 4)))
        return -SE050_EINVAL;
    status = create_lock();
    if (status != SE050_OK)
        return status;
    for (i = 0; i < SE050_TRANSIENT_OBJECT_COUNT; ++i)
    {
        if (transient_state[i] == 2)
            (void)transient_delete_locked(i);
        if (transient_state[i])
            continue;
        status = se050_key_exists(SE050_TRANSIENT_OBJECT_BASE + i, &exists);
        if (status != SE050_OK)
            goto exit;
        if (!exists)
            break; /* Pre-existing IDs are never adopted or deleted. */
    }
    if (i == SE050_TRANSIENT_OBJECT_COUNT)
    {
        status = -SE050_EFULL;
        goto exit;
    }
    status = ensure_curve(c);
    if (status != SE050_OK)
        goto exit;
    if (pub)
        policy[5] = 0x08;
    if (pub && update_public)
        policy[6] |= 0x10; /* NXP POLICY_OBJ_ALLOW_WRITE; public verify slot only. */
    n += tlv(data + n, 0x11, policy, sizeof(policy));
    n += object_tlv(data + n, SE050_TRANSIENT_OBJECT_BASE + i);
    n += tlv(data + n, 0x42, &c, 1);
    if (pub)
        n += tlv(data + n, 0x44, pub, pub_len);
    transient_state[i] = 2; /* The APDU may execute even if its response is lost. */
    status = command(0x81, pub ? 0x21 : 0x61, 0, data, n, NULL, 0, NULL);
    if (status == SE050_OK)
    {
        transient_state[i] = 1;
        transient_generation[i] = se050_session_generation();
        *id = SE050_TRANSIENT_OBJECT_BASE + i;
    }
    else
        (void)transient_delete_locked(i);
exit:
    se050_port_mutex_release(&create_mutex);
    return status;
}
se050_status_t se050_transient_delete(uint32_t id)
{
    unsigned slot;
    se050_status_t status;
    if (id < SE050_TRANSIENT_OBJECT_BASE ||
        id >= SE050_TRANSIENT_OBJECT_BASE + SE050_TRANSIENT_OBJECT_COUNT)
        return -SE050_EINVAL;
    slot = (unsigned)(id - SE050_TRANSIENT_OBJECT_BASE);
    status = create_lock();
    if (status != SE050_OK)
        return status;
    status = transient_state[slot] ? transient_delete_locked(slot) : -SE050_EINVAL;
    se050_port_mutex_release(&create_mutex);
    return status;
}
void se050_transient_status(unsigned *active, unsigned *pending)
{
    unsigned i;
    *active = *pending = 0;
    if (create_lock() != SE050_OK)
        return;
    for (i = 0; i < SE050_TRANSIENT_OBJECT_COUNT; ++i)
    {
        if (transient_state[i] == 1)
            ++*active;
        if (transient_state[i] == 2)
            ++*pending;
    }
    se050_port_mutex_release(&create_mutex);
}
se050_status_t se050_raw_to_der(const uint8_t *raw, size_t raw_len, size_t scalar, uint8_t *der,
                                size_t cap, size_t *length)
{
    uint8_t body[138];
    size_t i, j, n, pos = 0, head;
    if (length)
        *length = 0;
    if (!raw || !der || !length || !scalar || scalar > 66 || raw_len != 2 * scalar)
        return -SE050_EINVAL;
    for (i = 0; i < 2; ++i)
    {
        for (j = 0; j < scalar && raw[i * scalar + j] == 0; ++j)
        {
        }
        if (j == scalar)
            return -SE050_EINVAL;
        n = scalar - j;
        body[pos++] = 2;
        body[pos++] = (uint8_t)(n + ((raw[i * scalar + j] & 0x80) != 0));
        if (raw[i * scalar + j] & 0x80)
            body[pos++] = 0;
        memcpy(body + pos, raw + i * scalar + j, n);
        pos += n;
    }
    head = pos < 128 ? 2 : 3;
    if (cap < head + pos)
        return -SE050_EFULL;
    der[0] = 0x30;
    if (head == 2)
        der[1] = (uint8_t)pos;
    else
    {
        der[1] = 0x81;
        der[2] = (uint8_t)pos;
    }
    memcpy(der + head, body, pos);
    *length = head + pos;
    return SE050_OK;
}
se050_status_t se050_key_verify(uint32_t id, size_t bits, unsigned hash_bits, const uint8_t *hash,
                                size_t hash_len, const uint8_t *signature, size_t sig_len,
                                int *valid)
{
    uint8_t data[232], der[144], alg, answer = 0;
    size_t n = 0, der_len = 0, answer_len = 0;
    se050_status_t status;
    if (!valid)
        return -SE050_EINVAL;
    *valid = 0;
    alg = hash_bits == 256 ? 0x21 : hash_bits == 384 ? 0x22 : hash_bits == 512 ? 0x26 : 0;
    if (!object_valid(id) || !curve(bits) || !alg || !hash || hash_len != hash_bits / 8)
        return -SE050_EINVAL;
    status = se050_raw_to_der(signature, sig_len, (bits + 7) / 8, der, sizeof(der), &der_len);
    if (status != SE050_OK)
        return status;
    n += object_tlv(data + n, id);
    n += tlv(data + n, 0x42, &alg, 1);
    n += tlv(data + n, 0x43, hash, hash_len);
    n += tlv(data + n, 0x45, der, der_len);
    status = command(3, 0x0c, 0x0a, data, n, &answer, 1, &answer_len);
    if (status != SE050_OK)
        return status;
    if (answer_len != 1 || (answer != 1 && answer != 2))
        return -SE050_EIO;
    *valid = answer == 1;
    return SE050_OK;
}

void se050_key_reference(uint8_t output[SE050_KEY_REFERENCE_SIZE], uint32_t id, size_t bits)
{
    memcpy(output, "SE05", 4);
    put32(output + 4, id);
    put32(output + 8, (uint32_t)bits);
}
int se050_key_reference_parse(const uint8_t *input, size_t n, uint32_t *id, size_t *bits)
{
    if (!input || n != SE050_KEY_REFERENCE_SIZE || !id || !bits || memcmp(input, "SE05", 4))
        return 0;
    *id = get32(input + 4);
    *bits = get32(input + 8);
    return object_valid(*id) && curve(*bits);
}

se050_status_t se050_transient_create(size_t bits, const uint8_t *pub, size_t pub_len, uint32_t *id)
{
    return transient_create(bits, pub, pub_len, id, 0);
}

int se050_verify_reuse_enabled(void)
{
    return verify_reuse_enabled;
}

se050_status_t se050_verify_reuse_set(int enabled)
{
    se050_status_t status;
    if (enabled != 0 && enabled != 1)
        return -SE050_EINVAL;
    status = create_lock();
    if (status != SE050_OK)
        return status;
    if (verify_owner || verify_object)
        status = -SE050_EBUSY;
    else
        verify_reuse_enabled = enabled;
    se050_port_mutex_release(&create_mutex);
    return status;
}

se050_status_t se050_verify_scope_begin(void)
{
    se050_status_t status = create_lock();
    if (status != SE050_OK)
        return status;
    if (verify_owner || verify_object)
        status = -SE050_EBUSY;
    else if (verify_reuse_enabled)
    {
        verify_owner = se050_port_thread_self();
        if (!verify_owner)
            status = -SE050_EINVAL;
    }
    se050_port_mutex_release(&create_mutex);
    return status;
}

se050_status_t se050_verify_scope_end(void)
{
    se050_status_t status = create_lock();
    if (status != SE050_OK)
        return status;
    if (verify_owner && verify_owner != se050_port_thread_self())
        status = -SE050_EBUSY;
    else
    {
        if (verify_object)
            status =
                transient_delete_locked((unsigned)(verify_object - SE050_TRANSIENT_OBJECT_BASE));
        /* A failed DELETE stays quarantined in transient_state for recovery. */
        verify_object = 0;
        verify_bits = 0;
        verify_owner = NULL;
    }
    se050_port_mutex_release(&create_mutex);
    return status;
}

se050_status_t se050_verify_prepare(size_t bits, const uint8_t *pub, size_t pub_len, uint32_t *id,
                                    int *retained)
{
    uint8_t data[142];
    size_t n, scalar = (bits + 7) / 8;
    se050_status_t status;
    unsigned slot;
    int use_scope;
    if (!id || !retained)
        return -SE050_EINVAL;
    *id = 0;
    *retained = 0;
    if (!curve(bits) || !pub || pub_len != 1 + 2 * scalar || pub[0] != 4)
        return -SE050_EINVAL;
    status = create_lock();
    if (status != SE050_OK)
        return status;
    use_scope = verify_owner && verify_owner == se050_port_thread_self();
    se050_port_mutex_release(&create_mutex);
    if (!use_scope)
        return transient_create(bits, pub, pub_len, id, 0);
    if (verify_object)
    {
        status = create_lock();
        if (status != SE050_OK)
            return status;
        slot = (unsigned)(verify_object - SE050_TRANSIENT_OBJECT_BASE);
        if (transient_state[slot] != 1 || transient_generation[slot] != se050_session_generation())
            status = -SE050_EIO; /* Never use stale keys after reconnect/error. */
        else if (verify_bits != bits)
        {
            status = transient_delete_locked(slot);
            if (status == SE050_OK)
                verify_object = 0;
        }
        else
        {
            /* NXP WriteECKey update omits policy and curve. The fresh public
             * point is supplied on EVERY verification; no trust-result cache. */
            n = object_tlv(data, verify_object);
            n += tlv(data + n, 0x44, pub, pub_len);
            transient_state[slot] = 2;
            status = command(0x81, 0x01, 0, data, n, NULL, 0, NULL);
            if (status == SE050_OK)
            {
                transient_state[slot] = 1;
                transient_generation[slot] = se050_session_generation();
                *id = verify_object;
                *retained = 1;
            }
        }
        se050_port_mutex_release(&create_mutex);
        if (status != SE050_OK || *id)
            return status;
    }
    status = transient_create(bits, pub, pub_len, id, 1);
    if (status == SE050_OK)
    {
        verify_object = *id;
        verify_bits = bits;
        *retained = 1;
    }
    return status;
}
