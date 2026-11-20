/* APDU fixtures are from the NXP SE05x command definitions, not a target chip. */
#include <assert.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include "../src/se050_crypto.c"

static const uint8_t exists_cmd[] = {0x80, 4, 0, 0x27, 0, 0, 6, 0x41, 4, 0x53, 5, 1, 0, 0, 0};
static const uint8_t create_cmd[] = {0x80, 1,    0x61, 0, 0,    0, 20,   0x11, 9, 8, 0,    0, 0, 0,
                                     0x1c, 0x24, 0,    0, 0x41, 4, 0x53, 5,    1, 0, 0x42, 1, 3};
static const uint8_t curve_list_cmd[] = {0x80, 2, 0x0b, 0x25, 0, 0, 0};
static const uint8_t curves_ready[] = {0x41, 5, 2, 2, 2, 2, 2, 0x90, 0};
static const uint8_t absent[] = {0x41, 1, 2, 0x90, 0};
static const uint8_t present[] = {0x41, 1, 1, 0x90, 0};
static const uint8_t ok[] = {0x90, 0};
struct exchange
{
    const uint8_t *tx, *rx;
    size_t txlen, rxlen;
    int status;
};
static struct exchange script[64];
static unsigned queued, sent;
static uint32_t mock_generation = 1;
static void *mock_thread = (void *)1;
void *se050_port_thread_self(void)
{
    return mock_thread;
}
uint32_t se050_session_generation(void)
{
    return mock_generation;
}
void se050_port_critical_enter(void)
{
}
void se050_port_critical_exit(void)
{
}
void se050_port_printf(const char *fmt, ...)
{
    (void)fmt;
}
int se050_port_mutex_init(se050_mutex_t *m, const char *name, int f)
{
    (void)name;
    (void)f;
    m->held = 0;
    return 0;
}
int se050_port_mutex_take(se050_mutex_t *m, int t)
{
    (void)t;
    assert(!m->held);
    m->held = 1;
    return 0;
}
int se050_port_mutex_release(se050_mutex_t *m)
{
    assert(m->held);
    m->held = 0;
    return 0;
}
static void queue(const uint8_t *tx, size_t txlen, const uint8_t *rx, size_t rxlen, int status)
{
    assert(queued < 64);
    script[queued].tx = tx;
    script[queued].txlen = txlen;
    script[queued].rx = rx;
    script[queued].rxlen = rxlen;
    script[queued++].status = status;
}
se050_status_t se050_transceive(const uint8_t *tx, size_t n, uint8_t *rx, size_t cap,
                                size_t *length)
{
    const struct exchange *e;
    assert(sent < queued);
    e = &script[sent++];
    assert(n == e->txlen && memcmp(tx, e->tx, n) == 0);
    assert(cap >= e->rxlen);
    *length = e->rxlen;
    if (e->rxlen)
        memcpy(rx, e->rx, e->rxlen);
    if (e->status || e->rxlen < 2 || e->rx[e->rxlen - 2] != 0x90 || e->rx[e->rxlen - 1] != 0)
        ++mock_generation;
    return e->status;
}
static void zeros(const uint8_t *p, size_t n)
{
    size_t i;
    for (i = 0; i < n; ++i)
        assert(p[i] == 0);
}
static void create_tests(void)
{
    int exists = 7;
    assert(se050_key_exists(0x1234, &exists) == -SE050_EINVAL);
    queue(exists_cmd, sizeof(exists_cmd), absent, sizeof(absent), 0);
    queue(curve_list_cmd, sizeof(curve_list_cmd), curves_ready, sizeof(curves_ready), 0);
    queue(create_cmd, sizeof(create_cmd), ok, sizeof(ok), 0);
    assert(se050_key_create(SE050_CSR_OBJECT_BASE, 256, NULL, 0, NULL, 0) == 0);
    queue(exists_cmd, sizeof(exists_cmd), present, sizeof(present), 0);
    assert(se050_key_create(SE050_CSR_OBJECT_BASE, 256, NULL, 0, NULL, 0) == -SE050_EBUSY);
    assert(se050_key_create(SE050_CSR_OBJECT_BASE, 255, NULL, 0, NULL, 0) == -SE050_EINVAL);
    assert(se050_key_create(SE050_CSR_OBJECT_BASE, 256, NULL, 32, NULL, 0) == -SE050_EINVAL);
    assert(sent == queued);
    queued = sent = 0;
    {
        const uint8_t missing[] = {0x41, 5, 2, 2, 1, 2, 2, 0x90, 0};
        const uint8_t create_curve[] = {0x80, 1, 0x0b, 4, 0, 0, 3, 0x41, 1, 3};
        const uint8_t refused[] = {0x69, 0x85};
        ++mock_generation; /* reconnect invalidates the prior ready cache */
        queue(exists_cmd, sizeof(exists_cmd), absent, sizeof(absent), 0);
        queue(curve_list_cmd, sizeof(curve_list_cmd), missing, sizeof(missing), 0);
        queue(create_curve, sizeof(create_curve), refused, sizeof(refused), 0);
        /* A failed curve setup must never proceed with a private-key write. */
        assert(se050_key_create(SE050_CSR_OBJECT_BASE, 256, NULL, 0, NULL, 0) == -SE050_EIO);
        assert(sent == queued);
        queued = sent = 0;
    }
}
static void der_tests(void)
{
    uint8_t raw[132], wide[139], ref[12], invalid[12];
    const uint8_t small[] = {0x30, 6, 2, 1, 1, 2, 1, 2};
    const uint8_t negative[] = {0x30, 6, 2, 1, 0x80, 2, 1, 2};
    const uint8_t zero[] = {0x30, 6, 2, 1, 0, 2, 1, 2};
    const uint8_t pad[] = {0x30, 7, 2, 2, 0, 1, 2, 1, 2};
    const uint8_t padded[] = {0x30, 7, 2, 2, 0, 0x80, 2, 1, 2};
    size_t i, bits;
    uint32_t id;
    assert(se050_der_to_raw(small, sizeof(small), 32, raw, sizeof(raw)) == 0);
    zeros(raw, 31);
    assert(raw[31] == 1);
    zeros(raw + 32, 31);
    assert(raw[63] == 2);
    assert(se050_der_to_raw(padded, sizeof(padded), 32, raw, sizeof(raw)) == 0 && raw[31] == 0x80);
    assert(se050_der_to_raw(negative, sizeof(negative), 32, raw, sizeof(raw)) != 0);
    assert(se050_der_to_raw(zero, sizeof(zero), 32, raw, sizeof(raw)) != 0);
    assert(se050_der_to_raw(pad, sizeof(pad), 32, raw, sizeof(raw)) != 0);
    for (i = 0; i < sizeof(small); ++i)
        assert(se050_der_to_raw(small, i, 32, raw, sizeof(raw)) != 0);
    memset(wide, 1, sizeof(wide));
    wide[0] = 0x30;
    wide[1] = 0x81;
    wide[2] = 136;
    wide[3] = 2;
    wide[4] = 66;
    wide[71] = 2;
    wide[72] = 66;
    assert(se050_der_to_raw(wide, sizeof(wide), 66, raw, sizeof(raw)) == 0);
    for (i = 0; i < 132; ++i)
        assert(raw[i] == 1);
    assert(se050_der_to_raw(wide, sizeof(wide) - 1, 66, raw, sizeof(raw)) != 0);
    assert(se050_der_to_raw(wide, sizeof(wide), 66, raw, sizeof(raw) - 1) != 0);
    se050_key_reference(ref, SE050_TLS_ISO2_OBJECT, 256);
    assert(se050_key_reference_parse(ref, sizeof(ref), &id, &bits) && id == SE050_TLS_ISO2_OBJECT &&
           bits == 256);
    memcpy(invalid, ref, sizeof(ref));
    invalid[4] = 0;
    assert(!se050_key_reference_parse(invalid, sizeof(invalid), &id, &bits));
    ref[11] = 1;
    assert(!se050_key_reference_parse(ref, sizeof(ref), &id, &bits));
    assert(!se050_key_reference_parse(ref, sizeof(ref) - 1, &id, &bits));
}
static void operation_tests(void)
{
    uint8_t sign_cmd[52] = {0x80, 3, 0x0c, 9, 0,    0, 43,   0x41, 4,
                            0x53, 5, 1,    0, 0x42, 1, 0x21, 0x43, 32};
    uint8_t hash[32] = {0}, out[140], response[] = {0x41, 8, 0x30, 6, 2, 1, 1, 2, 1, 2, 0x90, 0};
    uint8_t dh_cmd[82] = {0x80, 3, 1, 0x0f, 0, 0, 73, 0x41, 4, 0x53, 5, 1, 0, 0x42, 65, 4};
    uint8_t peer[65] = {4}, shared[36] = {0x41, 32},
            read_cmd[] = {0x80, 2, 0, 0, 0, 0, 6, 0x41, 4, 0x53, 5, 1, 0, 0, 0};
    uint8_t point[138] = {0x41, 0x81, 133, 4};
    uint8_t sw_error[] = {0x69, 0x85};
    size_t n = 99;
    queue(sign_cmd, sizeof(sign_cmd), response, sizeof(response), 0);
    assert(se050_key_sign(SE050_CSR_OBJECT_BASE, 256, 256, hash, 32, out, sizeof(out), &n) == 0 &&
           n == 64);
    assert(out[31] == 1 && out[63] == 2);
    assert(se050_key_sign(SE050_CSR_OBJECT_BASE, 256, 256, hash, 32, out, 63, &n) == -SE050_EFULL &&
           n == 0);
    queue(sign_cmd, sizeof(sign_cmd), response, sizeof(response), -SE050_EIO);
    memset(out, 0xaa, sizeof(out));
    assert(se050_key_sign(SE050_CSR_OBJECT_BASE, 256, 256, hash, 32, out, sizeof(out), &n) ==
               -SE050_EIO &&
           n == 0);
    zeros(out, 64);
    queue(sign_cmd, sizeof(sign_cmd), sw_error, sizeof(sw_error), 0);
    assert(se050_key_sign(SE050_CSR_OBJECT_BASE, 256, 256, hash, 32, out, sizeof(out), &n) ==
               -SE050_EIO &&
           n == 0);
    response[4] = 3;
    queue(sign_cmd, sizeof(sign_cmd), response, sizeof(response), 0);
    assert(se050_key_sign(SE050_CSR_OBJECT_BASE, 256, 256, hash, 32, out, sizeof(out), &n) != 0 &&
           n == 0);
    zeros(out, 64);
    memset(shared + 2, 0xa5, 32);
    shared[34] = 0x90;
    queue(dh_cmd, sizeof(dh_cmd), shared, sizeof(shared), 0);
    assert(se050_key_ecdh(SE050_CSR_OBJECT_BASE, 256, peer, sizeof(peer), out, sizeof(out), &n) ==
               0 &&
           n == 32 && out[0] == 0xa5);
    shared[1] = 31;
    shared[33] = 0x90;
    shared[34] = 0;
    queue(dh_cmd, sizeof(dh_cmd), shared, 35, 0);
    assert(se050_key_ecdh(SE050_CSR_OBJECT_BASE, 256, peer, sizeof(peer), out, sizeof(out), &n) !=
               0 &&
           n == 0);
    zeros(out, sizeof(out));
    point[136] = 0x90;
    queue(read_cmd, sizeof(read_cmd), point, sizeof(point), 0);
    assert(se050_key_public(SE050_CSR_OBJECT_BASE, out, sizeof(out), &n) == 0 && n == 133 &&
           out[0] == 4);
    queue(read_cmd, sizeof(read_cmd), point, sizeof(point), 0);
    assert(se050_key_public(SE050_CSR_OBJECT_BASE, out, 132, &n) == -SE050_EFULL && n == 0);
    assert(sent == queued);
    queued = sent = 0;
}
static void verify_tests(void)
{
    uint8_t tx[62] = {0x80, 3, 0x0c, 0x0a, 0,    0, 53,   0x41, 4,
                      0x53, 5, 1,    0,    0x42, 1, 0x21, 0x43, 32};
    uint8_t hash[32] = {0}, sig[64] = {0};
    int valid = 7;
    const uint8_t tail[] = {0x45, 8, 0x30, 6, 2, 1, 1, 2, 1, 2};
    const uint8_t malformed[] = {0x41, 1, 3, 0x90, 0};
    uint8_t raw[132], der[144], back[132];
    size_t n, scalar;
    sig[31] = 1;
    sig[63] = 2;
    memcpy(tx + 50, tail, sizeof(tail));
    queue(tx, sizeof(tx), present, sizeof(present), 0);
    assert(se050_key_verify(SE050_CSR_OBJECT_BASE, 256, 256, hash, 32, sig, 64, &valid) == 0 &&
           valid == 1);
    queue(tx, sizeof(tx), absent, sizeof(absent), 0);
    assert(se050_key_verify(SE050_CSR_OBJECT_BASE, 256, 256, hash, 32, sig, 64, &valid) == 0 &&
           valid == 0);
    queue(tx, sizeof(tx), malformed, sizeof(malformed), 0);
    assert(se050_key_verify(SE050_CSR_OBJECT_BASE, 256, 256, hash, 32, sig, 64, &valid) ==
               -SE050_EIO &&
           valid == 0);
    queue(tx, sizeof(tx), NULL, 0, -SE050_EIO);
    assert(se050_key_verify(SE050_CSR_OBJECT_BASE, 256, 256, hash, 32, sig, 64, &valid) ==
               -SE050_EIO &&
           valid == 0);
    for (scalar = 32; scalar <= 66; scalar = scalar == 32 ? 48 : scalar == 48 ? 66 : 67)
    {
        memset(raw, 0x80, 2 * scalar);
        assert(se050_raw_to_der(raw, 2 * scalar, scalar, der, sizeof(der), &n) == 0);
        assert(se050_der_to_raw(der, n, scalar, back, sizeof(back)) == 0 &&
               memcmp(raw, back, 2 * scalar) == 0);
        assert(se050_raw_to_der(raw, 2 * scalar, scalar, der, n - 1, &n) == -SE050_EFULL && n == 0);
    }
    memset(raw, 0, sizeof(raw));
    assert(se050_raw_to_der(raw, 64, 32, der, sizeof(der), &n) == -SE050_EINVAL);
    assert(se050_raw_to_der(sig, 63, 32, der, sizeof(der), &n) == -SE050_EINVAL);
    assert(sent == queued);
    queued = sent = 0;
}
static void curve_cache_tests(void)
{
    const uint8_t short_list[] = {0x41, 2, 2, 2, 0x90, 0};
    const uint8_t unavailable[] = {0x41, 5, 2, 2, 0, 2, 2, 0x90, 0};
    uint32_t generation;
    ++mock_generation;
    assert(create_lock() == 0);
    queue(curve_list_cmd, sizeof(curve_list_cmd), curves_ready, sizeof(curves_ready), 0);
    assert(ensure_curve(3) == 0);
    /* One validated list covers P-256, P-384 and P-521 without more APDUs. */
    assert(ensure_curve(3) == 0 && ensure_curve(4) == 0 && ensure_curve(5) == 0);
    assert(ensure_curve(2) == -SE050_EINVAL);
    assert(sent == queued);
    queued = sent = 0;
    ++mock_generation;
    queue(curve_list_cmd, sizeof(curve_list_cmd), short_list, sizeof(short_list), 0);
    assert(ensure_curve(3) == -SE050_EIO);
    queue(curve_list_cmd, sizeof(curve_list_cmd), NULL, 0, -SE050_EIO);
    assert(ensure_curve(3) == -SE050_EIO);
    queue(curve_list_cmd, sizeof(curve_list_cmd), unavailable, sizeof(unavailable), 0);
    assert(ensure_curve(3) == -SE050_EIO);
    queue(curve_list_cmd, sizeof(curve_list_cmd), curves_ready, sizeof(curves_ready), 0);
    assert(ensure_curve(3) == 0);
    generation = mock_generation;
    assert(ensure_curve(4) == 0 && mock_generation == generation);
    /* First-use curve initialization is cached only after all parameters pass. */
    {
        const uint8_t missing[] = {0x41, 5, 2, 2, 1, 2, 2, 0x90, 0};
        const uint8_t create[] = {0x80, 1, 0x0b, 4, 0, 0, 3, 0x41, 1, 3};
        const uint8_t refused[] = {0x69, 0x85};
        uint8_t tx[160];
        unsigned i;
        size_t n;
        ++mock_generation;
        queue(curve_list_cmd, sizeof(curve_list_cmd), missing, sizeof(missing), 0);
        queue(create, sizeof(create), ok, sizeof(ok), 0);
        for (i = 0; i < 5; ++i)
        {
            static const uint8_t param[] = {1, 2, 4, 8, 0x10};
            const uint8_t *pv = i == 0   ? prime256v1_a
                                : i == 1 ? prime256v1_b
                                : i == 2 ? prime256v1_g
                                : i == 3 ? prime256v1_n
                                         : prime256v1_p;
            size_t pn = i == 0   ? sizeof(prime256v1_a)
                        : i == 1 ? sizeof(prime256v1_b)
                        : i == 2 ? sizeof(prime256v1_g)
                        : i == 3 ? sizeof(prime256v1_n)
                                 : sizeof(prime256v1_p);
            n = 0;
            tx[n++] = 0x80;
            tx[n++] = 1;
            tx[n++] = 0x0b;
            tx[n++] = 0x40;
            tx[n++] = 0;
            tx[n++] = 0;
            tx[n++] = (uint8_t)(8 + pn);
            tx[n++] = 0x41;
            tx[n++] = 1;
            tx[n++] = 3;
            tx[n++] = 0x42;
            tx[n++] = 1;
            tx[n++] = param[i];
            tx[n++] = 0x43;
            tx[n++] = (uint8_t)pn;
            memcpy(tx + n, pv, pn);
            n += pn;
            /* queue() stores pointers, so use dedicated storage for each APDU. */
            {
                static uint8_t fixture[5][160];
                memcpy(fixture[i], tx, n);
                queue(fixture[i], n, ok, sizeof(ok), 0);
            }
        }
        assert(ensure_curve(3) == 0);
        assert(ensure_curve(3) == 0 && ensure_curve(4) == 0 && ensure_curve(5) == 0);
        assert(sent == queued);
        queued = sent = 0;
        ++mock_generation;
        queue(curve_list_cmd, sizeof(curve_list_cmd), missing, sizeof(missing), 0);
        queue(create, sizeof(create), ok, sizeof(ok), 0);
        /* First parameter failure must not mark the curve initialized. */
        n = 0;
        tx[n++] = 0x80;
        tx[n++] = 1;
        tx[n++] = 0x0b;
        tx[n++] = 0x40;
        tx[n++] = 0;
        tx[n++] = 0;
        tx[n++] = (uint8_t)(8 + sizeof(prime256v1_a));
        tx[n++] = 0x41;
        tx[n++] = 1;
        tx[n++] = 3;
        tx[n++] = 0x42;
        tx[n++] = 1;
        tx[n++] = 1;
        tx[n++] = 0x43;
        tx[n++] = (uint8_t)sizeof(prime256v1_a);
        memcpy(tx + n, prime256v1_a, sizeof(prime256v1_a));
        n += sizeof(prime256v1_a);
        queue(tx, n, refused, sizeof(refused), 0);
        assert(ensure_curve(3) == -SE050_EIO);
        queue(curve_list_cmd, sizeof(curve_list_cmd), curves_ready, sizeof(curves_ready), 0);
        assert(ensure_curve(3) == 0);
    }
    se050_port_mutex_release(&create_mutex);
    assert(sent == queued);
    queued = sent = 0;
}
static void transient_tests(void)
{
    uint8_t exists0[] = {0x80, 4, 0, 0x27, 0, 0, 6, 0x41, 4, 0x53, 5, 2, 0, 0, 0};
    uint8_t exists1[] = {0x80, 4, 0, 0x27, 0, 0, 6, 0x41, 4, 0x53, 5, 2, 1, 0, 0};
    uint8_t gen[] = {0x80, 0x81, 0x61, 0, 0,    0, 20,   0x11, 9, 8, 0,    0, 0, 0,
                     4,    0x24, 0,    0, 0x41, 4, 0x53, 5,    2, 1, 0x42, 1, 3};
    uint8_t del[] = {0x80, 4, 0, 0x28, 0, 0, 6, 0x41, 4, 0x53, 5, 2, 1};
    uint8_t pubcmd[94] = {0x80, 0x81, 0x21, 0,    0, 0,    87, 0x11, 9, 8,    0, 0, 0,    0,  8,
                          0x24, 0,    0,    0x41, 4, 0x53, 5,  2,    0, 0x42, 1, 3, 0x44, 65, 4};
    uint8_t pub[65] = {4};
    uint32_t id;
    unsigned active, pending;
    const uint8_t refused[] = {0x69, 0x85};
    ++mock_generation;
    assert(se050_transient_delete(SE050_TLS_ISO20_OBJECT) == -SE050_EINVAL);
    /* A collision belongs to someone else: skip it and never delete it. */
    queue(exists0, sizeof(exists0), present, sizeof(present), 0);
    queue(exists1, sizeof(exists1), absent, sizeof(absent), 0);
    queue(curve_list_cmd, sizeof(curve_list_cmd), curves_ready, sizeof(curves_ready), 0);
    queue(gen, sizeof(gen), ok, sizeof(ok), 0);
    assert(se050_transient_create(256, NULL, 0, &id) == 0 && id == SE050_TRANSIENT_OBJECT_BASE + 1);
    assert(se050_transient_delete(SE050_TRANSIENT_OBJECT_BASE) == -SE050_EINVAL);
    se050_transient_status(&active, &pending);
    assert(active == 1 && pending == 0);
    /* Normal confirmed-live cleanup uses DELETE only, no EXISTS round trip. */
    queue(del, sizeof(del), ok, sizeof(ok), 0);
    assert(se050_transient_delete(id) == 0);
    se050_transient_status(&active, &pending);
    assert(active == 0 && pending == 0);
    assert(sent == queued);
    queued = sent = 0;
    /* Same-session public import uses the ready-curve cache. */
    queue(exists0, sizeof(exists0), absent, sizeof(absent), 0);
    queue(pubcmd, sizeof(pubcmd), ok, sizeof(ok), 0);
    assert(se050_transient_create(256, pub, sizeof(pub), &id) == 0 &&
           id == SE050_TRANSIENT_OBJECT_BASE);
    del[12] = 0;
    queue(del, sizeof(del), NULL, 0, -SE050_EIO);
    assert(se050_transient_delete(id) == -SE050_EIO);
    se050_transient_status(&active, &pending);
    assert(active == 0 && pending == 1);
    /* Retry only the known owned object; an uncertain cleanup needs EXISTS. */
    queue(exists0, sizeof(exists0), present, sizeof(present), 0);
    queue(del, sizeof(del), ok, sizeof(ok), 0);
    queue(exists0, sizeof(exists0), absent, sizeof(absent), 0);
    queue(curve_list_cmd, sizeof(curve_list_cmd), curves_ready, sizeof(curves_ready), 0);
    gen[23] = 0;
    queue(gen, sizeof(gen), NULL, 0, -SE050_EIO);
    /* A lost create response may hide a successful write: query before delete. */
    queue(exists0, sizeof(exists0), present, sizeof(present), 0);
    queue(del, sizeof(del), ok, sizeof(ok), 0);
    assert(se050_transient_create(256, NULL, 0, &id) == -SE050_EIO && id == 0);
    se050_transient_status(&active, &pending);
    assert(active == 0 && pending == 0);
    assert(sent == queued);
    queued = sent = 0;
    /* A reconnect may discard volatile keys. Missing objects need no DELETE. */
    queue(exists0, sizeof(exists0), absent, sizeof(absent), 0);
    queue(curve_list_cmd, sizeof(curve_list_cmd), curves_ready, sizeof(curves_ready), 0);
    queue(pubcmd, sizeof(pubcmd), ok, sizeof(ok), 0);
    assert(se050_transient_create(256, pub, sizeof(pub), &id) == 0);
    ++mock_generation;
    queue(exists0, sizeof(exists0), absent, sizeof(absent), 0);
    assert(se050_transient_delete(id) == 0);
    assert(sent == queued);
    queued = sent = 0;
    /* Status-word failure quarantines a live ID, even with a valid transport. */
    queue(exists0, sizeof(exists0), absent, sizeof(absent), 0);
    queue(curve_list_cmd, sizeof(curve_list_cmd), curves_ready, sizeof(curves_ready), 0);
    queue(pubcmd, sizeof(pubcmd), ok, sizeof(ok), 0);
    assert(se050_transient_create(256, pub, sizeof(pub), &id) == 0);
    queue(del, sizeof(del), refused, sizeof(refused), 0);
    assert(se050_transient_delete(id) == -SE050_EIO);
    se050_transient_status(&active, &pending);
    assert(active == 0 && pending == 1);
    queue(exists0, sizeof(exists0), NULL, 0, -SE050_EIO);
    assert(se050_transient_delete(id) == -SE050_EIO);
    se050_transient_status(&active, &pending);
    assert(active == 0 && pending == 1);
    queue(exists0, sizeof(exists0), absent, sizeof(absent), 0);
    assert(se050_transient_delete(id) == 0);
    se050_transient_status(&active, &pending);
    assert(active == 0 && pending == 0);
    assert(se050_transient_delete(SE050_TRANSIENT_OBJECT_BASE) == -SE050_EINVAL);
    assert(se050_transient_create(255, NULL, 0, &id) == -SE050_EINVAL);
    assert(sent == queued);
    queued = sent = 0;
}

static void reuse_tests(void)
{
    uint8_t exists[] = {0x80, 4, 0, 0x27, 0, 0, 6, 0x41, 4, 0x53, 5, 2, 0, 0, 0};
    uint8_t create[94] = {0x80, 0x81, 0x21, 0,    0, 0,    87, 0x11, 9, 8,    0, 0, 0,    0,  8,
                          0x34, 0,    0,    0x41, 4, 0x53, 5,  2,    0, 0x42, 1, 3, 0x44, 65, 4};
    uint8_t update[80] = {0x80, 0x81, 1, 0, 0, 0, 73, 0x41, 4, 0x53, 5, 2, 0, 0x44, 65, 4};
    uint8_t del[] = {0x80, 4, 0, 0x28, 0, 0, 6, 0x41, 4, 0x53, 5, 2, 0};
    uint8_t pub[65] = {4}, changed[65] = {4};
    uint32_t id;
    int retained;
    unsigned active, pending;
    const uint8_t refused[] = {0x69, 0x85};
    assert(!se050_verify_reuse_enabled());
    assert(se050_verify_scope_begin() == 0 && se050_verify_scope_end() == 0);
    assert(se050_verify_reuse_set(2) == -SE050_EINVAL);
    assert(se050_verify_reuse_set(1) == 0);
    ++mock_generation;
    assert(se050_verify_scope_begin() == 0);
    assert(se050_verify_scope_begin() == -SE050_EBUSY);
    assert(se050_verify_reuse_set(0) == -SE050_EBUSY);
    queue(exists, sizeof(exists), absent, sizeof(absent), 0);
    queue(curve_list_cmd, sizeof(curve_list_cmd), curves_ready, sizeof(curves_ready), 0);
    queue(create, sizeof(create), ok, sizeof(ok), 0);
    assert(se050_verify_prepare(256, pub, sizeof(pub), &id, &retained) == 0 && retained == 1);
    assert(id == SE050_TRANSIENT_OBJECT_BASE);
    changed[64] = 7;
    update[79] = 7;
    queue(update, sizeof(update), ok, sizeof(ok), 0);
    assert(se050_verify_prepare(256, changed, sizeof(changed), &id, &retained) == 0 &&
           retained == 1);
    /* Even an identical key is written again; no trust/verification cache. */
    queue(update, sizeof(update), ok, sizeof(ok), 0);
    assert(se050_verify_prepare(256, changed, sizeof(changed), &id, &retained) == 0);
    mock_thread = (void *)2;
    assert(se050_verify_scope_end() == -SE050_EBUSY);
    assert(se050_verify_scope_begin() == -SE050_EBUSY);
    mock_thread = (void *)1;
    queue(del, sizeof(del), ok, sizeof(ok), 0);
    assert(se050_verify_scope_end() == 0);
    se050_transient_status(&active, &pending);
    assert(!active && !pending);
    assert(sent == queued);
    sent = queued = 0;
    /* Failed update must not return a usable object; cleanup is fail-closed. */
    assert(se050_verify_scope_begin() == 0);
    queue(exists, sizeof(exists), absent, sizeof(absent), 0);
    queue(create, sizeof(create), ok, sizeof(ok), 0);
    assert(se050_verify_prepare(256, pub, sizeof(pub), &id, &retained) == 0);
    queue(update, sizeof(update), refused, sizeof(refused), 0);
    assert(se050_verify_prepare(256, changed, sizeof(changed), &id, &retained) == -SE050_EIO);
    assert(!id && !retained);
    queue(exists, sizeof(exists), present, sizeof(present), 0);
    queue(del, sizeof(del), ok, sizeof(ok), 0);
    assert(se050_verify_scope_end() == 0);
    se050_transient_status(&active, &pending);
    assert(!active && !pending);
    assert(sent == queued);
    sent = queued = 0;
    /* Reconnect invalidates retained ownership: no UPDATE/VERIFY on a stale id. */
    assert(se050_verify_scope_begin() == 0);
    queue(exists, sizeof(exists), absent, sizeof(absent), 0);
    queue(curve_list_cmd, sizeof(curve_list_cmd), curves_ready, sizeof(curves_ready), 0);
    queue(create, sizeof(create), ok, sizeof(ok), 0);
    assert(se050_verify_prepare(256, pub, sizeof(pub), &id, &retained) == 0);
    ++mock_generation;
    assert(se050_verify_prepare(256, pub, sizeof(pub), &id, &retained) == -SE050_EIO && !id);
    queue(exists, sizeof(exists), absent, sizeof(absent), 0);
    assert(se050_verify_scope_end() == 0);
    assert(sent == queued);
    sent = queued = 0;
    /* Delete response loss remains quarantined, never silently freed. */
    assert(se050_verify_scope_begin() == 0);
    queue(exists, sizeof(exists), absent, sizeof(absent), 0);
    queue(curve_list_cmd, sizeof(curve_list_cmd), curves_ready, sizeof(curves_ready), 0);
    queue(create, sizeof(create), ok, sizeof(ok), 0);
    assert(se050_verify_prepare(256, pub, sizeof(pub), &id, &retained) == 0);
    queue(del, sizeof(del), NULL, 0, -SE050_EIO);
    assert(se050_verify_scope_end() == -SE050_EIO);
    se050_transient_status(&active, &pending);
    assert(!active && pending == 1);
    queue(exists, sizeof(exists), absent, sizeof(absent), 0);
    assert(se050_transient_delete(id) == 0);
    /* Changing curves deletes the old slot before importing the new curve. */
    assert(sent == queued);
    sent = queued = 0;
    assert(se050_verify_scope_begin() == 0);
    queue(exists, sizeof(exists), absent, sizeof(absent), 0);
    queue(curve_list_cmd, sizeof(curve_list_cmd), curves_ready, sizeof(curves_ready), 0);
    queue(create, sizeof(create), ok, sizeof(ok), 0);
    assert(se050_verify_prepare(256, pub, sizeof(pub), &id, &retained) == 0);
    {
        uint8_t wide[97] = {4};
        uint8_t wide_create[126] = {0x80, 0x81, 0x21, 0, 0,    0,    119, 0x11, 9,    8,
                                    0,    0,    0,    0, 8,    0x34, 0,   0,    0x41, 4,
                                    0x53, 5,    2,    0, 0x42, 1,    4,   0x44, 97,   4};
        queue(del, sizeof(del), ok, sizeof(ok), 0);
        queue(exists, sizeof(exists), absent, sizeof(absent), 0);
        queue(wide_create, sizeof(wide_create), ok, sizeof(ok), 0);
        assert(se050_verify_prepare(384, wide, sizeof(wide), &id, &retained) == 0 && retained);
        queue(del, sizeof(del), ok, sizeof(ok), 0);
        assert(se050_verify_scope_end() == 0);
    }
    assert(sent == queued);
    sent = queued = 0;
    /* Another task must use a separate immutable temporary public object. */
    assert(se050_verify_scope_begin() == 0);
    mock_thread = (void *)2;
    create[15] = 0x24; /* no ALLOW_WRITE for the unrelated task */
    queue(exists, sizeof(exists), absent, sizeof(absent), 0);
    queue(create, sizeof(create), ok, sizeof(ok), 0);
    assert(se050_verify_prepare(256, pub, sizeof(pub), &id, &retained) == 0 && !retained);
    queue(del, sizeof(del), ok, sizeof(ok), 0);
    assert(se050_transient_delete(id) == 0);
    mock_thread = (void *)1;
    assert(se050_verify_scope_end() == 0);
    se050_transient_status(&active, &pending);
    assert(!active && !pending);
    assert(se050_verify_reuse_set(0) == 0);
    assert(se050_verify_prepare(256, NULL, 0, &id, &retained) == -SE050_EINVAL);
    assert(sent == queued);
    sent = queued = 0;
    puts("SE050 verification reuse tests passed (updates, ownership, reconnect, failed cleanup)");
}

int main(void)
{
    create_tests();
    der_tests();
    operation_tests();
    verify_tests();
    curve_cache_tests();
    transient_tests();
    reuse_tests();
    puts("SE050 EC/APDU tests passed (mock transport)");
    return 0;
}
