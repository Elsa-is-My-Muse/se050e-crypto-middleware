/* Host tests exercise the real session code with a scripted APDU transport. */
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include "../src/se050.c"

static int random_calls, selects, fail_call, bad_length, init_calls;
static int bad_frame, fail_status, record_waits;
static const uint8_t test_atr[] = {1, 0xA0, 0, 0, 3, 0x96, 4, 0, 100, 0, 254, 2, 11,
                                   1, 144,  0, 1, 0, 0,    0, 0, 0,   0, 0,   0};
static unsigned int mock_khz = 100;
se050_tick_t se050_port_tick_get(void)
{
    static se050_tick_t now;
    return ++now;
}
unsigned int se050_i2c_get_speed(void)
{
    return mock_khz;
}
se050_status_t se050_i2c_set_speed(unsigned int khz)
{
    mock_khz = khz;
    return 0;
}
void se050_port_critical_enter(void)
{
}
void se050_port_critical_exit(void)
{
}
int se050_port_mutex_init(se050_mutex_t *m, const char *n, int f)
{
    (void)n;
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
se050_status_t se050_i2c_probe(void)
{
    return 0;
}
U16 smComT1oI2C_Init(void **c, const char *s)
{
    (void)s;
    *c = &init_calls;
    ++init_calls;
    return SMCOM_OK;
}
U16 smComT1oI2C_Open(void *c, U8 m, U8 seq, U8 *a, U16 *n)
{
    (void)c;
    (void)m;
    (void)seq;
    assert(*n >= sizeof(test_atr));
    memcpy(a, test_atr, sizeof(test_atr));
    *n = sizeof(test_atr);
    return SMCOM_OK;
}
U16 smComT1oI2C_Close(void *c, U8 m)
{
    (void)c;
    (void)m;
    return SMCOM_OK;
}
void smCom_DeInit(void)
{
}
U32 smCom_TransceiveRaw(void *c, U8 *tx, U16 n, U8 *rx, U32 *cap)
{
    size_t count;
    (void)c;
    assert(session_mutex.held);
    if (tx[1] == 0xA4)
    {
        assert(n == 22 && tx[4] == 16 && tx[21] == 0);
        ++selects;
        rx[0] = 0x90;
        rx[1] = 0;
        *cap = 2;
        return SMCOM_OK;
    }
    assert(n == 13 && tx[0] == 0x80 && tx[1] == 4 && tx[3] == 0x49);
    assert(tx[4] == 0 && tx[5] == 0 && tx[6] == 4);
    assert(tx[7] == 0x41 && tx[8] == 2 && tx[9] == 0 && tx[11] == 0 && tx[12] == 0);
    ++random_calls;
    if (record_waits)
    {
        se050_transport_note_sleep_request(5, se050_port_tick_get());
        se050_transport_note_io(0, 0, 1, 0, se050_port_tick_get());
    }
    if (random_calls == fail_call)
        return SMCOM_COM_FAILED;
    if (bad_frame)
    {
        rx[0] = 0x90;
        *cap = 1;
        return SMCOM_OK;
    }
    if (fail_status)
    {
        rx[0] = 0x69;
        rx[1] = 0x85;
        *cap = 2;
        return SMCOM_OK;
    }
    count = tx[10];
    assert(count && count <= 64 && *cap >= count + 4);
    rx[0] = 0x41;
    rx[1] = (U8)(count - (bad_length != 0));
    memset(rx + 2, 0xA5, count);
    rx[count + 2] = 0x90;
    rx[count + 3] = 0;
    *cap = (U32)(count + 4);
    return SMCOM_OK;
}

int main(void)
{
    uint32_t generation;
    unsigned char out[160], rsp[] = {0x41, 0x81, 1, 0x55, 0x90, 0};
    unsigned char wide[] = {0x41, 0x82, 0, 1, 0x66, 0x90, 0};
    size_t n = 0, i;
    assert(response_data(rsp, sizeof rsp, out, sizeof out, &n) == 0 && n == 1 && out[0] == 0x55);
    assert(response_data(wide, sizeof wide, out, sizeof out, &n) == 0 && out[0] == 0x66);
    assert(response_data(rsp, sizeof rsp, out, 0, &n) == -SE050_EFULL);
    for (i = 0; i < sizeof rsp; ++i)
        assert(response_data(rsp, i, out, sizeof out, &n) != 0);
    rsp[5] = 1;
    assert(response_data(rsp, sizeof rsp, out, sizeof out, &n) != 0);
    rsp[5] = 0;
    rsp[1] = 0x80;
    assert(response_data(rsp, sizeof rsp, out, sizeof out, &n) != 0);
    assert(se050_get_random(NULL, 1) == -SE050_EINVAL);
    assert(se050_get_random(NULL, 0) == 0);
    assert(se050_session_generation() == 0);
    assert(se050_get_random(out, 150) == 0 && random_calls == 3 && selects == 1);
    generation = se050_session_generation();
    assert(generation != 0);
    assert(se050_init() == 0 && se050_session_generation() == generation);
    for (i = 0; i < 150; ++i)
        assert(out[i] == 0xA5);
    fail_call = random_calls + 2;
    assert(se050_get_random(out, 150) == -SE050_EIO);
    assert(se050_session_generation() != generation);
    generation = se050_session_generation();
    for (i = 0; i < 150; ++i)
        assert(out[i] == 0);
    fail_call = 0;
    assert(se050_get_random(out, 1) == 0 && init_calls == 2 && selects == 2);
    assert(se050_session_generation() != generation);
    bad_length = 1;
    assert(se050_get_random(out, 32) == -SE050_EIO);
    for (i = 0; i < 32; ++i)
        assert(out[i] == 0);
    {
        struct se050_transport_stats stats;
        assert(se050_bus_set(200) == -SE050_EINVAL && se050_bus_khz() == 100);
        assert(se050_bus_set(400) == 0 && se050_bus_khz() == 400);
        assert(se050_bus_set(100) == 0 && se050_bus_khz() == 100);
        se050_transport_stats_get(&stats);
        assert(stats.apdu_calls == (unsigned)(random_calls + selects));
        assert(stats.apdu_failures == 1);
        se050_transport_note_io(1, 17, 0, 0, se050_port_tick_get());
        se050_transport_note_io(0, 20, 1, 0, se050_port_tick_get());
        se050_transport_note_io(0, 20, 0, 1, se050_port_tick_get());
        se050_transport_note_sleep(se050_port_tick_get());
        se050_transport_stats_get(&stats);
        assert(stats.tx_bytes == 17 && stats.rx_bytes == 0);
        assert(stats.i2c_nacks == 1 && stats.i2c_errors == 1 && stats.sleep_calls == 1);
    }
    /* Bad SW invalidates cache but preserves link; malformed framing closes it. */
    bad_length = 0;
    generation = se050_session_generation();
    fail_status = 1;
    memset(out, 0xaa, sizeof(out));
    assert(se050_get_random(out, 32) == -SE050_EIO);
    for (i = 0; i < 32; ++i)
        assert(out[i] == 0);
    assert(opened && se050_session_generation() != generation);
    fail_status = 0;
    generation = se050_session_generation();
    bad_frame = 1;
    assert(se050_get_random(out, 32) == -SE050_EIO);
    assert(!opened && se050_session_generation() != generation);
    bad_frame = 0;
    generation = se050_session_generation();
    assert(se050_get_random(out, 1) == 0 && init_calls == 3 && selects == 3);
    assert(se050_session_generation() != generation);
    {
        struct se050_apdu_trace entry;
        struct se050_transport_stats stats;
        uint32_t first, next;
        unsigned int minimum;
        int enabled;
        uint8_t malformed[sizeof(test_atr)];
        assert(atr_minimum_poll_ms(test_atr, sizeof(test_atr)) == 1);
        for (i = 0; i < sizeof(test_atr); ++i)
            assert(atr_minimum_poll_ms(test_atr, i) == 0);
        memcpy(malformed, test_atr, sizeof(test_atr));
        malformed[6] = 255;
        assert(atr_minimum_poll_ms(malformed, sizeof(malformed)) == 0);
        memcpy(malformed, test_atr, sizeof(test_atr));
        malformed[11] = 1;
        assert(atr_minimum_poll_ms(malformed, sizeof(malformed)) == 0);
        memcpy(malformed, test_atr, sizeof(test_atr));
        malformed[16] = 5;
        assert(atr_minimum_poll_ms(malformed, sizeof(malformed)) == 5);
        assert(se050_read_poll_limit(&minimum) == 0 && minimum == 1);
        assert(se050_read_poll_set(201) == -SE050_EINVAL);
        assert(se050_read_poll_set(2) == 0 && se050_read_poll_limit(NULL) == 2);
        read_poll_minimum_ms = 5;
        assert(se050_read_poll_limit(NULL) == 0);
        assert(se050_read_poll_set(2) == -SE050_EINVAL);
        assert(se050_read_poll_set(5) == -SE050_EINVAL);
        assert(se050_read_poll_set(10) == 0);
        read_poll_minimum_ms = 0;
        assert(se050_read_poll_limit(NULL) == 0);
        assert(se050_read_poll_set(5) == -SE050_EINVAL);
        assert(se050_read_poll_set(0) == 0);
        read_poll_minimum_ms = 1;
        assert(se050_trace_set(2) == -SE050_EINVAL);
        assert(se050_trace_set(1) == 0);
        record_waits = 1;
        for (i = 0; i < SE050_TRACE_CAPACITY + 3; ++i)
            assert(se050_get_random(out, 1) == 0);
        se050_trace_status(&enabled, &first, &next);
        assert(enabled == 1 && first == 3 && next == SE050_TRACE_CAPACITY + 3);
        assert(se050_trace_read(first - 1, &entry) == -SE050_EINVAL);
        assert(se050_trace_read(next, &entry) == -SE050_EINVAL);
        assert(se050_trace_read(first, NULL) == -SE050_EINVAL);
        assert(se050_trace_read(next - 1, &entry) == 0);
        assert(entry.sequence == next - 1 && entry.instruction == 4);
        assert(entry.parameter1 == 0 && entry.parameter2 == 0x49);
        assert(entry.status == 0 && entry.status_word == 0x9000);
        assert(entry.tx_bytes == 13 && entry.rx_bytes == 5);
        assert(entry.sleep_calls == 1 && entry.sleep_requested_ms == 5);
        assert(entry.sleep_ms == 1 && entry.sleep_max_ms == 1 && entry.nacks == 1);
        fail_status = 1;
        assert(se050_get_random(out, 1) == -SE050_EIO);
        assert(se050_trace_read(next, &entry) == 0 && entry.status_word == 0x6985);
        fail_status = 0;
        assert(se050_trace_set(0) == 0);
        assert(se050_get_random(out, 1) == 0);
        se050_trace_status(&enabled, &first, &next);
        assert(!enabled && next == SE050_TRACE_CAPACITY + 4);
        assert(se050_trace_read(next - 1, &entry) == 0);
        assert(se050_trace_set(1) == 0);
        se050_trace_status(&enabled, &first, &next);
        assert(enabled && first == 0 && next == 0);
        se050_transport_stats_get(&stats);
        assert(stats.sleep_requested_ms != 0);
        /* Ring and sequence counters retain validity across uint32 wrap. */
        trace_first = trace_next = UINT32_MAX - 1;
        for (i = 0; i < 4; ++i)
            assert(se050_get_random(out, 1) == 0);
        assert(se050_trace_read(UINT32_MAX, &entry) == 0);
        assert(entry.sequence == UINT32_MAX);
        assert(se050_trace_read(0, &entry) == 0 && entry.sequence == 0);
        assert(se050_trace_set(0) == 0);
        record_waits = 0;
    }
    puts("SE050 session tests passed");
    return 0;
}
