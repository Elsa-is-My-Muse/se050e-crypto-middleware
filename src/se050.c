#include "se050_internal.h"
#include "se050_config.h"
#include "smCom.h"
#include "smComT1oI2C.h"
#include "phEseStatus.h"
#include <string.h>

static se050_mutex_t session_mutex;
static int mutex_ready;
static int opened;
/* Monotonic cache epoch; read without taking session_mutex (lock ordering). */
static uint32_t session_generation;
uint32_t se050_session_generation(void)
{
    uint32_t value;
    se050_port_critical_enter();
    value = session_generation;
    se050_port_critical_exit();
    return value;
}
static void session_changed(void)
{
    se050_port_critical_enter();
    ++session_generation;
    se050_port_critical_exit();
}
static void *connection;
static uint16_t last_sw;
static struct se050_transport_stats transport_stats;
static struct se050_apdu_trace trace_entries[SE050_TRACE_CAPACITY];
static uint32_t trace_first, trace_next;
static uint32_t trace_apdu_max_sleep;
static int trace_enabled, trace_active;
static unsigned int read_poll_cap_ms, read_poll_minimum_ms;

/* UM11225 rev 1.2 tables 11/13: lengths are decoded, not fixed offsets. */
static unsigned int atr_minimum_poll_ms(const uint8_t *atr, size_t length)
{
    size_t position, dll_length, plp_length, history_length;
    unsigned int minimum;
    if (!atr || length < 7 || atr[0] != 1)
        return 0;
    dll_length = atr[6];
    position = 7 + dll_length;
    if (dll_length < 4 || position + 2 > length || atr[position] != 2)
        return 0;
    plp_length = atr[position + 1];
    position += 2;
    if (plp_length < 4 || position + plp_length >= length)
        return 0;
    minimum = atr[position + 3];
    history_length = atr[position + plp_length];
    if (position + plp_length + 1 + history_length != length)
        return 0;
    /* Never go below the SDK's existing 1 ms polling minimum. */
    return minimum ? minimum : 1;
}
/* One tick guards against an early wake within a scheduler tick. */
static unsigned int read_poll_guard_ms(void)
{
    return read_poll_minimum_ms + (1000u + SE050_TICKS_PER_SECOND - 1u) / SE050_TICKS_PER_SECOND;
}
unsigned int se050_read_poll_limit(unsigned int *minimum_ms)
{
    unsigned int cap = 0;
    se050_port_critical_enter();
    if (minimum_ms)
        *minimum_ms = read_poll_minimum_ms;
    if (read_poll_minimum_ms && read_poll_cap_ms >= read_poll_guard_ms())
        cap = read_poll_cap_ms;
    se050_port_critical_exit();
    return cap;
}

static uint32_t transport_elapsed_ms(se050_tick_t start)
{
    return (uint32_t)(((uint64_t)(se050_tick_t)(se050_port_tick_get() - start) * 1000u) /
                      SE050_TICKS_PER_SECOND);
}
void se050_transport_stats_get(struct se050_transport_stats *stats)
{
    se050_port_critical_enter();
    *stats = transport_stats;
    se050_port_critical_exit();
}
void se050_transport_note_io(int write, size_t bytes, int nack, int error, se050_tick_t start)
{
    uint32_t elapsed = transport_elapsed_ms(start);
    se050_port_critical_enter();
    if (write)
        ++transport_stats.i2c_writes;
    else
        ++transport_stats.i2c_reads;
    if (!error && !nack)
    {
        if (write)
            transport_stats.tx_bytes += (uint32_t)bytes;
        else
            transport_stats.rx_bytes += (uint32_t)bytes;
    }
    transport_stats.i2c_ms += elapsed;
    if (nack)
        ++transport_stats.i2c_nacks;
    if (error)
        ++transport_stats.i2c_errors;
    se050_port_critical_exit();
}
void se050_transport_note_sleep_request(uint32_t requested_ms, se050_tick_t start)
{
    uint32_t elapsed = transport_elapsed_ms(start);
    se050_port_critical_enter();
    ++transport_stats.sleep_calls;
    transport_stats.sleep_ms += elapsed;
    transport_stats.sleep_requested_ms += requested_ms;
    if (elapsed > transport_stats.sleep_max_ms)
        transport_stats.sleep_max_ms = elapsed;
    if (trace_active && elapsed > trace_apdu_max_sleep)
        trace_apdu_max_sleep = elapsed;
    se050_port_critical_exit();
}
void se050_transport_note_sleep(se050_tick_t start)
{
    /* Compatibility for existing ports without a requested-delay argument. */
    se050_transport_note_sleep_request(0, start);
}

static int mutex_init(void)
{
    /* Public APIs run in thread context. A short scheduler critical section
     * ensures a single static mutex is initialized before any caller takes it. */
    se050_port_critical_enter();
    if (!mutex_ready &&
        se050_port_mutex_init(&session_mutex, "se050", SE050_MUTEX_PRIO) == SE050_OK)
        mutex_ready = 1;
    se050_port_critical_exit();
    return mutex_ready;
}

se050_status_t se050_trace_set(int enabled)
{
    se050_status_t status;
    if (enabled != 0 && enabled != 1)
        return -SE050_EINVAL;
    if (!mutex_init())
        return -SE050_ERROR;
    status = se050_port_mutex_take(&session_mutex, SE050_WAIT_FOREVER);
    if (status != SE050_OK)
        return status;
    se050_port_critical_enter();
    trace_enabled = enabled;
    if (enabled)
    {
        trace_first = trace_next = 0;
        memset(trace_entries, 0, sizeof(trace_entries));
    }
    se050_port_critical_exit();
    se050_port_mutex_release(&session_mutex);
    return SE050_OK;
}
void se050_trace_status(int *enabled, uint32_t *first, uint32_t *next)
{
    se050_port_critical_enter();
    if (enabled)
        *enabled = trace_enabled;
    if (first)
        *first = trace_first;
    if (next)
        *next = trace_next;
    se050_port_critical_exit();
}
se050_status_t se050_trace_read(uint32_t sequence, struct se050_apdu_trace *entry)
{
    se050_status_t status = -SE050_EINVAL;
    if (!entry)
        return status;
    se050_port_critical_enter();
    /* Unsigned distance remains valid when the sequence counter wraps. */
    if ((uint32_t)(sequence - trace_first) < (uint32_t)(trace_next - trace_first))
    {
        *entry = trace_entries[sequence % SE050_TRACE_CAPACITY];
        status = SE050_OK;
    }
    se050_port_critical_exit();
    return status;
}

se050_status_t se050_read_poll_set(unsigned int cap_ms)
{
    se050_status_t status;
    if (cap_ms > 200)
        return -SE050_EINVAL;
    if (!mutex_init())
        return -SE050_ERROR;
    status = se050_port_mutex_take(&session_mutex, SE050_WAIT_FOREVER);
    if (status != SE050_OK)
        return status;
    se050_port_critical_enter();
    if (cap_ms && (!read_poll_minimum_ms || cap_ms < read_poll_guard_ms()))
        status = -SE050_EINVAL;
    else
        read_poll_cap_ms = cap_ms;
    se050_port_critical_exit();
    se050_port_mutex_release(&session_mutex);
    return status;
}

static void close_locked(void)
{
    if (connection)
        (void)smComT1oI2C_Close(connection, 0);
    smCom_DeInit();
    connection = SE050_NULL;
    opened = 0;
    se050_port_critical_enter();
    read_poll_minimum_ms = 0; /* Revalidate ATR before tuning a new connection. */
    se050_port_critical_exit();
    session_changed();
}

static se050_status_t exchange_locked(const uint8_t *cmd, size_t cmd_len, uint8_t *rsp, size_t cap,
                                      size_t *len)
{
    uint32_t n = (uint32_t)cap, elapsed;
    struct se050_transport_stats before;
    int capture = trace_enabled;
    se050_tick_t start = se050_port_tick_get();
    se050_status_t status = SE050_OK;
    *len = 0;
    last_sw = 0;
    if (capture)
    {
        se050_transport_stats_get(&before);
        trace_apdu_max_sleep = 0;
        trace_active = 1;
    }
    if (smCom_TransceiveRaw(connection, (uint8_t *)cmd, (uint16_t)cmd_len, rsp, &n) != SMCOM_OK)
    {
        close_locked(); /* link state uncertain; next call reinitializes */
        status = -SE050_EIO;
    }
    else if (n < 2 || n > cap)
    {
        close_locked(); /* malformed framing also invalidates cached state */
        status = -SE050_EIO;
    }
    else
    {
        *len = n;
        last_sw = (uint16_t)((rsp[n - 2] << 8) | rsp[n - 1]);
        if (last_sw != 0x9000)
            session_changed();
    }
    elapsed = transport_elapsed_ms(start);
    se050_port_critical_enter();
    ++transport_stats.apdu_calls;
    transport_stats.apdu_ms += elapsed;
    if (capture)
    {
        struct se050_apdu_trace *entry = &trace_entries[trace_next % SE050_TRACE_CAPACITY];
        entry->sequence = trace_next;
        entry->elapsed_ms = elapsed;
        entry->io_ms = transport_stats.i2c_ms - before.i2c_ms;
        entry->nacks = transport_stats.i2c_nacks - before.i2c_nacks;
        entry->sleep_calls = transport_stats.sleep_calls - before.sleep_calls;
        entry->sleep_ms = transport_stats.sleep_ms - before.sleep_ms;
        entry->sleep_requested_ms = transport_stats.sleep_requested_ms - before.sleep_requested_ms;
        entry->sleep_max_ms = trace_apdu_max_sleep;
        entry->tx_bytes = (uint16_t)cmd_len;
        entry->rx_bytes = (uint16_t)*len;
        entry->status_word = last_sw;
        entry->instruction = cmd[1];
        entry->parameter1 = cmd[2];
        entry->parameter2 = cmd[3];
        entry->status = status;
        ++trace_next;
        if ((uint32_t)(trace_next - trace_first) > SE050_TRACE_CAPACITY)
            ++trace_first;
        trace_active = 0;
    }
    if (status != SE050_OK || last_sw != 0x9000)
        ++transport_stats.apdu_failures;
    se050_port_critical_exit();
    return status;
}

static se050_status_t open_locked(void)
{
    /* NXP IoT applet AID, from Plug & Trust sm_const.h. */
    static const uint8_t select[] = {0x00, 0xA4, 0x04, 0x00, 0x10, 0xA0, 0x00, 0x00,
                                     0x03, 0x96, 0x54, 0x53, 0x00, 0x00, 0x00, 0x01,
                                     0x03, 0x00, 0x00, 0x00, 0x00, 0x00};
    uint8_t atr[64], rsp[64];
    uint16_t atr_len = sizeof(atr);
    size_t n;
    if (opened)
        return SE050_OK;
    if (se050_i2c_probe() != SE050_OK)
        return -SE050_EIO;
    if (smComT1oI2C_Init(&connection, SE050_NULL) != SMCOM_OK)
        return -SE050_EIO;
    if (smComT1oI2C_Open(connection, ESE_MODE_NORMAL, 0, atr, &atr_len) != SMCOM_OK)
    {
        close_locked();
        return -SE050_EIO;
    }
    se050_port_critical_enter();
    read_poll_minimum_ms = atr_len <= sizeof(atr) ? atr_minimum_poll_ms(atr, atr_len) : 0;
    se050_port_critical_exit();
    if (exchange_locked(select, sizeof(select), rsp, sizeof(rsp), &n) != SE050_OK ||
        last_sw != 0x9000)
    {
        close_locked();
        return -SE050_EIO;
    }
    opened = 1;
    session_changed();
    return SE050_OK;
}

se050_status_t se050_init(void)
{
    se050_status_t status;
    if (!mutex_init())
        return -SE050_ERROR;
    status = se050_port_mutex_take(&session_mutex, SE050_WAIT_FOREVER);
    if (status != SE050_OK)
        return status;
    status = open_locked();
    se050_port_mutex_release(&session_mutex);
    return status;
}

se050_status_t se050_transceive(const uint8_t *cmd, size_t cmd_len, uint8_t *rsp, size_t cap,
                                size_t *len)
{
    se050_status_t status;
    if (!cmd || cmd_len < 4 || cmd_len > SE050_APDU_MAX || !rsp || cap < 2 ||
        cap > SE050_APDU_MAX || !len)
        return -SE050_EINVAL;
    *len = 0;
    if (!mutex_init())
        return -SE050_ERROR;
    {
        se050_tick_t start = se050_port_tick_get();
        uint32_t elapsed;
        status = se050_port_mutex_take(&session_mutex, SE050_WAIT_FOREVER);
        elapsed = transport_elapsed_ms(start);
        se050_port_critical_enter();
        transport_stats.lock_ms += elapsed;
        se050_port_critical_exit();
    }
    if (status != SE050_OK)
        return status;
    status = open_locked();
    if (status == SE050_OK)
        status = exchange_locked(cmd, cmd_len, rsp, cap, len);
    se050_port_mutex_release(&session_mutex);
    return status;
}

unsigned int se050_bus_khz(void)
{
    return se050_i2c_get_speed();
}
se050_status_t se050_bus_set(unsigned int khz)
{
    se050_status_t status;
    if (khz != 100u && khz != 400u)
        return -SE050_EINVAL;
    if (!mutex_init())
        return -SE050_ERROR;
    status = se050_port_mutex_take(&session_mutex, SE050_WAIT_FOREVER);
    if (status != SE050_OK)
        return status;
    status = se050_i2c_set_speed(khz);
    se050_port_mutex_release(&session_mutex);
    return status;
}

/* SE05x returns tag 0x41 with BER length (including 0x81/0x82 forms). */
static se050_status_t response_data(const uint8_t *rsp, size_t n, uint8_t *out, size_t cap,
                                    size_t *len)
{
    size_t p = 2, size;
    if (n < 4 || rsp[n - 2] != 0x90 || rsp[n - 1] != 0x00 || rsp[0] != 0x41)
        return -SE050_EIO;
    size = rsp[1];
    if (size == 0x81)
    {
        if (n < 5)
            return -SE050_EIO;
        size = rsp[p++];
    }
    else if (size == 0x82)
    {
        if (n < 6)
            return -SE050_EIO;
        size = ((size_t)rsp[p] << 8) | rsp[p + 1];
        p += 2;
    }
    else if (size > 0x7F)
        return -SE050_EIO;
    if (size != n - p - 2)
        return -SE050_EIO;
    if (size > cap)
        return -SE050_EFULL;
    memcpy(out, rsp + p, size);
    *len = size;
    return SE050_OK;
}

se050_status_t se050_get_version(uint8_t *out, size_t cap, size_t *len)
{
    const uint8_t cmd[] = {0x80, 0x04, 0x00, 0x20, 0x00};
    uint8_t rsp[64];
    size_t n;
    se050_status_t status;
    if (!out || !len)
        return -SE050_EINVAL;
    *len = 0;
    status = se050_transceive(cmd, sizeof(cmd), rsp, sizeof(rsp), &n);
    return status == SE050_OK ? response_data(rsp, n, out, cap, len) : status;
}

se050_status_t se050_get_random(uint8_t *out, size_t length)
{
    /* Extended case-4 APDU matching Se05x_API_GetRandom in NXP APDU_impl.h. */
    uint8_t cmd[] = {0x80, 0x04, 0x00, 0x49, 0x00, 0x00, 0x04, 0x41, 0x02, 0x00, 0x00, 0x00, 0x00};
    uint8_t rsp[72];
    size_t done = 0, n, received = 0, chunk;
    se050_status_t status;
    if (!out && length)
        return -SE050_EINVAL;
    while (done < length)
    {
        chunk = length - done;
        if (chunk > 64)
            chunk = 64;
        cmd[10] = (uint8_t)chunk;
        status = se050_transceive(cmd, sizeof(cmd), rsp, sizeof(rsp), &n);
        if (status == SE050_OK)
            status = response_data(rsp, n, out + done, chunk, &received);
        if (status != SE050_OK || received != chunk)
        {
            /* Never leave a partial random request for consumers to use. */
            volatile uint8_t *p = out;
            size_t i;
            for (i = 0; i < length; ++i)
                p[i] = 0;
            return status == SE050_OK ? -SE050_EIO : status;
        }
        done += chunk;
    }
    return SE050_OK;
}
