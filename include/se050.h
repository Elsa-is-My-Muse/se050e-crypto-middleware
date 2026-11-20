/** @file se050.h
 * @brief Session, transport tuning and metadata-only diagnostics. Task context only.
 */
#ifndef SSWL_SE050_H
#define SSWL_SE050_H
#include "se050_port.h"
#include <stddef.h>
#include <stdint.h>

/** Public C API; identical calling convention when included from C++. */
#ifdef __cplusplus
extern "C"
{
#endif

    /* Diagnostic counters contain lengths/timing only, never APDU payloads. */
    struct se050_transport_stats
    {
        uint32_t apdu_calls;
        uint32_t apdu_failures;
        uint32_t apdu_ms;
        uint32_t lock_ms;
        uint32_t i2c_reads;
        uint32_t i2c_writes;
        uint32_t tx_bytes;
        uint32_t rx_bytes;
        uint32_t i2c_nacks;
        uint32_t i2c_errors;
        uint32_t i2c_ms;
        uint32_t sleep_calls;
        uint32_t sleep_ms;
        uint32_t sleep_requested_ms;
        uint32_t sleep_max_ms;
    };
    void se050_transport_stats_get(struct se050_transport_stats *stats);
/* Bounded, opt-in metadata trace. No APDU payload, object ID, key, signature,
 * certificate or random sample is retained. Print only after the handshake. */
#define SE050_TRACE_CAPACITY 32U
    struct se050_apdu_trace
    {
        uint32_t sequence;
        uint32_t elapsed_ms;
        uint32_t io_ms;
        uint32_t nacks;
        uint32_t sleep_calls;
        uint32_t sleep_ms;
        uint32_t sleep_requested_ms;
        uint32_t sleep_max_ms;
        uint16_t tx_bytes;
        uint16_t rx_bytes;
        uint16_t status_word;
        uint8_t instruction;
        uint8_t parameter1;
        uint8_t parameter2;
        se050_status_t status;
    };
    se050_status_t se050_trace_set(int enabled);
    void se050_trace_status(int *enabled, uint32_t *first, uint32_t *next);
    se050_status_t se050_trace_read(uint32_t sequence, struct se050_apdu_trace *entry);

    unsigned int se050_bus_khz(void);
    se050_status_t se050_bus_set(unsigned int khz);
    /* Experimental READ-only polling. Zero retains the exact SDK backoff. A
     * nonzero target is accepted only after a valid ATR supplies MPOT; one
     * scheduler tick is added as a rounding guard. Existing
     * retry budgets, WRITE retries and recovery waits are not shortened. */
    se050_status_t se050_read_poll_set(unsigned int cap_ms);
    unsigned int se050_read_poll_limit(unsigned int *minimum_ms);

    /* Thread context only. All public calls serialize the entire T=1 exchange.
     * No key creation, deletion or provisioning is performed during init. */
    se050_status_t se050_init(void);
    /* Cache invalidation epoch: changes on open/close or an APDU status failure. */
    uint32_t se050_session_generation(void);
    se050_status_t se050_get_version(uint8_t *output, size_t capacity, size_t *length);
    se050_status_t se050_get_random(uint8_t *output, size_t length);
    /* Internal integration API: response includes SW1/SW2. Transport success does
     * not imply APDU success. Both buffers must be distinct. */
    se050_status_t se050_transceive(const uint8_t *command, size_t command_length,
                                    uint8_t *response, size_t capacity, size_t *length);

#ifdef __cplusplus
}
#endif

#endif
