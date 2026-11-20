/** @file se050_port_i2c.h
 * @brief Board transport contract and metadata-only profiling hooks.
 *
 * Implement these functions in exactly one board port. The core serializes
 * complete T=1 exchanges; board functions must not acquire the session mutex.
 * Also implement the NXP axI2C* entry points declared in nxp/i2c_a7.h.
 * See nxp/i2c_a7.h and port/at32f435/ for transport and timing reference code.
 */
#ifndef SE050_PORT_I2C_H
#define SE050_PORT_I2C_H

#include "se050.h"

#ifdef __cplusplus
extern "C"
{
#endif

    /** Return SE050_OK or a negative SE050_* error. Never provision keys here. */
    se050_status_t se050_i2c_init(void);
    se050_status_t se050_i2c_probe(void);
    se050_status_t se050_i2c_recover(void);
    se050_status_t se050_i2c_set_speed(unsigned int khz);
    unsigned int se050_i2c_get_speed(void);

    /** Implemented by the core; call from the board port, not vice versa.
     *  Counters store lengths/status/timing, never command or response contents.
     *  start is the monotonic OS tick captured before the operation.
     */
    void se050_transport_note_io(int write, size_t bytes, int nack, int error, se050_tick_t start);
    void se050_transport_note_sleep(se050_tick_t start);
    void se050_transport_note_sleep_request(uint32_t requested_ms, se050_tick_t start);

#ifdef __cplusplus
}
#endif

#endif /* SE050_PORT_I2C_H */
