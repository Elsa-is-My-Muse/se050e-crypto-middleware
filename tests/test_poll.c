/* Actual NXP PAL read/write loops with scripted I2C readiness and time. */
#include <assert.h>
#include <stdarg.h>
#include <stdio.h>
#include "../nxp/phNxpEsePal_i2c.c"

static unsigned int clock_ms, sleep_calls, ready_ms, reads, writes;
static unsigned int cap_ms, minimum_ms = 1;
static int hard_error, write_hard_error, just_nacked;
static unsigned int last_nack_ms;
unsigned int se050_read_poll_limit(unsigned int *minimum)
{
    *minimum = minimum_ms;
    return cap_ms;
}
void sm_sleep(uint32_t ms)
{
    clock_ms += ms;
    ++sleep_calls;
}
void nLog(const char *component, int level, const char *format, ...)
{
    (void)component;
    (void)level;
    (void)format;
}
void nLog_au8(const char *component, int level, const char *message, const unsigned char *array,
              size_t length)
{
    (void)component;
    (void)level;
    (void)message;
    (void)array;
    (void)length;
}
i2c_error_t axI2CInit(void **context, const char *name)
{
    (void)context;
    (void)name;
    return I2C_OK;
}
void axI2CTerm(void *context, int mode)
{
    (void)context;
    (void)mode;
}
i2c_error_t axI2CRead(void *context, unsigned char bus, unsigned char address, unsigned char *data,
                      unsigned short length)
{
    (void)context;
    (void)bus;
    (void)address;
    if (just_nacked && cap_ms)
        assert(clock_ms - last_nack_ms >= minimum_ms);
    ++reads;
    if (hard_error)
        return I2C_FAILED;
    if (clock_ms < ready_ms)
    {
        just_nacked = 1;
        last_nack_ms = clock_ms;
        return I2C_NACK_ON_ADDRESS;
    }
    just_nacked = 0;
    memset(data, 0xa5, length);
    return I2C_OK;
}
i2c_error_t axI2CWrite(void *context, unsigned char bus, unsigned char address, unsigned char *data,
                       unsigned short length)
{
    (void)context;
    (void)bus;
    (void)address;
    (void)data;
    (void)length;
    ++writes;
    return write_hard_error ? I2C_FAILED : I2C_NACK_ON_ADDRESS;
}
static void reset(unsigned int cap, unsigned int ready)
{
    cap_ms = cap;
    ready_ms = ready;
    clock_ms = reads = writes = sleep_calls = 0;
    hard_error = write_hard_error = just_nacked = 0;
    minimum_ms = 1;
    phPalEse_i2c_back_off_delay_reset();
}
int main(void)
{
    uint8_t data[2];
    unsigned int baseline, tuned, t, m;
    reset(0, 19);
    assert(phPalEse_i2c_read(NULL, data, 2) == 2);
    assert(clock_ms == 21 && reads == 7 && gBackoffDelay == 0);
    reset(2, 19);
    assert(phPalEse_i2c_read(NULL, data, 2) == 2);
    assert(clock_ms == 20 && gBackoffDelay == 0);
    reset(0, UINT32_MAX);
    assert(phPalEse_i2c_read(NULL, data, 2) == -1);
    baseline = clock_ms;
    assert(baseline == 45 && reads == 9 && sleep_calls == 9);
    reset(2, UINT32_MAX);
    assert(phPalEse_i2c_read(NULL, data, 2) == -1);
    assert(clock_ms >= baseline && reads > 9 && gBackoffDelay == 9);
    /* A generic bus failure is not mistaken for chip busy or retried. */
    reset(2, 19);
    hard_error = 1;
    assert(phPalEse_i2c_read(NULL, data, 2) == -1 && reads == 1 && !clock_ms);
    /* Baseline/tuned probes never shorten all-NACK wall-time sleep budget. */
    for (m = 1; m <= 5; ++m)
    {
        reset(10, UINT32_MAX);
        minimum_ms = m;
        assert(phPalEse_i2c_read(NULL, data, 2) == -1 && clock_ms >= baseline);
    }
    for (t = 0; t <= 36; ++t)
    {
        reset(0, t);
        assert(phPalEse_i2c_read(NULL, data, 2) == 2);
        baseline = clock_ms;
        reset(2, t);
        assert(phPalEse_i2c_read(NULL, data, 2) == 2);
        tuned = clock_ms;
        assert(tuned <= baseline + 2);
    }
    /* Even a failed burst near the 200 ms cap retains its wait budget. */
    reset(2, UINT32_MAX);
    gBackoffDelay = 199;
    assert(phPalEse_i2c_read(NULL, data, 2) == -1 && clock_ms == 1800);
    reset(0, UINT32_MAX);
    assert(phPalEse_i2c_write(NULL, data, 2) == -1);
    baseline = clock_ms;
    assert(baseline == 36 && writes == 9);
    reset(2, UINT32_MAX);
    assert(phPalEse_i2c_write(NULL, data, 2) == -1 && clock_ms == baseline && writes == 9);
    reset(2, UINT32_MAX);
    write_hard_error = 1;
    assert(phPalEse_i2c_write(NULL, data, 2) == -1 && writes == 1 && !clock_ms);
    puts("SE050 read-poll tests passed (SDK budget, MPOT, hard errors, unchanged WRITE)");
    return 0;
}
