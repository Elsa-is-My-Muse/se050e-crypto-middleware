#include <rtthread.h>
#include <stdarg.h>
#include "at32f435_437.h"
#include "sm_timer.h"
#include "nxLog.h"
#include "se050_port_i2c.h"

uint32_t sm_initSleep(void)
{
    return 0;
}
void sm_sleep(uint32_t msec)
{
    if (msec)
    {
        rt_tick_t start = rt_tick_get();
        rt_thread_mdelay((rt_int32_t)msec);
        se050_transport_note_sleep_request(msec, start);
    }
}
void sm_usleep(uint32_t us)
{
    CoreDebug->DEMCR |= CoreDebug_DEMCR_TRCENA_Msk;
    DWT->CTRL |= DWT_CTRL_CYCCNTENA_Msk;
    while (us)
    {
        uint32_t chunk = us > 1000 ? 1000 : us;
        uint32_t cycles = (system_core_clock / 1000000U) * chunk;
        uint32_t start = DWT->CYCCNT;
        while ((uint32_t)(DWT->CYCCNT - start) < cycles)
        {
        }
        us -= chunk;
    }
}
uint8_t nLog_Init(void)
{
    return 0;
}
void nLog_DeInit(void)
{
}
void nLog(const char *component, int level, const char *format, ...)
{
    char line[192];
    va_list args;
    /* Never print APDU buffers, keys or random samples. */
    if (level > NX_LEVEL_WARN)
        return;
    va_start(args, format);
    rt_vsnprintf(line, sizeof(line), format, args);
    va_end(args);
    rt_kprintf("[SE050/%s] %s\n", component, line);
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
