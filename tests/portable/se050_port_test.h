/* Unit-test-only OS contract. No RT-Thread headers or symbols are provided.
 * Production mutex/critical-section implementations must not use this mock.
 */
#ifndef SE050_PORT_TEST_H
#define SE050_PORT_TEST_H

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>

typedef int se050_status_t;
typedef uint32_t se050_tick_t;
typedef struct
{
    int held;
} se050_mutex_t;

#define SE050_OK 0
#define SE050_ERROR 1
#define SE050_ETIMEOUT 2
#define SE050_EFULL 3
#define SE050_EBUSY 7
#define SE050_EIO 8
#define SE050_EINVAL 10
#define SE050_NULL NULL
#define SE050_WAIT_FOREVER (-1)
#define SE050_MUTEX_PRIO 1
#define SE050_TICKS_PER_SECOND 1000

#ifdef __cplusplus
extern "C"
{
#endif
    int se050_port_mutex_init(se050_mutex_t *mutex, const char *name, int flags);
    int se050_port_mutex_take(se050_mutex_t *mutex, int timeout);
    int se050_port_mutex_release(se050_mutex_t *mutex);
    void se050_port_critical_enter(void);
    void se050_port_critical_exit(void);
    void *se050_port_thread_self(void);
    se050_tick_t se050_port_tick_get(void);
    void se050_port_printf(const char *format, ...);
#ifdef __cplusplus
}
#endif

#define se050_port_malloc malloc
#define se050_port_calloc calloc
#define se050_port_free free

#endif /* SE050_PORT_TEST_H */
