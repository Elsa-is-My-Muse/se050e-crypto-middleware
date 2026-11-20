/** @file se050_port_custom.h
 * @brief Deliberately incomplete OS-port template; not a no-op implementation.
 *
 * Copy to your platform directory. Supply a platform header, a real mutex type,
 * and the scheduler tick rate. Implement every declaration in a matching .c.
 * Do not select this template in the existing AT32/RT-Thread project.
 */
#ifndef SE050_PORT_CUSTOM_H
#define SE050_PORT_CUSTOM_H

#include <stddef.h>
#include <stdint.h>

#ifndef SE050_CUSTOM_PLATFORM_HEADER
#error "Define SE050_CUSTOM_PLATFORM_HEADER to your real OS/HAL type header"
#endif
#include SE050_CUSTOM_PLATFORM_HEADER

#ifndef SE050_CUSTOM_MUTEX_TYPE
#error "Define SE050_CUSTOM_MUTEX_TYPE to a statically allocated OS mutex type"
#endif
#ifndef SE050_CUSTOM_TICKS_PER_SECOND
#error "Define SE050_CUSTOM_TICKS_PER_SECOND to your monotonic scheduler tick rate"
#endif

typedef int se050_status_t;
typedef uint32_t se050_tick_t;
typedef SE050_CUSTOM_MUTEX_TYPE se050_mutex_t;

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
#define SE050_TICKS_PER_SECOND SE050_CUSTOM_TICKS_PER_SECOND

#ifdef __cplusplus
extern "C"
{
#endif

    /* Map OS return codes: zero on success, negative SE050_* on failure.
     * init must not block; the core calls it inside a short scheduler critical section.
     * A successful take must exclude other tasks for a complete T=1 transaction.
     */
    se050_status_t se050_port_mutex_init(se050_mutex_t *mutex, const char *name, int flags);
    se050_status_t se050_port_mutex_take(se050_mutex_t *mutex, int timeout);
    se050_status_t se050_port_mutex_release(se050_mutex_t *mutex);
    void se050_port_critical_enter(void);
    void se050_port_critical_exit(void);

    /* Stable, non-null identity unique among concurrent callers. Not an ISR API. */
    void *se050_port_thread_self(void);
    se050_tick_t se050_port_tick_get(void);
    void se050_port_printf(const char *format, ...);
    void *se050_port_malloc(size_t size);
    void *se050_port_calloc(size_t count, size_t size);
    void se050_port_free(void *pointer);

#ifdef __cplusplus
}
#endif

#endif /* SE050_PORT_CUSTOM_H */
