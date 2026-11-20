#ifndef SE050_PORT_RTTHREAD_H
#define SE050_PORT_RTTHREAD_H
#include <rtthread.h>
typedef rt_err_t se050_status_t;
typedef rt_tick_t se050_tick_t;
typedef struct rt_mutex se050_mutex_t;
#define SE050_OK RT_EOK
#define SE050_ERROR RT_ERROR
#define SE050_EINVAL RT_EINVAL
#define SE050_EIO RT_EIO
#define SE050_EFULL RT_EFULL
#define SE050_EBUSY RT_EBUSY
#define SE050_ETIMEOUT RT_ETIMEOUT
#define SE050_NULL RT_NULL
#define SE050_WAIT_FOREVER RT_WAITING_FOREVER
#define SE050_MUTEX_PRIO RT_IPC_FLAG_PRIO
#define SE050_TICKS_PER_SECOND RT_TICK_PER_SECOND
#define se050_port_mutex_init rt_mutex_init
#define se050_port_mutex_take rt_mutex_take
#define se050_port_mutex_release rt_mutex_release
#define se050_port_critical_enter rt_enter_critical
#define se050_port_critical_exit rt_exit_critical
#define se050_port_thread_self rt_thread_self
#define se050_port_tick_get rt_tick_get
#define se050_port_printf rt_kprintf
#define se050_port_malloc rt_malloc
#define se050_port_calloc rt_calloc
#define se050_port_free rt_free
#endif
