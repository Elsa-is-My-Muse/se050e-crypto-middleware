#ifndef TEST_RTTHREAD_H
#define TEST_RTTHREAD_H
#include <stddef.h>
#include <stdint.h>
typedef uint32_t rt_tick_t;
#define RT_TICK_PER_SECOND 1000
rt_tick_t rt_tick_get(void);
void *rt_thread_self(void);
typedef int rt_err_t;
struct rt_mutex
{
    int held;
};
#define RT_EOK 0
#define RT_ERROR 1
#define RT_ETIMEOUT 2
#define RT_EFULL 3
#define RT_EBUSY 7
#define RT_EIO 8
#define RT_EINVAL 10
#define RT_NULL NULL
#define RT_IPC_FLAG_PRIO 1
#define RT_WAITING_FOREVER (-1)
void rt_kprintf(const char *, ...);
void rt_enter_critical(void);
void rt_exit_critical(void);
int rt_mutex_init(struct rt_mutex *, const char *, int);
int rt_mutex_take(struct rt_mutex *, int);
int rt_mutex_release(struct rt_mutex *);
#endif
