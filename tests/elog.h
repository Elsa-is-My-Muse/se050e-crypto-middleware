/* Silence target diagnostic logging in native crypto integration tests. */
#ifndef TEST_ELOG_H
#define TEST_ELOG_H
#define log_i(...) ((void)0)
#define log_e(...) ((void)0)
#define log_w(...) ((void)0)
#define log_d(...) ((void)0)
#endif
