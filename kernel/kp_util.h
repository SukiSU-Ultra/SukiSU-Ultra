#ifndef __KSU_H_KP_UTIL
#define __KSU_H_KP_UTIL
#include <linux/types.h>

#ifndef preempt_enable_no_resched_notrace
#define preempt_enable_no_resched_notrace()                                    \
	do {                                                                   \
		barrier();                                                     \
		__preempt_count_dec();                                         \
	} while (0)
#endif

#ifndef preempt_disable_notrace
#define preempt_disable_notrace()                                              \
	do {                                                                   \
		__preempt_count_inc();                                         \
		barrier();                                                     \
	} while (0)
#endif

bool ksu_strncpy_retry(const char __user **char_usr_ptr, char *dest,
		    size_t dest_len, bool exit_atomic_ctx);

#endif
