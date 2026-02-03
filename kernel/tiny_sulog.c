#include <linux/string.h>
#include <linux/uaccess.h>
#include <linux/printk.h>
#include <linux/cred.h>
#include <linux/fs.h>
#include <linux/uaccess.h>
#include <linux/file.h>
#include <linux/mm.h>
#include <linux/slab.h>
#include <linux/binfmts.h>

#include "klog.h" // IWYU pragma: keep

// half assed ringbuffer
// 8 bytes
struct sulog_entry {
	uint32_t s_time; // uptime in seconds
	uint32_t data; // uint8_t[0,1,2] = uid, basically uint24_t, uint8_t[3] = symbol
} __attribute__((packed));

#define SULOG_ENTRY_MAX 250
#define SULOG_BUFSIZ SULOG_ENTRY_MAX *(sizeof(struct sulog_entry))

static void *sulog_buf_ptr = NULL;
static uint8_t sulog_index_next = 0;

static DEFINE_SPINLOCK(sulog_lock);

void sulog_init_heap()
{
	sulog_buf_ptr = kzalloc(SULOG_BUFSIZ, GFP_KERNEL);
	if (!sulog_buf_ptr)
		return;

	pr_info("sulog_init: allocated %lu bytes on 0x%p \n", SULOG_BUFSIZ,
		sulog_buf_ptr);
}

/*
 *
 *  boottime_s_get, get kernel uptime in seconds
 *
 * - handles sub 4.10 compat
 * - we do this forced pointer cast to cut down on compat, pre 4.10, ktime is a union
 *
 * - bs handling 64-bit division on 32-bit (do_div)
 * - remainder = do_div(dividend, divisor); dividend will hold the quotient 
 * - for 64-bit we can straight up just use divide
 *
 */
static inline uint32_t boottime_s_get()
{
	ktime_t boottime_kt = ktime_get_boottime();

#ifdef CONFIG_64BIT
	uint64_t boottime_s = *(uint64_t *)&boottime_kt / 1000000000;
#else
	uint64_t boottime_s = *(uint64_t *)&boottime_kt;
	do_div(boottime_s, 1000000000);
#endif

	return (uint32_t)boottime_s;
}

void write_sulog(uint8_t sym)
{
	if (!sulog_buf_ptr)
		return;

	unsigned int offset = sulog_index_next * sizeof(struct sulog_entry);
	struct sulog_entry entry = { 0 };

	// WARNING!!! this is LE only!
	entry.s_time = boottime_s_get();
	entry.data = (uint32_t)current_uid().val;
	*((char *)&entry.data + 3) = sym;

	// we can perform this write atomic on 64-bit
	// however this still has to be locked for exclusion as theres a reader

	spin_lock(&sulog_lock);

#ifdef CONFIG_64BIT
	*(volatile uint64_t *)(sulog_buf_ptr + offset) = *(uint64_t *)&entry;
#else
	__builtin_memcpy(sulog_buf_ptr + offset, &entry, sizeof(entry));
#endif
	spin_unlock(&sulog_lock);

	// move ptr for next iteration
	sulog_index_next = sulog_index_next + 1;

	if (sulog_index_next >= SULOG_ENTRY_MAX)
		sulog_index_next = 0;
}

struct sulog_entry_rcv_ptr {
	uint64_t index_ptr; // send index here
	uint64_t buf_ptr; // send buf here
	uint64_t uptime_ptr; // uptime
};

int send_sulog_dump(void __user *uptr)
{
	if (!sulog_buf_ptr)
		return 1;

	struct sulog_entry_rcv_ptr sbuf = { 0 };

	if (copy_from_user(&sbuf, uptr, sizeof(sbuf)))
		return 1;

	if (!sbuf.index_ptr || !sbuf.buf_ptr || !sbuf.uptime_ptr)
		return 1;

	// send uptime

	uint32_t uptime = boottime_s_get();

	if (copy_to_user((void __user *)sbuf.uptime_ptr, &uptime,
			 sizeof(uptime)))
		return 1;

	// send index
	if (copy_to_user((void __user *)sbuf.index_ptr, &sulog_index_next,
			 sizeof(sulog_index_next)))
		return 1;

	// send buffer data
	spin_lock(&sulog_lock);
	if (copy_to_user((void __user *)sbuf.buf_ptr, sulog_buf_ptr,
			 SULOG_BUFSIZ)) {
		spin_unlock(&sulog_lock);
		return 1;
	}
	spin_unlock(&sulog_lock);

	return 0;
}