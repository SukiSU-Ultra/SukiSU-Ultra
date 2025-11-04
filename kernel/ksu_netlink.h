#ifndef __KSU_NETLINK_H
#define __KSU_NETLINK_H

#include <linux/netlink.h>
#include <linux/skbuff.h>
#include <net/sock.h>
#include <linux/net.h>

#define KSU_NETLINK_PROTOCOL 2
#define KSU_NETLINK_CMD_MANUAL_SU 50

struct ksu_netlink_msg {
    int cmd;
    int option;
    uid_t target_uid;
    pid_t target_pid;
    char token_buffer[33];
    int result;
};

int ksu_netlink_init(void);
void ksu_netlink_exit(void);
void ksu_netlink_allow_socket_syscalls(struct task_struct *tsk);

#endif
