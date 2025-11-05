#ifndef __KSU_NETLINK_H
#define __KSU_NETLINK_H

#include <linux/netlink.h>
#include <linux/skbuff.h>
#include <net/sock.h>
#include <linux/net.h>

#define KSU_NETLINK_PROTOCOL 11

#define KSU_NETLINK_CMD_MANUAL_SU 100

struct ksu_netlink_hdr {
    int cmd;      // Command ID
    int result;   // Result code (output)
};

struct ksu_netlink_manual_su {
    struct ksu_netlink_hdr hdr;
    int option;
    uid_t target_uid;
    pid_t target_pid;
    char token_buffer[33];
};

union ksu_netlink_msg {
    struct ksu_netlink_hdr hdr;
    struct ksu_netlink_manual_su manual_su;
};

typedef int (*ksu_netlink_handler_t)(struct sk_buff *skb, struct nlmsghdr *nlh, void *msg_data);
typedef bool (*ksu_netlink_perm_check_t)(uid_t uid);

struct ksu_netlink_cmd_handler {
    int cmd;
    size_t msg_size;
    const char *name;
    ksu_netlink_handler_t handler;
    ksu_netlink_perm_check_t perm_check;
};

int ksu_netlink_init(void);
void ksu_netlink_exit(void);

#endif
