#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include "kernel_compat.h"
#include "ksu_netlink.h"
#include "manual_su.h"
#include "ksu.h"

static struct sock *ksu_nl_sock = NULL;

static bool manager_only(uid_t uid)
{
    return is_manager();
}

static bool manager_or_allowed(uid_t uid)
{
    return is_manager() || ksu_is_allow_uid(uid);
}

static bool always_allow(uid_t uid)
{
    return true;
}

static bool system_uid(uid_t uid)
{
    if (!current->mm || current->in_execve) {
        return 0;
    }
    
    uid_t caller_uid = current_uid().val;
    return caller_uid <= 2000;
}

// Manual SU
static int handle_manual_su(struct sk_buff *skb, struct nlmsghdr *nlh, void *msg_data)
{
    struct ksu_netlink_manual_su *msg = (struct ksu_netlink_manual_su *)msg_data;
    struct manual_su_request request;
    int res;

    pr_info("ksu_netlink: manual_su request, option=%d, uid=%d, pid=%d\n",
            msg->option, msg->target_uid, msg->target_pid);

    memset(&request, 0, sizeof(request));
    request.target_uid = msg->target_uid;
    request.target_pid = msg->target_pid;

    if (msg->option == MANUAL_SU_OP_GENERATE_TOKEN ||
        msg->option == MANUAL_SU_OP_ESCALATE) {
        memcpy(request.token_buffer, msg->token_buffer, sizeof(request.token_buffer));
    }

    res = ksu_handle_manual_su_request(msg->option, &request);

    msg->hdr.result = res;
    if (msg->option == MANUAL_SU_OP_GENERATE_TOKEN && res == 0) {
        memcpy(msg->token_buffer, request.token_buffer, sizeof(msg->token_buffer));
    }

    return 0;
}

// Command handlers mapping table
static const struct ksu_netlink_cmd_handler ksu_netlink_handlers[] = {
    {
        .cmd = KSU_NETLINK_CMD_MANUAL_SU,
        .msg_size = sizeof(struct ksu_netlink_manual_su),
        .name = "MANUAL_SU",
        .handler = handle_manual_su,
        .perm_check = system_uid
    },
    { .cmd = 0, .name = NULL, .handler = NULL, .perm_check = NULL }
};

static void ksu_netlink_recv_msg(struct sk_buff *skb)
{
    struct nlmsghdr *nlh;
    struct ksu_netlink_hdr *hdr;
    struct sk_buff *skb_out;
    const struct ksu_netlink_cmd_handler *handler_entry = NULL;
    void *msg_data;
    int res;
    u32 pid;
    uid_t sender_uid;
    int i;

    if (!skb) {
        pr_err("ksu_netlink: received NULL skb\n");
        return;
    }

    nlh = (struct nlmsghdr *)skb->data;
    pid = nlh->nlmsg_pid;
    sender_uid = NETLINK_CB(skb).creds.uid.val;

    if (!nlh || nlh->nlmsg_len < NLMSG_HDRLEN + sizeof(struct ksu_netlink_hdr)) {
        pr_err("ksu_netlink: invalid message size\n");
        return;
    }

    hdr = (struct ksu_netlink_hdr *)nlmsg_data(nlh);

    // Find command handler
    for (i = 0; ksu_netlink_handlers[i].handler; i++) {
        if (hdr->cmd == ksu_netlink_handlers[i].cmd) {
            handler_entry = &ksu_netlink_handlers[i];
            break;
        }
    }

    if (!handler_entry) {
        pr_warn("ksu_netlink: unknown command %d\n", hdr->cmd);
        return;
    }

    // Validate message size
    if (nlh->nlmsg_len < NLMSG_HDRLEN + handler_entry->msg_size) {
        pr_err("ksu_netlink: invalid message size for cmd %s\n", handler_entry->name);
        return;
    }

    // Permission check
    if (handler_entry->perm_check && !handler_entry->perm_check(sender_uid)) {
        pr_warn("ksu_netlink: permission denied for cmd %s from uid %d\n",
                handler_entry->name, sender_uid);
        hdr->result = -EPERM;
        goto send_reply;
    }

    // Allocate response buffer (reuse input data for response)
    msg_data = kmalloc(handler_entry->msg_size, GFP_KERNEL);
    if (!msg_data) {
        pr_err("ksu_netlink: failed to allocate message buffer\n");
        return;
    }
    memcpy(msg_data, hdr, handler_entry->msg_size);

    // Execute handler
    res = handler_entry->handler(skb, nlh, msg_data);
    if (res < 0) {
        pr_err("ksu_netlink: handler for cmd %s failed: %d\n", handler_entry->name, res);
        kfree(msg_data);
        return;
    }

send_reply:
    // Send reply
    skb_out = nlmsg_new(handler_entry->msg_size, GFP_KERNEL);
    if (!skb_out) {
        pr_err("ksu_netlink: failed to allocate reply skb\n");
        if (msg_data)
            kfree(msg_data);
        return;
    }

    nlh = nlmsg_put(skb_out, 0, 0, NLMSG_DONE, handler_entry->msg_size, 0);
    if (!nlh) {
        pr_err("ksu_netlink: nlmsg_put failed\n");
        kfree_skb(skb_out);
        if (msg_data)
            kfree(msg_data);
        return;
    }

    NETLINK_CB(skb_out).dst_group = 0;
    memcpy(nlmsg_data(nlh), msg_data ? msg_data : hdr, handler_entry->msg_size);

    if (msg_data)
        kfree(msg_data);

    res = nlmsg_unicast(ksu_nl_sock, skb_out, pid);
    if (res < 0) {
        pr_err("ksu_netlink: failed to send reply: %d\n", res);
    } else {
        pr_info("ksu_netlink: reply sent for cmd %s\n", handler_entry->name);
    }
}

int ksu_netlink_init(void)
{
    struct netlink_kernel_cfg cfg = {
        .input = ksu_netlink_recv_msg,
    };

    ksu_nl_sock = netlink_kernel_create(&init_net, KSU_NETLINK_PROTOCOL, &cfg);
    if (!ksu_nl_sock) {
        pr_err("ksu_netlink: failed to create netlink socket\n");
        return -ENOMEM;
    }

    pr_info("ksu_netlink: initialized with protocol %d\n", KSU_NETLINK_PROTOCOL);
    return 0;
}

void ksu_netlink_exit(void)
{
    if (ksu_nl_sock) {
        netlink_kernel_release(ksu_nl_sock);
        ksu_nl_sock = NULL;
        pr_info("ksu_netlink: released\n");
    }
}
