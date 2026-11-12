/* Read-only queue-admission tracing. Writes only the four owned maps. */
#define config vmlinux_config_type
#include "vmlinux.h"
#undef config
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

struct configuration {
    __u64 socket_inode, socket_cookie, netns_cookie, netns_inode;
    __u64 started_ns, deadline_ns;
    __u32 socket_uid, src_ip, dst_ip;
    __u16 src_port, dst_port;
    __u32 max_events, reserved;
    unsigned char payload[64];
};
struct event {
    __u64 entered_ns, exited_ns, socket_inode, socket_cookie, netns_cookie, netns_inode;
    __u32 socket_uid, src_ip, dst_ip;
    __u16 src_port, dst_port;
    unsigned char payload[64];
};
struct invocation { __u64 sk, skb, pid_tgid; __u32 cpu, reserved; };
struct counters { __u64 entry_matches, accepted, rejected, correlation_loss, overflow; };
_Static_assert(sizeof(struct configuration) == 136, "config ABI");
_Static_assert(sizeof(struct event) == 128, "event ABI");
_Static_assert(sizeof(struct invocation) == 32, "key ABI");
_Static_assert(sizeof(struct counters) == 40, "stats ABI");
struct { __uint(type,BPF_MAP_TYPE_ARRAY); __uint(max_entries,1); __type(key,__u32); __type(value,struct configuration); } config SEC(".maps");
struct { __uint(type,BPF_MAP_TYPE_HASH); __uint(max_entries,64); __type(key,struct invocation); __type(value,struct event); } pending SEC(".maps");
struct { __uint(type,BPF_MAP_TYPE_ARRAY); __uint(max_entries,16); __type(key,__u32); __type(value,struct event); } events SEC(".maps");
struct { __uint(type,BPF_MAP_TYPE_ARRAY); __uint(max_entries,1); __type(key,__u32); __type(value,struct counters); } stats SEC(".maps");

static __always_inline struct invocation invocation(struct sock *sk, struct sk_buff *skb)
{
    struct invocation key = { .sk=(__u64)sk, .skb=(__u64)skb,
        .pid_tgid=bpf_get_current_pid_tgid(), .cpu=bpf_get_smp_processor_id() };
    return key;
}

SEC("fentry/__udp_enqueue_schedule_skb")
int BPF_PROG(queue_entry, struct sock *sk, struct sk_buff *skb)
{
    __u32 zero=0;
    struct configuration *cfg=bpf_map_lookup_elem(&config,&zero);
    struct counters *count=bpf_map_lookup_elem(&stats,&zero);
    if (!cfg || !count || count->correlation_loss) return 0;
    struct event event = { .entered_ns=bpf_ktime_get_ns() };
    if (event.entered_ns < cfg->started_ns || event.entered_ns > cfg->deadline_ns) return 0;
    if (BPF_CORE_READ(sk,__sk_common.skc_family)!=2 || BPF_CORE_READ(sk,sk_protocol)!=17) return 0;
    event.socket_cookie=BPF_CORE_READ(sk,__sk_common.skc_cookie.counter);
    event.socket_uid=BPF_CORE_READ(sk,sk_uid.val);
    event.socket_inode=BPF_CORE_READ(sk,sk_socket,file,f_inode,i_ino);
    struct net *net=BPF_CORE_READ(sk,__sk_common.skc_net.net);
    event.netns_cookie=BPF_CORE_READ(net,net_cookie);
    event.netns_inode=BPF_CORE_READ(net,ns.inum);
    if (event.socket_cookie!=cfg->socket_cookie || event.socket_inode!=cfg->socket_inode ||
        event.socket_uid!=cfg->socket_uid || event.netns_cookie!=cfg->netns_cookie ||
        event.netns_inode!=cfg->netns_inode) return 0;
    if (BPF_CORE_READ(skb,len)!=64 || BPF_CORE_READ(skb,data_len)!=0) return 0;
    unsigned char *head=BPF_CORE_READ(skb,head), *data=BPF_CORE_READ(skb,data);
    __u16 network=BPF_CORE_READ(skb,network_header), transport=BPF_CORE_READ(skb,transport_header);
    __u32 tail=BPF_CORE_READ(skb,tail);
    if ((__u32)network+20>tail || (__u32)transport+8>tail || transport!=(__u32)network+20 || data!=head+transport+8) return 0;
    unsigned char ip[20], udp[8];
    if (bpf_probe_read_kernel(ip,sizeof(ip),head+network) || bpf_probe_read_kernel(udp,sizeof(udp),head+transport) ||
        bpf_probe_read_kernel(event.payload,sizeof(event.payload),data)) return 0;
    if (ip[0]!=0x45 || ip[9]!=17 || ip[2]!=0 || ip[3]!=92 || (ip[6]&0x3f) || ip[7] || udp[4]!=0 || udp[5]!=72) return 0;
    __builtin_memcpy(&event.src_ip,ip+12,4); __builtin_memcpy(&event.dst_ip,ip+16,4);
    event.src_port=((__u16)udp[0]<<8)|udp[1]; event.dst_port=((__u16)udp[2]<<8)|udp[3];
    if (event.src_ip!=cfg->src_ip || event.dst_ip!=cfg->dst_ip || event.src_port!=cfg->src_port || event.dst_port!=cfg->dst_port) return 0;
#pragma unroll
    for (int i=0;i<64;i++) if (event.payload[i]!=cfg->payload[i]) return 0;
    __sync_fetch_and_add(&count->entry_matches,1);
    struct invocation key=invocation(sk,skb);
    if (bpf_map_lookup_elem(&pending,&key)) {
        /* Sticky poison prevents a third entry from pairing with an old exit. */
        __sync_fetch_and_add(&count->correlation_loss,1);
        bpf_map_delete_elem(&pending,&key);
        return 0;
    }
    if (bpf_map_update_elem(&pending,&key,&event,BPF_NOEXIST))
        __sync_fetch_and_add(&count->correlation_loss,1);
    return 0;
}

SEC("fexit/__udp_enqueue_schedule_skb")
int BPF_PROG(queue_exit, struct sock *sk, struct sk_buff *skb, int ret)
{
    /* Pointer VALUES only: never dereference sk/skb after queue admission. */
    struct invocation key=invocation(sk,skb);
    struct event *saved=bpf_map_lookup_elem(&pending,&key);
    if (!saved) return 0; /* Ordinary nonmatching entry, not a loss. */
    struct event event=*saved;
    bpf_map_delete_elem(&pending,&key);
    __u32 zero=0;
    struct configuration *cfg=bpf_map_lookup_elem(&config,&zero);
    struct counters *count=bpf_map_lookup_elem(&stats,&zero);
    if (!cfg || !count || count->correlation_loss) return 0;
    if (ret!=0) { __sync_fetch_and_add(&count->rejected,1); return 0; }
    event.exited_ns=bpf_ktime_get_ns();
    if (event.exited_ns < event.entered_ns || event.exited_ns > cfg->deadline_ns) return 0;
    __u64 slot=__sync_fetch_and_add(&count->accepted,1);
    if (slot>=cfg->max_events || slot>=16) { __sync_fetch_and_add(&count->overflow,1); return 0; }
    __u32 index=slot;
    if (bpf_map_update_elem(&events,&index,&event,BPF_ANY))
        __sync_fetch_and_add(&count->overflow,1);
    return 0;
}
char LICENSE[] SEC("license")="GPL";
