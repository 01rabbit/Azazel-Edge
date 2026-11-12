/* Socket-bound protocol payload-copy tracing; only owned maps are written. */
#define config vmlinux_config_type
#include "vmlinux.h"
#undef config
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

struct configuration {
    __u64 socket_inode, socket_cookie, netns_cookie, netns_inode;
    __u64 started_ns, deadline_ns, pidns_device, pidns_inode;
    __u32 socket_uid, src_ip, dst_ip;
    __u16 src_port, dst_port;
    __u32 max_events, reserved;
    unsigned char payload[64];
};
struct event {
    __u64 entered_ns, consumed_ns, exited_ns;
    __u64 socket_inode, socket_cookie, netns_cookie, netns_inode;
    __u64 receiver_start_boottime_ns;
    __u32 socket_uid, receiver_real_uid, receiver_effective_uid;
    __u32 receiver_tgid, receiver_tid, src_ip, dst_ip;
    __u16 src_port, dst_port;
    unsigned char payload[64];
};
struct invocation { __u64 pid_tgid, sk; };
struct counters {
    __u64 entry_matches, consume_matches, accepted, rejected, correlation_loss, overflow;
};
_Static_assert(sizeof(struct configuration)==152,"config ABI");
_Static_assert(sizeof(struct event)==160,"event ABI");
_Static_assert(sizeof(struct invocation)==16,"key ABI");
_Static_assert(sizeof(struct counters)==48,"stats ABI");
struct { __uint(type,BPF_MAP_TYPE_ARRAY); __uint(max_entries,1); __type(key,__u32); __type(value,struct configuration); } config SEC(".maps");
struct { __uint(type,BPF_MAP_TYPE_HASH); __uint(max_entries,64); __type(key,struct invocation); __type(value,struct event); } pending SEC(".maps");
struct { __uint(type,BPF_MAP_TYPE_ARRAY); __uint(max_entries,16); __type(key,__u32); __type(value,struct event); } events SEC(".maps");
struct { __uint(type,BPF_MAP_TYPE_ARRAY); __uint(max_entries,1); __type(key,__u32); __type(value,struct counters); } stats SEC(".maps");

static __always_inline struct invocation invocation(struct sock *sk)
{
    struct invocation key={.pid_tgid=bpf_get_current_pid_tgid(),.sk=(__u64)sk};
    return key;
}

SEC("fentry/udp_recvmsg")
int BPF_PROG(copy_entry,struct sock *sk,struct msghdr *msg,size_t len,int flags,int *addr_len)
{
    __u32 zero=0;
    struct configuration *cfg=bpf_map_lookup_elem(&config,&zero);
    struct counters *count=bpf_map_lookup_elem(&stats,&zero);
    if (!cfg || !count || count->correlation_loss) return 0;
    struct event event={.entered_ns=bpf_ktime_get_ns()};
    if (event.entered_ns<cfg->started_ns || event.entered_ns>cfg->deadline_ns) return 0;
    if (flags!=0 && flags!=0x40) return 0; /* Only ordinary/DONTWAIT. */
    if (len<64 || BPF_CORE_READ(sk,__sk_common.skc_family)!=2 || BPF_CORE_READ(sk,sk_protocol)!=17) return 0;
    if (BPF_CORE_READ((struct udp_sock *)sk,udp_flags)&(1UL<<UDP_FLAGS_GRO_ENABLED)) return 0;
    __u8 iter=BPF_CORE_READ(msg,msg_iter.iter_type);
    if ((iter!=ITER_UBUF && iter!=ITER_IOVEC) || BPF_CORE_READ(msg,msg_iter.data_source) || BPF_CORE_READ(msg,msg_iter.count)<64) return 0;
    event.socket_cookie=BPF_CORE_READ(sk,__sk_common.skc_cookie.counter);
    event.socket_uid=BPF_CORE_READ(sk,sk_uid.val);
    event.socket_inode=BPF_CORE_READ(sk,sk_socket,file,f_inode,i_ino);
    struct net *net=BPF_CORE_READ(sk,__sk_common.skc_net.net);
    event.netns_cookie=BPF_CORE_READ(net,net_cookie);
    event.netns_inode=BPF_CORE_READ(net,ns.inum);
    if (event.socket_cookie!=cfg->socket_cookie || event.socket_inode!=cfg->socket_inode ||
        event.socket_uid!=cfg->socket_uid || event.netns_cookie!=cfg->netns_cookie || event.netns_inode!=cfg->netns_inode) return 0;
    struct task_struct *task=(struct task_struct *)bpf_get_current_task_btf();
    event.receiver_real_uid=BPF_CORE_READ(task,cred,uid.val);
    event.receiver_effective_uid=BPF_CORE_READ(task,cred,euid.val);
    if (event.receiver_real_uid!=cfg->socket_uid || event.receiver_effective_uid!=cfg->socket_uid) return 0;
    struct bpf_pidns_info ns={};
    if (bpf_get_ns_current_pid_tgid(cfg->pidns_device,cfg->pidns_inode,&ns,sizeof(ns))) return 0;
    event.receiver_tgid=ns.tgid; event.receiver_tid=ns.pid;
    event.receiver_start_boottime_ns=BPF_CORE_READ(task,group_leader,start_boottime);
    if (!event.receiver_tgid || !event.receiver_tid || !event.receiver_start_boottime_ns) return 0;
    struct invocation key=invocation(sk);
    __sync_fetch_and_add(&count->entry_matches,1);
    if (bpf_map_lookup_elem(&pending,&key) || bpf_map_update_elem(&pending,&key,&event,BPF_NOEXIST))
        __sync_fetch_and_add(&count->correlation_loss,1);
    return 0;
}

SEC("fentry/skb_consume_udp")
int BPF_PROG(copy_consume,struct sock *sk,struct sk_buff *skb,int len)
{
    struct invocation key=invocation(sk);
    struct event *event=bpf_map_lookup_elem(&pending,&key);
    if (!event) return 0;
    __u32 zero=0;
    struct configuration *cfg=bpf_map_lookup_elem(&config,&zero);
    struct counters *count=bpf_map_lookup_elem(&stats,&zero);
    if (!cfg || !count || count->correlation_loss) return 0;
    if (event->consumed_ns) { __sync_fetch_and_add(&count->correlation_loss,1); return 0; }
    __u64 now=bpf_ktime_get_ns();
    if (now<event->entered_ns || now>cfg->deadline_ns || len!=64 || BPF_CORE_READ(skb,len)!=64 || BPF_CORE_READ(skb,data_len)!=0) return 0;
    unsigned char *head=BPF_CORE_READ(skb,head), *data=BPF_CORE_READ(skb,data);
    __u32 end=BPF_CORE_READ(skb,end), tail=BPF_CORE_READ(skb,tail);
    struct skb_shared_info *shared=(struct skb_shared_info *)(head+end);
    if (BPF_CORE_READ(shared,gso_size) || BPF_CORE_READ(shared,gso_segs) || BPF_CORE_READ(shared,nr_frags) || BPF_CORE_READ(shared,frag_list)) return 0;
    __u16 network=BPF_CORE_READ(skb,network_header), transport=BPF_CORE_READ(skb,transport_header);
    if ((__u32)network+20>tail || (__u32)transport+72>tail || transport!=(__u32)network+20 || data!=head+transport+8) return 0;
    unsigned char ip[20],udp[8],payload[64];
    if (bpf_probe_read_kernel(ip,sizeof(ip),head+network) || bpf_probe_read_kernel(udp,sizeof(udp),head+transport) || bpf_probe_read_kernel(payload,sizeof(payload),data)) return 0;
    if (ip[0]!=0x45 || ip[9]!=17 || ip[2]!=0 || ip[3]!=92 || (ip[6]&0x3f) || ip[7] || udp[4]!=0 || udp[5]!=72) return 0;
    __u32 src,dst;
    __builtin_memcpy(&src,ip+12,4); __builtin_memcpy(&dst,ip+16,4);
    __u16 sport=((__u16)udp[0]<<8)|udp[1],dport=((__u16)udp[2]<<8)|udp[3];
    if (src!=cfg->src_ip || dst!=cfg->dst_ip || sport!=cfg->src_port || dport!=cfg->dst_port) return 0;
#pragma unroll
    for (int i=0;i<64;i++) if (payload[i]!=cfg->payload[i]) return 0;
    event->src_ip=src;event->dst_ip=dst;event->src_port=sport;event->dst_port=dport;
    __builtin_memcpy(event->payload,payload,64);
    event->consumed_ns=now;
    __sync_fetch_and_add(&count->consume_matches,1);
    return 0;
}

SEC("fexit/udp_recvmsg")
int BPF_PROG(copy_exit,struct sock *sk,struct msghdr *msg,size_t len,int flags,int *addr_len,int ret)
{
    /* Only pointer values and previously saved scalars: skb may be freed. */
    struct invocation key=invocation(sk);
    struct event *saved=bpf_map_lookup_elem(&pending,&key);
    if (!saved) return 0;
    struct event event=*saved;
    bpf_map_delete_elem(&pending,&key);
    __u32 zero=0;
    struct configuration *cfg=bpf_map_lookup_elem(&config,&zero);
    struct counters *count=bpf_map_lookup_elem(&stats,&zero);
    if (!cfg || !count || count->correlation_loss) return 0;
    event.exited_ns=bpf_ktime_get_ns();
    if (ret!=64 || !event.consumed_ns || event.exited_ns<event.consumed_ns || event.exited_ns>cfg->deadline_ns) {
        __sync_fetch_and_add(&count->rejected,1);return 0;
    }
    __u64 slot=__sync_fetch_and_add(&count->accepted,1);
    if (slot>=cfg->max_events || slot>=16) { __sync_fetch_and_add(&count->overflow,1);return 0; }
    __u32 index=slot;
    if (bpf_map_update_elem(&events,&index,&event,BPF_ANY)) __sync_fetch_and_add(&count->overflow,1);
    return 0;
}
char LICENSE[] SEC("license")="GPL";
