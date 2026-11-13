/* Fixed read-only AF_UNIX stream connect-return layer; not request admission. */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#if !defined(__TARGET_ARCH_arm64)
#error "Only frozen AArch64 profile supported"
#endif
struct configuration { __u64 pidns_device,pidns_inode,actor_start_ticks,started_ns,deadline_ns; __u32 actor_tgid,actor_uid,user_hz,max_events; };
struct observation { __u64 at_ns,start_ns,client_inode,peer_inode; __u32 tgid,tid,uid,peer_major,peer_minor,netns_inode; __s32 ret,addr_len; char path[108]; __u32 reserved; };
struct statistics { __u64 observed,emitted,overflow,identity_failure,read_failure; };
struct { __uint(type,BPF_MAP_TYPE_ARRAY); __uint(max_entries,1); __type(key,__u32); __type(value,struct configuration); } ingress_config __asm__("config") SEC(".maps");
struct { __uint(type,BPF_MAP_TYPE_ARRAY); __uint(max_entries,16); __type(key,__u32); __type(value,struct observation); } events SEC(".maps");
struct { __uint(type,BPF_MAP_TYPE_ARRAY); __uint(max_entries,1); __type(key,__u32); __type(value,struct statistics); } stats SEC(".maps");
SEC("fexit/unix_stream_connect") int authority_exit(__u64 *ctx) {
 __u32 z=0;struct configuration*c=bpf_map_lookup_elem(&ingress_config,&z);struct statistics*n=bpf_map_lookup_elem(&stats,&z);
 if(!c||!n||c->user_hz!=100||!c->max_events||c->max_events>16)return 0;
 __u64 now=bpf_ktime_get_ns();if(now<c->started_ns||now>c->deadline_ns)return 0;
 struct bpf_pidns_info ids={};if(bpf_get_ns_current_pid_tgid(c->pidns_device,c->pidns_inode,&ids,sizeof(ids))||ids.tgid!=c->actor_tgid)return 0;
 struct task_struct*t=(void*)bpf_get_current_task();__u64 start=BPF_CORE_READ(t,group_leader,start_boottime);
 __u64 ticks=start/1000000000*c->user_hz+(start%1000000000)*c->user_hz/1000000000;
 __u32 uid=BPF_CORE_READ(t,cred,uid.val),euid=BPF_CORE_READ(t,cred,euid.val);
 if(uid!=c->actor_uid||euid!=uid||!start||ticks!=c->actor_start_ticks){__sync_fetch_and_add(&n->identity_failure,1);return 0;}
 __u64 index=__sync_fetch_and_add(&n->observed,1);
 if(index>=c->max_events||index>=16){__sync_fetch_and_add(&n->overflow,1);return 0;}
 struct socket*socket=(void*)ctx[0];struct sockaddr_un*address=(void*)ctx[1];int len=ctx[2];__u16 family=0;
 struct observation e={.at_ns=now,.start_ns=start,.tgid=ids.tgid,.tid=ids.pid,.uid=uid,.ret=(__s32)ctx[4],.addr_len=len,.reserved=0};
 if(len<3||len>110||bpf_core_read(&family,sizeof(family),&address->sun_family)||family!=1){__sync_fetch_and_add(&n->read_failure,1);return 0;}
 __u32 path_bytes=len-2;
 if(bpf_probe_read_kernel(e.path,path_bytes,address->sun_path)){__sync_fetch_and_add(&n->read_failure,1);return 0;}
 int terminator=-1;
 #pragma unroll
 for(int i=0;i<108;i++)if(i<path_bytes&&e.path[i]==0&&terminator<0)terminator=i;
 if(terminator<1||terminator+3!=len||e.path[0]!='/'){__sync_fetch_and_add(&n->read_failure,1);return 0;}
 e.client_inode=BPF_CORE_READ(socket,file,f_inode,i_ino);struct sock*sk=BPF_CORE_READ(socket,sk);
 e.netns_inode=BPF_CORE_READ(sk,__sk_common.skc_net.net,ns.inum);
 if(!e.client_inode||!e.netns_inode)__sync_fetch_and_add(&n->read_failure,1);
 if(e.ret==0){
  struct sock*peer=BPF_CORE_READ((struct unix_sock*)sk,peer);struct dentry*d=BPF_CORE_READ((struct unix_sock*)peer,path.dentry);
  struct inode*i=BPF_CORE_READ(d,d_inode);e.peer_inode=BPF_CORE_READ(i,i_ino);__u32 dev=BPF_CORE_READ(i,i_sb,s_dev);
  e.peer_major=dev>>20;e.peer_minor=dev&0xfffff;
  if(!e.peer_inode)__sync_fetch_and_add(&n->read_failure,1);
 }
 __u32 key=index;if(bpf_map_update_elem(&events,&key,&e,BPF_ANY))__sync_fetch_and_add(&n->read_failure,1);
 else __sync_fetch_and_add(&n->emitted,1);
 return 0;
}
char LICENSE[] SEC("license")="GPL";
