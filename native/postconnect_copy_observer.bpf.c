/* Passive protocol-copy layer. No userspace reads, target writes or branch claim. */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#if !defined(__TARGET_ARCH_arm64)
#error "Only frozen native AArch64 profile"
#endif
struct configuration {__u64 pidns_device,pidns_inode,server_start_ticks,actor_start_ticks,started_ns,deadline_ns;__u32 server_tgid,actor_tgid,user_hz,max_events;};
struct observation {__u64 entered_ns,exited_ns,start_ns,receiver_inode,peer_inode,endpoint_inode;__u32 role,tgid,tid,uid,euid,netns_inode,endpoint_major,endpoint_minor,flags,iter_type,data_source,skip,chunk,consumed,skb_len,data_len;__s32 ret;__u32 reserved;unsigned char data[256];};
struct statistics {__u64 selected_entries,pending_inserted,successful_copies,emitted,copy_failure,unsupported,read_failure,identity_failure,correlation_loss,overflow,inflight,unmatched_exit;};
struct {__uint(type,BPF_MAP_TYPE_ARRAY);__uint(max_entries,1);__type(key,__u32);__type(value,struct configuration);} copy_config __asm__("config") SEC(".maps");
struct {__uint(type,BPF_MAP_TYPE_HASH);__uint(max_entries,2);__type(key,__u64);__type(value,struct observation);} pending SEC(".maps");
struct {__uint(type,BPF_MAP_TYPE_HASH);__uint(max_entries,16);__type(key,__u32);__type(value,struct observation);} events SEC(".maps");
struct {__uint(type,BPF_MAP_TYPE_ARRAY);__uint(max_entries,1);__uint(map_flags,128);__type(key,__u32);__type(value,struct observation);} zero_template SEC(".maps");
struct {__uint(type,BPF_MAP_TYPE_ARRAY);__uint(max_entries,1);__type(key,__u32);__type(value,struct statistics);} stats SEC(".maps");
/* Every required read checks rc, including legitimate zero-valued metadata. */
#define READ(dst,src) do {if(bpf_core_read(&(dst),sizeof(dst),(src))){__sync_fetch_and_add(&n->read_failure,1);goto discard;}}while(0)
SEC("fentry/unix_stream_read_actor") int copy_entry(__u64*ctx){
 __u32 zero=0;struct configuration*c=bpf_map_lookup_elem(&copy_config,&zero);struct statistics*n=bpf_map_lookup_elem(&stats,&zero);if(!c||!n||n->correlation_loss||c->user_hz!=100||!c->max_events||c->max_events>16)return 0;
 __u64 now=bpf_ktime_get_ns();if(now<c->started_ns||now>c->deadline_ns)return 0;
 struct bpf_pidns_info ids={};if(bpf_get_ns_current_pid_tgid(c->pidns_device,c->pidns_inode,&ids,sizeof(ids)))return 0;
 __u32 role=ids.tgid==c->server_tgid?0:ids.tgid==c->actor_tgid?1:2;if(role==2)return 0;
 __sync_fetch_and_add(&n->selected_entries,1);if(ids.pid!=ids.tgid){__sync_fetch_and_add(&n->identity_failure,1);return 0;}
 __u64 key=bpf_get_current_pid_tgid();
 if(bpf_map_lookup_elem(&pending,&key)){__sync_fetch_and_add(&n->correlation_loss,1);return 0;}
 /* Kernel-initialized, program-readonly allocation template; never evidence. */
 struct observation*allocation=bpf_map_lookup_elem(&zero_template,&zero);
 if(!allocation||bpf_map_update_elem(&pending,&key,allocation,BPF_NOEXIST)){__sync_fetch_and_add(&n->correlation_loss,1);return 0;}
 __sync_fetch_and_add(&n->pending_inserted,1);__sync_fetch_and_add(&n->inflight,1);
 struct observation*e=bpf_map_lookup_elem(&pending,&key);if(!e){__sync_fetch_and_add(&n->correlation_loss,1);goto discard;}
 __builtin_memset(e,0,sizeof(*e));e->entered_ns=now;e->role=role;e->tgid=ids.tgid;e->tid=ids.pid;
 struct task_struct*t=(void*)bpf_get_current_task(),*leader=0;const struct cred*cred=0;READ(leader,&t->group_leader);READ(e->start_ns,&leader->start_boottime);READ(cred,&t->cred);READ(e->uid,&cred->uid.val);READ(e->euid,&cred->euid.val);
 if(!e->start_ns||e->start_ns/10000000!=(role==0?c->server_start_ticks:c->actor_start_ticks)||e->uid||e->euid){__sync_fetch_and_add(&n->identity_failure,1);goto discard;}
 struct sk_buff*skb=(void*)ctx[0];int skip=ctx[1],chunk=ctx[2];struct unix_stream_read_state*s=(void*)ctx[3];
 int flags=0;READ(flags,&s->flags);e->flags=flags;READ(e->consumed,&((struct unix_skb_parms*)&skb->cb)->consumed);READ(e->skb_len,&skb->len);READ(e->data_len,&skb->data_len);
 if(skip<0||chunk<1||chunk>256||(flags!=0&&flags!=64)||e->data_len||e->consumed>e->skb_len||(__u32)skip>e->skb_len-e->consumed||(__u32)chunk>e->skb_len-e->consumed-(__u32)skip){__sync_fetch_and_add(&n->unsupported,1);goto discard;}
 e->skip=skip;e->chunk=chunk;struct socket*socket=0;struct msghdr*msg=0;READ(socket,&s->socket);READ(msg,&s->msg);if(!socket||!msg){__sync_fetch_and_add(&n->read_failure,1);goto discard;}
 __u8 iter_type=0;bool source=false;__u64 count=0;READ(iter_type,&msg->msg_iter.iter_type);READ(source,&msg->msg_iter.data_source);READ(count,&msg->msg_iter.count);e->iter_type=iter_type;e->data_source=source;
 if(iter_type>1||source||count<(__u32)chunk){__sync_fetch_and_add(&n->unsupported,1);goto discard;}
 struct sock*sk=0,*peer=0;__u16 family=0,type=0;READ(sk,&socket->sk);READ(family,&sk->__sk_common.skc_family);READ(type,&sk->sk_type);
 if(family!=1||type!=1){__sync_fetch_and_add(&n->unsupported,1);goto discard;}READ(peer,&((struct unix_sock*)sk)->peer);
 struct socket*peer_socket=0;struct file*file=0,*peer_file=0;struct inode*inode=0,*peer_inode=0;READ(peer_socket,&peer->sk_socket);READ(file,&socket->file);READ(peer_file,&peer_socket->file);READ(inode,&file->f_inode);READ(peer_inode,&peer_file->f_inode);READ(e->receiver_inode,&inode->i_ino);READ(e->peer_inode,&peer_inode->i_ino);
 struct net*net=0;READ(net,&sk->__sk_common.skc_net.net);READ(e->netns_inode,&net->ns.inum);
 struct unix_sock*bound=(void*)(role==0?sk:peer);struct dentry*dentry=0;struct inode*endpoint=0;struct super_block*sb=0;__u32 device=0;READ(dentry,&bound->path.dentry);READ(endpoint,&dentry->d_inode);READ(e->endpoint_inode,&endpoint->i_ino);READ(sb,&endpoint->i_sb);READ(device,&sb->s_dev);e->endpoint_major=device>>20;e->endpoint_minor=device&0xfffff;
 if(!e->receiver_inode||!e->peer_inode||!e->endpoint_inode||!e->netns_inode){__sync_fetch_and_add(&n->read_failure,1);goto discard;}
 unsigned char*data=0;READ(data,&skb->data);
 #pragma unroll
 for(int i=0;i<256;i++)if(i<chunk&&bpf_probe_read_kernel(&e->data[i],1,data+e->consumed+(__u32)skip+i)){__sync_fetch_and_add(&n->read_failure,1);goto discard;}
 return 0;
 discard:
 __sync_fetch_and_add(&n->correlation_loss,1);
 if(bpf_map_delete_elem(&pending,&key))__sync_fetch_and_add(&n->correlation_loss,1);else __sync_fetch_and_sub(&n->inflight,1);return 0;
}
SEC("fexit/unix_stream_read_actor") int copy_exit(__u64*ctx){
 __u32 zero=0;struct configuration*c=bpf_map_lookup_elem(&copy_config,&zero);struct statistics*n=bpf_map_lookup_elem(&stats,&zero);if(!c||!n)return 0;
 struct bpf_pidns_info ids={};if(bpf_get_ns_current_pid_tgid(c->pidns_device,c->pidns_inode,&ids,sizeof(ids))||ids.pid!=ids.tgid||(ids.tgid!=c->server_tgid&&ids.tgid!=c->actor_tgid))return 0;
 __u64 key=bpf_get_current_pid_tgid();struct observation*e=bpf_map_lookup_elem(&pending,&key);
 if(!e){__sync_fetch_and_add(&n->unmatched_exit,1);__sync_fetch_and_add(&n->correlation_loss,1);return 0;}
 if(!n->correlation_loss){e->ret=(__s32)ctx[4];e->exited_ns=bpf_ktime_get_ns();if(e->ret==e->chunk&&e->exited_ns>=e->entered_ns&&e->exited_ns<=c->deadline_ns){__u64 index=__sync_fetch_and_add(&n->successful_copies,1);if(index<c->max_events&&index<16){__u32 k=index;if(bpf_map_update_elem(&events,&k,e,BPF_NOEXIST))__sync_fetch_and_add(&n->correlation_loss,1);else __sync_fetch_and_add(&n->emitted,1);}else __sync_fetch_and_add(&n->overflow,1);}else __sync_fetch_and_add(&n->copy_failure,1);}
 if(bpf_map_delete_elem(&pending,&key))__sync_fetch_and_add(&n->correlation_loss,1);else __sync_fetch_and_sub(&n->inflight,1);return 0;
}
char LICENSE[] SEC("license")="GPL";
