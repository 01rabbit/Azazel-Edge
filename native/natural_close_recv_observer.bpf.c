/* Passive native recvfrom and protocol-copy facts. No target writes or user reads. */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#if !defined(__TARGET_ARCH_arm64)
#error "Only frozen native AArch64 profile"
#endif
struct configuration {__u64 pidns_device,pidns_inode,server_start_ticks,actor_start_ticks,started_ns,deadline_ns;__u32 server_tgid,actor_tgid,user_hz,max_events,server_uid,actor_uid;};
struct observation {__u64 token,entered_ns,exited_ns,start_ns,receiver_inode,peer_inode,endpoint_inode,requested_len;__s64 ret;__u32 kind,role,tgid,tid,uid,euid,netns_inode,fd,flags,iter_type,data_source,skip,chunk,consumed,skb_len,data_len,endpoint_major,endpoint_minor,peer_status,endpoint_status,reserved,reserved2;unsigned char data[256];};
struct statistics {__u64 selected_entries,pending_inserted,successful_copies,emitted,copy_failure,unsupported,read_failure,identity_failure,correlation_loss,overflow,inflight,unmatched_exit,recv_selected,recv_completed,recv_inflight,unmatched_recv_exit;};
struct {__uint(type,BPF_MAP_TYPE_ARRAY);__uint(max_entries,1);__type(key,__u32);__type(value,struct configuration);} recv_config __asm__("config") SEC(".maps");
struct {__uint(type,BPF_MAP_TYPE_HASH);__uint(max_entries,2);__type(key,__u64);__type(value,struct observation);} recv_pending SEC(".maps");
struct {__uint(type,BPF_MAP_TYPE_HASH);__uint(max_entries,2);__type(key,__u64);__type(value,struct observation);} copy_pending SEC(".maps");
struct {__uint(type,BPF_MAP_TYPE_HASH);__uint(max_entries,32);__type(key,__u32);__type(value,struct observation);} events SEC(".maps");
struct {__uint(type,BPF_MAP_TYPE_ARRAY);__uint(max_entries,1);__uint(map_flags,128);__type(key,__u32);__type(value,struct observation);} zero_template SEC(".maps");
struct {__uint(type,BPF_MAP_TYPE_ARRAY);__uint(max_entries,1);__type(key,__u32);__type(value,struct statistics);} stats SEC(".maps");
static __always_inline int publish(struct observation*e,struct configuration*c,struct statistics*n){
 __u64 index=__sync_fetch_and_add(&n->emitted,1);if(index>=c->max_events||index>=32){__sync_fetch_and_add(&n->overflow,1);return -1;}
 __u32 k=index;if(bpf_map_update_elem(&events,&k,e,BPF_NOEXIST)){__sync_fetch_and_add(&n->correlation_loss,1);return -1;}return 0;
}
static __always_inline int identity(struct observation*e,struct configuration*c,struct statistics*n){
 struct bpf_pidns_info ids={};if(bpf_get_ns_current_pid_tgid(c->pidns_device,c->pidns_inode,&ids,sizeof(ids)))return -1;
 __u32 role=ids.tgid==c->server_tgid?0:ids.tgid==c->actor_tgid?1:2;if(role==2)return -1;
 if(ids.pid!=ids.tgid){__sync_fetch_and_add(&n->identity_failure,1);return -1;}
 e->role=role;e->tgid=ids.tgid;e->tid=ids.pid;
 struct task_struct*t=(void*)bpf_get_current_task(),*leader=0;const struct cred*cred=0;
 if(bpf_core_read(&leader,sizeof(leader),&t->group_leader)||!leader||bpf_core_read(&e->start_ns,sizeof(e->start_ns),&leader->start_boottime)||bpf_core_read(&cred,sizeof(cred),&t->cred)||!cred||bpf_core_read(&e->uid,sizeof(e->uid),&cred->uid.val)||bpf_core_read(&e->euid,sizeof(e->euid),&cred->euid.val)){__sync_fetch_and_add(&n->read_failure,1);return -1;}
 if(!e->start_ns||e->start_ns/10000000!=(role==0?c->server_start_ticks:c->actor_start_ticks)||e->uid!=(role==0?c->server_uid:c->actor_uid)||e->euid!=(role==0?c->server_uid:c->actor_uid)){__sync_fetch_and_add(&n->identity_failure,1);return -1;}return 0;
}
/* Optional CURRENT identity is independent of required own-socket facts. */
static __always_inline void optional_identity(struct observation*e,struct sock*sk,struct statistics*n){
 struct sock*peer=0;struct socket*ps=0;struct file*pf=0;struct inode*pi=0;
 e->peer_inode=0;e->endpoint_inode=0;e->endpoint_major=0;e->endpoint_minor=0;e->peer_status=2;e->endpoint_status=2;
 if(bpf_core_read(&peer,sizeof(peer),&((struct unix_sock*)sk)->peer)){e->peer_status=3;__sync_fetch_and_add(&n->read_failure,1);}
 else if(peer){
  if(bpf_core_read(&ps,sizeof(ps),&peer->sk_socket)){e->peer_status=3;__sync_fetch_and_add(&n->read_failure,1);}
  else if(ps){
   if(bpf_core_read(&pf,sizeof(pf),&ps->file)){e->peer_status=3;__sync_fetch_and_add(&n->read_failure,1);}
   else if(pf){
    if(bpf_core_read(&pi,sizeof(pi),&pf->f_inode)){e->peer_status=3;__sync_fetch_and_add(&n->read_failure,1);}
    else if(pi){if(bpf_core_read(&e->peer_inode,sizeof(e->peer_inode),&pi->i_ino)){e->peer_status=3;__sync_fetch_and_add(&n->read_failure,1);}else if(e->peer_inode)e->peer_status=1;}
   }
  }
 }
 struct unix_sock*bound=(void*)(e->role==0?sk:peer);struct dentry*d=0;struct inode*i=0;struct super_block*sb=0;__u32 device=0;
 if(!bound)return;
 if(bpf_core_read(&d,sizeof(d),&bound->path.dentry)){e->endpoint_status=3;goto optional_error;}if(!d)return;
 if(bpf_core_read(&i,sizeof(i),&d->d_inode)){e->endpoint_status=3;goto optional_error;}if(!i)return;
 if(bpf_core_read(&e->endpoint_inode,sizeof(e->endpoint_inode),&i->i_ino)||bpf_core_read(&sb,sizeof(sb),&i->i_sb)){e->endpoint_status=3;goto optional_error;}if(!sb||!e->endpoint_inode){e->endpoint_inode=0;return;}
 if(bpf_core_read(&device,sizeof(device),&sb->s_dev)){e->endpoint_status=3;goto optional_error;}
 e->endpoint_major=device>>20;e->endpoint_minor=device&0xfffff;e->endpoint_status=1;return;
 optional_error:e->endpoint_inode=0;e->endpoint_major=0;e->endpoint_minor=0;__sync_fetch_and_add(&n->read_failure,1);
}
static __always_inline int own_socket(struct observation*e,struct socket*s,struct statistics*n){
 struct sock*sk=0;struct file*f=0;struct inode*i=0;struct net*net=0;__u16 family=0,type=0;
 if(!s||bpf_core_read(&sk,sizeof(sk),&s->sk)||!sk||bpf_core_read(&f,sizeof(f),&s->file)||!f||bpf_core_read(&i,sizeof(i),&f->f_inode)||!i||bpf_core_read(&e->receiver_inode,sizeof(e->receiver_inode),&i->i_ino)||bpf_core_read(&family,sizeof(family),&sk->__sk_common.skc_family)||bpf_core_read(&type,sizeof(type),&sk->sk_type)||bpf_core_read(&net,sizeof(net),&sk->__sk_common.skc_net.net)||!net||bpf_core_read(&e->netns_inode,sizeof(e->netns_inode),&net->ns.inum)){__sync_fetch_and_add(&n->read_failure,1);return -1;}
 if(family!=1||type!=1||!e->receiver_inode||!e->netns_inode){__sync_fetch_and_add(&n->unsupported,1);return -1;}optional_identity(e,sk,n);return 0;
}
#define REQUIRED(dst,src) do {if(bpf_core_read(&(dst),sizeof(dst),(src))){__sync_fetch_and_add(&n->read_failure,1);goto discard;}}while(0)
#define CONFIG() __u32 zero=0;struct configuration*c=bpf_map_lookup_elem(&recv_config,&zero);struct statistics*n=bpf_map_lookup_elem(&stats,&zero);if(!c||!n||c->server_uid!=65534||c->actor_uid!=65534||c->user_hz!=100||!c->max_events||c->max_events>32)return 0
SEC("fentry/__arm64_sys_recvfrom") int recv_entry(__u64*ctx){
 CONFIG();__u64 now=bpf_ktime_get_ns();if(now<c->started_ns||now>c->deadline_ns||n->correlation_loss)return 0;
 struct bpf_pidns_info ids={};if(bpf_get_ns_current_pid_tgid(c->pidns_device,c->pidns_inode,&ids,sizeof(ids))||(ids.tgid!=c->server_tgid&&ids.tgid!=c->actor_tgid))return 0;
 __sync_fetch_and_add(&n->recv_selected,1);__u64 key=bpf_get_current_pid_tgid();if(bpf_map_lookup_elem(&recv_pending,&key)){__sync_fetch_and_add(&n->correlation_loss,1);return 0;}
 struct observation*z=bpf_map_lookup_elem(&zero_template,&zero);if(!z||bpf_map_update_elem(&recv_pending,&key,z,BPF_NOEXIST)){__sync_fetch_and_add(&n->correlation_loss,1);return 0;}__sync_fetch_and_add(&n->recv_inflight,1);
 struct observation*e=bpf_map_lookup_elem(&recv_pending,&key);if(!e){__sync_fetch_and_add(&n->correlation_loss,1);goto discard;}
 e->token=e->entered_ns=now;e->kind=0;if(identity(e,c,n))goto discard;
 const struct pt_regs*r=(void*)ctx[0];__u64 fd=0,length=0,flags=0,pstate=0;REQUIRED(fd,&r->regs[0]);REQUIRED(length,&r->regs[2]);REQUIRED(flags,&r->regs[3]);REQUIRED(pstate,&r->pstate);
 if(fd>4095||!length||length>65536||flags||(pstate&31)){__sync_fetch_and_add(&n->unsupported,1);goto discard;}e->fd=fd;e->requested_len=length;e->flags=flags;
 struct task_struct*t=(void*)bpf_get_current_task();struct files_struct*files=0;struct fdtable*fdt=0;struct file**fds=0,*f=0,*sf=0;struct inode*i=0;struct socket*s=0;__u32 max=0;__u16 mode=0;
 REQUIRED(files,&t->files);if(!files)goto read_error;REQUIRED(fdt,&files->fdt);if(!fdt)goto read_error;REQUIRED(max,&fdt->max_fds);if(fd>=max){__sync_fetch_and_add(&n->unsupported,1);goto discard;}REQUIRED(fds,&fdt->fd);if(!fds)goto read_error;REQUIRED(f,&fds[fd]);if(!f)goto read_error;REQUIRED(i,&f->f_inode);if(!i)goto read_error;REQUIRED(mode,&i->i_mode);if((mode&0170000)!=0140000){__sync_fetch_and_add(&n->unsupported,1);goto discard;}REQUIRED(s,&f->private_data);if(!s)goto read_error;REQUIRED(sf,&s->file);if(sf!=f){__sync_fetch_and_add(&n->identity_failure,1);goto discard;}if(own_socket(e,s,n))goto discard;publish(e,c,n);return 0;
 read_error:__sync_fetch_and_add(&n->read_failure,1);
 discard:__sync_fetch_and_add(&n->correlation_loss,1);if(bpf_map_delete_elem(&recv_pending,&key))__sync_fetch_and_add(&n->correlation_loss,1);else __sync_fetch_and_sub(&n->recv_inflight,1);return 0;
}
SEC("fentry/unix_stream_read_actor") int copy_entry(__u64*ctx){
 CONFIG();__u64 now=bpf_ktime_get_ns();if(now<c->started_ns||now>c->deadline_ns||n->correlation_loss)return 0;
 __u64 key=bpf_get_current_pid_tgid();struct observation*call=bpf_map_lookup_elem(&recv_pending,&key);if(!call)return 0;
 __sync_fetch_and_add(&n->selected_entries,1);if(bpf_map_lookup_elem(&copy_pending,&key)||bpf_map_update_elem(&copy_pending,&key,call,BPF_NOEXIST)){__sync_fetch_and_add(&n->correlation_loss,1);return 0;}__sync_fetch_and_add(&n->pending_inserted,1);__sync_fetch_and_add(&n->inflight,1);
 struct observation*e=bpf_map_lookup_elem(&copy_pending,&key);if(!e){__sync_fetch_and_add(&n->correlation_loss,1);goto discard;}e->kind=1;e->entered_ns=now;e->exited_ns=0;e->ret=0;if(identity(e,c,n))goto discard;
 struct sk_buff*skb=(void*)ctx[0];int skip=ctx[1],chunk=ctx[2];struct unix_stream_read_state*s=(void*)ctx[3];int flags=0;
 REQUIRED(flags,&s->flags);e->flags=flags;REQUIRED(e->consumed,&((struct unix_skb_parms*)&skb->cb)->consumed);REQUIRED(e->skb_len,&skb->len);REQUIRED(e->data_len,&skb->data_len);
 if(skip<0||chunk<1||chunk>256||(flags!=0&&flags!=64)||e->data_len||e->consumed>e->skb_len||(__u32)skip>e->skb_len-e->consumed||(__u32)chunk>e->skb_len-e->consumed-(__u32)skip){__sync_fetch_and_add(&n->unsupported,1);goto discard;}e->skip=skip;e->chunk=chunk;
 struct socket*socket=0;struct msghdr*msg=0;REQUIRED(socket,&s->socket);REQUIRED(msg,&s->msg);if(!socket||!msg){__sync_fetch_and_add(&n->read_failure,1);goto discard;}
 __u8 iter=0;bool source=false;__u64 count=0;REQUIRED(iter,&msg->msg_iter.iter_type);REQUIRED(source,&msg->msg_iter.data_source);REQUIRED(count,&msg->msg_iter.count);e->iter_type=iter;e->data_source=source;if(iter>1||source||count<(__u32)chunk){__sync_fetch_and_add(&n->unsupported,1);goto discard;}
 if(own_socket(e,socket,n))goto discard;if(e->receiver_inode!=call->receiver_inode||e->netns_inode!=call->netns_inode||e->start_ns!=call->start_ns||e->role!=call->role){__sync_fetch_and_add(&n->identity_failure,1);goto discard;}
 unsigned char*data=0;REQUIRED(data,&skb->data);
 #pragma unroll
 for(int j=0;j<256;j++)if(j<chunk&&bpf_probe_read_kernel(&e->data[j],1,data+e->consumed+(__u32)skip+j)){__sync_fetch_and_add(&n->read_failure,1);goto discard;}return 0;
 discard:__sync_fetch_and_add(&n->correlation_loss,1);if(bpf_map_delete_elem(&copy_pending,&key))__sync_fetch_and_add(&n->correlation_loss,1);else __sync_fetch_and_sub(&n->inflight,1);return 0;
}
SEC("fexit/unix_stream_read_actor") int copy_exit(__u64*ctx){
 CONFIG();__u64 key=bpf_get_current_pid_tgid();struct observation*e=bpf_map_lookup_elem(&copy_pending,&key);if(!e)return 0;
 e->ret=(__s32)ctx[4];e->exited_ns=bpf_ktime_get_ns();if(!n->correlation_loss&&e->ret==e->chunk&&e->exited_ns>=e->entered_ns&&e->exited_ns<=c->deadline_ns){__sync_fetch_and_add(&n->successful_copies,1);publish(e,c,n);}else __sync_fetch_and_add(&n->copy_failure,1);
 if(bpf_map_delete_elem(&copy_pending,&key))__sync_fetch_and_add(&n->correlation_loss,1);else __sync_fetch_and_sub(&n->inflight,1);return 0;
}
SEC("fexit/__arm64_sys_recvfrom") int recv_exit(__u64*ctx){
 CONFIG();struct bpf_pidns_info ids={};if(bpf_get_ns_current_pid_tgid(c->pidns_device,c->pidns_inode,&ids,sizeof(ids))||(ids.tgid!=c->server_tgid&&ids.tgid!=c->actor_tgid))return 0;
 __u64 key=bpf_get_current_pid_tgid();struct observation*e=bpf_map_lookup_elem(&recv_pending,&key);if(!e){__sync_fetch_and_add(&n->unmatched_recv_exit,1);return 0;}
 e->kind=2;e->peer_inode=0;e->endpoint_inode=0;e->endpoint_major=0;e->endpoint_minor=0;e->peer_status=0;e->endpoint_status=0;e->ret=(__s64)ctx[1];e->exited_ns=bpf_ktime_get_ns();if(e->exited_ns>=e->entered_ns&&e->exited_ns<=c->deadline_ns){__sync_fetch_and_add(&n->recv_completed,1);publish(e,c,n);}else __sync_fetch_and_add(&n->copy_failure,1);
 if(bpf_map_delete_elem(&recv_pending,&key))__sync_fetch_and_add(&n->correlation_loss,1);else __sync_fetch_and_sub(&n->recv_inflight,1);return 0;
}
char LICENSE[] SEC("license")="GPL";
