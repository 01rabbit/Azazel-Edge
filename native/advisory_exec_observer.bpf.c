/* Passive native64 AArch64 syscall ENTRY observations; never an effect proof. */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#if !defined(__TARGET_ARCH_arm64)
#error "Only the frozen native64 AArch64 profile is supported"
#endif
struct configuration { __u64 pidns_device,pidns_inode,actor_start_ticks,started_ns,deadline_ns; __u32 actor_tgid,actor_uid,user_hz,max_events; };
struct calibration { __u64 calibrated_at_ns,start_boottime_ns; __u32 tgid,tid,uid,native_abi; };
struct observation { __u64 monotonic_ns,start_boottime_ns,syscall_id; __u32 tgid,tid,uid,event_kind,native_abi,reserved; };
struct statistics { __u64 observed,emitted,overflow,identity_failure,abi_rejected,uncalibrated,creation_attempts,calibration_conflict; };
struct { __uint(type,BPF_MAP_TYPE_ARRAY); __uint(max_entries,1); __type(key,__u32); __type(value,struct configuration); } exec_config __asm__("config") SEC(".maps");
struct { __uint(type,BPF_MAP_TYPE_ARRAY); __uint(max_entries,1); __type(key,__u32); __type(value,struct calibration); } state SEC(".maps");
struct { __uint(type,BPF_MAP_TYPE_ARRAY); __uint(max_entries,64); __type(key,__u32); __type(value,struct observation); } events SEC(".maps");
struct { __uint(type,BPF_MAP_TYPE_ARRAY); __uint(max_entries,1); __type(key,__u32); __type(value,struct statistics); } stats SEC(".maps");
SEC("raw_tp/sys_enter") int advisory_enter(struct bpf_raw_tracepoint_args *ctx) {
 __u32 zero=0;
 struct configuration *c=bpf_map_lookup_elem(&exec_config,&zero);
 struct calibration *s=bpf_map_lookup_elem(&state,&zero);
 struct statistics *n=bpf_map_lookup_elem(&stats,&zero);
 if(!c||!s||!n||c->user_hz!=100||!c->max_events||c->max_events>64)return 0;
 __u64 now=bpf_ktime_get_ns();if(now<c->started_ns||now>c->deadline_ns)return 0;
 __u64 nr=ctx->args[1];__u32 kind;
 if(nr==172)kind=0;else if(nr==221||nr==281)kind=1;else if(nr==220||nr==435)kind=2;else return 0;
 struct bpf_pidns_info ids={};
 if(bpf_get_ns_current_pid_tgid(c->pidns_device,c->pidns_inode,&ids,sizeof(ids))||ids.tgid!=c->actor_tgid)return 0;
 struct task_struct *task=(void *)bpf_get_current_task();
 __u64 start=BPF_CORE_READ(task,group_leader,start_boottime);
 __u64 ticks=start/1000000000*c->user_hz+(start%1000000000)*c->user_hz/1000000000;
 __u32 uid=BPF_CORE_READ(task,cred,uid.val),euid=BPF_CORE_READ(task,cred,euid.val);
 if(uid!=c->actor_uid||euid!=uid||!start||ticks!=c->actor_start_ticks){__sync_fetch_and_add(&n->identity_failure,1);return 0;}
 struct pt_regs *regs=(void *)ctx->args[0];__u64 pstate=0;
 if(bpf_core_read(&pstate,sizeof(pstate),&regs->pstate)||(pstate&0x1f)){__sync_fetch_and_add(&n->abi_rejected,1);return 0;}
 if(s->start_boottime_ns && s->start_boottime_ns!=start){__sync_fetch_and_add(&n->calibration_conflict,1);return 0;}
 if(kind==0){
  __u64 old=__sync_val_compare_and_swap(&s->start_boottime_ns,0,start);
  if(old){if(old!=start)__sync_fetch_and_add(&n->calibration_conflict,1);return 0;}
  s->tgid=ids.tgid;s->tid=ids.pid;s->uid=uid;s->native_abi=1;
  __sync_lock_test_and_set(&s->calibrated_at_ns,now);
 }else{
  if(kind==2)__sync_fetch_and_add(&n->creation_attempts,1);
  if(!s->calibrated_at_ns){__sync_fetch_and_add(&n->uncalibrated,1);return 0;}
 }
 struct observation e={.monotonic_ns=now,.start_boottime_ns=start,.syscall_id=nr,.tgid=ids.tgid,.tid=ids.pid,.uid=uid,.event_kind=kind,.native_abi=1,.reserved=0};
 __u64 index=__sync_fetch_and_add(&n->observed,1);
 if(index>=c->max_events||index>=64){__sync_fetch_and_add(&n->overflow,1);return 0;}
 __u32 key=index;
 if(bpf_map_update_elem(&events,&key,&e,BPF_ANY))__sync_fetch_and_add(&n->overflow,1);
 else __sync_fetch_and_add(&n->emitted,1);
 return 0;
}
char LICENSE[] SEC("license")="GPL";
