//! Explicit bounded in-memory observations; no operation retry or I/O.
use crate::audit_chain;
use serde_json::{json, Value};
const MAX:u64=(1u64<<63)-1;
const NAMES:[&str;3]=["poll_total","committed_hash","admitted_callback"];
#[derive(Clone,Copy)]
pub struct Stamp {wall:u64,process:u64,thread:u64}
fn clocks()->Option<Stamp> {
    Some(Stamp {wall:audit_chain::monotonic_ns()?,process:audit_chain::process_cpu_ns()?,thread:audit_chain::thread_cpu_ns()?})
}
fn finished()->Option<Stamp> {
    let thread=audit_chain::thread_cpu_ns()?;let process=audit_chain::process_cpu_ns()?;let wall=audit_chain::monotonic_ns()?;
    Some(Stamp {wall,process,thread})
}
#[derive(Debug,Clone,Copy,Default)]
struct Aggregate {count:u64,wall:u64,process:u64,thread:u64,max:u64}
#[derive(Debug,Default)]
pub struct Meter {phases:[Option<Aggregate>;3],reason:Option<&'static str>}
impl Meter {
    pub fn new()->Self {Self::default()}
    pub fn begin(&mut self)->Option<Stamp> {
        if self.reason.is_some(){return None;}
        let stamp=clocks();if stamp.is_none(){self.reason=Some("clock_error");}stamp
    }
    pub fn end(&mut self,phase:usize,start:Option<Stamp>) {
        if self.reason.is_some(){return;}
        let Some((start,end))=start.zip(finished()) else {self.reason=Some("clock_error");return;};
        self.record(phase,start,end);
    }
    fn record(&mut self,phase:usize,start:Stamp,end:Stamp) {
        let Some(wall)=end.wall.checked_sub(start.wall) else {self.reason=Some("clock_error");return;};
        let Some(process)=end.process.checked_sub(start.process) else {self.reason=Some("clock_error");return;};
        let Some(thread)=end.thread.checked_sub(start.thread) else {self.reason=Some("clock_error");return;};
        let mut a=self.phases[phase].unwrap_or_default();
        let add=|old:u64,n:u64|old.checked_add(n).filter(|v|*v<=MAX);
        let values=add(a.count,1).zip(add(a.wall,wall)).zip(add(a.process,process)).zip(add(a.thread,thread));
        let Some((((count,w),p),t))=values else {self.reason=Some("counter_overflow");return;};
        a=Aggregate {count,wall:w,process:p,thread:t,max:a.max.max(wall)};self.phases[phase]=Some(a);
    }
    pub fn snapshot(&self)->Value {
        let mut phases=serde_json::Map::new();
        for (name,value) in NAMES.iter().zip(self.phases) {
            phases.insert(name.to_string(),value.map(|a|json!({"count":a.count,"wall_ns":a.wall,
                "process_cpu_ns":a.process,"thread_cpu_ns":a.thread,"max_wall_ns":a.max})).unwrap_or(Value::Null));
        }
        json!({"schema_version":"azazel-edge/phase-cost/v1","complete":self.reason.is_none(),
            "invalid_reason":self.reason,"phases":phases})
    }
}
#[cfg(test)] mod tests {
    use super::*;
    fn stamp(n:u64)->Stamp {Stamp{wall:n,process:n,thread:n}}
    #[test] fn absent_and_sticky_faults_are_not_zero_costs() {
        let mut m=Meter::new();assert!(m.snapshot()["phases"]["poll_total"].is_null());
        m.record(0,stamp(1),stamp(5));assert_eq!(m.snapshot()["phases"]["poll_total"]["count"],1);
        m.record(1,stamp(5),stamp(1));assert_eq!(m.snapshot()["complete"],false);
        assert!(m.begin().is_none());assert_eq!(m.snapshot()["invalid_reason"],"clock_error");
    }
    #[test] fn arithmetic_never_wraps() {
        let mut m=Meter::new();m.phases[0]=Some(Aggregate{count:MAX,..Aggregate::default()});
        m.record(0,stamp(1),stamp(2));assert_eq!(m.snapshot()["invalid_reason"],"counter_overflow");
        assert_eq!(m.snapshot()["phases"]["poll_total"]["count"],MAX);
    }
    #[cfg(target_os="linux")]
    #[test] fn actual_linux_cpu_clocks_are_available_without_sidecar_reads() {
        let mut m=Meter::new();let start=m.begin();m.end(0,start);
        let value=m.snapshot();assert_eq!(value["complete"],true);
        assert_eq!(value["phases"]["poll_total"]["count"],1);
    }

}
