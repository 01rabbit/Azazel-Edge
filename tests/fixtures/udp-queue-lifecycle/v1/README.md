# Frozen UDP queue lifecycle acceptance

Actual Linux tests must use real BPF links/maps and real UDP traffic. Synthetic
libbpf failure tests are separate. A published report means capture returned signed
bytes and the harness sealed/pinned them before any subsequent fault. Kernel map
samples taken by the harness are NOT a published signed report.

SIGKILL before publication yields no report and unknown missing interval, even if
a volatile map briefly held a real event. Do not reconstruct or sign a replacement.
SIGSTOP pauses userspace, not attached BPF; the kernel's absolute deadline still
applies. Never describe SIGSTOP alone as proof of a kernel observation gap.
Linux 6.8 tracing links reject BPF_LINK_DETACH with EOPNOTSUPP. Owned link-FD loss
is the actual fault used here, not a simulated successful unsupported detach.
Re-reading a sealed report proves historical evidence, never a new measurement.
