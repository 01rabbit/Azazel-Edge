# Azazel-Edge Benchmark Results

Generated: 2026-05-14T12:57:24.551930+00:00  
Hardware: software-only  
Benchmark mode: software-only-eve-replay  
Claim scope: deterministic pipeline regression  
Commit: f59bd53  
Test suite baseline: see CI and release notes

---

## B-1: Software Pipeline Latency (T2->T5)

| Stage | Mean (ms) | Median (ms) | p95 (ms) | p99 (ms) |
|---|---|---|---|---|
| T2_eve_parse | 0.006 | 0.005 | 0.007 | 0.032 |
| T3_evidence_dispatch | 0.018 | 0.016 | 0.027 | 0.082 |
| T4_evaluators | 0.2 | 0.191 | 0.256 | 0.369 |
| T5_arbiter | 0.013 | 0.012 | 0.015 | 0.06 |

Total pipeline p95: 0.305 ms

## B-3: Detection Accuracy

- Detection rate: 100.0%
- Breach rate (software): 0.0%
- Total sessions: 5

| Session | Category | Technique | Detected | Action | Breach |
|---|---|---|---|---|---|
| arp_spoof_01 | arp_spoof | T1557 | True | throttle | False |
| c2_beacon_01 | c2_beacon | T1071 | True | throttle | False |
| dns_exfil_01 | dns_exfil | T1048 | True | throttle | False |
| phishing_01 | phishing | T1566 | True | throttle | False |
| port_scan_01 | port_scan | T1046 | True | throttle | False |

## Notes

- This suite validates deterministic pipeline behavior under software-only EVE replay.
- It does not claim inline forwarding throughput, live Suricata capture capacity, nftables/tc enforcement latency, OpenCanary redirect realism, or co-located Ollama/Mattermost performance.
- Power and startup hardware benchmarks must be run on Raspberry Pi hardware-in-the-loop plans.
