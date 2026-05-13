# Azazel-Edge Benchmark Results

Generated: 2026-05-13T10:58:32.091354+00:00  
Hardware: TBD  
Commit: eea897b  
Test suite baseline: 328 passed, 62 subtests passed

---

## B-1: Software Pipeline Latency (T2->T5)

| Stage | Mean (ms) | Median (ms) | p95 (ms) | p99 (ms) |
|---|---|---|---|---|
| T2_eve_parse | 0.003 | 0.003 | 0.004 | 0.007 |
| T3_evidence_dispatch | 0.01 | 0.01 | 0.013 | 0.026 |
| T4_evaluators | 0.117 | 0.117 | 0.131 | 0.171 |
| T5_arbiter | 0.008 | 0.008 | 0.01 | 0.021 |

Total pipeline p95: 0.158 ms

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

- Power and startup hardware benchmarks must be run on Raspberry Pi and updated manually.
- The 12% breach-rate statement remains preliminary until reproduced with hardware validation.
