# Azazel-Edge Benchmark Definitions

## D-1: Operational

The system is operational when all of the following are true:
1. `azazel-edge-web` is active.
2. `azazel-edge-control-daemon` is active.
3. `azazel-edge-suricata` is active.
4. `azazel-edge-opencanary` is active.
5. `GET /api/state` returns 200 and includes `posture`.
6. e-Paper shows a non-blank state.

## D-2: Detection time

Detection latency is measured from Suricata alert generation to Action Arbiter decision completion.
Software pipeline latency in this repository measures T2->T5 (EVE parse to Arbiter decision).

## D-3: Power consumption

Power is measured as steady-state DC draw at 5V rail using hardware power meter.
No `/proc` estimate is accepted.

## D-4: Breach rate

`breach_rate = breached_sessions / total_sessions * 100` where breach means expected attack detection was not achieved before session objective completion.

## Historical context: the 12% breach rate claim

The 12% figure has been cited in presentations as a breach-rate estimate.
The claim requires corpus, enforcement mode, and baseline clarification.
Until reproducibly measured, treat it as preliminary field observation.
The `azazel-bench accuracy` command provides reproducible software-path detection metrics.
