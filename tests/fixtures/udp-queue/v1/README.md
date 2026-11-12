# Frozen UDP socket queue admission cases

Synthetic event/parser/signature fixtures are NOT real kernel observations.
Actual Linux tests must attach both BPF programs and send real loopback UDP to a
separate unprivileged target. Retain frozen config/object/plan hashes BEFORE attach;
report hashes AFTER capture. No repaired pins or simulated kernel successes.
Positive means a full matching entry snapshot correlated to the SAME invocation's
successful enqueue return. It does not prove checksum validity, continued queue
residence or application receipt. No events, filtered packets and loss remain null.
The target's later receive is only a separate nonconsumption control, not the sensor.
MSG_PEEK/pidfd socket reads are excluded: peeking can discard invalid datagrams.
