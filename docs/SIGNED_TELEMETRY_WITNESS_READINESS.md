# Bounded initial witness readiness

Only the manual lab's initial pre-Popen phase may wait for a witness listener.
The existing two-second / 101-sample bounds are unchanged. Later-phase changes,
replacement, malformed rows and unknown observations remain fatal.

One additional pending state is recognized: an unnamed STREAM socket becomes the
expected abstract listener with the same Num, reference count, protocol, type,
state and inode. Only flags and the expected name may change. The witness must
uniquely hold the same FD/inode, with a matching FD readback. Every normal final
PID/start, unit, profile, namespace and file fence must still complete.

This transition is never a successful readiness proof. A private in-memory
candidate binds the immediately following complete stable sample to the same
inode, FD and name. Disappearance, replacement, FD change or another transition
fails. No caller JSON can supply that candidate. The public successful binding
shape, actor permissions, authentication and offline behavior are unchanged.

## Retained normal controls

The earlier source `84a04189373c44c8bb9bd245806a3dad621401fa` refused before
initialization when socket inode 12644 / PID 2233 / FD3 changed from unnamed
STREAM to the expected listener during sampling. Its final identity fence did
not complete, so the original refusal remains correct. The failed VM was stopped
and its scope was never repaired or retried. Private evidence SHA256:
`3d31462c9ac4a447b72c051c9f7654524bc7bf288d28f7fa97a81226023fabaa`
(552,960 bytes). The recorded rows match the new strict transition predicate;
this does not retroactively turn that failure into a pass.

A new fresh VM executed unchanged commissioning at corrected source
`61e905bd2e8a4adb186416489b411575c3618815`, source archive SHA256
`462c37714829a54d5f6efa0db6baef8a69f810725c18d8aadfc740701b732da3`, boot
`55a4f136-79a4-48f1-87a7-bc0d0a832a03`. Genuine initialization, registered
prepare/start/end source, LIVE input readiness and natural terminal completed.
EOF was 2308 bytes, journal sequence 10 and final witness anchor 11. Init/LIVE
proofs retained cap0, NNP, the enforcing role, private proc and three matching
FIFO descriptors. One original all-four-coverage sample and an empty finalize
were retained, with no provider actions or Outcomes.

Seven actor groups were empty, three namespaces absent, parent networking
unchanged, and no core process remained. Twelve Root children and the LIVE client
were reaped without forcing. The VM was stopped. Private evidence SHA256:
`1b210a317010c65b9ff0f694d897153b928e15a7288f2ee36e6771d7e29f942d`
(1,013,760 bytes), excluding private signing keys.

**The new transition branch was not observed in this successful VM run.** It
exercised the existing absent-listener wait followed by a stable listener. The
new transition's exact arithmetic, final fences and cross-sample replacement
refusals have focused software coverage; no branch-specific runtime or reliability
claim follows. Offline UID0/cap0 integration passed 268 checks. This is connection
commissioning, not a workload comparison, safety-count receipt, efficacy result
or production admission. The four-VM comparison remains withheld.
