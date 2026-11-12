# Frozen collection acceptance cases v1

These cases fix the acceptance boundary before implementation. They reuse the
signed synthetic observation recipes frozen for PR #585; no real sensor claim.
For diagnostic cases the named count applies to `protected_escape`; no category
has qualified safety counts. All returned authority flags remain false.
`rejected` means SafetyCollectionError and NO evaluation result or count.
`os-boundary` means a real separate-UID write attempt fails with PermissionError.

Build the valid scenario and sign its rows before retaining checkpoint bytes and
external digests. Apply corruption only afterwards. Never repair a negative by
re-pinning enrollment/checkpoint or regenerating expected heads. For tests of a
semantically invalid but genuinely enrolled configuration (e.g. wrong reader,
scope, capture), create that named configuration explicitly before its external
pin, then expect rejection. This is not permission to repair post-pin corruption.

Actual Linux tests use disposable root-controlled /run directories, root-owned
0444 artifacts and distinct nonroot producer/reader children. Test-only keys stay
in memory. No installed service, defense process or device is activated.
