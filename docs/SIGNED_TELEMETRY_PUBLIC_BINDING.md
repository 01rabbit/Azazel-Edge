# Public configuration continuity snapshot (code only)

`signed_network_telemetry_binding.public_auth_binding()` has no path arguments.
It requires the existing marked offline Root guard and explicit
`EDGE_SIGNED_NETWORK_TELEMETRY=1` before reading only the fixed Root-owned,
protected, nofollow `g.BUNDLE/trust.json` and `g.BUNDLE/origin.json`. Both reads
are bounded. No key, signed source contents, journal, sidecar or endpoint is read
or opened; configured paths are returned as metadata only.

The existing pure `TrustPolicy` parser checks its exact public schema, path and
role types. The snapshot accepts v3/v4 with fixed roles 61001/61002/0; v4 also
retains explicit witness-transport metadata. Current abstract lab callers require
v4 and separately verify the actual owned witness namespace/identity. Origin JSON
is strictly decoded (duplicates/nonfinite values refuse); its declared v4
live-core mode and selected public scope/key context must agree with trust. This
is deliberately not the full origin-registration/environment/native-image
validator. The unchanged observer API after GO still owns actual configuration
and cryptographic validation.

The snapshot retains raw SHA256 for each public file, the parsed trust digest,
selected scope/source/journal context, role UIDs and the configured registration
digest. The observed origin raw hash and configured registration digest remain
separate observations; this helper does not assert their equality or invent a
canonical registration digest. Byte changes, including harmless whitespace,
change continuity metadata.

Later reviewed initializer/live callers must retain and compare the current
snapshot at their specified fences. This chunk does not change those callers or
source-pin maps. The return value is sampled public Root configuration metadata,
not an atomic two-file snapshot, JSON authentication, observer-label binding,
source admission, trial authority or a successful API receipt. Its trust boundary
is the externally reviewed Root controller and protected current files, not the
snapshot's own JSON or hashes. No runtime has been executed for this chunk.
