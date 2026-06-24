# Handoff

The detailed Vegas readiness plan has been written into the repository, and the
GitHub child issues now exist under #283.

The next step is to execute the booth-device validation path:

- run repeated replay verification on the target device
- record at least 3 rehearsals
- generate the readiness/freeze artifacts from the helper commands
- select the final freeze candidate from booth-device evidence

Recommended helper commands:

```bash
bin/azazel-edge-bhusa-prep repo-sync
bin/azazel-edge-bhusa-prep daily-pack --force
bin/azazel-edge-bhusa-prep candidate-pack --force
bin/azazel-edge-bhusa-status
bin/azazel-edge-bhusa-status --include-freeze-check
bin/azazel-edge-bhusa-status --write-status-doc
bin/azazel-edge-bhusa-issues sync-links --write
bin/azazel-edge-bhusa-issues parent-comment --write
bin/azazel-edge-bhusa-issues progress-comment --write
bin/azazel-edge-bhusa-issues progress-comment
bin/azazel-edge-bhusa-report --force
bin/azazel-edge-bhusa-freeze-record --force
```
