# Created issue links

- [#284 — Lock Vegas demo story and talk track](https://github.com/01rabbit/Azazel-Edge/issues/284) `OPEN`
- [#285 — Stabilize deterministic replay for Arsenal booth demo](https://github.com/01rabbit/Azazel-Edge/issues/285) `OPEN`
- [#286 — Build operator decision-support booth view](https://github.com/01rabbit/Azazel-Edge/issues/286) `OPEN`
- [#287 — Prepare audit and explanation walkthrough](https://github.com/01rabbit/Azazel-Edge/issues/287) `OPEN`
- [#288 — Clarify live Tactical path vs replay fallback boundary](https://github.com/01rabbit/Azazel-Edge/issues/288) `OPEN`
- [#289 — Prepare booth rehearsal runbook](https://github.com/01rabbit/Azazel-Edge/issues/289) `OPEN`
- [#290 — Sync docs with public Black Hat session description](https://github.com/01rabbit/Azazel-Edge/issues/290) `OPEN`
- [#291 — Define final release freeze and no-risk rule](https://github.com/01rabbit/Azazel-Edge/issues/291) `OPEN`

Suggested workflow:

1. run `bin/azazel-edge-bhusa-issues create`
2. run `bin/azazel-edge-bhusa-issues create --apply` when needed for missing issues
3. run `bin/azazel-edge-bhusa-issues sync-links --write` to refresh this file from GitHub
4. run `bin/azazel-edge-bhusa-issues parent-comment`
5. run `bin/azazel-edge-bhusa-issues progress-comment` for later roadmap updates
