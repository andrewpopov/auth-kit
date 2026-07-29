---
kind: changed
summary: Release tooling bumped to release-kit v0.3.1
---

Development-only: `@andrewpopov/release-kit` moves from v0.2.0 to v0.3.1. No
runtime or API change — the published `dist/` is unaffected. v0.2.0 predated
kind-derived version bumps, which is why cutting 0.6.0 (a `breaking` fragment)
first produced a patch bump and needed an explicit `--version`. v0.3.1 derives
the level from fragment kinds, refuses to auto-version an implicit major/minor
when the strategy has not declared support, and fixes `release:hygiene` so a
branch that cuts a release can pass it.
