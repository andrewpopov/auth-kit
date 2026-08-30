---
kind: added
summary: runExternalIdentityStoreConformanceTests adds a concurrent claimPlaceholder race, catching non-atomic placeholder-claim adapters the suite previously missed.
---

`runExternalIdentityStoreConformanceTests` already promised (in its own doc
comment) that `bindExternalIdentity` and `claimPlaceholder` must decide and
act atomically, but only `bindExternalIdentity` had a genuine concurrency
canary — `claimPlaceholder` was exercised only once, sequentially, so a
non-atomic adapter could pass the suite while violating the stated contract.
The suite now also races N concurrent `claimPlaceholder` calls against ONE
placeholder, repeated over fresh placeholders (a new `raceRepeats` option,
default 5), asserting exactly one claim wins each round. Adapter authors
should re-run the suite against their real store.

Two refinements from the first pass: the race deliberately contends for a
SINGLE placeholder per round rather than several placeholders sharing one
normalized email — the latter spuriously fails against an otherwise-conforming
adapter that enforces email uniqueness. And the race is now documented as
PROBABILISTIC rather than implied-certain: `Promise.all` gives genuine
concurrency but no barrier between an adapter's internal read and write
phases, so a truly non-atomic adapter could still pass any single round by
scheduling luck — repeating over fresh state makes that unlikely across every
round, not impossible.
