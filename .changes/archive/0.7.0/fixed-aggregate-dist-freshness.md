---
kind: fixed
summary: the aggregate verification gate now rejects stale committed build output
---

`npm run verify` now invokes the existing `verify:dist-fresh` guard before
packing the package.
