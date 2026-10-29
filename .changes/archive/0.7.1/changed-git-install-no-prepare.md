---
kind: changed
summary: Installing from git no longer runs a full dependency install: the `prepare` script is gone (run `npm run hooks` once after cloning) and `build` is now `compile`
---

Git-pinned consumers no longer trigger nested installs in the clone. Run `npm run hooks` once after cloning to enable the pre-push gate; `npm run compile` replaces `npm run build`.
