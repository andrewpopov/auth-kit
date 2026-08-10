import { describe, it, expect } from 'vitest';
import { createMemorySingleUseTokenStore } from '../index';
import { runSingleUseTokenStoreConformanceTests } from '../conformance';

// Dogfoods the conformance suite itself against the in-memory reference
// store, using REAL vitest primitives (not a hand-rolled stand-in), to prove
// the injected-harness API actually works end to end. This does NOT prove
// anything about a real adapter's atomicity (see the suite's own doc comment
// and the README's "Testing a real adapter" section) — it only proves the
// suite runs, registers tests, and its assertions hold against a store that
// is known-correct.
runSingleUseTokenStoreConformanceTests(() => createMemorySingleUseTokenStore(), { describe, it, expect });
