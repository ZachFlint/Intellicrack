> # Workgroup Directive — Execution Order 10/23: `providers-meta`
>
> Spawn a multi-agent workgroup to drive **every F-#### finding below** to
> production release-ready. The workgroup must run this pipeline for every
> finding in this file:
>
> 1. **`developer`** agents (in parallel where findings touch disjoint
>    files) — implement the full fix per the finding's `Suggested
>    remediation summary`. No placeholders, mocks, stubs, hardcoded
>    returns, or fake-success paths. Re-verify each finding against the
>    cited source/lines before fixing; if already resolved, annotate
>    `[obsolete]` with the resolving commit hash and move on.
> 2. **`code-reviewer`** — verify each fix actually addresses the failure
>    mode described in `Why this is non-functional` and audit every caller
>    listed under `Callers / blast radius` for regressions.
> 3. **`test-writer`** — author production-grade tests that fail without
>    the fix and pass with it. Tests must execute against real binaries,
>    real bridges, and real protocols. No mocks of the unit under test.
> 4. **`test-reviewer`** — confirm tests genuinely validate the fix and
>    meet Intellicrack's no-mock standard.
> 5. **`linter`** — run `ruff check`, `basedpyright`, `pydoclint`, and
>    `pydocstyle`; resolve every finding without suppression directives.
>
> Hard constraints (non-negotiable):
>
> - Production-ready and immediately deployable; zero placeholders, mocks,
>   stubs, simulated implementations, or fake-success returns.
> - `ruff check` clean, fully `basedpyright` compliant, `pydoclint` and
>   `pydocstyle` clean — no inline suppression directives of any kind.
> - Windows-first compatibility, preserve existing functionality, never
>   delete a method binding — implement the missing function instead.
> - When this file is fully processed, every F-#### below must be either
>   fixed-and-tested or annotated `[obsolete]` with the resolving commit.
> - **All work for this file ships as one single PR (one PR per prompt /
>   per file).** Every F-#### in this file must be batched into the same
>   PR — do not split findings across multiple PRs, and do not merge any
>   subset until the whole file is fixed-and-tested or annotated
>   `[obsolete]`.
>
> ---
>
# Findings: providers-meta

## Files audited (3)

- src/intellicrack/providers/registry.py
- src/intellicrack/providers/discovery.py
- src/intellicrack/providers/**init**.py

## Findings

### Category 5 - Error Handling Anti-Patterns

#### F-0001 - Registry `connect_provider()` swallows wrong exception set; provider-raised `ProviderError`/`AuthenticationError` will bypass the handler

- **File:** `src/intellicrack/providers/registry.py`
- **Lines:** 165-172
- **Pattern:** Cat 5
- **Why this is non-functional:** Provider implementations routinely raise `ProviderError` and `AuthenticationError` from `connect()`. `ProviderError` derives from `IntellicrackError(Exception)`, NOT a subclass of any of `ConnectionError`/`TimeoutError`/`OSError`/`RuntimeError`/`ValueError`. The handler never catches the most common failure class.

### Category 24 - Recovery / Robustness Theater

#### F-0002 - Registry `connect_provider()` documents `bool` return but never returns `False`

- **File:** `src/intellicrack/providers/registry.py`
- **Lines:** 137-172
- **Pattern:** Cat 24

### Category 20 - Dead Code

#### F-0003 - `ProviderRegistry._credential_loader` parameter is wired but never reached

- **File:** `src/intellicrack/providers/registry.py`
- **Lines:** 36-52, 158-163, 244-259
- **Pattern:** Cat 20, Cat 12
- **Why this is non-functional:** `get_provider_registry()` (the only construction site) calls `ProviderRegistry()` with no arguments, so `self._credential_loader` is permanently `None`.

### Category 18 - Public API Plumbing

#### F-0004 - `get_provider_registry` is not exported from `providers/__init__.py`

- **File:** `src/intellicrack/providers/__init__.py`
- **Lines:** 48, 63-109
- **Pattern:** Cat 18

### Category 9 - Bridge / Tool Integration Failures

#### F-0005 - `ProviderRegistry` is not a true factory: it cannot map a `ProviderName` to a class

- **File:** `src/intellicrack/providers/registry.py`
- **Lines:** 30-122
- **Pattern:** Cat 9

### Category 7 - Concurrency / Async Issues

#### F-0006 - `ModelDiscovery._lock` is allocated but never used

- **File:** `src/intellicrack/providers/discovery.py`
- **Lines:** 314-324
- **Pattern:** Cat 7, Cat 20

#### F-0007 - `DiscoveryCache.get/set/invalidate` advertise thread safety via `_lock` but never acquire it for the hot path

- **File:** `src/intellicrack/providers/discovery.py`
- **Lines:** 88-157
- **Pattern:** Cat 7

### Category 4 - Ineffective Implementations

#### F-0008 - `ModelDiscovery.get_recommended_model` is `async` but never awaits anything

- **File:** `src/intellicrack/providers/discovery.py`
- **Lines:** 689-751
- **Pattern:** Cat 4

#### F-0009 - `get_recommended_model` silently returns an arbitrary first model on any unknown `task_type`

- **File:** `src/intellicrack/providers/discovery.py`
- **Lines:** 700-751
- **Pattern:** Cat 4

#### F-0010 - `DiscoveryFilter` regex matching uses `pattern.match` (start-anchored)

- **File:** `src/intellicrack/providers/discovery.py`
- **Lines:** 596-628
- **Pattern:** Cat 19

### Category 11 - Persistence / State Issues

#### F-0011 - `DiscoveryCache` stores empty model lists which are then returned as valid cached data

- **File:** `src/intellicrack/providers/discovery.py`
- **Lines:** 106-123, 503-541
- **Pattern:** Cat 11

#### F-0012 - `discover_all(use_cache=False, force_refresh=False)` leaks stale cache to other readers

- **File:** `src/intellicrack/providers/discovery.py`
- **Lines:** 335-470
- **Pattern:** Cat 11

### Category 5 - Error Handling Anti-Patterns (continued)

#### F-0013 - `disconnect_all` aborts the loop on the first provider that raises during disconnect

- **File:** `src/intellicrack/providers/registry.py`
- **Lines:** 174-188
- **Pattern:** Cat 5, Cat 24

#### F-0014 - `ProviderError` raised inside the registry never carries `provider_name`

- **File:** `src/intellicrack/providers/registry.py`
- **Lines:** 24-27, 109-114, 161-163, 199-202
- **Pattern:** Cat 5

### Category 7 - Concurrency / Async Issues (continued)

#### F-0015 - Singleton pattern offers no reset/teardown API and no DI of credential_loader

- **File:** `src/intellicrack/providers/registry.py`
- **Lines:** 235-259
- **Pattern:** Cat 7, Cat 22

### Category 11 - Persistence / State Issues (continued)

#### F-0016 - `disconnect_provider` does not clear `_active_provider` when the active provider is disconnected

- **File:** `src/intellicrack/providers/registry.py`
- **Lines:** 174-215
- **Pattern:** Cat 11

#### F-0017 - `discover_one` returns `[]` for unconnected providers but does not invalidate cache

- **File:** `src/intellicrack/providers/discovery.py`
- **Lines:** 392-405
- **Pattern:** Cat 11

### Category 4 - DRY Violations

#### F-0018 - `discover_one` and `discover_provider` duplicate the cache-set / new-removed-diff logic verbatim

- **File:** `src/intellicrack/providers/discovery.py`
- **Lines:** 414-435 and 537-552
- **Pattern:** Cat 4

#### F-0019 - `DiscoveryCache.save_to_disk` calls `time.time()` per iteration instead of snapshotting once

- **File:** `src/intellicrack/providers/discovery.py`
- **Lines:** 198-225
- **Pattern:** Cat 4

### Category 11 - Persistence (continued)

#### F-0020 - `DiscoveryCache.load_from_disk` partially overwrites in-memory cache and offers no atomicity

- **File:** `src/intellicrack/providers/discovery.py`
- **Lines:** 244-292
- **Pattern:** Cat 11

#### F-0021 - `discover_all` records error events but never invalidates the now-known-stale cache entry

- **File:** `src/intellicrack/providers/discovery.py`
- **Lines:** 437-467
- **Pattern:** Cat 11

### Category 7 - Concurrency

#### F-0022 - `ProviderRegistry.register/unregister/set_active` mutate shared state without internal locking

- **File:** `src/intellicrack/providers/registry.py`
- **Lines:** 54-85
- **Pattern:** Cat 7

### Category 18 - Public API Bloat

#### F-0023 - `__init__.py` re-exports private TypedDict helpers that have no external consumers

- **File:** `src/intellicrack/providers/__init__.py`
- **Lines:** 14-27, 63-109
- **Pattern:** Cat 18

### Category 5 - Validation Theater

#### F-0024 - `DiscoveryFilter` invalid regex silently degrades to "no regex applied" instead of failing closed

- **File:** `src/intellicrack/providers/discovery.py`
- **Lines:** 596-628
- **Pattern:** Cat 5
