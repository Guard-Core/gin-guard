Release Notes
=============

___

v1.5.0 (2026-10-16)
-------------------

The custom response modifier and the guard-core-go v4.4.0 floor (the reference-alignment engine)
------------------------------------------------------------------------------------------------

### Fixed

- **The `CustomResponseModifier` is applied, and the status handed to the response pass is the real one** (#42): `Engine.ModifyResponse` is applied in the reference order (security headers, CORS, modifier, then CORS again), and the status handed to `Engine.ProcessResponse` comes from `c.Writer.Status()`, so a handler that only calls `c.Status(500)` is recorded as 500 instead of 200. With a modifier configured the adapter holds the whole handler response in memory until the handler returns, so streamed responses are delivered at the end; without one nothing changes, and hijacked connections are left alone.

### Changed

- **Raised the engine floor to `github.com/rennf93/guard-core-go/v4 v4.4.0`, the reference-alignment release.** The v4.4.0 engine adds the per-request scan time budget (`Detection.MaxScanSeconds`, `pattern_timeout`), honors `Detection.ThreatScoreThreshold`, canonicalizes client identity (IPv4-mapped addresses, brackets, zones), follows the reference IP list precedence, answers an unresolved client address with 403 under `FailSecure`, applies dynamic rule versions over the base config, fixes the filtered-value scan bypass (GHSA-w9j2-2m3v-5hcc) and scans the Cookie header one pair at a time. No adapter code change was needed: the full gate (gofmt, vet, staticcheck, unit and integration tests with Redis, the 100% coverage gate, govulncheck) is green on the new floor.
- **Behavior to know before upgrading.** The v4.4.0 engine changes what some requests get, and this adapter passes it straight through. A request that reaches the engine with an empty remote address is now answered 403 `Client address could not be determined` under `FailSecure` (the adapter always hands over the connection's remote address, so only a server that leaves it empty is affected). IPv4 blacklist, whitelist, exempt and emergency entries now also match clients that connect as `::ffff:a.b.c.d`, and an IPv4 CIDR no longer trusts a mapped peer as a proxy. A configured whitelist now decides alone (a route whitelist overrides the route blacklist and skips the global lists, a global whitelist overrides the global blacklist), so an entry that relied on the blacklist beating the whitelist must move. A dynamic rule version no longer stacks on the previous one, so a field a version does not set returns to the base value. A request that spends `Detection.MaxScanSeconds` (default 10.0) of regex CPU time is blocked with a `pattern_timeout` threat, and a set `Detection.ThreatScoreThreshold` now changes verdicts. A passive-mode log match on the old penetration wording needs updating.
- **Docs and CI**: the examples and docs no longer claim the default address headers need a manual `ExcludedDetectionHeaders` entry or that `EnableAgent` fails validation (both verified against the engine), the weekly lint runs on Go 1.26.x, `codeql-action` moves to 4.38.3, the docs links and mkdocs `site_url` point at the live site root, and the README gets the content-parity pass.

___

v1.4.0 (2026-10-09)
-------------------

The websocket guard, the status route and the adapter lifecycle surface (guard-core-go v4.3.2 floor)
----------------------------------------------------------------------------------------------------

### Added

- **The websocket handshake guard** (#24): `GuardWebSocket(engine, c)` ports the reference websocket guard onto the Gin adapter, running the engine's handshake checks over the upgrade request (identity resolution, the fail-secure unknown-address close, the ban probe, the `is_ip_allowed` verdict, the ws rate limit, and the penetration detection pass sharing the HTTP pipeline's suspicious counts). A nil result allows the upgrade; a non-nil reason closes it; a nil engine fails closed with the security-check-failed reason. `WebSocketHTTPStatus` maps a close reason onto the HTTP status an upgrade rejection carries (503 try-again-later, 403 policy violation), and the ws request shim mirrors the reference `_WebSocketGuardRequest` (method WEBSOCKET, empty body, repeated headers joined with a comma, fresh request state).
- **The reference status route** (#25): `AddStatusRoute(r, engine, path)` registers a GET handler serving the engine's initialization snapshot JSON (cloud_providers ready/last_refreshed/entries per provider, geo_ip null or the configured resolver's status, redis enabled plus a live O(1) probe with the failure string) at `DefaultStatusPath` (`/_guard/status`) by default, never mutating engine state, the sibling adapters' `AddStatusRoute` over Gin's router.
- **The adapter lifecycle surface** (#26): the fastapi-guard middleware lifecycle ops (the FEATURE_MATRIX_GO adapter row's PARTIAL/MISSING entries) as explicit functions over the engine handle (the same seam as `GuardWebSocket` and `AddStatusRoute`): `MarkInitialized` (a warmed engine makes `Initialize` a no-op), `GetInitializationStatus` (the payload `AddStatusRoute` serves), `Reset` (the rate limiter's windows, redis and in-memory), `AgentStats` (enabled/degraded merged with the wired handler's stats), and `RefreshCloudIPRanges` (the redis-backed refresh at the configured TTL, the reference `cloud_handler.refresh_async`, or the in-memory refresh; no blocked providers is the reference's no-op early return).

### Changed

- **Raised the engine floor to `github.com/rennf93/guard-core-go/v4 v4.3.2`, the adapter-parity release.** The v4.3.2 engine carries the ReDoS static-safety trio with the pattern_safety corpus going registry-free (94/94, 0 divergences), the sus-patterns runtime registry with the `pattern_detected` envelope and real dynamic-rules application, the `custom_response_modifier` response pass (`Engine.ModifyResponse` exposes it to this adapter for pass-through composition), the websocket guard surface `GuardWebSocket` drives with suspicious counts shared with the HTTP pipeline, the fifteen SecurityConfig knobs with the performance-monitor wiring, and the lifecycle/state surface the functions above call (manager exports, `GeoIPManager.IsInitialized`, the cross-instance middleware state registry, the engine side of `MarkInitialized`/`AgentStats`). The floor also brings `redis/go-redis/v9` v9.23.0 transitively, clearing the stdlib-adjacent x/sys exposure; govulncheck stays clean. Everything else flows through the unchanged middleware surface.
- **`golang.org/x/net` bumped to v0.60.0 as an explicit indirect floor** (#28), clearing the five 2026 http2 findings (GO-2026-6603/6610/6611/6612/6617) reachable through the x/net http2 paths (`FrameType.String`, `Transport.RoundTrip`).
- **Post-transfer metadata sweep** (23c6788): repo URLs, docs links, and ecosystem references point at the Guard-Core org, and the upstream-drift suite checks out `Guard-Core/guard-core-go@master`. Module paths, Go imports, and the CHANGELOG history line are deliberately unchanged.

___

v1.3.0 (2026-10-01)
-------------------

guard-core-go v4.3.0 floor (the corpus-parity engine)
-----------------------------------------------------

### Changed

- **Raised the engine floor to `github.com/rennf93/guard-core-go/v4 v4.3.0`, the corpus-parity release.** The v4.3.0 engine is validated against the full conformance corpus: the pattern_safety, events and redis_interop suite kinds now run against the real engine alongside detect and pipeline (fail-closed baselines), the spec 12 observable event stream is ported (security event bus, metrics collector, dynamic-rules agent pipeline, the emission fidelity wave that closes the events surface to reference parity at 32 of 38 cases), plus the detection performance monitor, the security-headers Redis cache with the cross-worker sync contract, and the manager-level geo country verdict (`GeoIPManager.CheckCountryAccess`). Everything flows to the adapter through the unchanged middleware surface: agent integrations receive the new event stream via the existing handler hooks, and the engine-level changes require no adapter code. The module's `go` directive follows the engine to 1.26.0 (the engine's toolchain floor), and the CI matrix (ci.yml and release.yml), the example-app smoke images and the Makefile's GO_IMAGE move to go 1.26 with it, mirroring the engine's own go 1.26 floor wave (guard-core-go #36).
- **Dependency bumps**: the codeql-action suite to 4.38.2 (#17, #18) and golang.org/x/text v0.41.0 to v0.42.0 via the engine module graph.

### Added

- **A hard 100% coverage gate wired into CI** (#22): the adapter surface is fully covered (`coverage_test.go` drives the shim and middleware paths the pipeline exercises), and the gate (`check_coverage.sh`) fails closed on a missing or empty profile and refuses anything under 100% total.
- **staticcheck joins the CI gates** (#21) with the findings fixed ahead of the gate.
- **The upstream-drift suite runs on go 1.26** (#20) to match engine master's toolchain floor.
- **The guard-core process baseline** (#21): hygiene files (SECURITY, CONTRIBUTING, Code of Conduct, funding, issue and PR templates), dependabot, the labeler and scheduled lint.

___

v1.2.0 (2026-09-27)
-------------------

guard-core-go v4.2.0 floor (the parity engine)
----------------------------------------------

### Changed

- **Raised the engine floor to `github.com/rennf93/guard-core-go/v4 v4.2.0`, replacing the master pseudo-version pin with the real parity tag.** The v4.2.0 engine is the parity release validated against the shared conformance corpus (spec 4.1.0, 219 cases; pipeline gate 35 passed, 0 failed, 0 xfail, 0 config divergences) and carries everything the pseudo-version pin already exercised plus the full feature surface: behavior rules (global_behavior_rules, per-route BehaviorRules, Engine.ProcessResponse return rules), the IPInfo geo lifecycle with OnGeoEvent (country_blocked, geo_lookup_failed, decorator_violation), per-route detection exclusions and enable_suspicious_detection, Retry-After from the tripped rate-limit tier window, the corrected CORS response surface (Allow-Methods/Headers, 3600 Max-Age, wildcard plus credentials downgraded at policy resolution), and the reference-shape passive on_block hook payloads (empty trigger_info, null status_code, inline ip_security/deny dispatch). The intermediate master pin (v4.0.5-0.20260927055209) existed only to pick up the 4.1.0 passive on_block contract ahead of the tag; v4.2.0 supersedes it.

___

v1.1.0 (2026-09-26)
-------------------

Security headers on pass-through responses
------------------------------------------

### Added

- **Security headers on every pass-through response.** The adapter applies the engine's `ResponseHeaders()` set in one loop before the handler writes, so clean responses carry the same default header set as blocked ones (mirroring the engine's `process_response`). Disabling `SecurityHeaders` restores the header-free pass, and config overrides plus custom headers flow through the adapter untouched.

___

v1.0.1 (2026-09-26)
-------------------

guard-core-go v4.1.0 floor bump
-------------------------------

### Changed

- **Raised the engine floor to `github.com/rennf93/guard-core-go/v4 v4.1.0`.** The engine now attaches its default security headers to blocked responses, and the adapter translates that header set verbatim alongside the verdict status and body. The floor also carries the engine's per-route IP allow/block lists, `exempt_ips`, geo country blocking, and CORS support.
- **The suite now requires the engine's security headers on blocked responses.** The `TestMiddlewareBlocksBannedIPExactly` lockstep window (headers optional while the adapter floor lagged the engine) is closed: a blocked response must carry exactly the engine's default security header set, verbatim, with nothing added and nothing stripped.

___

v1.0.0 (2026-09-24)
-------------------

First stable release (v1.0.0)
-----------------------------

### Added

- **The first stable release of gin-guard, the Gin middleware adapter for the guard-core-go engine.** It translates `*gin.Context` into the guardcore request surface, runs the engine, and translates verdicts to exact Gin responses (status, headers, body, then abort). Works with any `gin.Engine` or `gin.RouterGroup` chain via `router.Use`.
- **17/17 security checks parity with guard-core 4.0.4**, covering suspicious activity detection, penetration attempts, IP bans and allow lists, cloud provider detection, rate limiting, HTTPS enforcement, required headers, referrer policy, user agent filtering, and route-level configuration, with binary-noise gates on the detection engine.
- **Fail-closed behavior on engine malfunctions**: any engine error answers 500 instead of letting the request through. Detection covers at most the first `MaxBodyBytes` of the body (default 262144, tunable via `guardgin.WithMaxBodyBytes`); payloads beyond the bound are not scanned, and the full body still reaches your handler untouched.
- **Route-level configuration** via `engine.Routes.Register` plus `guardgin.WithRouteID(ctx, id)` on the request context (set `c.Request` to the wrapped context in a middleware registered before the guard), and a swappable fail-closed logger via `guardgin.WithLogger(l)`.
- **Documentation site** (MkDocs: index and usage/configuration pages), simple and advanced example apps, and a dockerized live smoke workflow over the example apps.

### Changed

- **Migrated to the guard-core-go `/v4` module path.** The dependency is now `github.com/rennf93/guard-core-go/v4 v4.0.4` and every import uses `github.com/rennf93/guard-core-go/v4/guardcore`. The previous `github.com/rennf93/guard-core-go v0.1.0` pre-release is retired.
- **Release engineering harmonized with guard-core-go**: a dockerized `Makefile` (install, test, lint, clean, bump-version) and a stdlib-only `.github/scripts/bump_version.py` that scaffolds this changelog; the git tag is the version.
- **Upstream drift guard, demo container publishing, and community workflows** from the parity polish: a daily test run of the adapter suite against guard-core-go@master, a container-release workflow for the demo image, docs publishing to GitHub Pages, plus labeling, staleness, and greetings workflows.

___
