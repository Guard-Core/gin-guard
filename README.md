# gin-guard

Gin middleware adapter for [guard-core-go](https://github.com/rennf93/guard-core-go). Translates `*gin.Context` into the guardcore request surface, runs the engine, and translates verdicts to exact Gin responses (status, headers, body, then abort). Works with any `gin.Engine` or `gin.RouterGroup` chain via `router.Use`.

Docs: <https://rennf93.github.io/gin-guard/>

## Install

Released: `v1.1.0` on the Go module proxy. The engine stays pinned to the `guard-core-go` master pseudo-version below until the synchronized 4.2.0 train retags it:

```
go get github.com/rennf93/gin-guard@v1.1.0 github.com/rennf93/guard-core-go/v4@v4.0.5-0.20260926230539-e39ac203568b
```

The package name is `gin`, which collides with `github.com/gin-gonic/gin` (also package `gin`), so import the adapter with an explicit alias such as `guardgin`.

## Usage

```go
package main

import (
	"log"

	ginlib "github.com/gin-gonic/gin"
	guardcore "github.com/rennf93/guard-core-go/v4/guardcore"
	guardgin "github.com/rennf93/gin-guard"
)

func main() {
	cfg := guardcore.DefaultSecurityConfig()
	engine, err := guardcore.NewEngine(cfg)
	if err != nil {
		log.Fatal(err)
	}
	if err := engine.Initialize(); err != nil {
		log.Fatal(err)
	}

	guard, err := guardgin.New(engine)
	if err != nil {
		log.Fatal(err)
	}

	router := ginlib.New()
	router.Use(guard)
	router.GET("/", func(c *ginlib.Context) {
		c.String(200, "ok")
	})

	log.Fatal(router.Run(":8080"))
}
```

Options: `guardgin.WithMaxBodyBytes(n)` bounds the body bytes the engine scans (default 262144), `guardgin.WithLogger(l)` swaps the fail-closed logger. Route-level configuration uses `engine.Routes.Register` plus `guardgin.WithRouteID(ctx, id)` on the request context (set `c.Request` to the wrapped context in a middleware registered before the guard).

Every engine `SecurityConfig` field is reachable through this adapter: global tuning (behavior rules with `BehaviorScanResponseBody` and the inspect-bytes budget, the geo lifecycle with `IPInfoToken`/`OnGeoEvent`, CORS, security headers, custom error bodies) goes through the `SecurityConfig` you hand to `guardcore.NewEngine`, per-route detection exclusions and per-route behavior/IP rules through `engine.Routes.Register`. On every pass-through response the adapter merges `Engine.ResponseHeaders()` with `Engine.CORSResponseHeaders(req)` and reports the response (status plus the leading inspect-budget bytes of the body when `BehaviorScanResponseBody` is on) to `Engine.ProcessResponse` for the behavioral return rules. See [docs/configuration.md](docs/configuration.md).

Engine malfunctions fail closed with a 500. Detection covers at most the first `MaxBodyBytes` of the body; payloads beyond the bound are not scanned, and the full body still reaches your handler untouched.

## Development

The middleware consumes the core as a normal module dependency, currently pinned to the guard-core-go master surface (`v4.0.5-0.20260926230539-e39ac203568b`, the behavior-rules / geo-lifecycle / route-detection-exclusions wave); no `replace` directive is used or needed. For cross-repo work on the core itself, add a temporary local `replace` line in your own checkout and drop it before committing.

Integration tests run against real Redis:

```
REDIS_HOST=127.0.0.1 go test -tags integration ./...
```

## License

MIT
