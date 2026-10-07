package gin

import (
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"testing"

	ginlib "github.com/gin-gonic/gin"
	"github.com/rennf93/guard-core-go/v4/guardcore"
)

func wsTestEngine(t *testing.T, mutate func(*guardcore.SecurityConfig)) *guardcore.Engine {
	t.Helper()
	cfg, err := guardcore.NewSecurityConfig(func(c *guardcore.SecurityConfig) {
		c.EnableRedis = false
		if mutate != nil {
			mutate(c)
		}
	})
	if err != nil {
		t.Fatalf("NewSecurityConfig: %v", err)
	}
	engine, err := guardcore.NewEngine(cfg)
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	return engine
}

func wsUpgradeContext(t *testing.T, remote string, mutate func(r *http.Request)) *ginlib.Context {
	t.Helper()
	r := httptest.NewRequest(http.MethodGet, "/ws", nil)
	r.RemoteAddr = remote
	r.Header.Set("Upgrade", "websocket")
	r.Header.Set("Connection", "Upgrade")
	if mutate != nil {
		mutate(r)
	}
	w := httptest.NewRecorder()
	c, _ := ginlib.CreateTestContext(w)
	c.Request = r
	return c
}

func TestGuardWebSocketAllowsCleanUpgrade(t *testing.T) {
	engine := wsTestEngine(t, nil)
	if reason := GuardWebSocket(engine, wsUpgradeContext(t, "203.0.113.9:12345", nil)); reason != nil {
		t.Fatalf("clean upgrade must pass, got %+v", reason)
	}
	if status := WebSocketHTTPStatus(nil); status != http.StatusOK {
		t.Fatalf("nil reason must map to 200, got %d", status)
	}
}

func TestGuardWebSocketBannedIPCloses(t *testing.T) {
	engine := wsTestEngine(t, nil)
	if _, err := engine.Ban.Ban("203.0.113.9", 60, "test"); err != nil {
		t.Fatalf("Ban: %v", err)
	}
	reason := GuardWebSocket(engine, wsUpgradeContext(t, "203.0.113.9:12345", nil))
	if reason == nil || *reason != guardcore.WSCloseIPBanned {
		t.Fatalf("banned IP must close with the banned reason, got %+v", reason)
	}
	if status := WebSocketHTTPStatus(reason); status != http.StatusForbidden {
		t.Fatalf("policy violation must map to 403, got %d", status)
	}
}

func TestGuardWebSocketSuspiciousHandshakeCloses(t *testing.T) {
	engine := wsTestEngine(t, nil)
	reason := GuardWebSocket(engine, wsUpgradeContext(t, "203.0.113.9:12345", func(r *http.Request) {
		r.URL.Path = "/ws/search"
		r.URL.RawQuery = "q=1%27%20UNION%20SELECT%20username%2Cpassword%20FROM%20users--"
	}))
	if reason == nil || *reason != guardcore.WSCloseSuspiciousActivity {
		t.Fatalf("suspicious handshake must close with the suspicious reason, got %+v", reason)
	}
	if status := WebSocketHTTPStatus(reason); status != http.StatusForbidden {
		t.Fatalf("suspicious must map to 403, got %d", status)
	}
}

func TestGuardWebSocketFailSecureUnknownAddress(t *testing.T) {
	engine := wsTestEngine(t, nil) // fail_secure defaults true
	reason := GuardWebSocket(engine, wsUpgradeContext(t, "", nil))
	if reason == nil || *reason != guardcore.WSCloseClientAddressUnknown {
		t.Fatalf("unknown address under fail_secure must close, got %+v", reason)
	}
}

func TestGuardWebSocketNilEngineFailsClosed(t *testing.T) {
	reason := GuardWebSocket(nil, wsUpgradeContext(t, "203.0.113.9:12345", nil))
	if reason == nil || *reason != guardcore.WSCloseSecurityCheckFailed {
		t.Fatalf("nil engine must fail closed, got %+v", reason)
	}
	if status := WebSocketHTTPStatus(reason); status != http.StatusServiceUnavailable {
		t.Fatalf("security-check-failed must map to 503, got %d", status)
	}
}

func TestWSRequestShimContract(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/ws?a=1&a=2", nil)
	req.RemoteAddr = "203.0.113.9:12345"
	req.Header["X-Custom"] = []string{"one", "two"}
	req.TLS = &tls.ConnectionState{}
	shim := newWSRequestShim(req)
	if shim.Method() != "WEBSOCKET" {
		t.Fatalf("the ws shim must report the WEBSOCKET method, got %q", shim.Method())
	}
	if body, err := shim.Body(); err != nil || body != nil {
		t.Fatalf("the ws shim must carry an empty body, got (%v, %v)", body, err)
	}
	if joined, _ := shim.Headers().Get("X-Custom"); joined != "one, two" {
		t.Fatalf("repeated headers must join with a comma, got %q", joined)
	}
	if shim.QueryParams()["a"] != "1" {
		t.Fatalf("query params must keep the first value, got %q", shim.QueryParams()["a"])
	}
	if shim.ClientHost() != "203.0.113.9" {
		t.Fatalf("client host must strip the port, got %q", shim.ClientHost())
	}
	if shim.State() == nil {
		t.Fatal("the ws shim must expose a request state")
	}
	if shim.URLScheme() != "https" {
		t.Fatalf("the ws shim must resolve the request scheme, got %q", shim.URLScheme())
	}
	if full := shim.URLFull(); full != "https://example.com/ws?a=1&a=2" {
		t.Fatalf("the ws shim must build the full URL, got %q", full)
	}
	if replaced := shim.URLReplaceScheme("wss"); replaced != "wss://example.com/ws?a=1&a=2" {
		t.Fatalf("scheme replacement must swap the scheme, got %q", replaced)
	}
	if same := shim.URLReplaceScheme(""); same != shim.URLFull() {
		t.Fatalf("empty scheme replacement must keep the URL, got %q", same)
	}

	plain := newWSRequestShim(httptest.NewRequest(http.MethodGet, "/ws", nil))
	if plain.URLScheme() != "http" {
		t.Fatalf("a plaintext request must resolve http, got %q", plain.URLScheme())
	}
	if full := plain.URLFull(); full != "http://example.com/ws" {
		t.Fatalf("the ws shim must build the plain full URL, got %q", full)
	}
}
