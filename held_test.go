package gin

import (
	"bufio"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"

	ginlib "github.com/gin-gonic/gin"
	"github.com/rennf93/guard-core-go/v4/guardcore"
)

func TestParityHeldWriterContract(t *testing.T) {
	rec := httptest.NewRecorder()
	ctx, _ := ginlib.CreateTestContext(rec)
	held := &heldWriter{ResponseWriter: ctx.Writer, status: http.StatusOK}
	if held.Written() || held.Size() != -1 {
		t.Fatal("a fresh held writer has not written")
	}
	held.WriteHeader(0)
	held.WriteHeader(http.StatusAccepted)
	held.WriteHeaderNow()
	held.WriteHeader(http.StatusTeapot)
	held.Flush()
	if _, err := held.Write([]byte("ab")); err != nil {
		t.Fatal(err)
	}
	if held.Status() != http.StatusAccepted || !held.Written() || held.Size() != 2 || string(held.body) != "ab" {
		t.Fatalf("held writer state wrong: %d %v %d %q", held.Status(), held.Written(), held.Size(), held.body)
	}
	if rec.Body.Len() != 0 {
		t.Fatal("nothing may reach the client before release")
	}
}

type hijackRecorder struct {
	*httptest.ResponseRecorder
}

func (hijackRecorder) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	server, client := net.Pipe()
	_ = client.Close()
	return server, bufio.NewReadWriter(bufio.NewReader(server), bufio.NewWriter(server)), nil
}

func TestParityHijackedResponseIsNotReleased(t *testing.T) {
	engine := newTestEngine(t, func(c *guardcore.SecurityConfig) {
		c.CustomResponseModifier = func(resp *guardcore.Response) *guardcore.Response {
			t.Error("a hijacked connection must not reach the modifier")
			return resp
		}
	})
	guard, err := New(engine)
	if err != nil {
		t.Fatal(err)
	}
	router := ginlib.New()
	router.Use(guard)
	router.Any("/*wildcard", func(c *ginlib.Context) {
		conn, _, err := c.Writer.Hijack()
		if err != nil {
			t.Errorf("hijack: %v", err)
			return
		}
		_ = conn.Close()
	})
	router.ServeHTTP(hijackRecorder{httptest.NewRecorder()}, httptest.NewRequest("GET", "/ws", nil))
}
