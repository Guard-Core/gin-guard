package gin

import (
	"bufio"
	"net"
	"net/http"
	"strconv"

	ginlib "github.com/gin-gonic/gin"
	"github.com/rennf93/guard-core-go/v4/guardcore"
)

// heldWriter buffers the handler's response (status, headers, body) so the
// engine's CustomResponseModifier can rewrite it before anything reaches the
// client. The reference response factory applies the modifier to the
// pass-through response object, which the Go net/http model can only mirror
// by holding the response: the adapter installs this writer only when a
// modifier is configured, so streaming responses are untouched otherwise.
type heldWriter struct {
	ginlib.ResponseWriter
	status   int
	written  bool
	hijacked bool
	body     []byte
}

func (w *heldWriter) WriteHeader(code int) {
	if code > 0 && !w.written {
		w.status = code
	}
}

func (w *heldWriter) WriteHeaderNow() { w.written = true }

func (w *heldWriter) Write(p []byte) (int, error) {
	w.written = true
	w.body = append(w.body, p...)
	return len(p), nil
}

func (w *heldWriter) WriteString(s string) (int, error) {
	return w.Write([]byte(s))
}

func (w *heldWriter) Status() int { return w.status }

func (w *heldWriter) Size() int {
	if !w.written {
		return -1
	}
	return len(w.body)
}

func (w *heldWriter) Written() bool { return w.written }

// Flush only marks the response written (gin's Flush calls WriteHeaderNow):
// the bytes stay held until the handler chain returns.
func (w *heldWriter) Flush() { w.written = true }

func (w *heldWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	w.hijacked = true
	return w.ResponseWriter.Hijack()
}

// release runs the modifier over the held response and writes the result to
// the real writer. Headers the modifier did not touch keep every value
// (Set-Cookie and friends); changed or added ones are set, removed ones are
// deleted. CORS headers are applied again after the modifier, as the
// reference dispatch injects them on the processed response.
func (w *heldWriter) release(engine *guardcore.Engine, resp *guardcore.Response, cors map[string]string) {
	header := w.ResponseWriter.Header()
	before := make(map[string]string, len(resp.Headers))
	for name, value := range resp.Headers {
		before[name] = value
	}
	out := engine.ModifyResponse(resp)
	for name := range before {
		if _, kept := out.Headers[name]; !kept {
			header.Del(name)
		}
	}
	for name, value := range out.Headers {
		if prev, seen := before[name]; !seen || prev != value {
			header.Set(name, value)
		}
	}
	if header.Get("Content-Length") != "" {
		header.Set("Content-Length", strconv.Itoa(len(out.Body)))
	}
	for name, value := range cors {
		header.Set(name, value)
	}
	w.ResponseWriter.WriteHeader(out.StatusCode)
	if len(out.Body) > 0 {
		_, _ = w.ResponseWriter.Write(out.Body)
	}
}

func headerSnapshot(h http.Header) map[string]string {
	out := make(map[string]string, len(h))
	for name, values := range h {
		if len(values) > 0 {
			out[name] = values[0]
		}
	}
	return out
}
