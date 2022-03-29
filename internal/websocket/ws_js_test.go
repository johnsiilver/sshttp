package websocket_test

import (
	"context"
	"github.com/johnsiilver/sshttp/http"
	"os"
	"testing"
	"time"

	"github.com/johnsiilver/sshttp/internal/websocket"
	"github.com/johnsiilver/sshttp/internal/websocket/internal/test/assert"
	"github.com/johnsiilver/sshttp/internal/websocket/internal/test/wstest"
)

func TestWasm(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	c, resp, err := websocket.Dial(ctx, os.Getenv("WS_ECHO_SERVER_URL"), &websocket.DialOptions{
		Subprotocols: []string{"echo"},
	})
	assert.Success(t, err)
	defer c.Close(websocket.StatusInternalError, "")

	assert.Equal(t, "subprotocol", "echo", c.Subprotocol())
	assert.Equal(t, "response code", http.StatusSwitchingProtocols, resp.StatusCode)

	c.SetReadLimit(65536)
	for i := 0; i < 10; i++ {
		err = wstest.Echo(ctx, c, 65536)
		assert.Success(t, err)
	}

	err = c.Close(websocket.StatusNormalClosure, "")
	assert.Success(t, err)
}
