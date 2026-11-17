package ws

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"testing"

	"github.com/gorilla/websocket"
)

func TestIsNormalDisconnect(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{
			name: "context canceled",
			err:  context.Canceled,
			want: true,
		},
		{
			name: "io.EOF",
			err:  io.EOF,
			want: true,
		},
		{
			name: "net.ErrClosed",
			err:  net.ErrClosed,
			want: true,
		},
		{
			name: "wrapped EOF",
			err:  fmt.Errorf("read error: %w", io.EOF),
			want: true,
		},
		{
			name: "websocket CloseNormalClosure",
			err:  &websocket.CloseError{Code: websocket.CloseNormalClosure, Text: "normal closure"},
			want: true,
		},
		{
			name: "websocket CloseGoingAway",
			err:  &websocket.CloseError{Code: websocket.CloseGoingAway, Text: "going away"},
			want: true,
		},
		{
			name: "websocket CloseAbnormalClosure",
			err:  &websocket.CloseError{Code: websocket.CloseAbnormalClosure, Text: "abnormal closure"},
			want: true,
		},
		{
			name: "websocket CloseNoStatusReceived",
			err:  &websocket.CloseError{Code: websocket.CloseNoStatusReceived, Text: "no status"},
			want: true,
		},
		{
			name: "websocket CloseProtocolError",
			err:  &websocket.CloseError{Code: websocket.CloseProtocolError, Text: "protocol error"},
			want: false,
		},
		{
			name: "generic error",
			err:  errors.New("unexpected connection reset"),
			want: false,
		},
		{
			name: "nil error",
			err:  nil,
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isNormalDisconnect(tt.err); got != tt.want {
				t.Errorf("isNormalDisconnect(%v) = %v, want %v", tt.err, got, tt.want)
			}
		})
	}
}
