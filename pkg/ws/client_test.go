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

func TestIsExpectedDisconnect(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		expected bool
	}{
		{
			name:     "nil error",
			err:      nil,
			expected: false,
		},
		{
			name:     "context.Canceled",
			err:      context.Canceled,
			expected: true,
		},
		{
			name:     "wrapped context.Canceled",
			err:      fmt.Errorf("connection context done: %w", context.Canceled),
			expected: true,
		},
		{
			name:     "net.ErrClosed",
			err:      net.ErrClosed,
			expected: true,
		},
		{
			name:     "wrapped net.ErrClosed",
			err:      fmt.Errorf("socket closed: %w", net.ErrClosed),
			expected: true,
		},
		{
			name:     "io.EOF",
			err:      io.EOF,
			expected: true,
		},
		{
			name:     "wrapped io.EOF",
			err:      fmt.Errorf("read error: %w", io.EOF),
			expected: true,
		},
		{
			name: "websocket CloseNormalClosure",
			err: &websocket.CloseError{
				Code: websocket.CloseNormalClosure,
				Text: "normal closure",
			},
			expected: true,
		},
		{
			name: "websocket CloseGoingAway",
			err: &websocket.CloseError{
				Code: websocket.CloseGoingAway,
				Text: "going away",
			},
			expected: true,
		},
		{
			name: "websocket CloseAbnormalClosure",
			err: &websocket.CloseError{
				Code: websocket.CloseAbnormalClosure,
				Text: "abnormal closure",
			},
			expected: true,
		},
		{
			name: "wrapped CloseAbnormalClosure",
			err: fmt.Errorf("read error: %w", &websocket.CloseError{
				Code: websocket.CloseAbnormalClosure,
				Text: "unexpected EOF",
			}),
			expected: true,
		},
		{
			name: "websocket CloseProtocolError",
			err: &websocket.CloseError{
				Code: websocket.CloseProtocolError,
				Text: "protocol error",
			},
			expected: false,
		},
		{
			name:     "generic unexpected error",
			err:      errors.New("unexpected database error"),
			expected: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			actual := isExpectedDisconnect(tc.err)
			if actual != tc.expected {
				t.Errorf("isExpectedDisconnect(%v) = %v, want %v", tc.err, actual, tc.expected)
			}
		})
	}
}
