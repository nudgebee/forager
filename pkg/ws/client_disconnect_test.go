package ws

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"syscall"
	"testing"

	"github.com/gorilla/websocket"
)

type customNetError struct{}

func (e *customNetError) Error() string   { return "custom net error" }
func (e *customNetError) Timeout() bool   { return true }
func (e *customNetError) Temporary() bool { return true }

func TestIsRoutineDisconnect(t *testing.T) {
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
			name: "dialHTTPError 401 unauthorized",
			err: &dialHTTPError{
				StatusCode: 401,
				Body:       []byte("unauthorized"),
				Err:        errors.New("bad status"),
			},
			expected: false,
		},
		{
			name: "dialHTTPError 403 forbidden",
			err: &dialHTTPError{
				StatusCode: 403,
				Body:       []byte("forbidden"),
				Err:        errors.New("bad status"),
			},
			expected: false,
		},
		{
			name: "dialHTTPError 500 internal server error",
			err: &dialHTTPError{
				StatusCode: 500,
				Body:       []byte("internal error"),
				Err:        errors.New("bad status"),
			},
			expected: true,
		},
		{
			name: "dialHTTPError 502 bad gateway",
			err: &dialHTTPError{
				StatusCode: 502,
				Body:       []byte("bad gateway"),
				Err:        errors.New("bad status"),
			},
			expected: true,
		},
		{
			name:     "context canceled",
			err:      context.Canceled,
			expected: true,
		},
		{
			name:     "context deadline exceeded",
			err:      context.DeadlineExceeded,
			expected: true,
		},
		{
			name: "websocket close error",
			err: &websocket.CloseError{
				Code: websocket.CloseGoingAway,
				Text: "going away",
			},
			expected: true,
		},
		{
			name:     "io EOF",
			err:      io.EOF,
			expected: true,
		},
		{
			name:     "io ErrUnexpectedEOF",
			err:      io.ErrUnexpectedEOF,
			expected: true,
		},
		{
			name:     "syscall ECONNRESET",
			err:      syscall.ECONNRESET,
			expected: true,
		},
		{
			name:     "syscall ECONNREFUSED",
			err:      syscall.ECONNREFUSED,
			expected: true,
		},
		{
			name:     "syscall EPIPE",
			err:      syscall.EPIPE,
			expected: true,
		},
		{
			name:     "net.Error",
			err:      &customNetError{},
			expected: true,
		},
		{
			name:     "wrapped net.OpError",
			err:      &net.OpError{Op: "dial", Net: "tcp", Err: errors.New("timeout")},
			expected: true,
		},
		{
			name:     "wrapped routine error",
			err:      fmt.Errorf("connection failed: %w", syscall.ECONNRESET),
			expected: true,
		},
		{
			name:     "arbitrary internal error",
			err:      errors.New("unhandled failure"),
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isRoutineDisconnect(tt.err)
			if got != tt.expected {
				t.Errorf("isRoutineDisconnect(%v) = %v, want %v", tt.err, got, tt.expected)
			}
		})
	}
}

func TestDialHTTPError(t *testing.T) {
	underlying := errors.New("handshake failed")
	err := &dialHTTPError{
		StatusCode: 401,
		Body:       []byte("unauthorized access"),
		Err:        underlying,
	}

	if !errors.Is(err, underlying) {
		t.Errorf("errors.Is(err, underlying) = false, want true")
	}

	expectedStr := `dial failed: handshake failed (status=401 body="unauthorized access")`
	if err.Error() != expectedStr {
		t.Errorf("err.Error() = %q, want %q", err.Error(), expectedStr)
	}
}
