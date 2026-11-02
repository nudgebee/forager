package ws

import (
	"context"
	"errors"
	"io"
	"net"
	"testing"

	"github.com/gorilla/websocket"
)

func TestIsTransientCloseError(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{"nil error", nil, false},
		{"io.EOF", io.EOF, true},
		{"io.ErrUnexpectedEOF", io.ErrUnexpectedEOF, true},
		{"context.Canceled", context.Canceled, true},
		{"CloseGoingAway", &websocket.CloseError{Code: websocket.CloseGoingAway}, true},
		{"CloseNormalClosure", &websocket.CloseError{Code: websocket.CloseNormalClosure}, true},
		{"CloseNoStatusReceived", &websocket.CloseError{Code: websocket.CloseNoStatusReceived}, true},
		{"CloseAbnormalClosure", &websocket.CloseError{Code: websocket.CloseAbnormalClosure}, true},
		{"CloseServiceRestart", &websocket.CloseError{Code: websocket.CloseServiceRestart}, true},
		{"CloseTryAgainLater", &websocket.CloseError{Code: websocket.CloseTryAgainLater}, true},
		{"CloseProtocolError", &websocket.CloseError{Code: websocket.CloseProtocolError}, false},
		{"CloseUnsupportedData", &websocket.CloseError{Code: websocket.CloseUnsupportedData}, false},
		{"net.OpError", &net.OpError{Op: "read", Net: "tcp", Err: errors.New("connection reset by peer")}, true},
		{"generic error", errors.New("some unexpected error"), false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isTransientCloseError(tt.err); got != tt.want {
				t.Errorf("isTransientCloseError() = %v, want %v", got, tt.want)
			}
		})
	}
}
