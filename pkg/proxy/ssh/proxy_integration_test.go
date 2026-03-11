package ssh

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"testing"

	"github.com/pkg/sftp"
	gossh "golang.org/x/crypto/ssh"

	"nudgebee/forager/pkg/proxy"
)

// mockSSHServer spins up an in-memory SSH server for integration tests.
type mockSSHServer struct {
	listener net.Listener
	config   *gossh.ServerConfig
	addr     string
}

func newMockSSHServer(t *testing.T) *mockSSHServer {
	t.Helper()

	// Generate host key
	hostKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate host key: %v", err)
	}
	hostSigner, err := gossh.NewSignerFromKey(hostKey)
	if err != nil {
		t.Fatalf("host signer: %v", err)
	}

	config := &gossh.ServerConfig{
		PasswordCallback: func(conn gossh.ConnMetadata, password []byte) (*gossh.Permissions, error) {
			if conn.User() == "testuser" && string(password) == "testpass" {
				return nil, nil
			}
			return nil, fmt.Errorf("auth failed")
		},
	}
	config.AddHostKey(hostSigner)

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}

	s := &mockSSHServer{
		listener: listener,
		config:   config,
		addr:     listener.Addr().String(),
	}

	go s.serve(t)
	return s
}

func (s *mockSSHServer) serve(t *testing.T) {
	t.Helper()
	for {
		conn, err := s.listener.Accept()
		if err != nil {
			return // listener closed
		}
		go s.handleConn(t, conn)
	}
}

func (s *mockSSHServer) handleConn(t *testing.T, nConn net.Conn) {
	t.Helper()
	sshConn, chans, reqs, err := gossh.NewServerConn(nConn, s.config)
	if err != nil {
		return
	}
	defer func() { _ = sshConn.Close() }()

	go gossh.DiscardRequests(reqs)

	for newChan := range chans {
		switch newChan.ChannelType() {
		case "session":
			go s.handleSession(t, newChan)
		case "subsystem":
			go s.handleSession(t, newChan)
		default:
			_ = newChan.Reject(gossh.UnknownChannelType, "unknown channel type")
		}
	}
}

func (s *mockSSHServer) handleSession(t *testing.T, newChan gossh.NewChannel) {
	t.Helper()
	ch, reqs, err := newChan.Accept()
	if err != nil {
		return
	}
	defer func() { _ = ch.Close() }()

	for req := range reqs {
		switch req.Type {
		case "exec":
			// Parse command from the request payload
			// SSH exec payload: uint32 len + string command
			if len(req.Payload) < 4 {
				_ = req.Reply(false, nil)
				continue
			}
			cmdLen := int(req.Payload[0])<<24 | int(req.Payload[1])<<16 | int(req.Payload[2])<<8 | int(req.Payload[3])
			if len(req.Payload) < 4+cmdLen {
				_ = req.Reply(false, nil)
				continue
			}
			cmd := string(req.Payload[4 : 4+cmdLen])
			_ = req.Reply(true, nil)

			switch cmd {
			case "echo hello":
				_, _ = ch.Write([]byte("hello\n"))
				sendExitStatus(ch, 0)
			case "exit 42":
				_, _ = ch.Stderr().Write([]byte("error occurred\n"))
				sendExitStatus(ch, 42)
			case "echo stderr >&2":
				_, _ = ch.Stderr().Write([]byte("stderr output\n"))
				sendExitStatus(ch, 0)
			default:
				_, _ = fmt.Fprintf(ch, "executed: %s\n", cmd)
				sendExitStatus(ch, 0)
			}
			return

		case "subsystem":
			// SFTP subsystem
			if len(req.Payload) < 4 {
				_ = req.Reply(false, nil)
				continue
			}
			subsysLen := int(req.Payload[0])<<24 | int(req.Payload[1])<<16 | int(req.Payload[2])<<8 | int(req.Payload[3])
			subsys := string(req.Payload[4 : 4+subsysLen])
			if subsys == "sftp" {
				_ = req.Reply(true, nil)
				server, err := sftp.NewServer(ch)
				if err != nil {
					return
				}
				_ = server.Serve()
				return
			}
			_ = req.Reply(false, nil)

		default:
			if req.WantReply {
				_ = req.Reply(false, nil)
			}
		}
	}
}

func sendExitStatus(ch gossh.Channel, code uint32) {
	_, _ = ch.SendRequest("exit-status", false, gossh.Marshal(struct{ Status uint32 }{code}))
	_ = ch.CloseWrite()
}

func (s *mockSSHServer) close() {
	_ = s.listener.Close()
}

// configureProxy creates and configures a Proxy connected to the mock server.
func configureProxy(t *testing.T, s *mockSSHServer) *Proxy {
	t.Helper()
	host, port, _ := net.SplitHostPort(s.addr)

	p := New(testLogger())
	err := p.Configure(
		map[string]any{"host": host, "port": port}, // port as string — tests the coercion fix
		map[string]string{"username": "testuser", "password": "testpass"},
	)
	if err != nil {
		t.Fatalf("configure proxy: %v", err)
	}
	return p
}

// --- Happy-path tests ---

func TestIntegration_ExecCommand(t *testing.T) {
	srv := newMockSSHServer(t)
	defer srv.close()

	p := configureProxy(t, srv)
	defer func() { _ = p.Close() }()

	resp, err := p.HandleRequest(context.Background(), &proxy.ActionRequest{
		Action: "ssh_command",
		Params: map[string]any{"command": "echo hello"},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.StatusCode != 200 {
		t.Fatalf("expected status 200, got %d", resp.StatusCode)
	}

	var result map[string]any
	if err := json.Unmarshal([]byte(resp.Data), &result); err != nil {
		t.Fatalf("unmarshal response data: %v", err)
	}

	if result["stdout"] != "hello\n" {
		t.Errorf("expected stdout 'hello\\n', got %q", result["stdout"])
	}
	if result["exit_code"].(float64) != 0 {
		t.Errorf("expected exit_code 0, got %v", result["exit_code"])
	}
}

func TestIntegration_ExecCommand_NonZeroExit(t *testing.T) {
	srv := newMockSSHServer(t)
	defer srv.close()

	p := configureProxy(t, srv)
	defer func() { _ = p.Close() }()

	resp, err := p.HandleRequest(context.Background(), &proxy.ActionRequest{
		Action: "ssh_command",
		Params: map[string]any{"command": "exit 42"},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var result map[string]any
	if err := json.Unmarshal([]byte(resp.Data), &result); err != nil {
		t.Fatalf("unmarshal response data: %v", err)
	}

	if result["exit_code"].(float64) != 42 {
		t.Errorf("expected exit_code 42, got %v", result["exit_code"])
	}
	if result["stderr"] != "error occurred\n" {
		t.Errorf("expected stderr 'error occurred\\n', got %q", result["stderr"])
	}
}

func TestIntegration_ExecCommand_Stderr(t *testing.T) {
	srv := newMockSSHServer(t)
	defer srv.close()

	p := configureProxy(t, srv)
	defer func() { _ = p.Close() }()

	resp, err := p.HandleRequest(context.Background(), &proxy.ActionRequest{
		Action: "ssh_command",
		Params: map[string]any{"command": "echo stderr >&2"},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var result map[string]any
	if err := json.Unmarshal([]byte(resp.Data), &result); err != nil {
		t.Fatalf("unmarshal response data: %v", err)
	}

	if result["stderr"] != "stderr output\n" {
		t.Errorf("expected stderr 'stderr output\\n', got %q", result["stderr"])
	}
	if result["exit_code"].(float64) != 0 {
		t.Errorf("expected exit_code 0, got %v", result["exit_code"])
	}
}

func TestIntegration_UploadDownload(t *testing.T) {
	srv := newMockSSHServer(t)
	defer srv.close()

	p := configureProxy(t, srv)
	defer func() { _ = p.Close() }()

	content := "hello from forager"
	contentB64 := base64.StdEncoding.EncodeToString([]byte(content))
	remotePath := t.TempDir() + "/upload_test.txt"

	// Upload
	uploadResp, err := p.HandleRequest(context.Background(), &proxy.ActionRequest{
		Action: "ssh_upload",
		Params: map[string]any{
			"remote_path": remotePath,
			"content":     contentB64,
		},
	})
	if err != nil {
		t.Fatalf("upload error: %v", err)
	}
	if uploadResp.StatusCode != 200 {
		t.Fatalf("upload status: expected 200, got %d", uploadResp.StatusCode)
	}

	var uploadResult map[string]any
	if err := json.Unmarshal([]byte(uploadResp.Data), &uploadResult); err != nil {
		t.Fatalf("unmarshal upload response: %v", err)
	}
	if int(uploadResult["bytes_written"].(float64)) != len(content) {
		t.Errorf("expected %d bytes written, got %v", len(content), uploadResult["bytes_written"])
	}

	// Download and verify
	downloadResp, err := p.HandleRequest(context.Background(), &proxy.ActionRequest{
		Action: "ssh_download",
		Params: map[string]any{"remote_path": remotePath},
	})
	if err != nil {
		t.Fatalf("download error: %v", err)
	}
	if downloadResp.StatusCode != 200 {
		t.Fatalf("download status: expected 200, got %d", downloadResp.StatusCode)
	}

	var downloadResult map[string]any
	if err := json.Unmarshal([]byte(downloadResp.Data), &downloadResult); err != nil {
		t.Fatalf("unmarshal download response: %v", err)
	}

	decoded, err := base64.StdEncoding.DecodeString(downloadResult["content"].(string))
	if err != nil {
		t.Fatalf("decode downloaded content: %v", err)
	}
	if string(decoded) != content {
		t.Errorf("expected content %q, got %q", content, string(decoded))
	}
}

func TestIntegration_ListDir(t *testing.T) {
	srv := newMockSSHServer(t)
	defer srv.close()

	p := configureProxy(t, srv)
	defer func() { _ = p.Close() }()

	// Upload a file first so the directory isn't empty
	dir := t.TempDir()
	contentB64 := base64.StdEncoding.EncodeToString([]byte("test"))
	_, err := p.HandleRequest(context.Background(), &proxy.ActionRequest{
		Action: "ssh_upload",
		Params: map[string]any{"remote_path": dir + "/file.txt", "content": contentB64},
	})
	if err != nil {
		t.Fatalf("upload for list_dir setup: %v", err)
	}

	// List directory
	resp, err := p.HandleRequest(context.Background(), &proxy.ActionRequest{
		Action: "ssh_list_dir",
		Params: map[string]any{"remote_path": dir},
	})
	if err != nil {
		t.Fatalf("list_dir error: %v", err)
	}
	if resp.StatusCode != 200 {
		t.Fatalf("list_dir status: expected 200, got %d", resp.StatusCode)
	}

	var entries []map[string]any
	if err := json.Unmarshal([]byte(resp.Data), &entries); err != nil {
		t.Fatalf("unmarshal list_dir response: %v", err)
	}
	if len(entries) == 0 {
		t.Fatal("expected at least one directory entry")
	}

	found := false
	for _, e := range entries {
		if e["name"] == "file.txt" {
			found = true
			if e["is_dir"].(bool) {
				t.Error("expected file.txt to not be a directory")
			}
		}
	}
	if !found {
		t.Errorf("expected to find file.txt in listing, got %v", entries)
	}
}

func TestIntegration_HealthCheck(t *testing.T) {
	srv := newMockSSHServer(t)
	defer srv.close()

	p := configureProxy(t, srv)
	defer func() { _ = p.Close() }()

	if err := p.HealthCheck(context.Background()); err != nil {
		t.Fatalf("health check failed: %v", err)
	}
}

func TestIntegration_Configure_PortAsString(t *testing.T) {
	srv := newMockSSHServer(t)
	defer srv.close()

	host, port, _ := net.SplitHostPort(srv.addr)

	p := New(testLogger())
	// Pass port as string — this is what the relay actually sends
	err := p.Configure(
		map[string]any{"host": host, "port": port},
		map[string]string{"username": "testuser", "password": "testpass"},
	)
	if err != nil {
		t.Fatalf("configure with string port should work: %v", err)
	}
	defer func() { _ = p.Close() }()

	// Verify it actually works
	resp, err := p.HandleRequest(context.Background(), &proxy.ActionRequest{
		Action: "ssh_command",
		Params: map[string]any{"command": "echo hello"},
	})
	if err != nil {
		t.Fatalf("exec after string port configure: %v", err)
	}
	if resp.StatusCode != 200 {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
}

func TestIntegration_Close(t *testing.T) {
	srv := newMockSSHServer(t)
	defer srv.close()

	p := configureProxy(t, srv)

	if err := p.Close(); err != nil {
		t.Fatalf("close failed: %v", err)
	}

	// Requests should fail after close
	_, err := p.HandleRequest(context.Background(), &proxy.ActionRequest{
		Action: "ssh_command",
		Params: map[string]any{"command": "echo hello"},
	})
	if err == nil {
		t.Fatal("expected error after close")
	}
}

