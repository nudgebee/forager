package ws

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"sync"
	"time"

	"github.com/gorilla/websocket"
)

const (
	writeWait  = 10 * time.Second
	pongWait   = 40 * time.Second
	pingPeriod = 30 * time.Second

	maxReconnectDelay   = 30 * time.Second
	initialDelay        = 3 * time.Second
	defaultHealthPeriod = 10 * time.Minute
	initialHealthDelay  = 10 * time.Second
)

// HealthReportFunc returns per-datasource health to be sent to the relay.
type HealthReportFunc func(ctx context.Context) map[string]any

// DatasourceInventoryItem describes a locally configured datasource for auto-registration.
type DatasourceInventoryItem struct {
	ID        string `json:"id"`
	Type      string `json:"type"`
	ProxyType string `json:"proxy_type"`
	Name      string `json:"name"`
}

// InventoryReportFunc returns the list of locally configured datasources.
type InventoryReportFunc func() []DatasourceInventoryItem

// MetadataReportFunc collects version and metadata from all datasources.
// Returns datasourceID → metadata map.
type MetadataReportFunc func(ctx context.Context) map[string]map[string]any

// Client manages the WebSocket connection to the relay server.
type Client struct {
	relayURL     string
	accessKey    string
	accessSecret string
	handler      MessageHandler
	healthFn     HealthReportFunc
	healthPeriod time.Duration
	inventoryFn  InventoryReportFunc
	metadataFn   MetadataReportFunc

	conn   *websocket.Conn
	connMu sync.Mutex
	sendCh chan []byte

	logger *slog.Logger
	done   chan struct{}
}

// MessageHandler processes incoming messages from the relay server.
type MessageHandler interface {
	HandleMessage(ctx context.Context, msg []byte) ([]byte, error)
}

// NewClient creates a new WebSocket client.
// healthCheckIntervalMin sets the health report interval in minutes. If <= 0, defaults to 10 minutes.
func NewClient(relayURL, accessKey, accessSecret string, handler MessageHandler, logger *slog.Logger, healthCheckIntervalMin int) *Client {
	period := defaultHealthPeriod
	if healthCheckIntervalMin > 0 {
		period = time.Duration(healthCheckIntervalMin) * time.Minute
	}
	return &Client{
		relayURL:     relayURL,
		accessKey:    accessKey,
		accessSecret: accessSecret,
		handler:      handler,
		healthPeriod: period,
		sendCh:       make(chan []byte, 64),
		logger:       logger,
		done:         make(chan struct{}),
	}
}

// SetHealthReporter sets the function called periodically to report datasource health.
func (c *Client) SetHealthReporter(fn HealthReportFunc) {
	c.healthFn = fn
}

// SetInventoryReporter sets the function called on connect to register local datasources.
func (c *Client) SetInventoryReporter(fn InventoryReportFunc) {
	c.inventoryFn = fn
}

// SetMetadataReporter sets the function called on connect to collect and send datasource metadata.
func (c *Client) SetMetadataReporter(fn MetadataReportFunc) {
	c.metadataFn = fn
}

// Run connects and maintains the WebSocket connection with auto-reconnect.
// Blocks until context is cancelled.
func (c *Client) Run(ctx context.Context) error {
	delay := initialDelay

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		err := c.connectAndServe(ctx)
		if err != nil {
			c.logger.Error("websocket session ended", "err", err)
		}

		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(delay):
		}

		// Exponential backoff
		delay = delay * 2
		if delay > maxReconnectDelay {
			delay = maxReconnectDelay
		}
		c.logger.Info("reconnecting to relay", "delay", delay)
	}
}

func (c *Client) connectAndServe(ctx context.Context) error {
	// Build auth header
	auth := base64.StdEncoding.EncodeToString([]byte(c.accessKey + ":" + c.accessSecret))
	header := http.Header{}
	header.Set("Authorization", "Basic "+auth)

	c.logger.Info("connecting to relay", "url", c.relayURL)

	conn, _, err := websocket.DefaultDialer.DialContext(ctx, c.relayURL, header)
	if err != nil {
		return fmt.Errorf("dial failed: %w", err)
	}

	c.connMu.Lock()
	c.conn = conn
	c.connMu.Unlock()

	defer func() {
		_ = conn.Close()
		c.connMu.Lock()
		c.conn = nil
		c.connMu.Unlock()
	}()

	// Send greeting
	greeting := map[string]any{
		"action":     "auth",
		"agent_type": "proxy",
		"version":    "1.0.0",
		"capabilities": map[string]bool{
			"http-proxy":  true,
			"db-proxy":    true,
			"mcp-proxy":   true,
			"ssh-proxy":   true,
			"mongo-proxy": true,
			"redis-proxy": true,
			"kafka-proxy": true,
		},
	}
	greetingBytes, _ := json.Marshal(greeting)
	if err := conn.WriteMessage(websocket.TextMessage, greetingBytes); err != nil {
		return fmt.Errorf("greeting send failed: %w", err)
	}

	c.logger.Info("connected to relay, greeting sent")

	// Send datasource inventory for auto-registration
	c.sendInventory()

	// Setup ping/pong
	conn.SetReadDeadline(time.Now().Add(pongWait)) // nolint:errcheck
	conn.SetPongHandler(func(string) error {
		conn.SetReadDeadline(time.Now().Add(pongWait)) // nolint:errcheck
		return nil
	})

	// Start writer, pinger, reader
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	var wg sync.WaitGroup

	// Writer goroutine
	wg.Add(1)
	go func() {
		defer wg.Done()
		c.writeLoop(ctx, conn)
	}()

	// Ping goroutine
	wg.Add(1)
	go func() {
		defer wg.Done()
		c.pingLoop(ctx, conn)
	}()

	// Health reporting goroutine
	if c.healthFn != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			c.healthReportLoop(ctx)
		}()
	}

	// Metadata collection goroutine (runs once, async)
	if c.metadataFn != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			c.sendMetadata(ctx)
		}()
	}

	// Reader (blocking)
	err = c.readLoop(ctx, conn)

	cancel()
	wg.Wait()
	return err
}

func (c *Client) readLoop(ctx context.Context, conn *websocket.Conn) error {
	for {
		conn.SetReadDeadline(time.Now().Add(pongWait)) // nolint:errcheck
		_, msg, err := conn.ReadMessage()
		if err != nil {
			if websocket.IsCloseError(err, websocket.CloseNormalClosure, websocket.CloseGoingAway) {
				return nil
			}
			return fmt.Errorf("read error: %w", err)
		}

		// Process message in goroutine to not block reading
		go func(raw []byte) {
			resp, err := c.handler.HandleMessage(ctx, raw)
			if err != nil {
				c.logger.Error("handler error", "err", err)
				return
			}
			if resp != nil {
				c.Send(resp)
			}
		}(msg)
	}
}

func (c *Client) writeLoop(ctx context.Context, conn *websocket.Conn) {
	for {
		select {
		case <-ctx.Done():
			return
		case msg := <-c.sendCh:
			conn.SetWriteDeadline(time.Now().Add(writeWait)) // nolint:errcheck
			if err := conn.WriteMessage(websocket.TextMessage, msg); err != nil {
				c.logger.Error("write error", "err", err)
				return
			}
		}
	}
}

func (c *Client) pingLoop(ctx context.Context, conn *websocket.Conn) {
	ticker := time.NewTicker(pingPeriod)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			conn.SetWriteDeadline(time.Now().Add(writeWait)) // nolint:errcheck
			if err := conn.WriteMessage(websocket.PingMessage, nil); err != nil {
				c.logger.Error("ping error", "err", err)
				return
			}
		}
	}
}

func (c *Client) healthReportLoop(ctx context.Context) {
	// Wait a bit before first report to let datasources initialize
	select {
	case <-ctx.Done():
		return
	case <-time.After(initialHealthDelay):
	}

	ticker := time.NewTicker(c.healthPeriod)
	defer ticker.Stop()

	for {
		c.sendHealthReport(ctx)

		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

func (c *Client) sendInventory() {
	if c.inventoryFn == nil {
		return
	}

	items := c.inventoryFn()
	if len(items) == 0 {
		return
	}

	msg := map[string]any{
		"action":      "datasource_inventory",
		"datasources": items,
	}
	data, err := json.Marshal(msg)
	if err != nil {
		c.logger.Error("failed to marshal datasource inventory", "err", err)
		return
	}
	c.Send(data)
	c.logger.Info("sent datasource inventory for auto-registration", "datasource_count", len(items))
}

func (c *Client) sendMetadata(ctx context.Context) {
	if c.metadataFn == nil {
		return
	}

	metadata := c.metadataFn(ctx)
	if len(metadata) == 0 {
		return
	}

	msg := map[string]any{
		"action":   "datasource_metadata",
		"metadata": metadata,
	}
	data, err := json.Marshal(msg)
	if err != nil {
		c.logger.Error("failed to marshal datasource metadata", "err", err)
		return
	}
	c.Send(data)
	c.logger.Info("sent datasource metadata", "datasource_count", len(metadata))
}

func (c *Client) sendHealthReport(ctx context.Context) {
	report := c.healthFn(ctx)
	if len(report) == 0 {
		return
	}

	msg := map[string]any{
		"action":      "datasource_health_update",
		"datasources": report,
	}
	data, err := json.Marshal(msg)
	if err != nil {
		c.logger.Error("failed to marshal health report", "err", err)
		return
	}
	c.Send(data)
	c.logger.Debug("sent datasource health report", "datasource_count", len(report))
}

// Send queues a message to be sent over the WebSocket.
func (c *Client) Send(msg []byte) {
	select {
	case c.sendCh <- msg:
	default:
		c.logger.Warn("send channel full, dropping message")
	}
}
