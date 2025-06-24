package websocket

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"golang.org/x/time/rate"

	"onthread/internal/models"
	"onthread/pkg/constants"
	"onthread/pkg/logger"

	"github.com/sirupsen/logrus"
)

// Client represents a WebSocket client connection
type Client struct {
	// Connection details
	ID     string             `json:"id"`
	UserID primitive.ObjectID `json:"user_id"`
	User   *models.User       `json:"user,omitempty"`
	Conn   *websocket.Conn    `json:"-"`
	Hub    *Hub               `json:"-"`

	// Communication channels
	Send chan *Message `json:"-"`
	Done chan struct{} `json:"-"`

	// Client state
	IsAuthenticated bool            `json:"is_authenticated"`
	ConnectedAt     time.Time       `json:"connected_at"`
	LastActivity    time.Time       `json:"last_activity"`
	IPAddress       string          `json:"ip_address"`
	UserAgent       string          `json:"user_agent"`
	Rooms           map[string]bool `json:"rooms"`
	IsOnline        bool            `json:"is_online"`

	// Rate limiting
	RateLimiter *rate.Limiter `json:"-"`

	// Concurrency control
	mu sync.RWMutex `json:"-"`

	// Context for cancellation
	ctx    context.Context    `json:"-"`
	cancel context.CancelFunc `json:"-"`

	// Metrics
	MessagesSent     int64 `json:"messages_sent"`
	MessagesReceived int64 `json:"messages_received"`
	ErrorCount       int64 `json:"error_count"`
}

// ClientConfig represents client configuration
type ClientConfig struct {
	WriteWait       time.Duration
	PongWait        time.Duration
	PingPeriod      time.Duration
	MaxMessageSize  int64
	ReadBufferSize  int
	WriteBufferSize int
	RateLimit       rate.Limit
	RateBurst       int
}

// DefaultClientConfig returns default client configuration
func DefaultClientConfig() *ClientConfig {
	return &ClientConfig{
		WriteWait:       constants.WebSocketWriteWait,
		PongWait:        constants.WebSocketPongWait,
		PingPeriod:      constants.WebSocketPingPeriod,
		MaxMessageSize:  constants.WebSocketMessageSizeLimit,
		ReadBufferSize:  constants.WebSocketReadBufferSize,
		WriteBufferSize: constants.WebSocketWriteBufferSize,
		RateLimit:       rate.Limit(30), // 30 messages per second
		RateBurst:       60,             // Allow burst of 60 messages
	}
}

// getClientIP extracts client IP from request
func getClientIP(req *http.Request) string {
	if ip := req.Header.Get("X-Forwarded-For"); ip != "" {
		return strings.Split(ip, ",")[0]
	}
	if ip := req.Header.Get("X-Real-IP"); ip != "" {
		return ip
	}
	return req.RemoteAddr
}

// NewClient creates a new WebSocket client
func NewClient(hub *Hub, conn *websocket.Conn, userID primitive.ObjectID, user *models.User, req *http.Request) *Client {
	ctx, cancel := context.WithCancel(context.Background())

	client := &Client{
		ID:              primitive.NewObjectID().Hex(),
		UserID:          userID,
		User:            user,
		Conn:            conn,
		Hub:             hub,
		Send:            make(chan *Message, 256),
		Done:            make(chan struct{}),
		IsAuthenticated: true,
		ConnectedAt:     time.Now(),
		LastActivity:    time.Now(),
		IPAddress:       getClientIP(req),
		UserAgent:       req.UserAgent(),
		Rooms:           make(map[string]bool),
		IsOnline:        true,
		RateLimiter:     rate.NewLimiter(rate.Limit(30), 60),
		ctx:             ctx,
		cancel:          cancel,
	}

	return client
}

// Start starts the client's read and write pumps
func (c *Client) Start(config *ClientConfig) {
	if config == nil {
		config = DefaultClientConfig()
	}

	// Configure connection
	c.Conn.SetReadLimit(config.MaxMessageSize)
	c.Conn.SetReadDeadline(time.Now().Add(config.PongWait))
	c.Conn.SetPongHandler(func(string) error {
		c.Conn.SetReadDeadline(time.Now().Add(config.PongWait))
		c.UpdateLastActivity()
		return nil
	})

	// Start read and write pumps
	go c.writePump(config)
	go c.readPump(config)
	go c.pingPump(config)

	// Log connection
	logger.WithUserID(c.UserID).WithFields(logrus.Fields{
		"client_id":  c.ID,
		"ip_address": c.IPAddress,
		"user_agent": c.UserAgent,
	}).Info("WebSocket client connected")

	// Notify user came online
	c.Hub.BroadcastToFollowers(c.UserID, CreateOnlineStatusMessage(
		c.UserID.Hex(),
		c.User.Username,
		true,
		time.Now(),
	))
}

// Stop stops the client and closes connections
func (c *Client) Stop() {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.IsOnline {
		c.IsOnline = false

		// Cancel context
		c.cancel()

		// Close channels
		close(c.Done)
		close(c.Send)

		// Close WebSocket connection
		c.Conn.Close()

		// Remove from all rooms
		for room := range c.Rooms {
			c.Hub.LeaveRoom(c, room)
		}

		// Notify user went offline
		c.Hub.BroadcastToFollowers(c.UserID, CreateOnlineStatusMessage(
			c.UserID.Hex(),
			c.User.Username,
			false,
			time.Now(),
		))

		// Log disconnection
		logger.WithUserID(c.UserID).WithFields(logrus.Fields{
			"client_id":         c.ID,
			"duration_seconds":  time.Since(c.ConnectedAt).Seconds(),
			"messages_sent":     c.MessagesSent,
			"messages_received": c.MessagesReceived,
			"error_count":       c.ErrorCount,
		}).Info("WebSocket client disconnected")
	}
}

// SendMessage sends a message to the client
func (c *Client) SendMessage(message *Message) {
	if !c.IsOnline {
		return
	}

	// Set user ID if not set
	if message.UserID == "" {
		message.SetUserID(c.UserID.Hex())
	}

	select {
	case c.Send <- message:
		c.mu.Lock()
		c.MessagesSent++
		c.mu.Unlock()
	default:
		// Channel is full, client is slow
		logger.WithUserID(c.UserID).Warn("Client send channel is full, closing connection")
		c.Stop()
	}
}

// SendError sends an error message to the client
func (c *Client) SendError(code, message, details string) {
	errorMsg := CreateErrorMessage(code, message, details)
	c.SendMessage(errorMsg)

	c.mu.Lock()
	c.ErrorCount++
	c.mu.Unlock()
}

// WriteMessage writes a message to the WebSocket connection
func (c *Client) WriteMessage(message *Message) error {
	data, err := message.ToJSON()
	if err != nil {
		return err
	}
	return c.Conn.WriteMessage(websocket.TextMessage, data)
}

// UpdateLastActivity updates the client's last activity time
func (c *Client) UpdateLastActivity() {
	c.updateLastActivity()
}

// Close closes the client connection
func (c *Client) Close() {
	c.Stop() // Delegate to existing Stop method
}

// JoinRoom adds the client to a room
func (c *Client) JoinRoom(room string) {
	c.mu.Lock()
	c.Rooms[room] = true
	c.mu.Unlock()

	c.Hub.JoinRoom(c, room)

	logger.WithUserID(c.UserID).WithField("room", room).Debug("Client joined room")
}

// LeaveRoom removes the client from a room
func (c *Client) LeaveRoom(room string) {
	c.mu.Lock()
	delete(c.Rooms, room)
	c.mu.Unlock()

	c.Hub.LeaveRoom(c, room)

	logger.WithUserID(c.UserID).WithField("room", room).Debug("Client left room")
}

// IsInRoom checks if client is in a specific room
func (c *Client) IsInRoom(room string) bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.Rooms[room]
}

// GetRooms returns a copy of client's rooms
func (c *Client) GetRooms() []string {
	c.mu.RLock()
	defer c.mu.RUnlock()

	rooms := make([]string, 0, len(c.Rooms))
	for room := range c.Rooms {
		rooms = append(rooms, room)
	}
	return rooms
}

// updateLastActivity updates the last activity timestamp (private method)
func (c *Client) updateLastActivity() {
	c.mu.Lock()
	c.LastActivity = time.Now()
	c.mu.Unlock()
}

// readPump pumps messages from the WebSocket connection to the hub
func (c *Client) readPump(config *ClientConfig) {
	defer c.Stop()

	for {
		select {
		case <-c.ctx.Done():
			return
		default:
			// Read message
			_, messageData, err := c.Conn.ReadMessage()
			if err != nil {
				if websocket.IsUnexpectedCloseError(err, websocket.CloseGoingAway, websocket.CloseAbnormalClosure) {
					logger.WithUserID(c.UserID).WithError(err).Error("WebSocket connection error")
				}
				return
			}

			// Update activity
			c.updateLastActivity()

			// Rate limiting
			if !c.RateLimiter.Allow() {
				c.SendError("RATE_LIMIT_EXCEEDED", "Too many messages", "Please slow down")
				continue
			}

			// Parse message
			message, err := FromJSON(messageData)
			if err != nil {
				c.SendError("INVALID_MESSAGE", "Invalid message format", err.Error())
				continue
			}

			// Validate message
			if !message.IsValid() {
				c.SendError("INVALID_MESSAGE_TYPE", "Invalid message type", message.Type)
				continue
			}

			// Update metrics
			c.mu.Lock()
			c.MessagesReceived++
			c.mu.Unlock()

			// Handle message
			c.handleMessage(message)
		}
	}
}

// writePump pumps messages from the hub to the WebSocket connection
func (c *Client) writePump(config *ClientConfig) {
	ticker := time.NewTicker(config.PingPeriod)
	defer func() {
		ticker.Stop()
		c.Stop()
	}()

	for {
		select {
		case <-c.ctx.Done():
			return
		case message, ok := <-c.Send:
			c.Conn.SetWriteDeadline(time.Now().Add(config.WriteWait))
			if !ok {
				c.Conn.WriteMessage(websocket.CloseMessage, []byte{})
				return
			}

			// Convert message to JSON
			data, err := message.ToJSON()
			if err != nil {
				logger.WithUserID(c.UserID).WithError(err).Error("Failed to marshal WebSocket message")
				continue
			}

			// Write message
			if err := c.Conn.WriteMessage(websocket.TextMessage, data); err != nil {
				logger.WithUserID(c.UserID).WithError(err).Error("Failed to write WebSocket message")
				return
			}

		case <-ticker.C:
			c.Conn.SetWriteDeadline(time.Now().Add(config.WriteWait))
			if err := c.Conn.WriteMessage(websocket.PingMessage, nil); err != nil {
				return
			}
		}
	}
}

// pingPump sends periodic ping messages
func (c *Client) pingPump(config *ClientConfig) {
	ticker := time.NewTicker(config.PingPeriod)
	defer ticker.Stop()

	for {
		select {
		case <-c.ctx.Done():
			return
		case <-ticker.C:
			// Send ping message through the message system
			pingMsg := CreatePingMessage()
			c.SendMessage(pingMsg)
		}
	}
}

// handleMessage handles incoming messages from the client
func (c *Client) handleMessage(message *Message) {
	switch message.Type {
	case constants.WSTypePong:
		// Handle pong response
		c.updateLastActivity()

	case "subscribe":
		// Handle room subscription
		c.handleSubscribeMessage(message)

	case "user_activity":
		// Handle user activity updates
		c.handleUserActivityMessage(message)

	case constants.WSTypeTyping:
		// Handle typing indicator
		c.handleTypingMessage(message)

	case constants.WSTypeMessage:
		// Handle direct messages (should be handled through HTTP API)
		c.SendError("UNSUPPORTED_OPERATION", "Direct messages should be sent through HTTP API", "")

	default:
		// Unknown message type
		c.SendError("UNKNOWN_MESSAGE_TYPE", "Unknown message type", message.Type)
	}
}

// handleSubscribeMessage handles room subscription messages
func (c *Client) handleSubscribeMessage(message *Message) {
	var subMsg SubscribeMessage
	data, _ := json.Marshal(message.Data)
	if err := json.Unmarshal(data, &subMsg); err != nil {
		c.SendError("INVALID_SUBSCRIBE_MESSAGE", "Invalid subscribe message format", err.Error())
		return
	}

	switch subMsg.Action {
	case "join":
		c.JoinRoom(subMsg.Room)
	case "leave":
		c.LeaveRoom(subMsg.Room)
	default:
		c.SendError("INVALID_SUBSCRIBE_ACTION", "Invalid subscribe action", subMsg.Action)
	}
}

// handleUserActivityMessage handles user activity updates
func (c *Client) handleUserActivityMessage(message *Message) {
	var activityMsg UserActivityMessage
	data, _ := json.Marshal(message.Data)
	if err := json.Unmarshal(data, &activityMsg); err != nil {
		c.SendError("INVALID_ACTIVITY_MESSAGE", "Invalid activity message format", err.Error())
		return
	}

	// Update user activity in hub
	c.Hub.UpdateUserActivity(c.UserID, activityMsg.Activity, activityMsg.ResourceID, activityMsg.ResourceType)
}

// handleTypingMessage handles typing indicator messages
func (c *Client) handleTypingMessage(message *Message) {
	var typingMsg TypingMessage
	data, _ := json.Marshal(message.Data)
	if err := json.Unmarshal(data, &typingMsg); err != nil {
		c.SendError("INVALID_TYPING_MESSAGE", "Invalid typing message format", err.Error())
		return
	}

	// Set user info
	typingMsg.UserID = c.UserID.Hex()
	typingMsg.Username = c.User.Username

	// Broadcast typing indicator to conversation participants
	if typingMsg.ConversationID != "" {
		typingMessage := CreateTypingMessage(
			typingMsg.ConversationID,
			typingMsg.UserID,
			typingMsg.Username,
			typingMsg.IsTyping,
		)

		// Broadcast to conversation room
		roomID := fmt.Sprintf("conversation:%s", typingMsg.ConversationID)
		c.Hub.BroadcastToRoom(roomID, typingMessage, c.UserID)
	}
}
