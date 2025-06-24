package handlers

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"go.mongodb.org/mongo-driver/bson/primitive"

	"onthread/internal/services"
	"onthread/internal/utils"
	"onthread/internal/websocket"
	"onthread/pkg/constants"
	"onthread/pkg/logger"
)

// WebSocketHandler handles WebSocket connections and real-time communication
type WebSocketHandler struct {
	hub         *websocket.Hub
	authService services.AuthService
	upgrader    websocket.Upgrader
}

// NewWebSocketHandler creates a new WebSocket handler
func NewWebSocketHandler(hub *websocket.Hub, authService services.AuthService) *WebSocketHandler {
	return &WebSocketHandler{
		hub:         hub,
		authService: authService,
		upgrader: websocket.Upgrader{
			ReadBufferSize:  1024,
			WriteBufferSize: 1024,
			CheckOrigin: func(r *http.Request) bool {
				// Configure based on your CORS policy
				// For production, implement proper origin checking
				return true
			},
			EnableCompression: true,
		},
	}
}

// ===============================
// Main WebSocket Connection Handler
// ===============================

// HandleWebSocketConnection handles WebSocket connection requests
func (h *WebSocketHandler) HandleWebSocketConnection(c *gin.Context) {
	// Get authentication token
	token := h.extractToken(c)
	if token == "" {
		utils.Unauthorized(c, "Authentication token required")
		return
	}

	// Validate token and get user info
	userID, err := h.authService.ValidateToken(token)
	if err != nil {
		utils.Unauthorized(c, "Invalid authentication token")
		return
	}

	// Upgrade connection to WebSocket
	conn, err := h.upgrader.Upgrade(c.Writer, c.Request, nil)
	if err != nil {
		logger.WithError(err).Error("Failed to upgrade WebSocket connection")
		return
	}

	// Get user details
	user, err := h.authService.GetUserByID(c.Request.Context(), userID)
	if err != nil {
		conn.Close()
		logger.WithError(err).WithUserID(userID).Error("Failed to get user details for WebSocket connection")
		return
	}

	// Create WebSocket client
	client := websocket.NewClient(
		conn,
		userID,
		user.Username,
		c.ClientIP(),
		c.GetHeader("User-Agent"),
		h.hub,
	)

	// Register client with hub
	h.hub.RegisterClient(client)

	// Start client handlers in goroutines
	go h.handleClientWrite(client)
	go h.handleClientRead(client)

	logger.WithUserID(userID).WithField("username", user.Username).Info("WebSocket client connected")
}

// extractToken extracts authentication token from request
func (h *WebSocketHandler) extractToken(c *gin.Context) string {
	// Try query parameter first
	token := c.Query("token")
	if token != "" {
		return token
	}

	// Try authorization header
	authHeader := c.GetHeader("Authorization")
	if authHeader != "" && len(authHeader) > 7 && authHeader[:7] == "Bearer " {
		return authHeader[7:]
	}

	return ""
}

// ===============================
// Client Communication Handlers
// ===============================

// handleClientWrite handles writing messages to client
func (h *WebSocketHandler) handleClientWrite(client *websocket.Client) {
	defer func() {
		client.Close()
	}()

	// Set up ping ticker for keep-alive
	pingTicker := time.NewTicker(constants.WebSocketPingPeriod)
	defer pingTicker.Stop()

	for {
		select {
		case message, ok := <-client.SendChan:
			client.Conn.SetWriteDeadline(time.Now().Add(constants.WebSocketWriteWait))

			if !ok {
				// Channel closed
				client.Conn.WriteMessage(websocket.CloseMessage, []byte{})
				return
			}

			// Send message
			if err := client.WriteMessage(message); err != nil {
				logger.WithError(err).WithUserID(client.UserID).Error("Failed to write WebSocket message")
				return
			}

		case <-pingTicker.C:
			client.Conn.SetWriteDeadline(time.Now().Add(constants.WebSocketWriteWait))
			if err := client.Conn.WriteMessage(websocket.PingMessage, nil); err != nil {
				logger.WithError(err).WithUserID(client.UserID).Error("Failed to send ping message")
				return
			}

		case <-client.Done:
			return
		}
	}
}

// handleClientRead handles reading messages from client
func (h *WebSocketHandler) handleClientRead(client *websocket.Client) {
	defer func() {
		h.hub.UnregisterClient(client)
		client.Close()
	}()

	// Configure connection settings
	client.Conn.SetReadLimit(constants.WebSocketMessageSizeLimit)
	client.Conn.SetReadDeadline(time.Now().Add(constants.WebSocketPongWait))
	client.Conn.SetPongHandler(func(string) error {
		client.Conn.SetReadDeadline(time.Now().Add(constants.WebSocketPongWait))
		client.UpdateLastActivity()
		return nil
	})

	for {
		// Read message
		_, messageData, err := client.Conn.ReadMessage()
		if err != nil {
			if websocket.IsUnexpectedCloseError(err, websocket.CloseGoingAway, websocket.CloseAbnormalClosure) {
				logger.WithError(err).WithUserID(client.UserID).Error("Unexpected WebSocket close error")
			}
			break
		}

		// Update client activity
		client.UpdateLastActivity()

		// Parse message
		var message websocket.Message
		if err := json.Unmarshal(messageData, &message); err != nil {
			logger.WithError(err).WithUserID(client.UserID).Error("Failed to parse WebSocket message")
			client.SendError("invalid_message", "Failed to parse message", "")
			continue
		}

		// Validate message
		if !message.IsValid() {
			client.SendError("invalid_message_type", "Invalid message type", "")
			continue
		}

		// Set user ID for message
		message.SetUserID(client.UserID.Hex())

		// Handle message based on type
		h.handleIncomingMessage(client, &message)
	}
}

// ===============================
// Message Processing
// ===============================

// handleIncomingMessage handles incoming WebSocket messages
func (h *WebSocketHandler) handleIncomingMessage(client *websocket.Client, message *websocket.Message) {
	switch message.Type {
	case constants.WSTypePing:
		// Respond with pong
		h.handlePingMessage(client, message)

	case constants.WSTypePong:
		// Update last activity (already done in pong handler)
		break

	case "subscribe":
		h.handleRoomSubscription(client, message)

	case "user_activity":
		h.handleUserActivity(client, message)

	case constants.WSTypeTyping:
		h.handleTypingIndicator(client, message)

	case "auth":
		h.handleAuthMessage(client, message)

	case constants.WSTypeMessage:
		h.handleDirectMessage(client, message)

	case "heartbeat":
		h.handleHeartbeat(client, message)

	default:
		// Forward message to appropriate handler based on context
		h.forwardMessage(client, message)
	}
}

// handlePingMessage responds to ping with pong
func (h *WebSocketHandler) handlePingMessage(client *websocket.Client, message *websocket.Message) {
	pongMessage := websocket.CreatePongMessage()
	client.SendMessage(pongMessage)
}

// handleRoomSubscription handles room subscription/unsubscription
func (h *WebSocketHandler) handleRoomSubscription(client *websocket.Client, message *websocket.Message) {
	var subscribeMsg websocket.SubscribeMessage

	// Parse subscription data
	if dataBytes, err := json.Marshal(message.Data); err == nil {
		if err := json.Unmarshal(dataBytes, &subscribeMsg); err != nil {
			client.SendError("invalid_subscribe_data", "Invalid subscription data", "")
			return
		}
	} else {
		client.SendError("invalid_subscribe_data", "Failed to parse subscription data", "")
		return
	}

	switch subscribeMsg.Action {
	case "join":
		h.hub.JoinRoom(client, subscribeMsg.Room)
		logger.WithUserID(client.UserID).WithField("room", subscribeMsg.Room).Info("Client joined room")

		// Send confirmation
		client.SendMessage(websocket.CreateMessage("room_joined", gin.H{
			"room":      subscribeMsg.Room,
			"timestamp": time.Now(),
		}))

	case "leave":
		h.hub.LeaveRoom(client, subscribeMsg.Room)
		logger.WithUserID(client.UserID).WithField("room", subscribeMsg.Room).Info("Client left room")

		// Send confirmation
		client.SendMessage(websocket.CreateMessage("room_left", gin.H{
			"room":      subscribeMsg.Room,
			"timestamp": time.Now(),
		}))

	default:
		client.SendError("invalid_subscribe_action", "Invalid subscription action", "")
	}
}

// handleUserActivity handles user activity updates
func (h *WebSocketHandler) handleUserActivity(client *websocket.Client, message *websocket.Message) {
	var activityMsg websocket.UserActivityMessage

	// Parse activity data
	if dataBytes, err := json.Marshal(message.Data); err == nil {
		if err := json.Unmarshal(dataBytes, &activityMsg); err != nil {
			client.SendError("invalid_activity_data", "Invalid activity data", "")
			return
		}
	} else {
		client.SendError("invalid_activity_data", "Failed to parse activity data", "")
		return
	}

	// Update user activity in hub
	h.hub.UpdateUserActivity(client.UserID, activityMsg.Activity, activityMsg.ResourceID, activityMsg.ResourceType)

	// Broadcast activity to followers if needed
	if activityMsg.Activity == "viewing_thread" || activityMsg.Activity == "in_conversation" {
		activityMessage := websocket.CreateMessage("user_activity", &activityMsg)
		h.hub.BroadcastToFollowers(client.UserID, activityMessage)
	}

	// Send confirmation
	client.SendMessage(websocket.CreateMessage("activity_updated", gin.H{
		"activity":  activityMsg.Activity,
		"timestamp": time.Now(),
	}))
}

// handleTypingIndicator handles typing indicators
func (h *WebSocketHandler) handleTypingIndicator(client *websocket.Client, message *websocket.Message) {
	var typingMsg websocket.TypingMessage

	// Parse typing data
	if dataBytes, err := json.Marshal(message.Data); err == nil {
		if err := json.Unmarshal(dataBytes, &typingMsg); err != nil {
			client.SendError("invalid_typing_data", "Invalid typing data", "")
			return
		}
	} else {
		client.SendError("invalid_typing_data", "Failed to parse typing data", "")
		return
	}

	// Set user info
	typingMsg.UserID = client.UserID.Hex()
	typingMsg.Username = client.User.Username

	// Broadcast typing indicator to conversation participants
	if typingMsg.ConversationID != "" {
		typingMessage := websocket.CreateTypingMessage(
			typingMsg.ConversationID,
			typingMsg.UserID,
			typingMsg.Username,
			typingMsg.IsTyping,
		)

		// Broadcast to conversation room
		roomID := fmt.Sprintf("conversation:%s", typingMsg.ConversationID)
		h.hub.BroadcastToRoom(roomID, typingMessage, client.UserID)
	}
}

// handleAuthMessage handles authentication messages
func (h *WebSocketHandler) handleAuthMessage(client *websocket.Client, message *websocket.Message) {
	var authMsg websocket.AuthMessage

	// Parse auth data
	if dataBytes, err := json.Marshal(message.Data); err == nil {
		if err := json.Unmarshal(dataBytes, &authMsg); err != nil {
			client.SendError("invalid_auth_data", "Invalid authentication data", "")
			return
		}
	} else {
		client.SendError("invalid_auth_data", "Failed to parse authentication data", "")
		return
	}

	// Validate new token if provided
	if authMsg.Token != "" {
		userID, err := h.authService.ValidateToken(authMsg.Token)
		if err != nil {
			client.SendError("invalid_token", "Invalid authentication token", "")
			return
		}

		// Update client user ID if token is valid and different
		if userID != client.UserID {
			client.SendError("token_mismatch", "Token does not match current user", "")
			return
		}

		// Send authentication success response
		client.SendMessage(websocket.CreateMessage("auth_success", gin.H{
			"user_id":   userID.Hex(),
			"timestamp": time.Now(),
		}))
	}
}

// handleDirectMessage handles direct messages
func (h *WebSocketHandler) handleDirectMessage(client *websocket.Client, message *websocket.Message) {
	// This would integrate with your message service
	logger.WithUserID(client.UserID).WithField("type", message.Type).Debug("Handling direct message")

	// You can add logic here to process the message and store it in database
	// then broadcast to recipients
}

// handleHeartbeat handles heartbeat messages
func (h *WebSocketHandler) handleHeartbeat(client *websocket.Client, message *websocket.Message) {
	client.SendMessage(websocket.CreateMessage("heartbeat_ack", gin.H{
		"timestamp": time.Now(),
	}))
}

// forwardMessage forwards messages to appropriate handlers
func (h *WebSocketHandler) forwardMessage(client *websocket.Client, message *websocket.Message) {
	// This can be used to forward messages to other services or handlers
	// based on message type or content

	switch message.Type {
	case constants.WSTypeNotification:
		// Handle notification messages
		logger.WithUserID(client.UserID).WithField("type", message.Type).Debug("Forwarding message to notification service")

	case constants.WSTypeThreadUpdate:
		// Handle thread update messages
		logger.WithUserID(client.UserID).WithField("type", message.Type).Debug("Forwarding message to thread service")

	default:
		logger.WithUserID(client.UserID).WithField("type", message.Type).Debug("Unknown message type for forwarding")
	}
}

// ===============================
// Public API Methods
// ===============================

// SendMessageToUser sends a message to a specific user
func (h *WebSocketHandler) SendMessageToUser(userID primitive.ObjectID, message *websocket.Message) error {
	clients := h.hub.GetUserClients(userID)
	if len(clients) == 0 {
		return fmt.Errorf("user not connected")
	}

	for _, client := range clients {
		client.SendMessage(message)
	}

	return nil
}

// SendMessageToRoom sends a message to all users in a room
func (h *WebSocketHandler) SendMessageToRoom(roomID string, message *websocket.Message, excludeUserID primitive.ObjectID) error {
	h.hub.BroadcastToRoom(roomID, message, excludeUserID)
	return nil
}

// BroadcastToAll broadcasts a message to all connected users
func (h *WebSocketHandler) BroadcastToAll(message *websocket.Message) error {
	h.hub.BroadcastToAll(message)
	return nil
}

// DisconnectUser forcefully disconnects a user
func (h *WebSocketHandler) DisconnectUser(userID primitive.ObjectID, reason string) error {
	clients := h.hub.GetUserClients(userID)
	for _, client := range clients {
		client.SendError("forced_disconnect", fmt.Sprintf("Connection terminated: %s", reason), "")
		client.Close()
	}
	return nil
}

// GetUserConnectionInfo gets connection information for a user
func (h *WebSocketHandler) GetUserConnectionInfo(userID primitive.ObjectID) ([]gin.H, error) {
	clients := h.hub.GetUserClients(userID)

	connectionInfo := make([]gin.H, len(clients))
	for i, client := range clients {
		connectionInfo[i] = gin.H{
			"id":            client.ID,
			"connected_at":  client.ConnectedAt,
			"last_activity": client.LastActivity,
			"is_online":     client.IsOnline,
			"rooms":         client.GetRooms(),
			"ip_address":    client.RemoteAddr,
			"user_agent":    client.UserAgent,
		}
	}

	return connectionInfo, nil
}

// IsUserOnline checks if a user is currently online
func (h *WebSocketHandler) IsUserOnline(userID primitive.ObjectID) bool {
	return h.hub.IsUserOnline(userID)
}

// GetOnlineUsers gets list of online users
func (h *WebSocketHandler) GetOnlineUsers() []primitive.ObjectID {
	return h.hub.GetOnlineUsers()
}

// UpdateUserActivity updates user activity
func (h *WebSocketHandler) UpdateUserActivity(userID primitive.ObjectID, activity, resourceID, resourceType string) {
	h.hub.UpdateUserActivity(userID, activity, resourceID, resourceType)
}

// JoinRoom adds a user to a room
func (h *WebSocketHandler) JoinRoom(userID primitive.ObjectID, roomID string) error {
	clients := h.hub.GetUserClients(userID)
	for _, client := range clients {
		h.hub.JoinRoom(client, roomID)
	}
	return nil
}

// LeaveRoom removes a user from a room
func (h *WebSocketHandler) LeaveRoom(userID primitive.ObjectID, roomID string) error {
	clients := h.hub.GetUserClients(userID)
	for _, client := range clients {
		h.hub.LeaveRoom(client, roomID)
	}
	return nil
}

// GetRoomUsers gets all users in a room
func (h *WebSocketHandler) GetRoomUsers(roomID string) []primitive.ObjectID {
	return h.hub.GetRoomUsers(roomID)
}

// GetUserRooms gets all rooms a user is in
func (h *WebSocketHandler) GetUserRooms(userID primitive.ObjectID) []string {
	clients := h.hub.GetUserClients(userID)
	if len(clients) == 0 {
		return []string{}
	}
	// Return rooms from first client (they should all be the same)
	return clients[0].GetRooms()
}

// ===============================
// Utility Methods
// ===============================

// NotifyUserOffline notifies when a user goes offline
func (h *WebSocketHandler) NotifyUserOffline(userID primitive.ObjectID, username string) {
	// Create offline status message
	statusMessage := websocket.CreateOnlineStatusMessage(
		userID.Hex(),
		username,
		false,
		time.Now(),
	)

	// Broadcast to followers
	h.hub.BroadcastToFollowers(userID, statusMessage)
}

// NotifyUserOnline notifies when a user comes online
func (h *WebSocketHandler) NotifyUserOnline(userID primitive.ObjectID, username string) {
	// Create online status message
	statusMessage := websocket.CreateOnlineStatusMessage(
		userID.Hex(),
		username,
		true,
		time.Now(),
	)

	// Broadcast to followers
	h.hub.BroadcastToFollowers(userID, statusMessage)
}

// SendSystemNotification sends a system-wide notification
func (h *WebSocketHandler) SendSystemNotification(title, content, msgType, priority string) {
	systemMessage := websocket.CreateSystemMessage(title, content, msgType, priority)
	h.hub.BroadcastToAll(systemMessage)
}

// GetConnectionStats gets WebSocket connection statistics
func (h *WebSocketHandler) GetConnectionStats() gin.H {
	stats := h.hub.GetStats()
	return gin.H{
		"active_connections": stats.ActiveConnections,
		"total_users":        stats.TotalUsers,
		"rooms_count":        stats.RoomsCount,
		"messages_sent":      stats.MessagesSent,
		"messages_received":  stats.MessagesReceived,
		"last_updated":       stats.LastUpdated,
	}
}
