package handlers

import (
	"fmt"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/gorilla/websocket"
	"go.mongodb.org/mongo-driver/bson/primitive"

	"onthread/internal/services"
	"onthread/internal/utils"
	wsocket "onthread/internal/websocket"
	"onthread/pkg/logger"
)

// WebSocketHandler handles WebSocket connections and real-time communication
type WebSocketHandler struct {
	hub         *wsocket.Hub
	authService services.AuthService
	upgrader    websocket.Upgrader
}

// NewWebSocketHandler creates a new WebSocket handler
func NewWebSocketHandler(hub *wsocket.Hub, authService services.AuthService) *WebSocketHandler {
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
		logger.WithError(err).WithField("user_id", userID).Error("Failed to get user details for WebSocket connection")
		return
	}

	// Create WebSocket client - Fixed constructor call
	client := wsocket.NewClient(
		h.hub,
		conn,
		userID,
		user,
		c.Request,
	)

	// Register client with hub
	h.hub.RegisterClient(client)

	// Start client - this handles the read/write pumps internally
	go client.Start(nil)

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
// Public API Methods
// ===============================

// SendMessageToUser sends a message to a specific user
func (h *WebSocketHandler) SendMessageToUser(userID primitive.ObjectID, message *wsocket.Message) error {
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
func (h *WebSocketHandler) SendMessageToRoom(roomID string, message *wsocket.Message, excludeUserID primitive.ObjectID) error {
	h.hub.BroadcastToRoom(roomID, message, excludeUserID)
	return nil
}

// BroadcastToAll broadcasts a message to all connected users
func (h *WebSocketHandler) BroadcastToAll(message *wsocket.Message) error {
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
			"ip_address":    client.IPAddress,
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
	statusMessage := wsocket.CreateOnlineStatusMessage(
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
	statusMessage := wsocket.CreateOnlineStatusMessage(
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
	systemMessage := wsocket.CreateSystemMessage(title, content, msgType, priority)
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
