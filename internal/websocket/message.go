package websocket

import (
	"encoding/json"
	"time"

	"onthread/internal/models"
	"onthread/pkg/constants"

	"go.mongodb.org/mongo-driver/bson/primitive"
)

// Message represents a WebSocket message
type Message struct {
	Type      string      `json:"type"`
	Data      interface{} `json:"data,omitempty"`
	Error     *ErrorData  `json:"error,omitempty"`
	Timestamp time.Time   `json:"timestamp"`
	MessageID string      `json:"message_id"`
	UserID    string      `json:"user_id,omitempty"`
	RoomID    string      `json:"room_id,omitempty"`
}

// ErrorData represents error information in WebSocket messages
type ErrorData struct {
	Code    string `json:"code"`
	Message string `json:"message"`
	Details string `json:"details,omitempty"`
}

// NotificationMessage represents a real-time notification
type NotificationMessage struct {
	Notification *models.Notification `json:"notification"`
	UnreadCount  int64                `json:"unread_count"`
}

// ThreadUpdateMessage represents a thread update
type ThreadUpdateMessage struct {
	Thread    *models.Thread `json:"thread"`
	Action    string         `json:"action"` // "created", "updated", "deleted", "liked", "reposted"
	UserID    string         `json:"user_id"`
	Timestamp time.Time      `json:"timestamp"`
}

// MessageUpdateMessage represents a conversation message update
type MessageUpdateMessage struct {
	Message        *models.Message `json:"message"`
	ConversationID string          `json:"conversation_id"`
	Action         string          `json:"action"` // "created", "updated", "deleted", "read"
	UserID         string          `json:"user_id"`
	Timestamp      time.Time       `json:"timestamp"`
}

// TypingMessage represents typing indicator
type TypingMessage struct {
	ConversationID string    `json:"conversation_id"`
	UserID         string    `json:"user_id"`
	Username       string    `json:"username"`
	IsTyping       bool      `json:"is_typing"`
	Timestamp      time.Time `json:"timestamp"`
}

// OnlineStatusMessage represents user online status
type OnlineStatusMessage struct {
	UserID    string    `json:"user_id"`
	Username  string    `json:"username"`
	IsOnline  bool      `json:"is_online"`
	LastSeen  time.Time `json:"last_seen"`
	Timestamp time.Time `json:"timestamp"`
}

// SystemMessage represents system-wide messages
type SystemMessage struct {
	Title     string                 `json:"title"`
	Content   string                 `json:"content"`
	Type      string                 `json:"type"`     // "maintenance", "announcement", "alert"
	Priority  string                 `json:"priority"` // "low", "medium", "high", "urgent"
	ActionURL string                 `json:"action_url,omitempty"`
	Metadata  map[string]interface{} `json:"metadata,omitempty"`
	Timestamp time.Time              `json:"timestamp"`
	ExpiresAt *time.Time             `json:"expires_at,omitempty"`
}

// PingMessage represents ping/pong messages
type PingMessage struct {
	Timestamp time.Time `json:"timestamp"`
	ServerID  string    `json:"server_id,omitempty"`
}

// AuthMessage represents authentication message
type AuthMessage struct {
	Token string `json:"token"`
	Type  string `json:"type"` // "access", "refresh"
}

// SubscribeMessage represents room subscription (FIXED: Added missing struct)
type SubscribeMessage struct {
	Room   string `json:"room"`
	Action string `json:"action"` // "join", "leave"
}

// UserActivityMessage represents user activity updates (FIXED: Added missing struct)
type UserActivityMessage struct {
	UserID       string    `json:"user_id"`
	Activity     string    `json:"activity"` // "viewing_thread", "in_conversation", "idle"
	ResourceID   string    `json:"resource_id,omitempty"`
	ResourceType string    `json:"resource_type,omitempty"` // "thread", "conversation", "profile"
	Timestamp    time.Time `json:"timestamp"`
}

// CreateMessage creates a new WebSocket message
func CreateMessage(msgType string, data interface{}) *Message {
	return &Message{
		Type:      msgType,
		Data:      data,
		Timestamp: time.Now(),
		MessageID: primitive.NewObjectID().Hex(),
	}
}

// CreateErrorMessage creates an error WebSocket message
func CreateErrorMessage(code, message, details string) *Message {
	return &Message{
		Type: constants.WSTypeError,
		Error: &ErrorData{
			Code:    code,
			Message: message,
			Details: details,
		},
		Timestamp: time.Now(),
		MessageID: primitive.NewObjectID().Hex(),
	}
}

// CreateNotificationMessage creates a notification WebSocket message
func CreateNotificationMessage(notification *models.Notification, unreadCount int64) *Message {
	return CreateMessage(constants.WSTypeNotification, &NotificationMessage{
		Notification: notification,
		UnreadCount:  unreadCount,
	})
}

// CreateThreadUpdateMessage creates a thread update WebSocket message
func CreateThreadUpdateMessage(thread *models.Thread, action, userID string) *Message {
	return CreateMessage(constants.WSTypeThreadUpdate, &ThreadUpdateMessage{
		Thread:    thread,
		Action:    action,
		UserID:    userID,
		Timestamp: time.Now(),
	})
}

// CreateMessageUpdateMessage creates a message update WebSocket message
func CreateMessageUpdateMessage(message *models.Message, conversationID, action, userID string) *Message {
	return CreateMessage(constants.WSTypeMessage, &MessageUpdateMessage{
		Message:        message,
		ConversationID: conversationID,
		Action:         action,
		UserID:         userID,
		Timestamp:      time.Now(),
	})
}

// CreateTypingMessage creates a typing indicator WebSocket message
func CreateTypingMessage(conversationID, userID, username string, isTyping bool) *Message {
	return CreateMessage(constants.WSTypeTyping, &TypingMessage{
		ConversationID: conversationID,
		UserID:         userID,
		Username:       username,
		IsTyping:       isTyping,
		Timestamp:      time.Now(),
	})
}

// CreateOnlineStatusMessage creates an online status WebSocket message
func CreateOnlineStatusMessage(userID, username string, isOnline bool, lastSeen time.Time) *Message {
	return CreateMessage(constants.WSTypeOnlineStatus, &OnlineStatusMessage{
		UserID:    userID,
		Username:  username,
		IsOnline:  isOnline,
		LastSeen:  lastSeen,
		Timestamp: time.Now(),
	})
}

// CreateSystemMessage creates a system WebSocket message
func CreateSystemMessage(title, content, msgType, priority string) *Message {
	return CreateMessage("system", &SystemMessage{
		Title:     title,
		Content:   content,
		Type:      msgType,
		Priority:  priority,
		Timestamp: time.Now(),
	})
}

// CreatePingMessage creates a ping WebSocket message
func CreatePingMessage() *Message {
	return CreateMessage(constants.WSTypePing, &PingMessage{
		Timestamp: time.Now(),
	})
}

// CreatePongMessage creates a pong WebSocket message
func CreatePongMessage() *Message {
	return CreateMessage(constants.WSTypePong, &PingMessage{
		Timestamp: time.Now(),
	})
}

// ToJSON converts message to JSON bytes
func (m *Message) ToJSON() ([]byte, error) {
	return json.Marshal(m)
}

// FromJSON creates message from JSON bytes
func FromJSON(data []byte) (*Message, error) {
	var msg Message
	err := json.Unmarshal(data, &msg)
	if err != nil {
		return nil, err
	}
	return &msg, nil
}

// SetUserID sets the user ID for the message
func (m *Message) SetUserID(userID string) *Message {
	m.UserID = userID
	return m
}

// SetRoomID sets the room ID for the message
func (m *Message) SetRoomID(roomID string) *Message {
	m.RoomID = roomID
	return m
}

// IsValid validates the message structure
func (m *Message) IsValid() bool {
	if m.Type == "" {
		return false
	}

	// Check if it's a valid message type
	validTypes := []string{
		constants.WSTypeMessage,
		constants.WSTypeNotification,
		constants.WSTypeTyping,
		constants.WSTypeOnlineStatus,
		constants.WSTypeThreadUpdate,
		constants.WSTypeError,
		constants.WSTypePing,
		constants.WSTypePong,
		"system",
		"auth",
		"subscribe",
		"user_activity",
		"heartbeat",
	}

	for _, validType := range validTypes {
		if m.Type == validType {
			return true
		}
	}

	return false
}
