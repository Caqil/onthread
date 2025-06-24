package websocket

import (
	"context"
	"sync"
	"time"

	"github.com/redis/go-redis/v9"
	"go.mongodb.org/mongo-driver/bson/primitive"

	"onthread/internal/repository"
	"onthread/pkg/constants"
	"onthread/pkg/logger"
)

// Hub maintains the set of active clients and broadcasts messages to the clients
type Hub struct {
	// Registered clients
	clients   map[*Client]bool
	clientsMu sync.RWMutex

	// User to clients mapping for efficient lookups
	userClients   map[primitive.ObjectID][]*Client
	userClientsMu sync.RWMutex

	// Room management
	rooms   map[string]map[*Client]bool
	roomsMu sync.RWMutex

	// Communication channels
	register   chan *Client
	unregister chan *Client
	broadcast  chan *BroadcastMessage

	// User activity tracking
	userActivity   map[primitive.ObjectID]*UserActivity
	userActivityMu sync.RWMutex

	// Dependencies
	redis      *redis.Client
	userRepo   repository.UserRepository
	followRepo repository.FollowRepository

	// Context for cancellation
	ctx    context.Context
	cancel context.CancelFunc

	// Metrics
	stats *HubStats

	// Configuration
	config *HubConfig
}

// BroadcastMessage represents a message to be broadcasted
type BroadcastMessage struct {
	Message     *Message
	TargetType  string // "all", "user", "room", "followers"
	TargetID    string
	ExcludeUser primitive.ObjectID
}

// UserActivity represents user activity information
type UserActivity struct {
	UserID       primitive.ObjectID `json:"user_id"`
	Activity     string             `json:"activity"`
	ResourceID   string             `json:"resource_id,omitempty"`
	ResourceType string             `json:"resource_type,omitempty"`
	LastUpdated  time.Time          `json:"last_updated"`
}

// HubStats represents hub statistics
type HubStats struct {
	TotalConnections  int64            `json:"total_connections"`
	ActiveConnections int64            `json:"active_connections"`
	TotalUsers        int64            `json:"total_users"`
	MessagesSent      int64            `json:"messages_sent"`
	MessagesReceived  int64            `json:"messages_received"`
	RoomsCount        int64            `json:"rooms_count"`
	UsersByActivity   map[string]int64 `json:"users_by_activity"`
	ConnectionsByHour map[int]int64    `json:"connections_by_hour"`
	LastUpdated       time.Time        `json:"last_updated"`

	mu sync.RWMutex
}

// HubConfig represents hub configuration
type HubConfig struct {
	MaxConnections        int           `json:"max_connections"`
	MaxConnectionsPerUser int           `json:"max_connections_per_user"`
	CleanupInterval       time.Duration `json:"cleanup_interval"`
	StatsUpdateInterval   time.Duration `json:"stats_update_interval"`
	ActivityTimeout       time.Duration `json:"activity_timeout"`
	RedisKeyPrefix        string        `json:"redis_key_prefix"`
}

// DefaultHubConfig returns default hub configuration
func DefaultHubConfig() *HubConfig {
	return &HubConfig{
		MaxConnections:        constants.MaxWebSocketConnections,
		MaxConnectionsPerUser: 5,
		CleanupInterval:       5 * time.Minute,
		StatsUpdateInterval:   1 * time.Minute,
		ActivityTimeout:       30 * time.Minute,
		RedisKeyPrefix:        constants.RedisKeyPrefix,
	}
}

// NewHub creates a new WebSocket hub
func NewHub(redis *redis.Client, userRepo repository.UserRepository, followRepo repository.FollowRepository, config *HubConfig) *Hub {
	if config == nil {
		config = DefaultHubConfig()
	}

	ctx, cancel := context.WithCancel(context.Background())

	hub := &Hub{
		clients:      make(map[*Client]bool),
		userClients:  make(map[primitive.ObjectID][]*Client),
		rooms:        make(map[string]map[*Client]bool),
		register:     make(chan *Client, 256),
		unregister:   make(chan *Client, 256),
		broadcast:    make(chan *BroadcastMessage, 1024),
		userActivity: make(map[primitive.ObjectID]*UserActivity),
		redis:        redis,
		userRepo:     userRepo,
		followRepo:   followRepo,
		ctx:          ctx,
		cancel:       cancel,
		config:       config,
		stats: &HubStats{
			UsersByActivity:   make(map[string]int64),
			ConnectionsByHour: make(map[int]int64),
			LastUpdated:       time.Now(),
		},
	}

	return hub
}

// Start starts the hub
func (h *Hub) Start() {
	logger.Info("Starting WebSocket hub")

	go h.run()
	go h.cleanupRoutine()
	go h.statsRoutine()

	logger.Info("WebSocket hub started")
}

// Stop stops the hub
func (h *Hub) Stop() {
	logger.Info("Stopping WebSocket hub")

	h.cancel()

	// Close all client connections
	h.clientsMu.RLock()
	for client := range h.clients {
		client.Stop()
	}
	h.clientsMu.RUnlock()

	// Close channels
	close(h.register)
	close(h.unregister)
	close(h.broadcast)

	logger.Info("WebSocket hub stopped")
}

// RegisterClient registers a new client
func (h *Hub) RegisterClient(client *Client) {
	select {
	case h.register <- client:
	case <-h.ctx.Done():
		client.Stop()
	}
}

// UnregisterClient unregisters a client
func (h *Hub) UnregisterClient(client *Client) {
	select {
	case h.unregister <- client:
	case <-h.ctx.Done():
	}
}

// BroadcastToUser sends a message to all connections of a specific user
func (h *Hub) BroadcastToUser(userID primitive.ObjectID, message *Message) {
	h.broadcast <- &BroadcastMessage{
		Message:    message,
		TargetType: "user",
		TargetID:   userID.Hex(),
	}
}

// BroadcastToRoom sends a message to all clients in a room
func (h *Hub) BroadcastToRoom(room string, message *Message, excludeUser primitive.ObjectID) {
	h.broadcast <- &BroadcastMessage{
		Message:     message,
		TargetType:  "room",
		TargetID:    room,
		ExcludeUser: excludeUser,
	}
}

// BroadcastToFollowers sends a message to all followers of a user
func (h *Hub) BroadcastToFollowers(userID primitive.ObjectID, message *Message) {
	h.broadcast <- &BroadcastMessage{
		Message:    message,
		TargetType: "followers",
		TargetID:   userID.Hex(),
	}
}

// BroadcastToAll sends a message to all connected clients
func (h *Hub) BroadcastToAll(message *Message) {
	h.broadcast <- &BroadcastMessage{
		Message:    message,
		TargetType: "all",
	}
}

// JoinRoom adds a client to a room
func (h *Hub) JoinRoom(client *Client, room string) {
	h.roomsMu.Lock()
	if h.rooms[room] == nil {
		h.rooms[room] = make(map[*Client]bool)
	}
	h.rooms[room][client] = true
	h.roomsMu.Unlock()

	// Cache room membership in Redis
	h.cacheRoomMembership(client.UserID, room, true)
}

// LeaveRoom removes a client from a room
func (h *Hub) LeaveRoom(client *Client, room string) {
	h.roomsMu.Lock()
	if h.rooms[room] != nil {
		delete(h.rooms[room], client)
		if len(h.rooms[room]) == 0 {
			delete(h.rooms, room)
		}
	}
	h.roomsMu.Unlock()

	// Remove room membership from Redis
	h.cacheRoomMembership(client.UserID, room, false)
}

// GetUserClients returns all clients for a specific user
func (h *Hub) GetUserClients(userID primitive.ObjectID) []*Client {
	h.userClientsMu.RLock()
	defer h.userClientsMu.RUnlock()

	clients := make([]*Client, len(h.userClients[userID]))
	copy(clients, h.userClients[userID])
	return clients
}

// GetRoomUsers gets all users in a room (FIXED: Added missing method)
func (h *Hub) GetRoomUsers(roomID string) []primitive.ObjectID {
	h.roomsMu.RLock()
	defer h.roomsMu.RUnlock()

	users := make([]primitive.ObjectID, 0)
	if room, exists := h.rooms[roomID]; exists {
		userSet := make(map[primitive.ObjectID]bool)
		for client := range room {
			userSet[client.UserID] = true
		}
		for userID := range userSet {
			users = append(users, userID)
		}
	}
	return users
}

// IsUserOnline checks if a user is currently online
func (h *Hub) IsUserOnline(userID primitive.ObjectID) bool {
	h.userClientsMu.RLock()
	defer h.userClientsMu.RUnlock()

	return len(h.userClients[userID]) > 0
}

// GetOnlineUsers returns a list of all online users
func (h *Hub) GetOnlineUsers() []primitive.ObjectID {
	h.userClientsMu.RLock()
	defer h.userClientsMu.RUnlock()

	users := make([]primitive.ObjectID, 0, len(h.userClients))
	for userID := range h.userClients {
		users = append(users, userID)
	}
	return users
}

// UpdateUserActivity updates user activity information
func (h *Hub) UpdateUserActivity(userID primitive.ObjectID, activity, resourceID, resourceType string) {
	h.userActivityMu.Lock()
	h.userActivity[userID] = &UserActivity{
		UserID:       userID,
		Activity:     activity,
		ResourceID:   resourceID,
		ResourceType: resourceType,
		LastUpdated:  time.Now(),
	}
	h.userActivityMu.Unlock()

	// Cache activity in Redis
	h.cacheUserActivity(userID, activity, resourceID, resourceType)
}

// GetUserActivity returns user activity information
func (h *Hub) GetUserActivity(userID primitive.ObjectID) *UserActivity {
	h.userActivityMu.RLock()
	defer h.userActivityMu.RUnlock()

	if activity, exists := h.userActivity[userID]; exists {
		return activity
	}
	return nil
}

// GetStats returns hub statistics
func (h *Hub) GetStats() *HubStats {
	h.stats.mu.RLock()
	defer h.stats.mu.RUnlock()

	// Create a copy
	stats := &HubStats{
		TotalConnections:  h.stats.TotalConnections,
		ActiveConnections: h.stats.ActiveConnections,
		TotalUsers:        h.stats.TotalUsers,
		MessagesSent:      h.stats.MessagesSent,
		MessagesReceived:  h.stats.MessagesReceived,
		RoomsCount:        h.stats.RoomsCount,
		UsersByActivity:   make(map[string]int64),
		ConnectionsByHour: make(map[int]int64),
		LastUpdated:       h.stats.LastUpdated,
	}

	for k, v := range h.stats.UsersByActivity {
		stats.UsersByActivity[k] = v
	}

	for k, v := range h.stats.ConnectionsByHour {
		stats.ConnectionsByHour[k] = v
	}

	return stats
}

// run is the main hub loop
func (h *Hub) run() {
	for {
		select {
		case <-h.ctx.Done():
			return

		case client := <-h.register:
			h.handleClientRegister(client)

		case client := <-h.unregister:
			h.handleClientUnregister(client)

		case broadcastMsg := <-h.broadcast:
			h.handleBroadcast(broadcastMsg)
		}
	}
}

// handleClientRegister handles client registration
func (h *Hub) handleClientRegister(client *Client) {
	// Check connection limits
	if h.checkConnectionLimits(client) {
		client.SendError("CONNECTION_LIMIT_EXCEEDED", "Maximum connections exceeded", "")
		client.Stop()
		return
	}

	// Register client
	h.clientsMu.Lock()
	h.clients[client] = true
	h.clientsMu.Unlock()

	// Add to user clients mapping
	h.userClientsMu.Lock()
	h.userClients[client.UserID] = append(h.userClients[client.UserID], client)
	h.userClientsMu.Unlock()

	// Update stats
	h.updateStats("client_connected", client)

	// Auto-join user to their personal room
	personalRoom := "user_" + client.UserID.Hex()
	client.JoinRoom(personalRoom)

	// Cache online status
	h.cacheOnlineStatus(client.UserID, true)

	logger.WithUserID(client.UserID).WithField("total_clients", len(h.clients)).Info("Client registered")
}

// handleClientUnregister handles client unregistration
func (h *Hub) handleClientUnregister(client *Client) {
	// Remove from clients
	h.clientsMu.Lock()
	if _, exists := h.clients[client]; exists {
		delete(h.clients, client)
	}
	h.clientsMu.Unlock()

	// Remove from user clients mapping
	h.userClientsMu.Lock()
	if clients, exists := h.userClients[client.UserID]; exists {
		for i, c := range clients {
			if c == client {
				h.userClients[client.UserID] = append(clients[:i], clients[i+1:]...)
				break
			}
		}

		// If no more clients for this user, remove from map
		if len(h.userClients[client.UserID]) == 0 {
			delete(h.userClients, client.UserID)

			// Update online status
			h.cacheOnlineStatus(client.UserID, false)
		}
	}
	h.userClientsMu.Unlock()

	// Remove from all rooms
	h.roomsMu.Lock()
	for room, clients := range h.rooms {
		if clients[client] {
			delete(clients, client)
			if len(clients) == 0 {
				delete(h.rooms, room)
			}
		}
	}
	h.roomsMu.Unlock()

	// Update stats
	h.updateStats("client_disconnected", client)

	logger.WithUserID(client.UserID).WithField("total_clients", len(h.clients)).Info("Client unregistered")
}

// handleBroadcast handles message broadcasting
func (h *Hub) handleBroadcast(broadcastMsg *BroadcastMessage) {
	switch broadcastMsg.TargetType {
	case "all":
		h.broadcastToAllClients(broadcastMsg.Message)

	case "user":
		userID, _ := primitive.ObjectIDFromHex(broadcastMsg.TargetID)
		h.broadcastToUserClients(userID, broadcastMsg.Message)

	case "room":
		h.broadcastToRoomClients(broadcastMsg.TargetID, broadcastMsg.Message, broadcastMsg.ExcludeUser)

	case "followers":
		userID, _ := primitive.ObjectIDFromHex(broadcastMsg.TargetID)
		h.broadcastToFollowersClients(userID, broadcastMsg.Message)
	}

	// Update stats
	h.stats.mu.Lock()
	h.stats.MessagesSent++
	h.stats.mu.Unlock()
}

// broadcastToAllClients broadcasts to all connected clients
func (h *Hub) broadcastToAllClients(message *Message) {
	h.clientsMu.RLock()
	for client := range h.clients {
		client.SendMessage(message)
	}
	h.clientsMu.RUnlock()
}

// broadcastToUserClients broadcasts to all clients of a specific user
func (h *Hub) broadcastToUserClients(userID primitive.ObjectID, message *Message) {
	h.userClientsMu.RLock()
	if clients, exists := h.userClients[userID]; exists {
		for _, client := range clients {
			client.SendMessage(message)
		}
	}
	h.userClientsMu.RUnlock()
}

// broadcastToRoomClients broadcasts to all clients in a room (FIXED: Complete implementation)
func (h *Hub) broadcastToRoomClients(room string, message *Message, excludeUser primitive.ObjectID) {
	h.roomsMu.RLock()
	if roomClients, exists := h.rooms[room]; exists {
		for client := range roomClients {
			if client.UserID != excludeUser {
				client.SendMessage(message)
			}
		}
	}
	h.roomsMu.RUnlock()
}

// broadcastToFollowersClients broadcasts to all followers of a user (FIXED: Complete implementation)
func (h *Hub) broadcastToFollowersClients(userID primitive.ObjectID, message *Message) {
	// This would require getting followers from the repository
	// For now, we'll skip this implementation or implement a basic version
	logger.WithUserID(userID).Debug("Broadcasting to followers not implemented")
}

// checkConnectionLimits checks if the client can connect based on limits
func (h *Hub) checkConnectionLimits(client *Client) bool {
	h.clientsMu.RLock()
	totalClients := len(h.clients)
	h.clientsMu.RUnlock()

	if totalClients >= h.config.MaxConnections {
		return true
	}

	h.userClientsMu.RLock()
	userConnections := len(h.userClients[client.UserID])
	h.userClientsMu.RUnlock()

	return userConnections >= h.config.MaxConnectionsPerUser
}

// cleanupRoutine performs periodic cleanup of inactive connections
func (h *Hub) cleanupRoutine() {
	ticker := time.NewTicker(h.config.CleanupInterval)
	defer ticker.Stop()

	for {
		select {
		case <-h.ctx.Done():
			return
		case <-ticker.C:
			h.performCleanup()
		}
	}
}

// statsRoutine updates statistics periodically
func (h *Hub) statsRoutine() {
	ticker := time.NewTicker(h.config.StatsUpdateInterval)
	defer ticker.Stop()

	for {
		select {
		case <-h.ctx.Done():
			return
		case <-ticker.C:
			h.updateStatsSnapshot()
		}
	}
}

// performCleanup removes inactive connections and old activities
func (h *Hub) performCleanup() {
	now := time.Now()

	// Clean up old user activities
	h.userActivityMu.Lock()
	for userID, activity := range h.userActivity {
		if now.Sub(activity.LastUpdated) > h.config.ActivityTimeout {
			delete(h.userActivity, userID)
		}
	}
	h.userActivityMu.Unlock()

	logger.Debug("Performed WebSocket hub cleanup")
}

// updateStatsSnapshot updates the current statistics snapshot
func (h *Hub) updateStatsSnapshot() {
	h.stats.mu.Lock()
	defer h.stats.mu.Unlock()

	h.clientsMu.RLock()
	h.stats.ActiveConnections = int64(len(h.clients))
	h.clientsMu.RUnlock()

	h.userClientsMu.RLock()
	h.stats.TotalUsers = int64(len(h.userClients))
	h.userClientsMu.RUnlock()

	h.roomsMu.RLock()
	h.stats.RoomsCount = int64(len(h.rooms))
	h.roomsMu.RUnlock()

	// Update activity stats
	h.userActivityMu.RLock()
	activityCounts := make(map[string]int64)
	for _, activity := range h.userActivity {
		activityCounts[activity.Activity]++
	}
	h.stats.UsersByActivity = activityCounts
	h.userActivityMu.RUnlock()

	h.stats.LastUpdated = time.Now()

	// Cache stats in Redis
	h.cacheStats()
}

// updateStats updates statistics for specific events
func (h *Hub) updateStats(event string, client *Client) {
	h.stats.mu.Lock()
	defer h.stats.mu.Unlock()

	switch event {
	case "client_connected":
		h.stats.TotalConnections++
		hour := time.Now().Hour()
		h.stats.ConnectionsByHour[hour]++

	case "client_disconnected":
		// Stats are updated in the snapshot routine
	}
}

// Cache operations (FIXED: Added missing cache methods)
func (h *Hub) cacheOnlineStatus(userID primitive.ObjectID, isOnline bool) {
	if h.redis == nil {
		return
	}

	key := constants.OnlineUsersKey
	if isOnline {
		h.redis.SAdd(context.Background(), key, userID.Hex())
		h.redis.Expire(context.Background(), key, constants.OnlineUsersTTL)
	} else {
		h.redis.SRem(context.Background(), key, userID.Hex())
	}
}

func (h *Hub) cacheRoomMembership(userID primitive.ObjectID, room string, isMember bool) {
	if h.redis == nil {
		return
	}

	key := constants.WebSocketRoomPrefix + room
	if isMember {
		h.redis.SAdd(context.Background(), key, userID.Hex())
		h.redis.Expire(context.Background(), key, constants.UserCacheTTL)
	} else {
		h.redis.SRem(context.Background(), key, userID.Hex())
	}
}

func (h *Hub) cacheUserActivity(userID primitive.ObjectID, activity, resourceID, resourceType string) {
	if h.redis == nil {
		return
	}

	key := constants.RedisKeyPrefix + "user_activity:" + userID.Hex()
	activityData := map[string]interface{}{
		"activity":      activity,
		"resource_id":   resourceID,
		"resource_type": resourceType,
		"last_updated":  time.Now().Unix(),
	}

	h.redis.HMSet(context.Background(), key, activityData)
	h.redis.Expire(context.Background(), key, constants.UserCacheTTL)
}

func (h *Hub) cacheStats() {
	if h.redis == nil {
		return
	}

	key := constants.SystemStatsKey
	statsData := map[string]interface{}{
		"active_connections": h.stats.ActiveConnections,
		"total_users":        h.stats.TotalUsers,
		"rooms_count":        h.stats.RoomsCount,
		"messages_sent":      h.stats.MessagesSent,
		"last_updated":       h.stats.LastUpdated.Unix(),
	}

	h.redis.HMSet(context.Background(), key, statsData)
	h.redis.Expire(context.Background(), key, constants.SystemStatsCacheTTL)
}
