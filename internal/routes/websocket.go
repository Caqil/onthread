package routes

import (
	"net/http"

	"onthread/internal/utils"
	"onthread/pkg/constants"

	"github.com/gin-gonic/gin"
)

// setupWebSocketHandlers sets up WebSocket routes
func setupWebSocketHandlers(ws *gin.RouterGroup, deps *Dependencies) {
	// WebSocket connection endpoint
	ws.GET("/connect", deps.WebSocketHandler.HandleWebSocketConnection)

	// WebSocket info endpoint (for debugging/monitoring)
	ws.GET("/info", deps.AuthMiddleware.RequireAuth(), func(c *gin.Context) {
		userID := deps.AuthMiddleware.GetUserID(c)

		// Get user's WebSocket connections
		clients := deps.WebSocketHub.GetUserClients(userID)

		connectionInfo := make([]gin.H, len(clients))
		for i, client := range clients {
			connectionInfo[i] = gin.H{
				"id":            client.ID,
				"connected_at":  client.ConnectedAt,
				"last_activity": client.LastActivity,
				"is_online":     client.IsOnline,
				"rooms":         client.GetRooms(),
			}
		}

		utils.SuccessResponse(c, http.StatusOK, "WebSocket connection info", gin.H{
			"user_id":           userID.Hex(),
			"total_connections": len(clients),
			"connections":       connectionInfo,
			"is_online":         deps.WebSocketHub.IsUserOnline(userID),
		})
	})

	// WebSocket health check
	ws.GET("/health", func(c *gin.Context) {
		stats := deps.WebSocketHub.GetStats()

		utils.SuccessResponse(c, http.StatusOK, "WebSocket service is healthy", gin.H{
			"active_connections": stats.ActiveConnections,
			"total_users":        stats.TotalUsers,
			"rooms_count":        stats.RoomsCount,
			"messages_sent":      stats.MessagesSent,
			"last_updated":       stats.LastUpdated,
		})
	})
}

// Additional routes for message and notification handling
func setupMessageRoutes(api *gin.RouterGroup, deps *Dependencies) {
	messages := api.Group("/messages")
	messages.Use(deps.AuthMiddleware.RequireAuth())

	// Rate limiting for messages
	messageRateLimit := deps.RateLimitMiddleware.CreateRateLimiter(
		constants.MessageSendRateLimit,
		"send_message",
	)

	// Conversations
	conversations := messages.Group("/conversations")
	{
		conversations.GET("", deps.MessageHandler.GetConversations)
		conversations.POST("", deps.MessageHandler.CreateConversation)
		conversations.GET("/:conversation_id", deps.MessageHandler.GetConversation)
		conversations.PUT("/:conversation_id", deps.MessageHandler.UpdateConversation)
		conversations.DELETE("/:conversation_id", deps.MessageHandler.DeleteConversation)
		conversations.POST("/:conversation_id/leave", deps.MessageHandler.LeaveConversation)
		conversations.POST("/:conversation_id/join", deps.MessageHandler.JoinConversation)

		// Conversation messages
		conversations.GET("/:conversation_id/messages", deps.MessageHandler.GetMessages)
		conversations.POST("/:conversation_id/messages", messageRateLimit, deps.MessageHandler.SendMessage)
		conversations.PUT("/:conversation_id/messages/:message_id", deps.MessageHandler.UpdateMessage)
		conversations.DELETE("/:conversation_id/messages/:message_id", deps.MessageHandler.DeleteMessage)
		conversations.POST("/:conversation_id/messages/:message_id/react", deps.MessageHandler.ReactToMessage)
		conversations.DELETE("/:conversation_id/messages/:message_id/react", deps.MessageHandler.RemoveReaction)
		conversations.POST("/:conversation_id/messages/:message_id/forward", deps.MessageHandler.ForwardMessage)

		// Message status
		conversations.POST("/:conversation_id/read", deps.MessageHandler.MarkAsRead)
		conversations.POST("/:conversation_id/typing", deps.MessageHandler.SendTypingIndicator)

		// Conversation management
		conversations.GET("/:conversation_id/participants", deps.MessageHandler.GetParticipants)
		conversations.POST("/:conversation_id/participants", deps.MessageHandler.AddParticipant)
		conversations.DELETE("/:conversation_id/participants/:user_id", deps.MessageHandler.RemoveParticipant)
		conversations.PUT("/:conversation_id/participants/:user_id/role", deps.MessageHandler.UpdateParticipantRole)
		conversations.POST("/:conversation_id/mute", deps.MessageHandler.MuteConversation)
		conversations.DELETE("/:conversation_id/mute", deps.MessageHandler.UnmuteConversation)
	}

	// Direct messages (shortcut routes)
	dm := messages.Group("/dm")
	{
		dm.GET("/:username", deps.MessageHandler.GetDirectMessages)
		dm.POST("/:username", messageRateLimit, deps.MessageHandler.SendDirectMessage)
	}

	// Message search
	messages.GET("/search", deps.MessageHandler.SearchMessages)

	// Message requests
	requests := messages.Group("/requests")
	{
		requests.GET("", deps.MessageHandler.GetMessageRequests)
		requests.POST("/:request_id/accept", deps.MessageHandler.AcceptMessageRequest)
		requests.POST("/:request_id/decline", deps.MessageHandler.DeclineMessageRequest)
	}
}

func setupNotificationRoutes(api *gin.RouterGroup, deps *Dependencies) {
	notifications := api.Group("/notifications")
	notifications.Use(deps.AuthMiddleware.RequireAuth())

	// Notification management
	notifications.GET("", deps.NotificationHandler.GetNotifications)
	notifications.GET("/unread", deps.NotificationHandler.GetUnreadNotifications)
	notifications.GET("/count", deps.NotificationHandler.GetNotificationCount)
	notifications.POST("/read", deps.NotificationHandler.MarkAllAsRead)
	notifications.POST("/:notification_id/read", deps.NotificationHandler.MarkAsRead)
	notifications.DELETE("/:notification_id", deps.NotificationHandler.DeleteNotification)
	notifications.POST("/clear", deps.NotificationHandler.ClearAllNotifications)

	// Notification settings
	settings := notifications.Group("/settings")
	{
		settings.GET("", deps.NotificationHandler.GetNotificationSettings)
		settings.PUT("", deps.NotificationHandler.UpdateNotificationSettings)
		settings.GET("/devices", deps.NotificationHandler.GetDevices)
		settings.POST("/devices", deps.NotificationHandler.RegisterDevice)
		settings.DELETE("/devices/:device_id", deps.NotificationHandler.UnregisterDevice)
		settings.POST("/test", deps.NotificationHandler.TestNotification)
	}

	// Notification subscriptions
	subscriptions := notifications.Group("/subscriptions")
	{
		subscriptions.GET("", deps.NotificationHandler.GetSubscriptions)
		subscriptions.POST("/thread/:thread_id", deps.NotificationHandler.SubscribeToThread)
		subscriptions.DELETE("/thread/:thread_id", deps.NotificationHandler.UnsubscribeFromThread)
		subscriptions.POST("/user/:user_id", deps.NotificationHandler.SubscribeToUser)
		subscriptions.DELETE("/user/:user_id", deps.NotificationHandler.UnsubscribeFromUser)
	}
}

func setupUploadRoutes(api *gin.RouterGroup, deps *Dependencies) {
	upload := api.Group("/upload")
	upload.Use(deps.AuthMiddleware.RequireAuth())

	// Rate limiting for uploads
	uploadRateLimit := deps.RateLimitMiddleware.CreateRateLimiter(
		constants.UploadRateLimit,
		"upload",
	)

	// File uploads
	upload.POST("/image", uploadRateLimit, deps.UploadHandler.UploadImage)
	upload.POST("/video", uploadRateLimit, deps.UploadHandler.UploadVideo)
	upload.POST("/audio", uploadRateLimit, deps.UploadHandler.UploadAudio)
	upload.POST("/document", uploadRateLimit, deps.UploadHandler.UploadDocument)

	// Chunked uploads for large files
	upload.POST("/chunk/init", deps.UploadHandler.InitChunkedUpload)
	upload.POST("/chunk/upload", deps.UploadHandler.UploadChunk)
	upload.POST("/chunk/complete", deps.UploadHandler.CompleteChunkedUpload)
	upload.DELETE("/chunk/:upload_id", deps.UploadHandler.CancelChunkedUpload)

	// Upload management
	upload.GET("/history", deps.UploadHandler.GetUploadHistory)
	upload.DELETE("/:file_id", deps.UploadHandler.DeleteFile)
	upload.GET("/:file_id/info", deps.UploadHandler.GetFileInfo)

	// Avatar/cover specific uploads
	upload.POST("/avatar", uploadRateLimit, deps.UploadHandler.UploadAvatar)
	upload.POST("/cover", uploadRateLimit, deps.UploadHandler.UploadCover)

	// Temporary uploads (for drafts, etc.)
	upload.POST("/temp", uploadRateLimit, deps.UploadHandler.UploadTemporary)
	upload.POST("/temp/:temp_id/permanent", deps.UploadHandler.MakePermanent)
}
