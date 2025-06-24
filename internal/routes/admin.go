package routes

import (
	"github.com/gin-gonic/gin"
)

// setupAdminRoutes sets up admin panel routes
func setupAdminRoutes(api *gin.RouterGroup, deps *Dependencies) {
	admin := api.Group("/admin")
	admin.Use(deps.AdminMiddleware.RequireAdmin())

	// Admin authentication
	adminAuth := admin.Group("/auth")
	{
		adminAuth.POST("/login", deps.AdminHandler.Login)
		adminAuth.POST("/logout", deps.AdminHandler.Logout)
		adminAuth.GET("/me", deps.AdminHandler.GetCurrentAdmin)
		adminAuth.POST("/change-password", deps.AdminHandler.ChangePassword)
		adminAuth.GET("/sessions", deps.AdminHandler.GetAdminSessions)
		adminAuth.DELETE("/sessions/:session_id", deps.AdminHandler.RevokeAdminSession)
	}

	// Dashboard and analytics
	dashboard := admin.Group("/dashboard")
	{
		dashboard.GET("/stats", deps.AdminHandler.GetDashboardStats)
		dashboard.GET("/metrics", deps.AdminHandler.GetSystemMetrics)
		dashboard.GET("/activity", deps.AdminHandler.GetRecentActivity)
		dashboard.GET("/growth", deps.AdminHandler.GetGrowthMetrics)
		dashboard.GET("/engagement", deps.AdminHandler.GetEngagementMetrics)
	}

	// User management
	users := admin.Group("/users")
	{
		users.GET("", deps.AdminHandler.GetAllUsers)
		users.GET("/stats", deps.AdminHandler.GetUserStats)
		users.GET("/growth", deps.AdminHandler.GetUserGrowth)
		users.GET("/verification-requests", deps.AdminHandler.GetVerificationRequests)
		users.POST("/verification-requests/:request_id/approve", deps.AdminHandler.ApproveVerification)
		users.POST("/verification-requests/:request_id/reject", deps.AdminHandler.RejectVerification)
		users.GET("/:user_id", deps.AdminHandler.GetUserDetails)
		users.GET("/:user_id/activity", deps.AdminHandler.GetUserActivity)
		users.GET("/:user_id/reports", deps.AdminHandler.GetUserReports)
		users.POST("/:user_id/actions", deps.AdminHandler.TakeUserAction)
		users.GET("/:user_id/action-history", deps.AdminHandler.GetUserActionHistory)
	}

	// Content management
	content := admin.Group("/content")
	{
		content.GET("/threads", deps.AdminHandler.GetAllThreads)
		content.GET("/threads/stats", deps.AdminHandler.GetContentStats)
		content.GET("/threads/reported", deps.AdminHandler.GetReportedContent)
		content.GET("/threads/flagged", deps.AdminHandler.GetFlaggedContent)
		content.POST("/threads/:thread_id/actions", deps.AdminHandler.TakeContentAction)
		content.GET("/hashtags", deps.AdminHandler.GetHashtags)
		content.GET("/hashtags/trending", deps.AdminHandler.GetTrendingHashtags)
		content.POST("/hashtags/:hashtag/block", deps.AdminHandler.BlockHashtag)
		content.DELETE("/hashtags/:hashtag/block", deps.AdminHandler.UnblockHashtag)
	}

	// Reports and moderation
	moderation := admin.Group("/moderation")
	{
		moderation.GET("/reports", deps.AdminHandler.GetAllReports)
		moderation.GET("/reports/stats", deps.AdminHandler.GetReportStats)
		moderation.GET("/reports/:report_id", deps.AdminHandler.GetReportDetails)
		moderation.POST("/reports/:report_id/review", deps.AdminHandler.ReviewReport)
		moderation.POST("/reports/:report_id/resolve", deps.AdminHandler.ResolveReport)
		moderation.POST("/reports/:report_id/dismiss", deps.AdminHandler.DismissReport)
		moderation.GET("/actions", deps.AdminHandler.GetModerationActions)
		moderation.GET("/actions/stats", deps.AdminHandler.GetModerationStats)
		moderation.POST("/actions/:action_id/reverse", deps.AdminHandler.ReverseModerationAction)
	}

	// System configuration
	system := admin.Group("/system")
	{
		system.GET("/config", deps.AdminHandler.GetSystemConfig)
		system.PUT("/config", deps.AdminHandler.UpdateSystemConfig)
		system.GET("/config/:key", deps.AdminHandler.GetConfigValue)
		system.PUT("/config/:key", deps.AdminHandler.UpdateConfigValue)
		system.GET("/features", deps.AdminHandler.GetFeatureFlags)
		system.PUT("/features/:feature", deps.AdminHandler.UpdateFeatureFlag)
		system.GET("/maintenance", deps.AdminHandler.GetMaintenanceStatus)
		system.POST("/maintenance/enable", deps.AdminHandler.EnableMaintenance)
		system.POST("/maintenance/disable", deps.AdminHandler.DisableMaintenance)
	}

	// Storage management
	storage := admin.Group("/storage")
	{
		storage.GET("/stats", deps.AdminHandler.GetStorageStats)
		storage.GET("/files", deps.AdminHandler.GetStorageFiles)
		storage.DELETE("/files/:file_id", deps.AdminHandler.DeleteStorageFile)
		storage.POST("/cleanup", deps.AdminHandler.CleanupStorage)
		storage.GET("/usage", deps.AdminHandler.GetStorageUsage)
		storage.PUT("/settings", deps.AdminHandler.UpdateStorageSettings)
	}

	// Admin management (super admin only)
	adminMgmt := admin.Group("/admins")
	adminMgmt.Use(deps.AdminMiddleware.RequireSuperAdmin())
	{
		adminMgmt.GET("", deps.AdminHandler.GetAllAdmins)
		adminMgmt.POST("", deps.AdminHandler.CreateAdmin)
		adminMgmt.GET("/:admin_id", deps.AdminHandler.GetAdminDetails)
		adminMgmt.PUT("/:admin_id", deps.AdminHandler.UpdateAdmin)
		adminMgmt.DELETE("/:admin_id", deps.AdminHandler.DeleteAdmin)
		adminMgmt.POST("/:admin_id/activate", deps.AdminHandler.ActivateAdmin)
		adminMgmt.POST("/:admin_id/deactivate", deps.AdminHandler.DeactivateAdmin)
		adminMgmt.GET("/:admin_id/activity", deps.AdminHandler.GetAdminActivity)
		adminMgmt.PUT("/:admin_id/permissions", deps.AdminHandler.UpdateAdminPermissions)
	}

	// Audit logs
	audit := admin.Group("/audit")
	{
		audit.GET("/logs", deps.AdminHandler.GetAuditLogs)
		audit.GET("/logs/export", deps.AdminHandler.ExportAuditLogs)
		audit.GET("/logs/stats", deps.AdminHandler.GetAuditStats)
	}

	// Content filters
	filters := admin.Group("/filters")
	{
		filters.GET("", deps.AdminHandler.GetContentFilters)
		filters.POST("", deps.AdminHandler.CreateContentFilter)
		filters.GET("/:filter_id", deps.AdminHandler.GetContentFilter)
		filters.PUT("/:filter_id", deps.AdminHandler.UpdateContentFilter)
		filters.DELETE("/:filter_id", deps.AdminHandler.DeleteContentFilter)
		filters.POST("/:filter_id/test", deps.AdminHandler.TestContentFilter)
		filters.GET("/:filter_id/matches", deps.AdminHandler.GetFilterMatches)
	}

	// Analytics and insights
	analytics := admin.Group("/analytics")
	{
		analytics.GET("/overview", deps.AdminHandler.GetAnalyticsOverview)
		analytics.GET("/users", deps.AdminHandler.GetUserAnalytics)
		analytics.GET("/content", deps.AdminHandler.GetContentAnalytics)
		analytics.GET("/engagement", deps.AdminHandler.GetEngagementAnalytics)
		analytics.GET("/reports", deps.AdminHandler.GetAnalyticsReports)
		analytics.GET("/export", deps.AdminHandler.ExportAnalytics)
	}

	// WebSocket management
	websocket := admin.Group("/websocket")
	{
		websocket.GET("/stats", deps.AdminHandler.GetWebSocketStats)
		websocket.GET("/connections", deps.AdminHandler.GetActiveConnections)
		websocket.DELETE("/connections/:connection_id", deps.AdminHandler.DisconnectUser)
		websocket.POST("/broadcast", deps.AdminHandler.BroadcastMessage)
		websocket.GET("/rooms", deps.AdminHandler.GetWebSocketRooms)
	}
}
