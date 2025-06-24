package routes

import (
	"onthread/pkg/constants"

	"github.com/gin-gonic/gin"
)

// setupUserRoutes sets up user management routes
func setupUserRoutes(api *gin.RouterGroup, deps *Dependencies) {
	users := api.Group("/users")

	// Rate limiting for user actions
	followRateLimit := deps.RateLimitMiddleware.CreateRateLimiter(
		constants.FollowRateLimit,
		"follow",
	)

	// Public user routes
	users.GET("/search", deps.UserHandler.SearchUsers)
	users.GET("/suggestions", deps.UserHandler.GetSuggestions)
	users.GET("/:username", deps.UserHandler.GetUserByUsername)
	users.GET("/:username/threads", deps.UserHandler.GetUserThreads)
	users.GET("/:username/replies", deps.UserHandler.GetUserReplies)
	users.GET("/:username/media", deps.UserHandler.GetUserMedia)
	users.GET("/:username/likes", deps.UserHandler.GetUserLikes)

	// Protected user routes
	authenticated := users.Group("")
	authenticated.Use(deps.AuthMiddleware.RequireAuth())
	{
		// Profile management
		authenticated.GET("/me/profile", deps.UserHandler.GetProfile)
		authenticated.PUT("/me/profile", deps.UserHandler.UpdateProfile)
		authenticated.POST("/me/avatar", deps.UserHandler.UpdateAvatar)
		authenticated.POST("/me/cover", deps.UserHandler.UpdateCover)
		authenticated.DELETE("/me/avatar", deps.UserHandler.RemoveAvatar)
		authenticated.DELETE("/me/cover", deps.UserHandler.RemoveCover)

		// Settings
		authenticated.GET("/me/settings", deps.UserHandler.GetSettings)
		authenticated.PUT("/me/settings", deps.UserHandler.UpdateSettings)
		authenticated.GET("/me/privacy", deps.UserHandler.GetPrivacySettings)
		authenticated.PUT("/me/privacy", deps.UserHandler.UpdatePrivacySettings)

		// Account management
		authenticated.POST("/me/deactivate", deps.UserHandler.DeactivateAccount)
		authenticated.POST("/me/reactivate", deps.UserHandler.ReactivateAccount)
		authenticated.DELETE("/me/account", deps.UserHandler.DeleteAccount)
		authenticated.GET("/me/export", deps.UserHandler.ExportData)

		// Follow system
		authenticated.POST("/:username/follow", followRateLimit, deps.UserHandler.FollowUser)
		authenticated.DELETE("/:username/follow", deps.UserHandler.UnfollowUser)
		authenticated.GET("/:username/followers", deps.UserHandler.GetFollowers)
		authenticated.GET("/:username/following", deps.UserHandler.GetFollowing)
		authenticated.GET("/me/followers", deps.UserHandler.GetMyFollowers)
		authenticated.GET("/me/following", deps.UserHandler.GetMyFollowing)
		authenticated.GET("/me/follow-requests", deps.UserHandler.GetFollowRequests)
		authenticated.POST("/me/follow-requests/:user_id/accept", deps.UserHandler.AcceptFollowRequest)
		authenticated.POST("/me/follow-requests/:user_id/decline", deps.UserHandler.DeclineFollowRequest)

		// Block system
		authenticated.POST("/:username/block", deps.UserHandler.BlockUser)
		authenticated.DELETE("/:username/block", deps.UserHandler.UnblockUser)
		authenticated.GET("/me/blocked", deps.UserHandler.GetBlockedUsers)

		// Mute system
		authenticated.POST("/:username/mute", deps.UserHandler.MuteUser)
		authenticated.DELETE("/:username/mute", deps.UserHandler.UnmuteUser)
		authenticated.GET("/me/muted", deps.UserHandler.GetMutedUsers)

		// Lists
		authenticated.GET("/me/lists", deps.UserHandler.GetUserLists)
		authenticated.POST("/me/lists", deps.UserHandler.CreateList)
		authenticated.GET("/me/lists/:list_id", deps.UserHandler.GetList)
		authenticated.PUT("/me/lists/:list_id", deps.UserHandler.UpdateList)
		authenticated.DELETE("/me/lists/:list_id", deps.UserHandler.DeleteList)
		authenticated.POST("/me/lists/:list_id/members", deps.UserHandler.AddListMember)
		authenticated.DELETE("/me/lists/:list_id/members/:user_id", deps.UserHandler.RemoveListMember)
		authenticated.GET("/me/lists/:list_id/members", deps.UserHandler.GetListMembers)
		authenticated.POST("/lists/:list_id/follow", deps.UserHandler.FollowList)
		authenticated.DELETE("/lists/:list_id/follow", deps.UserHandler.UnfollowList)

		// Analytics
		authenticated.GET("/me/analytics", deps.UserHandler.GetUserAnalytics)
		authenticated.GET("/me/activity", deps.UserHandler.GetUserActivity)

		// Verification
		authenticated.POST("/me/verification/request", deps.UserHandler.RequestVerification)
		authenticated.GET("/me/verification/status", deps.UserHandler.GetVerificationStatus)
	}

	// Admin user routes
	admin := users.Group("/admin")
	admin.Use(deps.AdminMiddleware.RequireAdmin())
	{
		admin.GET("", deps.UserHandler.GetAllUsers)
		admin.GET("/:user_id", deps.UserHandler.GetUserByID)
		admin.PUT("/:user_id/verify", deps.UserHandler.VerifyUser)
		admin.DELETE("/:user_id/verify", deps.UserHandler.UnverifyUser)
		admin.POST("/:user_id/suspend", deps.UserHandler.SuspendUser)
		admin.POST("/:user_id/unsuspend", deps.UserHandler.UnsuspendUser)
		admin.POST("/:user_id/ban", deps.UserHandler.BanUser)
		admin.POST("/:user_id/unban", deps.UserHandler.UnbanUser)
		admin.GET("/:user_id/activity", deps.UserHandler.GetUserActivityAdmin)
		admin.GET("/:user_id/sessions", deps.UserHandler.GetUserSessions)
		admin.DELETE("/:user_id/sessions", deps.UserHandler.RevokeUserSessions)
	}
}
