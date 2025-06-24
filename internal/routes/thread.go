package routes

import (
	"onthread/pkg/constants"

	"github.com/gin-gonic/gin"
)

// setupThreadRoutes sets up thread/content routes
func setupThreadRoutes(api *gin.RouterGroup, deps *Dependencies) {
	threads := api.Group("/threads")

	// Rate limiting for thread actions
	threadRateLimit := deps.RateLimitMiddleware.CreateRateLimiter(
		constants.ThreadPostRateLimit,
		"thread_post",
	)

	likeRateLimit := deps.RateLimitMiddleware.CreateRateLimiter(
		constants.LikeRateLimit,
		"like",
	)

	// Public thread routes
	threads.GET("", deps.ThreadHandler.GetPublicTimeline)
	threads.GET("/trending", deps.ThreadHandler.GetTrendingThreads)
	threads.GET("/search", deps.ThreadHandler.SearchThreads)
	threads.GET("/:thread_id", deps.ThreadHandler.GetThread)
	threads.GET("/:thread_id/replies", deps.ThreadHandler.GetThreadReplies)
	threads.GET("/:thread_id/quotes", deps.ThreadHandler.GetThreadQuotes)
	threads.GET("/:thread_id/reposts", deps.ThreadHandler.GetThreadReposts)
	threads.GET("/:thread_id/likes", deps.ThreadHandler.GetThreadLikes)

	// Hashtags and mentions
	threads.GET("/hashtags/:hashtag", deps.ThreadHandler.GetHashtagThreads)
	threads.GET("/hashtags/trending", deps.ThreadHandler.GetTrendingHashtags)
	threads.GET("/mentions/:username", deps.ThreadHandler.GetMentionThreads)

	// Protected thread routes
	authenticated := threads.Group("")
	authenticated.Use(deps.AuthMiddleware.RequireAuth())
	{
		// Thread CRUD
		authenticated.POST("", threadRateLimit, deps.ThreadHandler.CreateThread)
		authenticated.PUT("/:thread_id", deps.ThreadHandler.UpdateThread)
		authenticated.DELETE("/:thread_id", deps.ThreadHandler.DeleteThread)
		authenticated.POST("/:thread_id/restore", deps.ThreadHandler.RestoreThread)

		// Thread interactions
		authenticated.POST("/:thread_id/like", likeRateLimit, deps.InteractionHandler.LikeThread)
		authenticated.DELETE("/:thread_id/like", deps.InteractionHandler.UnlikeThread)
		authenticated.POST("/:thread_id/repost", deps.InteractionHandler.RepostThread)
		authenticated.DELETE("/:thread_id/repost", deps.InteractionHandler.UnrepostThread)
		authenticated.POST("/:thread_id/quote", deps.InteractionHandler.QuoteThread)
		authenticated.POST("/:thread_id/reply", deps.InteractionHandler.ReplyThread)
		authenticated.POST("/:thread_id/bookmark", deps.InteractionHandler.BookmarkThread)
		authenticated.DELETE("/:thread_id/bookmark", deps.InteractionHandler.UnbookmarkThread)
		authenticated.POST("/:thread_id/share", deps.InteractionHandler.ShareThread)
		authenticated.POST("/:thread_id/report", deps.InteractionHandler.ReportThread)
		authenticated.POST("/:thread_id/pin", deps.ThreadHandler.PinThread)
		authenticated.DELETE("/:thread_id/pin", deps.ThreadHandler.UnpinThread)

		// Thread moderation (self)
		authenticated.POST("/:thread_id/hide", deps.ThreadHandler.HideThread)
		authenticated.POST("/:thread_id/unhide", deps.ThreadHandler.UnhideThread)
		authenticated.PUT("/:thread_id/visibility", deps.ThreadHandler.UpdateThreadVisibility)
		authenticated.PUT("/:thread_id/reply-settings", deps.ThreadHandler.UpdateReplySettings)

		// Bookmarks
		authenticated.GET("/bookmarks", deps.InteractionHandler.GetBookmarks)
		authenticated.GET("/bookmarks/folders", deps.InteractionHandler.GetBookmarkFolders)
		authenticated.POST("/bookmarks/folders", deps.InteractionHandler.CreateBookmarkFolder)
		authenticated.PUT("/bookmarks/folders/:folder_id", deps.InteractionHandler.UpdateBookmarkFolder)
		authenticated.DELETE("/bookmarks/folders/:folder_id", deps.InteractionHandler.DeleteBookmarkFolder)
		authenticated.POST("/bookmarks/:bookmark_id/move", deps.InteractionHandler.MoveBookmark)

		// Scheduled threads
		authenticated.GET("/scheduled", deps.ThreadHandler.GetScheduledThreads)
		authenticated.POST("/scheduled", deps.ThreadHandler.ScheduleThread)
		authenticated.PUT("/scheduled/:thread_id", deps.ThreadHandler.UpdateScheduledThread)
		authenticated.DELETE("/scheduled/:thread_id", deps.ThreadHandler.CancelScheduledThread)
		authenticated.POST("/scheduled/:thread_id/publish", deps.ThreadHandler.PublishScheduledThread)

		// Drafts
		authenticated.GET("/drafts", deps.ThreadHandler.GetDrafts)
		authenticated.POST("/drafts", deps.ThreadHandler.SaveDraft)
		authenticated.PUT("/drafts/:draft_id", deps.ThreadHandler.UpdateDraft)
		authenticated.DELETE("/drafts/:draft_id", deps.ThreadHandler.DeleteDraft)
		authenticated.POST("/drafts/:draft_id/publish", deps.ThreadHandler.PublishDraft)

		// User feeds
		authenticated.GET("/feed", deps.ThreadHandler.GetUserFeed)
		authenticated.GET("/feed/following", deps.ThreadHandler.GetFollowingFeed)
		authenticated.GET("/feed/lists/:list_id", deps.ThreadHandler.GetListFeed)
		authenticated.GET("/feed/mentions", deps.ThreadHandler.GetMentionsFeed)

		// Thread analytics
		authenticated.GET("/:thread_id/analytics", deps.ThreadHandler.GetThreadAnalytics)
		authenticated.GET("/me/analytics", deps.ThreadHandler.GetUserThreadAnalytics)

		// Polls
		authenticated.POST("/:thread_id/poll/vote", deps.InteractionHandler.VoteInPoll)
		authenticated.DELETE("/:thread_id/poll/vote", deps.InteractionHandler.RemovePollVote)
		authenticated.GET("/:thread_id/poll/results", deps.InteractionHandler.GetPollResults)
	}

	// Admin thread routes
	admin := threads.Group("/admin")
	admin.Use(deps.AdminMiddleware.RequireAdmin())
	{
		admin.GET("", deps.ThreadHandler.GetAllThreads)
		admin.GET("/reported", deps.ThreadHandler.GetReportedThreads)
		admin.GET("/flagged", deps.ThreadHandler.GetFlaggedThreads)
		admin.GET("/:thread_id/reports", deps.ThreadHandler.GetThreadReports)
		admin.POST("/:thread_id/moderate", deps.ThreadHandler.ModerateThread)
		admin.POST("/:thread_id/feature", deps.ThreadHandler.FeatureThread)
		admin.DELETE("/:thread_id/feature", deps.ThreadHandler.UnfeatureThread)
		admin.POST("/:thread_id/lock", deps.ThreadHandler.LockThread)
		admin.POST("/:thread_id/unlock", deps.ThreadHandler.UnlockThread)
		admin.DELETE("/:thread_id", deps.ThreadHandler.AdminDeleteThread)
		admin.POST("/:thread_id/restore", deps.ThreadHandler.AdminRestoreThread)
	}
}
