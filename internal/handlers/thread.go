package handlers

import (
	"net/http"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	"go.mongodb.org/mongo-driver/bson/primitive"

	"onthread/internal/models"
	"onthread/internal/services"
	"onthread/internal/utils"
	"onthread/pkg/constants"
	"onthread/pkg/errors"
	"onthread/pkg/logger"
)

type ThreadHandler struct {
	threadService services.ThreadService
	userService   services.UserService
}

func NewThreadHandler(threadService services.ThreadService, userService services.UserService) *ThreadHandler {
	return &ThreadHandler{
		threadService: threadService,
		userService:   userService,
	}
}

// CreateThread creates a new thread
func (h *ThreadHandler) CreateThread(c *gin.Context) {
	var req struct {
		Content        string           `json:"content" binding:"required,max=500"`
		MediaFiles     []models.Media   `json:"media_files"`
		Type           string           `json:"type" binding:"required,thread_type"`
		ParentID       *string          `json:"parent_id"`
		QuotedThreadID *string          `json:"quoted_thread_id"`
		Hashtags       []string         `json:"hashtags"`
		Mentions       []string         `json:"mentions"`
		Visibility     string           `json:"visibility" binding:"required,visibility"`
		ReplySettings  string           `json:"reply_settings" binding:"required,reply_settings"`
		Location       *models.Location `json:"location"`
		Poll           *models.Poll     `json:"poll"`
		ScheduledAt    *time.Time       `json:"scheduled_at"`
		ContentWarning string           `json:"content_warning"`
		IsSensitive    bool             `json:"is_sensitive"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		errors := utils.GetValidationErrors(err)
		utils.ValidationErrorResponse(c, errors)
		return
	}

	userID, exists := c.Get("user_id")
	if !exists {
		utils.Unauthorized(c, "User not authenticated")
		return
	}

	// Convert string IDs to ObjectIDs
	var parentID, quotedThreadID *primitive.ObjectID
	if req.ParentID != nil {
		if id, err := primitive.ObjectIDFromHex(*req.ParentID); err == nil {
			parentID = &id
		} else {
			utils.BadRequest(c, "Invalid parent thread ID")
			return
		}
	}
	if req.QuotedThreadID != nil {
		if id, err := primitive.ObjectIDFromHex(*req.QuotedThreadID); err == nil {
			quotedThreadID = &id
		} else {
			utils.BadRequest(c, "Invalid quoted thread ID")
			return
		}
	}

	// Validate content length
	if len(req.Content) > constants.MaxThreadContentLength {
		utils.BadRequest(c, "Thread content too long")
		return
	}

	// Validate media files
	if len(req.MediaFiles) > constants.MaxMediaFilesPerThread {
		utils.BadRequest(c, "Too many media files")
		return
	}

	// Validate hashtags
	if len(req.Hashtags) > constants.MaxHashtagsPerThread {
		utils.BadRequest(c, "Too many hashtags")
		return
	}

	// Validate mentions
	if len(req.Mentions) > constants.MaxMentionsPerThread {
		utils.BadRequest(c, "Too many mentions")
		return
	}

	thread, err := h.threadService.CreateThread(c.Request.Context(), &services.CreateThreadRequest{
		AuthorID:       userID.(primitive.ObjectID),
		Content:        req.Content,
		MediaFiles:     req.MediaFiles,
		Type:           req.Type,
		ParentID:       parentID,
		QuotedThreadID: quotedThreadID,
		Hashtags:       req.Hashtags,
		Mentions:       req.Mentions,
		Visibility:     req.Visibility,
		ReplySettings:  req.ReplySettings,
		Location:       req.Location,
		Poll:           req.Poll,
		ScheduledAt:    req.ScheduledAt,
		ContentWarning: req.ContentWarning,
		IsSensitive:    req.IsSensitive,
	})

	if err != nil {
		if errors.IsAppError(err) {
			appErr := err.(*errors.AppError)
			utils.ErrorResponse(c, appErr.StatusCode, appErr.Code, appErr.Message)
		} else {
			utils.InternalServerError(c, "Failed to create thread")
		}
		return
	}

	logger.WithUserID(userID.(primitive.ObjectID)).WithField("thread_id", thread.ID).Info("Thread created successfully")

	statusCode := http.StatusCreated
	message := "Thread created successfully"
	if req.ScheduledAt != nil {
		message = "Thread scheduled successfully"
	}

	utils.SuccessResponse(c, statusCode, message, gin.H{
		"thread": thread,
	})
}

// GetThread retrieves a specific thread
func (h *ThreadHandler) GetThread(c *gin.Context) {
	threadIDStr := c.Param("thread_id")
	threadID, err := primitive.ObjectIDFromHex(threadIDStr)
	if err != nil {
		utils.BadRequest(c, "Invalid thread ID")
		return
	}

	// Get current user ID if authenticated
	var currentUserID *primitive.ObjectID
	if userID, exists := c.Get("user_id"); exists {
		id := userID.(primitive.ObjectID)
		currentUserID = &id
	}

	thread, err := h.threadService.GetThread(c.Request.Context(), threadID, currentUserID)
	if err != nil {
		if errors.IsAppError(err) {
			appErr := err.(*errors.AppError)
			utils.ErrorResponse(c, appErr.StatusCode, appErr.Code, appErr.Message)
		} else {
			utils.NotFound(c, "Thread not found")
		}
		return
	}

	utils.SuccessResponse(c, http.StatusOK, "Thread retrieved successfully", gin.H{
		"thread": thread,
	})
}

// UpdateThread updates an existing thread
func (h *ThreadHandler) UpdateThread(c *gin.Context) {
	threadIDStr := c.Param("thread_id")
	threadID, err := primitive.ObjectIDFromHex(threadIDStr)
	if err != nil {
		utils.BadRequest(c, "Invalid thread ID")
		return
	}

	var req struct {
		Content        string           `json:"content" binding:"max=500"`
		MediaFiles     []models.Media   `json:"media_files"`
		Hashtags       []string         `json:"hashtags"`
		Mentions       []string         `json:"mentions"`
		Location       *models.Location `json:"location"`
		ContentWarning string           `json:"content_warning"`
		IsSensitive    bool             `json:"is_sensitive"`
		EditReason     string           `json:"edit_reason" binding:"max=200"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		errors := utils.GetValidationErrors(err)
		utils.ValidationErrorResponse(c, errors)
		return
	}

	userID, exists := c.Get("user_id")
	if !exists {
		utils.Unauthorized(c, "User not authenticated")
		return
	}

	thread, err := h.threadService.UpdateThread(c.Request.Context(), threadID, userID.(primitive.ObjectID), &services.UpdateThreadRequest{
		Content:        req.Content,
		MediaFiles:     req.MediaFiles,
		Hashtags:       req.Hashtags,
		Mentions:       req.Mentions,
		Location:       req.Location,
		ContentWarning: req.ContentWarning,
		IsSensitive:    req.IsSensitive,
		EditReason:     req.EditReason,
	})

	if err != nil {
		if errors.IsAppError(err) {
			appErr := err.(*errors.AppError)
			utils.ErrorResponse(c, appErr.StatusCode, appErr.Code, appErr.Message)
		} else {
			utils.InternalServerError(c, "Failed to update thread")
		}
		return
	}

	utils.SuccessResponse(c, http.StatusOK, "Thread updated successfully", gin.H{
		"thread": thread,
	})
}

// DeleteThread deletes a thread
func (h *ThreadHandler) DeleteThread(c *gin.Context) {
	threadIDStr := c.Param("thread_id")
	threadID, err := primitive.ObjectIDFromHex(threadIDStr)
	if err != nil {
		utils.BadRequest(c, "Invalid thread ID")
		return
	}

	userID, exists := c.Get("user_id")
	if !exists {
		utils.Unauthorized(c, "User not authenticated")
		return
	}

	err = h.threadService.DeleteThread(c.Request.Context(), threadID, userID.(primitive.ObjectID))
	if err != nil {
		if errors.IsAppError(err) {
			appErr := err.(*errors.AppError)
			utils.ErrorResponse(c, appErr.StatusCode, appErr.Code, appErr.Message)
		} else {
			utils.InternalServerError(c, "Failed to delete thread")
		}
		return
	}

	utils.SuccessResponse(c, http.StatusOK, "Thread deleted successfully", nil)
}

// RestoreThread restores a deleted thread
func (h *ThreadHandler) RestoreThread(c *gin.Context) {
	threadIDStr := c.Param("thread_id")
	threadID, err := primitive.ObjectIDFromHex(threadIDStr)
	if err != nil {
		utils.BadRequest(c, "Invalid thread ID")
		return
	}

	userID, exists := c.Get("user_id")
	if !exists {
		utils.Unauthorized(c, "User not authenticated")
		return
	}

	thread, err := h.threadService.RestoreThread(c.Request.Context(), threadID, userID.(primitive.ObjectID))
	if err != nil {
		if errors.IsAppError(err) {
			appErr := err.(*errors.AppError)
			utils.ErrorResponse(c, appErr.StatusCode, appErr.Code, appErr.Message)
		} else {
			utils.InternalServerError(c, "Failed to restore thread")
		}
		return
	}

	utils.SuccessResponse(c, http.StatusOK, "Thread restored successfully", gin.H{
		"thread": thread,
	})
}

// GetPublicTimeline returns the public timeline
func (h *ThreadHandler) GetPublicTimeline(c *gin.Context) {
	params := utils.GetPaginationParams(c)

	// Get current user ID if authenticated
	var currentUserID *primitive.ObjectID
	if userID, exists := c.Get("user_id"); exists {
		id := userID.(primitive.ObjectID)
		currentUserID = &id
	}

	result, err := h.threadService.GetPublicTimeline(c.Request.Context(), currentUserID, params)
	if err != nil {
		utils.InternalServerError(c, "Failed to get public timeline")
		return
	}

	utils.SuccessResponseWithMeta(c, http.StatusOK, "Public timeline retrieved", result.Data, &utils.Meta{
		Pagination: result.Pagination,
	})
}

// GetUserFeed returns the user's personalized feed
func (h *ThreadHandler) GetUserFeed(c *gin.Context) {
	userID, exists := c.Get("user_id")
	if !exists {
		utils.Unauthorized(c, "User not authenticated")
		return
	}

	params := utils.GetPaginationParams(c)
	algorithm := c.DefaultQuery("algorithm", "chronological") // "chronological", "recommended"

	result, err := h.threadService.GetUserFeed(c.Request.Context(), userID.(primitive.ObjectID), algorithm, params)
	if err != nil {
		utils.InternalServerError(c, "Failed to get user feed")
		return
	}

	utils.SuccessResponseWithMeta(c, http.StatusOK, "User feed retrieved", result.Data, &utils.Meta{
		Pagination: result.Pagination,
	})
}

// GetFollowingFeed returns threads from users the user follows
func (h *ThreadHandler) GetFollowingFeed(c *gin.Context) {
	userID, exists := c.Get("user_id")
	if !exists {
		utils.Unauthorized(c, "User not authenticated")
		return
	}

	params := utils.GetPaginationParams(c)

	result, err := h.threadService.GetFollowingFeed(c.Request.Context(), userID.(primitive.ObjectID), params)
	if err != nil {
		utils.InternalServerError(c, "Failed to get following feed")
		return
	}

	utils.SuccessResponseWithMeta(c, http.StatusOK, "Following feed retrieved", result.Data, &utils.Meta{
		Pagination: result.Pagination,
	})
}

// GetTrendingThreads returns trending threads
func (h *ThreadHandler) GetTrendingThreads(c *gin.Context) {
	params := utils.GetPaginationParams(c)
	timeframe := c.DefaultQuery("timeframe", "24h") // "1h", "24h", "7d"

	// Get current user ID if authenticated
	var currentUserID *primitive.ObjectID
	if userID, exists := c.Get("user_id"); exists {
		id := userID.(primitive.ObjectID)
		currentUserID = &id
	}

	result, err := h.threadService.GetTrendingThreads(c.Request.Context(), currentUserID, timeframe, params)
	if err != nil {
		utils.InternalServerError(c, "Failed to get trending threads")
		return
	}

	utils.SuccessResponseWithMeta(c, http.StatusOK, "Trending threads retrieved", result.Data, &utils.Meta{
		Pagination: result.Pagination,
	})
}

// SearchThreads searches for threads
func (h *ThreadHandler) SearchThreads(c *gin.Context) {
	query := c.Query("q")
	if query == "" {
		utils.BadRequest(c, "Search query is required")
		return
	}

	params := utils.GetPaginationParams(c)
	filters := &services.SearchFilters{
		Type:      c.Query("type"),
		From:      c.Query("from"),
		HasMedia:  c.Query("has_media") == "true",
		Language:  c.Query("lang"),
		SinceDate: c.Query("since"),
		UntilDate: c.Query("until"),
	}

	// Get current user ID if authenticated
	var currentUserID *primitive.ObjectID
	if userID, exists := c.Get("user_id"); exists {
		id := userID.(primitive.ObjectID)
		currentUserID = &id
	}

	result, err := h.threadService.SearchThreads(c.Request.Context(), query, currentUserID, filters, params)
	if err != nil {
		utils.InternalServerError(c, "Search failed")
		return
	}

	utils.SuccessResponseWithMeta(c, http.StatusOK, "Search results", result.Data, &utils.Meta{
		Pagination: result.Pagination,
	})
}

// GetThreadReplies returns replies to a thread
func (h *ThreadHandler) GetThreadReplies(c *gin.Context) {
	threadIDStr := c.Param("thread_id")
	threadID, err := primitive.ObjectIDFromHex(threadIDStr)
	if err != nil {
		utils.BadRequest(c, "Invalid thread ID")
		return
	}

	params := utils.GetPaginationParams(c)

	// Get current user ID if authenticated
	var currentUserID *primitive.ObjectID
	if userID, exists := c.Get("user_id"); exists {
		id := userID.(primitive.ObjectID)
		currentUserID = &id
	}

	result, err := h.threadService.GetThreadReplies(c.Request.Context(), threadID, currentUserID, params)
	if err != nil {
		utils.InternalServerError(c, "Failed to get thread replies")
		return
	}

	utils.SuccessResponseWithMeta(c, http.StatusOK, "Thread replies retrieved", result.Data, &utils.Meta{
		Pagination: result.Pagination,
	})
}

// GetThreadQuotes returns quote threads
func (h *ThreadHandler) GetThreadQuotes(c *gin.Context) {
	threadIDStr := c.Param("thread_id")
	threadID, err := primitive.ObjectIDFromHex(threadIDStr)
	if err != nil {
		utils.BadRequest(c, "Invalid thread ID")
		return
	}

	params := utils.GetPaginationParams(c)

	// Get current user ID if authenticated
	var currentUserID *primitive.ObjectID
	if userID, exists := c.Get("user_id"); exists {
		id := userID.(primitive.ObjectID)
		currentUserID = &id
	}

	result, err := h.threadService.GetThreadQuotes(c.Request.Context(), threadID, currentUserID, params)
	if err != nil {
		utils.InternalServerError(c, "Failed to get thread quotes")
		return
	}

	utils.SuccessResponseWithMeta(c, http.StatusOK, "Thread quotes retrieved", result.Data, &utils.Meta{
		Pagination: result.Pagination,
	})
}

// GetThreadReposts returns users who reposted a thread
func (h *ThreadHandler) GetThreadReposts(c *gin.Context) {
	threadIDStr := c.Param("thread_id")
	threadID, err := primitive.ObjectIDFromHex(threadIDStr)
	if err != nil {
		utils.BadRequest(c, "Invalid thread ID")
		return
	}

	params := utils.GetPaginationParams(c)

	result, err := h.threadService.GetThreadReposts(c.Request.Context(), threadID, params)
	if err != nil {
		utils.InternalServerError(c, "Failed to get thread reposts")
		return
	}

	utils.SuccessResponseWithMeta(c, http.StatusOK, "Thread reposts retrieved", result.Data, &utils.Meta{
		Pagination: result.Pagination,
	})
}

// GetThreadLikes returns users who liked a thread
func (h *ThreadHandler) GetThreadLikes(c *gin.Context) {
	threadIDStr := c.Param("thread_id")
	threadID, err := primitive.ObjectIDFromHex(threadIDStr)
	if err != nil {
		utils.BadRequest(c, "Invalid thread ID")
		return
	}

	params := utils.GetPaginationParams(c)

	result, err := h.threadService.GetThreadLikes(c.Request.Context(), threadID, params)
	if err != nil {
		utils.InternalServerError(c, "Failed to get thread likes")
		return
	}

	utils.SuccessResponseWithMeta(c, http.StatusOK, "Thread likes retrieved", result.Data, &utils.Meta{
		Pagination: result.Pagination,
	})
}

// GetHashtagThreads returns threads with a specific hashtag
func (h *ThreadHandler) GetHashtagThreads(c *gin.Context) {
	hashtag := c.Param("hashtag")
	if hashtag == "" {
		utils.BadRequest(c, "Hashtag is required")
		return
	}

	params := utils.GetPaginationParams(c)

	// Get current user ID if authenticated
	var currentUserID *primitive.ObjectID
	if userID, exists := c.Get("user_id"); exists {
		id := userID.(primitive.ObjectID)
		currentUserID = &id
	}

	result, err := h.threadService.GetHashtagThreads(c.Request.Context(), hashtag, currentUserID, params)
	if err != nil {
		utils.InternalServerError(c, "Failed to get hashtag threads")
		return
	}

	utils.SuccessResponseWithMeta(c, http.StatusOK, "Hashtag threads retrieved", result.Data, &utils.Meta{
		Pagination: result.Pagination,
	})
}

// GetTrendingHashtags returns trending hashtags
func (h *ThreadHandler) GetTrendingHashtags(c *gin.Context) {
	limit := 20
	if l := c.Query("limit"); l != "" {
		if parsed, err := strconv.Atoi(l); err == nil && parsed > 0 && parsed <= 100 {
			limit = parsed
		}
	}

	timeframe := c.DefaultQuery("timeframe", "24h")

	hashtags, err := h.threadService.GetTrendingHashtags(c.Request.Context(), timeframe, limit)
	if err != nil {
		utils.InternalServerError(c, "Failed to get trending hashtags")
		return
	}

	utils.SuccessResponse(c, http.StatusOK, "Trending hashtags retrieved", gin.H{
		"hashtags": hashtags,
	})
}

// GetMentionThreads returns threads mentioning a user
func (h *ThreadHandler) GetMentionThreads(c *gin.Context) {
	username := c.Param("username")
	if username == "" {
		utils.BadRequest(c, "Username is required")
		return
	}

	params := utils.GetPaginationParams(c)

	// Get current user ID if authenticated
	var currentUserID *primitive.ObjectID
	if userID, exists := c.Get("user_id"); exists {
		id := userID.(primitive.ObjectID)
		currentUserID = &id
	}

	result, err := h.threadService.GetMentionThreads(c.Request.Context(), username, currentUserID, params)
	if err != nil {
		utils.InternalServerError(c, "Failed to get mention threads")
		return
	}

	utils.SuccessResponseWithMeta(c, http.StatusOK, "Mention threads retrieved", result.Data, &utils.Meta{
		Pagination: result.Pagination,
	})
}

// GetMentionsFeed returns threads mentioning the current user
func (h *ThreadHandler) GetMentionsFeed(c *gin.Context) {
	userID, exists := c.Get("user_id")
	if !exists {
		utils.Unauthorized(c, "User not authenticated")
		return
	}

	params := utils.GetPaginationParams(c)

	result, err := h.threadService.GetMentionsFeed(c.Request.Context(), userID.(primitive.ObjectID), params)
	if err != nil {
		utils.InternalServerError(c, "Failed to get mentions feed")
		return
	}

	utils.SuccessResponseWithMeta(c, http.StatusOK, "Mentions feed retrieved", result.Data, &utils.Meta{
		Pagination: result.Pagination,
	})
}

// GetListFeed returns threads from users in a list
func (h *ThreadHandler) GetListFeed(c *gin.Context) {
	listIDStr := c.Param("list_id")
	listID, err := primitive.ObjectIDFromHex(listIDStr)
	if err != nil {
		utils.BadRequest(c, "Invalid list ID")
		return
	}

	userID, exists := c.Get("user_id")
	if !exists {
		utils.Unauthorized(c, "User not authenticated")
		return
	}

	params := utils.GetPaginationParams(c)

	result, err := h.threadService.GetListFeed(c.Request.Context(), userID.(primitive.ObjectID), listID, params)
	if err != nil {
		if errors.IsAppError(err) {
			appErr := err.(*errors.AppError)
			utils.ErrorResponse(c, appErr.StatusCode, appErr.Code, appErr.Message)
		} else {
			utils.InternalServerError(c, "Failed to get list feed")
		}
		return
	}

	utils.SuccessResponseWithMeta(c, http.StatusOK, "List feed retrieved", result.Data, &utils.Meta{
		Pagination: result.Pagination,
	})
}

// Thread moderation
func (h *ThreadHandler) PinThread(c *gin.Context) {
	threadIDStr := c.Param("thread_id")
	threadID, err := primitive.ObjectIDFromHex(threadIDStr)
	if err != nil {
		utils.BadRequest(c, "Invalid thread ID")
		return
	}

	userID, exists := c.Get("user_id")
	if !exists {
		utils.Unauthorized(c, "User not authenticated")
		return
	}

	err = h.threadService.PinThread(c.Request.Context(), threadID, userID.(primitive.ObjectID))
	if err != nil {
		if errors.IsAppError(err) {
			appErr := err.(*errors.AppError)
			utils.ErrorResponse(c, appErr.StatusCode, appErr.Code, appErr.Message)
		} else {
			utils.InternalServerError(c, "Failed to pin thread")
		}
		return
	}

	utils.SuccessResponse(c, http.StatusOK, "Thread pinned successfully", nil)
}

func (h *ThreadHandler) UnpinThread(c *gin.Context) {
	threadIDStr := c.Param("thread_id")
	threadID, err := primitive.ObjectIDFromHex(threadIDStr)
	if err != nil {
		utils.BadRequest(c, "Invalid thread ID")
		return
	}

	userID, exists := c.Get("user_id")
	if !exists {
		utils.Unauthorized(c, "User not authenticated")
		return
	}

	err = h.threadService.UnpinThread(c.Request.Context(), threadID, userID.(primitive.ObjectID))
	if err != nil {
		if errors.IsAppError(err) {
			appErr := err.(*errors.AppError)
			utils.ErrorResponse(c, appErr.StatusCode, appErr.Code, appErr.Message)
		} else {
			utils.InternalServerError(c, "Failed to unpin thread")
		}
		return
	}

	utils.SuccessResponse(c, http.StatusOK, "Thread unpinned successfully", nil)
}

func (h *ThreadHandler) HideThread(c *gin.Context) {
	threadIDStr := c.Param("thread_id")
	threadID, err := primitive.ObjectIDFromHex(threadIDStr)
	if err != nil {
		utils.BadRequest(c, "Invalid thread ID")
		return
	}

	userID, exists := c.Get("user_id")
	if !exists {
		utils.Unauthorized(c, "User not authenticated")
		return
	}

	err = h.threadService.HideThread(c.Request.Context(), threadID, userID.(primitive.ObjectID))
	if err != nil {
		if errors.IsAppError(err) {
			appErr := err.(*errors.AppError)
			utils.ErrorResponse(c, appErr.StatusCode, appErr.Code, appErr.Message)
		} else {
			utils.InternalServerError(c, "Failed to hide thread")
		}
		return
	}

	utils.SuccessResponse(c, http.StatusOK, "Thread hidden successfully", nil)
}

func (h *ThreadHandler) UnhideThread(c *gin.Context) {
	threadIDStr := c.Param("thread_id")
	threadID, err := primitive.ObjectIDFromHex(threadIDStr)
	if err != nil {
		utils.BadRequest(c, "Invalid thread ID")
		return
	}

	userID, exists := c.Get("user_id")
	if !exists {
		utils.Unauthorized(c, "User not authenticated")
		return
	}

	err = h.threadService.UnhideThread(c.Request.Context(), threadID, userID.(primitive.ObjectID))
	if err != nil {
		if errors.IsAppError(err) {
			appErr := err.(*errors.AppError)
			utils.ErrorResponse(c, appErr.StatusCode, appErr.Code, appErr.Message)
		} else {
			utils.InternalServerError(c, "Failed to unhide thread")
		}
		return
	}

	utils.SuccessResponse(c, http.StatusOK, "Thread unhidden successfully", nil)
}

func (h *ThreadHandler) UpdateThreadVisibility(c *gin.Context) {
	threadIDStr := c.Param("thread_id")
	threadID, err := primitive.ObjectIDFromHex(threadIDStr)
	if err != nil {
		utils.BadRequest(c, "Invalid thread ID")
		return
	}

	var req struct {
		Visibility string `json:"visibility" binding:"required,visibility"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		utils.BadRequest(c, "Valid visibility is required")
		return
	}

	userID, exists := c.Get("user_id")
	if !exists {
		utils.Unauthorized(c, "User not authenticated")
		return
	}

	err = h.threadService.UpdateThreadVisibility(c.Request.Context(), threadID, userID.(primitive.ObjectID), req.Visibility)
	if err != nil {
		if errors.IsAppError(err) {
			appErr := err.(*errors.AppError)
			utils.ErrorResponse(c, appErr.StatusCode, appErr.Code, appErr.Message)
		} else {
			utils.InternalServerError(c, "Failed to update thread visibility")
		}
		return
	}

	utils.SuccessResponse(c, http.StatusOK, "Thread visibility updated successfully", nil)
}

func (h *ThreadHandler) UpdateReplySettings(c *gin.Context) {
	threadIDStr := c.Param("thread_id")
	threadID, err := primitive.ObjectIDFromHex(threadIDStr)
	if err != nil {
		utils.BadRequest(c, "Invalid thread ID")
		return
	}

	var req struct {
		ReplySettings string `json:"reply_settings" binding:"required,reply_settings"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		utils.BadRequest(c, "Valid reply settings are required")
		return
	}

	userID, exists := c.Get("user_id")
	if !exists {
		utils.Unauthorized(c, "User not authenticated")
		return
	}

	err = h.threadService.UpdateReplySettings(c.Request.Context(), threadID, userID.(primitive.ObjectID), req.ReplySettings)
	if err != nil {
		if errors.IsAppError(err) {
			appErr := err.(*errors.AppError)
			utils.ErrorResponse(c, appErr.StatusCode, appErr.Code, appErr.Message)
		} else {
			utils.InternalServerError(c, "Failed to update reply settings")
		}
		return
	}

	utils.SuccessResponse(c, http.StatusOK, "Reply settings updated successfully", nil)
}

// Scheduled threads
func (h *ThreadHandler) GetScheduledThreads(c *gin.Context) {
	userID, exists := c.Get("user_id")
	if !exists {
		utils.Unauthorized(c, "User not authenticated")
		return
	}

	params := utils.GetPaginationParams(c)

	result, err := h.threadService.GetScheduledThreads(c.Request.Context(), userID.(primitive.ObjectID), params)
	if err != nil {
		utils.InternalServerError(c, "Failed to get scheduled threads")
		return
	}

	utils.SuccessResponseWithMeta(c, http.StatusOK, "Scheduled threads retrieved", result.Data, &utils.Meta{
		Pagination: result.Pagination,
	})
}

func (h *ThreadHandler) ScheduleThread(c *gin.Context) {
	var req struct {
		Content        string           `json:"content" binding:"required,max=500"`
		MediaFiles     []models.Media   `json:"media_files"`
		Hashtags       []string         `json:"hashtags"`
		Mentions       []string         `json:"mentions"`
		Visibility     string           `json:"visibility" binding:"required,visibility"`
		ReplySettings  string           `json:"reply_settings" binding:"required,reply_settings"`
		Location       *models.Location `json:"location"`
		Poll           *models.Poll     `json:"poll"`
		ScheduledAt    time.Time        `json:"scheduled_at" binding:"required"`
		ContentWarning string           `json:"content_warning"`
		IsSensitive    bool             `json:"is_sensitive"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		errors := utils.GetValidationErrors(err)
		utils.ValidationErrorResponse(c, errors)
		return
	}

	if req.ScheduledAt.Before(time.Now().Add(5 * time.Minute)) {
		utils.BadRequest(c, "Scheduled time must be at least 5 minutes in the future")
		return
	}

	userID, exists := c.Get("user_id")
	if !exists {
		utils.Unauthorized(c, "User not authenticated")
		return
	}

	thread, err := h.threadService.ScheduleThread(c.Request.Context(), &services.ScheduleThreadRequest{
		AuthorID:       userID.(primitive.ObjectID),
		Content:        req.Content,
		MediaFiles:     req.MediaFiles,
		Hashtags:       req.Hashtags,
		Mentions:       req.Mentions,
		Visibility:     req.Visibility,
		ReplySettings:  req.ReplySettings,
		Location:       req.Location,
		Poll:           req.Poll,
		ScheduledAt:    req.ScheduledAt,
		ContentWarning: req.ContentWarning,
		IsSensitive:    req.IsSensitive,
	})

	if err != nil {
		utils.InternalServerError(c, "Failed to schedule thread")
		return
	}

	utils.SuccessResponse(c, http.StatusCreated, "Thread scheduled successfully", gin.H{
		"thread": thread,
	})
}

func (h *ThreadHandler) UpdateScheduledThread(c *gin.Context) {
	threadIDStr := c.Param("thread_id")
	threadID, err := primitive.ObjectIDFromHex(threadIDStr)
	if err != nil {
		utils.BadRequest(c, "Invalid thread ID")
		return
	}

	var req struct {
		Content        string           `json:"content" binding:"max=500"`
		MediaFiles     []models.Media   `json:"media_files"`
		Hashtags       []string         `json:"hashtags"`
		Mentions       []string         `json:"mentions"`
		Visibility     string           `json:"visibility" binding:"visibility"`
		ReplySettings  string           `json:"reply_settings" binding:"reply_settings"`
		Location       *models.Location `json:"location"`
		Poll           *models.Poll     `json:"poll"`
		ScheduledAt    *time.Time       `json:"scheduled_at"`
		ContentWarning string           `json:"content_warning"`
		IsSensitive    bool             `json:"is_sensitive"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		errors := utils.GetValidationErrors(err)
		utils.ValidationErrorResponse(c, errors)
		return
	}

	userID, exists := c.Get("user_id")
	if !exists {
		utils.Unauthorized(c, "User not authenticated")
		return
	}

	thread, err := h.threadService.UpdateScheduledThread(c.Request.Context(), threadID, userID.(primitive.ObjectID), &services.UpdateScheduledThreadRequest{
		Content:        req.Content,
		MediaFiles:     req.MediaFiles,
		Hashtags:       req.Hashtags,
		Mentions:       req.Mentions,
		Visibility:     req.Visibility,
		ReplySettings:  req.ReplySettings,
		Location:       req.Location,
		Poll:           req.Poll,
		ScheduledAt:    req.ScheduledAt,
		ContentWarning: req.ContentWarning,
		IsSensitive:    req.IsSensitive,
	})

	if err != nil {
		if errors.IsAppError(err) {
			appErr := err.(*errors.AppError)
			utils.ErrorResponse(c, appErr.StatusCode, appErr.Code, appErr.Message)
		} else {
			utils.InternalServerError(c, "Failed to update scheduled thread")
		}
		return
	}

	utils.SuccessResponse(c, http.StatusOK, "Scheduled thread updated successfully", gin.H{
		"thread": thread,
	})
}

func (h *ThreadHandler) CancelScheduledThread(c *gin.Context) {
	threadIDStr := c.Param("thread_id")
	threadID, err := primitive.ObjectIDFromHex(threadIDStr)
	if err != nil {
		utils.BadRequest(c, "Invalid thread ID")
		return
	}

	userID, exists := c.Get("user_id")
	if !exists {
		utils.Unauthorized(c, "User not authenticated")
		return
	}

	err = h.threadService.CancelScheduledThread(c.Request.Context(), threadID, userID.(primitive.ObjectID))
	if err != nil {
		if errors.IsAppError(err) {
			appErr := err.(*errors.AppError)
			utils.ErrorResponse(c, appErr.StatusCode, appErr.Code, appErr.Message)
		} else {
			utils.InternalServerError(c, "Failed to cancel scheduled thread")
		}
		return
	}

	utils.SuccessResponse(c, http.StatusOK, "Scheduled thread cancelled successfully", nil)
}

func (h *ThreadHandler) PublishScheduledThread(c *gin.Context) {
	threadIDStr := c.Param("thread_id")
	threadID, err := primitive.ObjectIDFromHex(threadIDStr)
	if err != nil {
		utils.BadRequest(c, "Invalid thread ID")
		return
	}

	userID, exists := c.Get("user_id")
	if !exists {
		utils.Unauthorized(c, "User not authenticated")
		return
	}

	thread, err := h.threadService.PublishScheduledThread(c.Request.Context(), threadID, userID.(primitive.ObjectID))
	if err != nil {
		if errors.IsAppError(err) {
			appErr := err.(*errors.AppError)
			utils.ErrorResponse(c, appErr.StatusCode, appErr.Code, appErr.Message)
		} else {
			utils.InternalServerError(c, "Failed to publish scheduled thread")
		}
		return
	}

	utils.SuccessResponse(c, http.StatusOK, "Thread published successfully", gin.H{
		"thread": thread,
	})
}

// Drafts
func (h *ThreadHandler) GetDrafts(c *gin.Context) {
	userID, exists := c.Get("user_id")
	if !exists {
		utils.Unauthorized(c, "User not authenticated")
		return
	}

	params := utils.GetPaginationParams(c)

	result, err := h.threadService.GetDrafts(c.Request.Context(), userID.(primitive.ObjectID), params)
	if err != nil {
		utils.InternalServerError(c, "Failed to get drafts")
		return
	}

	utils.SuccessResponseWithMeta(c, http.StatusOK, "Drafts retrieved", result.Data, &utils.Meta{
		Pagination: result.Pagination,
	})
}

func (h *ThreadHandler) SaveDraft(c *gin.Context) {
	var req struct {
		Content        string           `json:"content" binding:"max=500"`
		MediaFiles     []models.Media   `json:"media_files"`
		Hashtags       []string         `json:"hashtags"`
		Mentions       []string         `json:"mentions"`
		Visibility     string           `json:"visibility" binding:"visibility"`
		ReplySettings  string           `json:"reply_settings" binding:"reply_settings"`
		Location       *models.Location `json:"location"`
		Poll           *models.Poll     `json:"poll"`
		ContentWarning string           `json:"content_warning"`
		IsSensitive    bool             `json:"is_sensitive"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		errors := utils.GetValidationErrors(err)
		utils.ValidationErrorResponse(c, errors)
		return
	}

	userID, exists := c.Get("user_id")
	if !exists {
		utils.Unauthorized(c, "User not authenticated")
		return
	}

	draft, err := h.threadService.SaveDraft(c.Request.Context(), &services.SaveDraftRequest{
		AuthorID:       userID.(primitive.ObjectID),
		Content:        req.Content,
		MediaFiles:     req.MediaFiles,
		Hashtags:       req.Hashtags,
		Mentions:       req.Mentions,
		Visibility:     req.Visibility,
		ReplySettings:  req.ReplySettings,
		Location:       req.Location,
		Poll:           req.Poll,
		ContentWarning: req.ContentWarning,
		IsSensitive:    req.IsSensitive,
	})

	if err != nil {
		utils.InternalServerError(c, "Failed to save draft")
		return
	}

	utils.SuccessResponse(c, http.StatusCreated, "Draft saved successfully", gin.H{
		"draft": draft,
	})
}

func (h *ThreadHandler) UpdateDraft(c *gin.Context) {
	draftIDStr := c.Param("draft_id")
	draftID, err := primitive.ObjectIDFromHex(draftIDStr)
	if err != nil {
		utils.BadRequest(c, "Invalid draft ID")
		return
	}

	var req struct {
		Content        string           `json:"content" binding:"max=500"`
		MediaFiles     []models.Media   `json:"media_files"`
		Hashtags       []string         `json:"hashtags"`
		Mentions       []string         `json:"mentions"`
		Visibility     string           `json:"visibility" binding:"visibility"`
		ReplySettings  string           `json:"reply_settings" binding:"reply_settings"`
		Location       *models.Location `json:"location"`
		Poll           *models.Poll     `json:"poll"`
		ContentWarning string           `json:"content_warning"`
		IsSensitive    bool             `json:"is_sensitive"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		errors := utils.GetValidationErrors(err)
		utils.ValidationErrorResponse(c, errors)
		return
	}

	userID, exists := c.Get("user_id")
	if !exists {
		utils.Unauthorized(c, "User not authenticated")
		return
	}

	draft, err := h.threadService.UpdateDraft(c.Request.Context(), draftID, userID.(primitive.ObjectID), &services.UpdateDraftRequest{
		Content:        req.Content,
		MediaFiles:     req.MediaFiles,
		Hashtags:       req.Hashtags,
		Mentions:       req.Mentions,
		Visibility:     req.Visibility,
		ReplySettings:  req.ReplySettings,
		Location:       req.Location,
		Poll:           req.Poll,
		ContentWarning: req.ContentWarning,
		IsSensitive:    req.IsSensitive,
	})

	if err != nil {
		if errors.IsAppError(err) {
			appErr := err.(*errors.AppError)
			utils.ErrorResponse(c, appErr.StatusCode, appErr.Code, appErr.Message)
		} else {
			utils.InternalServerError(c, "Failed to update draft")
		}
		return
	}

	utils.SuccessResponse(c, http.StatusOK, "Draft updated successfully", gin.H{
		"draft": draft,
	})
}

func (h *ThreadHandler) DeleteDraft(c *gin.Context) {
	draftIDStr := c.Param("draft_id")
	draftID, err := primitive.ObjectIDFromHex(draftIDStr)
	if err != nil {
		utils.BadRequest(c, "Invalid draft ID")
		return
	}

	userID, exists := c.Get("user_id")
	if !exists {
		utils.Unauthorized(c, "User not authenticated")
		return
	}

	err = h.threadService.DeleteDraft(c.Request.Context(), draftID, userID.(primitive.ObjectID))
	if err != nil {
		if errors.IsAppError(err) {
			appErr := err.(*errors.AppError)
			utils.ErrorResponse(c, appErr.StatusCode, appErr.Code, appErr.Message)
		} else {
			utils.InternalServerError(c, "Failed to delete draft")
		}
		return
	}

	utils.SuccessResponse(c, http.StatusOK, "Draft deleted successfully", nil)
}

func (h *ThreadHandler) PublishDraft(c *gin.Context) {
	draftIDStr := c.Param("draft_id")
	draftID, err := primitive.ObjectIDFromHex(draftIDStr)
	if err != nil {
		utils.BadRequest(c, "Invalid draft ID")
		return
	}

	userID, exists := c.Get("user_id")
	if !exists {
		utils.Unauthorized(c, "User not authenticated")
		return
	}

	thread, err := h.threadService.PublishDraft(c.Request.Context(), draftID, userID.(primitive.ObjectID))
	if err != nil {
		if errors.IsAppError(err) {
			appErr := err.(*errors.AppError)
			utils.ErrorResponse(c, appErr.StatusCode, appErr.Code, appErr.Message)
		} else {
			utils.InternalServerError(c, "Failed to publish draft")
		}
		return
	}

	utils.SuccessResponse(c, http.StatusOK, "Draft published successfully", gin.H{
		"thread": thread,
	})
}

// Analytics
func (h *ThreadHandler) GetThreadAnalytics(c *gin.Context) {
	threadIDStr := c.Param("thread_id")
	threadID, err := primitive.ObjectIDFromHex(threadIDStr)
	if err != nil {
		utils.BadRequest(c, "Invalid thread ID")
		return
	}

	userID, exists := c.Get("user_id")
	if !exists {
		utils.Unauthorized(c, "User not authenticated")
		return
	}

	analytics, err := h.threadService.GetThreadAnalytics(c.Request.Context(), threadID, userID.(primitive.ObjectID))
	if err != nil {
		if errors.IsAppError(err) {
			appErr := err.(*errors.AppError)
			utils.ErrorResponse(c, appErr.StatusCode, appErr.Code, appErr.Message)
		} else {
			utils.InternalServerError(c, "Failed to get thread analytics")
		}
		return
	}

	utils.SuccessResponse(c, http.StatusOK, "Thread analytics retrieved", gin.H{
		"analytics": analytics,
	})
}

func (h *ThreadHandler) GetUserThreadAnalytics(c *gin.Context) {
	userID, exists := c.Get("user_id")
	if !exists {
		utils.Unauthorized(c, "User not authenticated")
		return
	}

	timeframe := c.DefaultQuery("timeframe", "30d")

	analytics, err := h.threadService.GetUserThreadAnalytics(c.Request.Context(), userID.(primitive.ObjectID), timeframe)
	if err != nil {
		utils.InternalServerError(c, "Failed to get user thread analytics")
		return
	}

	utils.SuccessResponse(c, http.StatusOK, "User thread analytics retrieved", gin.H{
		"analytics": analytics,
	})
}

// Admin functions
func (h *ThreadHandler) GetAllThreads(c *gin.Context) {
	params := utils.GetPaginationParams(c)
	filter := c.Query("filter")

	result, err := h.threadService.GetAllThreads(c.Request.Context(), params, filter)
	if err != nil {
		utils.InternalServerError(c, "Failed to get threads")
		return
	}

	utils.SuccessResponseWithMeta(c, http.StatusOK, "Threads retrieved", result.Data, &utils.Meta{
		Pagination: result.Pagination,
	})
}

func (h *ThreadHandler) GetReportedThreads(c *gin.Context) {
	params := utils.GetPaginationParams(c)

	result, err := h.threadService.GetReportedThreads(c.Request.Context(), params)
	if err != nil {
		utils.InternalServerError(c, "Failed to get reported threads")
		return
	}

	utils.SuccessResponseWithMeta(c, http.StatusOK, "Reported threads retrieved", result.Data, &utils.Meta{
		Pagination: result.Pagination,
	})
}

func (h *ThreadHandler) GetFlaggedThreads(c *gin.Context) {
	params := utils.GetPaginationParams(c)

	result, err := h.threadService.GetFlaggedThreads(c.Request.Context(), params)
	if err != nil {
		utils.InternalServerError(c, "Failed to get flagged threads")
		return
	}

	utils.SuccessResponseWithMeta(c, http.StatusOK, "Flagged threads retrieved", result.Data, &utils.Meta{
		Pagination: result.Pagination,
	})
}

func (h *ThreadHandler) GetThreadReports(c *gin.Context) {
	threadIDStr := c.Param("thread_id")
	threadID, err := primitive.ObjectIDFromHex(threadIDStr)
	if err != nil {
		utils.BadRequest(c, "Invalid thread ID")
		return
	}

	params := utils.GetPaginationParams(c)

	result, err := h.threadService.GetThreadReports(c.Request.Context(), threadID, params)
	if err != nil {
		utils.InternalServerError(c, "Failed to get thread reports")
		return
	}

	utils.SuccessResponseWithMeta(c, http.StatusOK, "Thread reports retrieved", result.Data, &utils.Meta{
		Pagination: result.Pagination,
	})
}

func (h *ThreadHandler) ModerateThread(c *gin.Context) {
	threadIDStr := c.Param("thread_id")
	threadID, err := primitive.ObjectIDFromHex(threadIDStr)
	if err != nil {
		utils.BadRequest(c, "Invalid thread ID")
		return
	}

	var req struct {
		Action string `json:"action" binding:"required"`
		Reason string `json:"reason" binding:"required"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		utils.BadRequest(c, "Action and reason are required")
		return
	}

	adminID, exists := c.Get("admin_id")
	if !exists {
		utils.Unauthorized(c, "Admin not authenticated")
		return
	}

	err = h.threadService.ModerateThread(c.Request.Context(), threadID, adminID.(primitive.ObjectID), req.Action, req.Reason)
	if err != nil {
		if errors.IsAppError(err) {
			appErr := err.(*errors.AppError)
			utils.ErrorResponse(c, appErr.StatusCode, appErr.Code, appErr.Message)
		} else {
			utils.InternalServerError(c, "Failed to moderate thread")
		}
		return
	}

	utils.SuccessResponse(c, http.StatusOK, "Thread moderated successfully", nil)
}

func (h *ThreadHandler) FeatureThread(c *gin.Context) {
	threadIDStr := c.Param("thread_id")
	threadID, err := primitive.ObjectIDFromHex(threadIDStr)
	if err != nil {
		utils.BadRequest(c, "Invalid thread ID")
		return
	}

	adminID, exists := c.Get("admin_id")
	if !exists {
		utils.Unauthorized(c, "Admin not authenticated")
		return
	}

	err = h.threadService.FeatureThread(c.Request.Context(), threadID, adminID.(primitive.ObjectID))
	if err != nil {
		utils.InternalServerError(c, "Failed to feature thread")
		return
	}

	utils.SuccessResponse(c, http.StatusOK, "Thread featured successfully", nil)
}

func (h *ThreadHandler) UnfeatureThread(c *gin.Context) {
	threadIDStr := c.Param("thread_id")
	threadID, err := primitive.ObjectIDFromHex(threadIDStr)
	if err != nil {
		utils.BadRequest(c, "Invalid thread ID")
		return
	}

	adminID, exists := c.Get("admin_id")
	if !exists {
		utils.Unauthorized(c, "Admin not authenticated")
		return
	}

	err = h.threadService.UnfeatureThread(c.Request.Context(), threadID, adminID.(primitive.ObjectID))
	if err != nil {
		utils.InternalServerError(c, "Failed to unfeature thread")
		return
	}

	utils.SuccessResponse(c, http.StatusOK, "Thread unfeatured successfully", nil)
}

func (h *ThreadHandler) LockThread(c *gin.Context) {
	threadIDStr := c.Param("thread_id")
	threadID, err := primitive.ObjectIDFromHex(threadIDStr)
	if err != nil {
		utils.BadRequest(c, "Invalid thread ID")
		return
	}

	var req struct {
		Reason string `json:"reason" binding:"required"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		utils.BadRequest(c, "Reason is required")
		return
	}

	adminID, exists := c.Get("admin_id")
	if !exists {
		utils.Unauthorized(c, "Admin not authenticated")
		return
	}

	err = h.threadService.LockThread(c.Request.Context(), threadID, adminID.(primitive.ObjectID), req.Reason)
	if err != nil {
		utils.InternalServerError(c, "Failed to lock thread")
		return
	}

	utils.SuccessResponse(c, http.StatusOK, "Thread locked successfully", nil)
}

func (h *ThreadHandler) UnlockThread(c *gin.Context) {
	threadIDStr := c.Param("thread_id")
	threadID, err := primitive.ObjectIDFromHex(threadIDStr)
	if err != nil {
		utils.BadRequest(c, "Invalid thread ID")
		return
	}

	adminID, exists := c.Get("admin_id")
	if !exists {
		utils.Unauthorized(c, "Admin not authenticated")
		return
	}

	err = h.threadService.UnlockThread(c.Request.Context(), threadID, adminID.(primitive.ObjectID))
	if err != nil {
		utils.InternalServerError(c, "Failed to unlock thread")
		return
	}

	utils.SuccessResponse(c, http.StatusOK, "Thread unlocked successfully", nil)
}

func (h *ThreadHandler) AdminDeleteThread(c *gin.Context) {
	threadIDStr := c.Param("thread_id")
	threadID, err := primitive.ObjectIDFromHex(threadIDStr)
	if err != nil {
		utils.BadRequest(c, "Invalid thread ID")
		return
	}

	var req struct {
		Reason string `json:"reason" binding:"required"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		utils.BadRequest(c, "Reason is required")
		return
	}

	adminID, exists := c.Get("admin_id")
	if !exists {
		utils.Unauthorized(c, "Admin not authenticated")
		return
	}

	err = h.threadService.AdminDeleteThread(c.Request.Context(), threadID, adminID.(primitive.ObjectID), req.Reason)
	if err != nil {
		utils.InternalServerError(c, "Failed to delete thread")
		return
	}

	utils.SuccessResponse(c, http.StatusOK, "Thread deleted successfully", nil)
}

func (h *ThreadHandler) AdminRestoreThread(c *gin.Context) {
	threadIDStr := c.Param("thread_id")
	threadID, err := primitive.ObjectIDFromHex(threadIDStr)
	if err != nil {
		utils.BadRequest(c, "Invalid thread ID")
		return
	}

	var req struct {
		Reason string `json:"reason" binding:"required"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		utils.BadRequest(c, "Reason is required")
		return
	}

	adminID, exists := c.Get("admin_id")
	if !exists {
		utils.Unauthorized(c, "Admin not authenticated")
		return
	}

	thread, err := h.threadService.AdminRestoreThread(c.Request.Context(), threadID, adminID.(primitive.ObjectID), req.Reason)
	if err != nil {
		utils.InternalServerError(c, "Failed to restore thread")
		return
	}

	utils.SuccessResponse(c, http.StatusOK, "Thread restored successfully", gin.H{
		"thread": thread,
	})
}
