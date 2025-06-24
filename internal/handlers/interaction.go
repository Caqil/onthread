package handlers

import (
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"go.mongodb.org/mongo-driver/bson/primitive"

	"onthread/internal/models"
	"onthread/internal/repository"
	"onthread/internal/services"
	"onthread/internal/utils"
	"onthread/pkg/errors"
	"onthread/pkg/logger"
)

type InteractionHandler struct {
	interactionRepo     repository.InteractionRepository
	threadService       services.ThreadService
	userService         services.UserService
	notificationService services.NotificationService
}

func NewInteractionHandler(
	interactionRepo repository.InteractionRepository,
	threadService services.ThreadService,
	userService services.UserService,
	notificationService services.NotificationService,
) *InteractionHandler {
	return &InteractionHandler{
		interactionRepo:     interactionRepo,
		threadService:       threadService,
		userService:         userService,
		notificationService: notificationService,
	}
}

// LikeThread likes a thread
func (h *InteractionHandler) LikeThread(c *gin.Context) {
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

	// Check if thread exists and user can interact with it
	uid := userID.(primitive.ObjectID)
	thread, err := h.threadService.GetThread(c.Request.Context(), threadID, &uid)
	if err != nil {
		if errors.IsAppError(err) {
			appErr := err.(*errors.AppError)
			utils.ErrorResponse(c, appErr.StatusCode, appErr.Code, appErr.Message)
		} else {
			utils.NotFound(c, "Thread not found")
		}
		return
	}

	// Check if already liked
	exists, err = h.interactionRepo.HasLiked(c.Request.Context(), userID.(primitive.ObjectID), threadID)
	if err != nil {
		utils.InternalServerError(c, "Failed to check like status")
		return
	}

	if exists {
		utils.Conflict(c, "Thread already liked")
		return
	}

	// Create like
	like := &models.Like{
		UserID:   userID.(primitive.ObjectID),
		ThreadID: threadID,
		LikedAt:  time.Now(),
	}

	err = h.interactionRepo.CreateLike(c.Request.Context(), like)
	if err != nil {
		utils.InternalServerError(c, "Failed to like thread")
		return
	}

	// Update thread likes count
	err = h.threadService.IncrementLikesCount(c.Request.Context(), threadID, 1)
	if err != nil {
		logger.WithError(err).Error("Failed to increment likes count")
	}

	// Send notification if not self-like
	if thread.AuthorID != userID.(primitive.ObjectID) {
		go h.notificationService.CreateNotification(c.Request.Context(), &services.CreateNotificationRequest{
			RecipientID: thread.AuthorID,
			ActorID:     userID.(primitive.ObjectID),
			Type:        "like",
			TargetType:  "thread",
			TargetID:    &threadID,
			ThreadID:    &threadID,
		})
	}

	logger.WithUserID(userID.(primitive.ObjectID)).WithField("thread_id", threadID).Info("Thread liked")

	utils.SuccessResponse(c, http.StatusOK, "Thread liked successfully", gin.H{
		"liked_at": like.LikedAt,
	})
}

// UnlikeThread unlikes a thread
func (h *InteractionHandler) UnlikeThread(c *gin.Context) {
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

	// Check if liked
	exists, err = h.interactionRepo.HasLiked(c.Request.Context(), userID.(primitive.ObjectID), threadID)
	if err != nil {
		utils.InternalServerError(c, "Failed to check like status")
		return
	}

	if !exists {
		utils.NotFound(c, "Like not found")
		return
	}

	// Remove like
	err = h.interactionRepo.DeleteLike(c.Request.Context(), userID.(primitive.ObjectID), threadID)
	if err != nil {
		utils.InternalServerError(c, "Failed to unlike thread")
		return
	}

	// Update thread likes count
	err = h.threadService.IncrementLikesCount(c.Request.Context(), threadID, -1)
	if err != nil {
		logger.WithError(err).Error("Failed to decrement likes count")
	}

	logger.WithUserID(userID.(primitive.ObjectID)).WithField("thread_id", threadID).Info("Thread unliked")

	utils.SuccessResponse(c, http.StatusOK, "Thread unliked successfully", nil)
}

// RepostThread reposts a thread
func (h *InteractionHandler) RepostThread(c *gin.Context) {
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

	// Check if thread exists and user can interact with it
	uid := userID.(primitive.ObjectID)
	thread, err := h.threadService.GetThread(c.Request.Context(), threadID, &uid)
	if err != nil {
		if errors.IsAppError(err) {
			appErr := err.(*errors.AppError)
			utils.ErrorResponse(c, appErr.StatusCode, appErr.Code, appErr.Message)
		} else {
			utils.NotFound(c, "Thread not found")
		}
		return
	}

	// Check if already reposted
	exists, err = h.interactionRepo.HasReposted(c.Request.Context(), userID.(primitive.ObjectID), threadID)
	if err != nil {
		utils.InternalServerError(c, "Failed to check repost status")
		return
	}

	if exists {
		utils.Conflict(c, "Thread already reposted")
		return
	}

	// Create repost thread
	repostThread, err := h.threadService.CreateThread(c.Request.Context(), &services.CreateThreadRequest{
		AuthorID:         userID.(primitive.ObjectID),
		Content:          "",
		Type:             "repost",
		OriginalThreadID: &threadID,
		Visibility:       "public",
		ReplySettings:    "everyone",
	})

	if err != nil {
		utils.InternalServerError(c, "Failed to create repost")
		return
	}

	// Create repost record
	repost := &models.Repost{
		UserID:           userID.(primitive.ObjectID),
		ThreadID:         repostThread.ID,
		OriginalThreadID: threadID,
		Type:             "repost",
		RepostedAt:       time.Now(),
	}

	err = h.interactionRepo.CreateRepost(c.Request.Context(), repost)
	if err != nil {
		utils.InternalServerError(c, "Failed to create repost record")
		return
	}

	// Update original thread reposts count
	err = h.threadService.IncrementRepostsCount(c.Request.Context(), threadID, 1)
	if err != nil {
		logger.WithError(err).Error("Failed to increment reposts count")
	}

	// Send notification if not self-repost
	if thread.AuthorID != userID.(primitive.ObjectID) {
		go h.notificationService.CreateNotification(c.Request.Context(), &services.CreateNotificationRequest{
			RecipientID: thread.AuthorID,
			ActorID:     userID.(primitive.ObjectID),
			Type:        "repost",
			TargetType:  "thread",
			TargetID:    &threadID,
			ThreadID:    &threadID,
		})
	}

	logger.WithUserID(userID.(primitive.ObjectID)).WithField("thread_id", threadID).Info("Thread reposted")

	utils.SuccessResponse(c, http.StatusOK, "Thread reposted successfully", gin.H{
		"repost_thread": repostThread,
		"reposted_at":   repost.RepostedAt,
	})
}

// UnrepostThread removes a repost
func (h *InteractionHandler) UnrepostThread(c *gin.Context) {
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

	// Get repost record
	repost, err := h.interactionRepo.GetRepost(c.Request.Context(), userID.(primitive.ObjectID), threadID)
	if err != nil {
		utils.NotFound(c, "Repost not found")
		return
	}

	// Delete the repost thread
	err = h.threadService.DeleteThread(c.Request.Context(), repost.ThreadID, userID.(primitive.ObjectID))
	if err != nil {
		utils.InternalServerError(c, "Failed to delete repost thread")
		return
	}

	// Delete repost record
	err = h.interactionRepo.DeleteRepost(c.Request.Context(), userID.(primitive.ObjectID), threadID)
	if err != nil {
		utils.InternalServerError(c, "Failed to delete repost record")
		return
	}

	// Update original thread reposts count
	err = h.threadService.IncrementRepostsCount(c.Request.Context(), threadID, -1)
	if err != nil {
		logger.WithError(err).Error("Failed to decrement reposts count")
	}

	logger.WithUserID(userID.(primitive.ObjectID)).WithField("thread_id", threadID).Info("Thread unreposted")

	utils.SuccessResponse(c, http.StatusOK, "Repost removed successfully", nil)
}

// QuoteThread creates a quote thread
func (h *InteractionHandler) QuoteThread(c *gin.Context) {
	threadIDStr := c.Param("thread_id")
	threadID, err := primitive.ObjectIDFromHex(threadIDStr)
	if err != nil {
		utils.BadRequest(c, "Invalid thread ID")
		return
	}

	var req struct {
		Content        string         `json:"content" binding:"required,max=500"`
		MediaFiles     []models.Media `json:"media_files"`
		Hashtags       []string       `json:"hashtags"`
		Mentions       []string       `json:"mentions"`
		Visibility     string         `json:"visibility" binding:"required,visibility"`
		ReplySettings  string         `json:"reply_settings" binding:"required,reply_settings"`
		ContentWarning string         `json:"content_warning"`
		IsSensitive    bool           `json:"is_sensitive"`
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

	// Check if thread exists and user can interact with it
	uid := userID.(primitive.ObjectID)
	thread, err := h.threadService.GetThread(c.Request.Context(), threadID, &uid)
	if err != nil {
		if errors.IsAppError(err) {
			appErr := err.(*errors.AppError)
			utils.ErrorResponse(c, appErr.StatusCode, appErr.Code, appErr.Message)
		} else {
			utils.NotFound(c, "Thread not found")
		}
		return
	}

	// Create quote thread
	quoteThread, err := h.threadService.CreateThread(c.Request.Context(), &services.CreateThreadRequest{
		AuthorID:       userID.(primitive.ObjectID),
		Content:        req.Content,
		MediaFiles:     req.MediaFiles,
		Type:           "quote",
		QuotedThreadID: &threadID,
		Hashtags:       req.Hashtags,
		Mentions:       req.Mentions,
		Visibility:     req.Visibility,
		ReplySettings:  req.ReplySettings,
		ContentWarning: req.ContentWarning,
		IsSensitive:    req.IsSensitive,
	})

	if err != nil {
		utils.InternalServerError(c, "Failed to create quote thread")
		return
	}

	// Update original thread quotes count
	err = h.threadService.IncrementQuotesCount(c.Request.Context(), threadID, 1)
	if err != nil {
		logger.WithError(err).Error("Failed to increment quotes count")
	}

	// Send notification if not self-quote
	if thread.AuthorID != userID.(primitive.ObjectID) {
		go h.notificationService.CreateNotification(c.Request.Context(), &services.CreateNotificationRequest{
			RecipientID: thread.AuthorID,
			ActorID:     userID.(primitive.ObjectID),
			Type:        "quote",
			TargetType:  "thread",
			TargetID:    &threadID,
			ThreadID:    &quoteThread.ID,
		})
	}

	logger.WithUserID(userID.(primitive.ObjectID)).WithField("thread_id", threadID).Info("Thread quoted")

	utils.SuccessResponse(c, http.StatusCreated, "Quote thread created successfully", gin.H{
		"thread": quoteThread,
	})
}

// ReplyThread creates a reply to a thread
func (h *InteractionHandler) ReplyThread(c *gin.Context) {
	threadIDStr := c.Param("thread_id")
	threadID, err := primitive.ObjectIDFromHex(threadIDStr)
	if err != nil {
		utils.BadRequest(c, "Invalid thread ID")
		return
	}

	var req struct {
		Content        string         `json:"content" binding:"required,max=500"`
		MediaFiles     []models.Media `json:"media_files"`
		Hashtags       []string       `json:"hashtags"`
		Mentions       []string       `json:"mentions"`
		Visibility     string         `json:"visibility" binding:"required,visibility"`
		ContentWarning string         `json:"content_warning"`
		IsSensitive    bool           `json:"is_sensitive"`
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

	uid := userID.(primitive.ObjectID)
	thread, err := h.threadService.GetThread(c.Request.Context(), threadID, &uid)
	if err != nil {
		if errors.IsAppError(err) {
			appErr := err.(*errors.AppError)
			utils.ErrorResponse(c, appErr.StatusCode, appErr.Code, appErr.Message)
		} else {
			utils.NotFound(c, "Thread not found")
		}
		return
	}

	// Check reply permissions
	canReply, err := h.threadService.CanReply(c.Request.Context(), threadID, userID.(primitive.ObjectID))
	if err != nil {
		utils.InternalServerError(c, "Failed to check reply permissions")
		return
	}

	if !canReply {
		utils.Forbidden(c, "You cannot reply to this thread")
		return
	}

	// Create reply thread
	replyThread, err := h.threadService.CreateThread(c.Request.Context(), &services.CreateThreadRequest{
		AuthorID:       userID.(primitive.ObjectID),
		Content:        req.Content,
		MediaFiles:     req.MediaFiles,
		Type:           "reply",
		ParentID:       &threadID,
		Hashtags:       req.Hashtags,
		Mentions:       req.Mentions,
		Visibility:     req.Visibility,
		ReplySettings:  "everyone",
		ContentWarning: req.ContentWarning,
		IsSensitive:    req.IsSensitive,
	})

	if err != nil {
		utils.InternalServerError(c, "Failed to create reply")
		return
	}

	// Update parent thread replies count
	err = h.threadService.IncrementRepliesCount(c.Request.Context(), threadID, 1)
	if err != nil {
		logger.WithError(err).Error("Failed to increment replies count")
	}

	// Send notification if not self-reply
	if thread.AuthorID != userID.(primitive.ObjectID) {
		go h.notificationService.CreateNotification(c.Request.Context(), &services.CreateNotificationRequest{
			RecipientID: thread.AuthorID,
			ActorID:     userID.(primitive.ObjectID),
			Type:        "reply",
			TargetType:  "thread",
			TargetID:    &threadID,
			ThreadID:    &replyThread.ID,
		})
	}

	logger.WithUserID(userID.(primitive.ObjectID)).WithField("thread_id", threadID).Info("Thread replied")

	utils.SuccessResponse(c, http.StatusCreated, "Reply created successfully", gin.H{
		"thread": replyThread,
	})
}

// BookmarkThread bookmarks a thread
func (h *InteractionHandler) BookmarkThread(c *gin.Context) {
	threadIDStr := c.Param("thread_id")
	threadID, err := primitive.ObjectIDFromHex(threadIDStr)
	if err != nil {
		utils.BadRequest(c, "Invalid thread ID")
		return
	}

	var req struct {
		FolderID *string `json:"folder_id"`
		Notes    string  `json:"notes" binding:"max=500"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		// Notes and folder are optional
	}

	userID, exists := c.Get("user_id")
	if !exists {
		utils.Unauthorized(c, "User not authenticated")
		return
	}

	// Check if thread exists
	uid := userID.(primitive.ObjectID)
	_, err = h.threadService.GetThread(c.Request.Context(), threadID, &uid)
	if err != nil {
		if errors.IsAppError(err) {
			appErr := err.(*errors.AppError)
			utils.ErrorResponse(c, appErr.StatusCode, appErr.Code, appErr.Message)
		} else {
			utils.NotFound(c, "Thread not found")
		}
		return
	}

	// Check if already bookmarked
	exists, err = h.interactionRepo.HasBookmarked(c.Request.Context(), userID.(primitive.ObjectID), threadID)
	if err != nil {
		utils.InternalServerError(c, "Failed to check bookmark status")
		return
	}

	if exists {
		utils.Conflict(c, "Thread already bookmarked")
		return
	}

	// Convert folder ID if provided
	var folderID *primitive.ObjectID
	if req.FolderID != nil {
		if id, err := primitive.ObjectIDFromHex(*req.FolderID); err == nil {
			// Verify folder belongs to user
			if hasFolder, err := h.interactionRepo.HasBookmarkFolder(c.Request.Context(), userID.(primitive.ObjectID), id); err == nil && hasFolder {
				folderID = &id
			} else {
				utils.BadRequest(c, "Invalid folder ID")
				return
			}
		} else {
			utils.BadRequest(c, "Invalid folder ID format")
			return
		}
	}

	// Create bookmark
	bookmark := &models.Bookmark{
		UserID:    userID.(primitive.ObjectID),
		ThreadID:  threadID,
		FolderID:  folderID,
		Notes:     req.Notes,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}

	err = h.interactionRepo.CreateBookmark(c.Request.Context(), bookmark)
	if err != nil {
		utils.InternalServerError(c, "Failed to bookmark thread")
		return
	}

	// Update thread bookmarks count
	err = h.threadService.IncrementBookmarksCount(c.Request.Context(), threadID, 1)
	if err != nil {
		logger.WithError(err).Error("Failed to increment bookmarks count")
	}

	logger.WithUserID(userID.(primitive.ObjectID)).WithField("thread_id", threadID).Info("Thread bookmarked")

	utils.SuccessResponse(c, http.StatusOK, "Thread bookmarked successfully", gin.H{
		"bookmark": bookmark,
	})
}

// UnbookmarkThread removes a bookmark
func (h *InteractionHandler) UnbookmarkThread(c *gin.Context) {
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

	// Check if bookmarked
	exists, err = h.interactionRepo.HasBookmarked(c.Request.Context(), userID.(primitive.ObjectID), threadID)
	if err != nil {
		utils.InternalServerError(c, "Failed to check bookmark status")
		return
	}

	if !exists {
		utils.NotFound(c, "Bookmark not found")
		return
	}

	// Remove bookmark
	err = h.interactionRepo.DeleteBookmark(c.Request.Context(), userID.(primitive.ObjectID), threadID)
	if err != nil {
		utils.InternalServerError(c, "Failed to remove bookmark")
		return
	}

	// Update thread bookmarks count
	err = h.threadService.IncrementBookmarksCount(c.Request.Context(), threadID, -1)
	if err != nil {
		logger.WithError(err).Error("Failed to decrement bookmarks count")
	}

	logger.WithUserID(userID.(primitive.ObjectID)).WithField("thread_id", threadID).Info("Thread unbookmarked")

	utils.SuccessResponse(c, http.StatusOK, "Bookmark removed successfully", nil)
}

// ShareThread records a thread share
func (h *InteractionHandler) ShareThread(c *gin.Context) {
	threadIDStr := c.Param("thread_id")
	threadID, err := primitive.ObjectIDFromHex(threadIDStr)
	if err != nil {
		utils.BadRequest(c, "Invalid thread ID")
		return
	}

	var req struct {
		ShareType string `json:"share_type" binding:"required"`
		Platform  string `json:"platform"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		utils.BadRequest(c, "Share type is required")
		return
	}

	userID, exists := c.Get("user_id")
	if !exists {
		utils.Unauthorized(c, "User not authenticated")
		return
	}

	// Check if thread exists
	uid := userID.(primitive.ObjectID)
	_, err = h.threadService.GetThread(c.Request.Context(), threadID, &uid)
	if err != nil {
		if errors.IsAppError(err) {
			appErr := err.(*errors.AppError)
			utils.ErrorResponse(c, appErr.StatusCode, appErr.Code, appErr.Message)
		} else {
			utils.NotFound(c, "Thread not found")
		}
		return
	}

	// Create share record
	share := &models.Share{
		UserID:    userID.(primitive.ObjectID),
		ThreadID:  threadID,
		ShareType: req.ShareType,
		Platform:  req.Platform,
		SharedAt:  time.Now(),
	}

	err = h.interactionRepo.CreateShare(c.Request.Context(), share)
	if err != nil {
		utils.InternalServerError(c, "Failed to record share")
		return
	}

	// Update thread shares count
	err = h.threadService.IncrementSharesCount(c.Request.Context(), threadID, 1)
	if err != nil {
		logger.WithError(err).Error("Failed to increment shares count")
	}

	logger.WithUserID(userID.(primitive.ObjectID)).WithField("thread_id", threadID).Info("Thread shared")

	utils.SuccessResponse(c, http.StatusOK, "Thread shared successfully", gin.H{
		"shared_at": share.SharedAt,
	})
}

// ReportThread reports a thread
func (h *InteractionHandler) ReportThread(c *gin.Context) {
	threadIDStr := c.Param("thread_id")
	threadID, err := primitive.ObjectIDFromHex(threadIDStr)
	if err != nil {
		utils.BadRequest(c, "Invalid thread ID")
		return
	}

	var req struct {
		ReportType  string                  `json:"report_type" binding:"required"`
		Category    string                  `json:"category" binding:"required"`
		Description string                  `json:"description" binding:"required,max=1000"`
		Evidence    []models.ReportEvidence `json:"evidence"`
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

	// Check if thread exists
	uid := userID.(primitive.ObjectID)
	_, err = h.threadService.GetThread(c.Request.Context(), threadID, &uid)
	if err != nil {
		if errors.IsAppError(err) {
			appErr := err.(*errors.AppError)
			utils.ErrorResponse(c, appErr.StatusCode, appErr.Code, appErr.Message)
		} else {
			utils.NotFound(c, "Thread not found")
		}
		return
	}

	// Check if user has already reported this thread
	hasReported, err := h.interactionRepo.HasReported(c.Request.Context(), userID.(primitive.ObjectID), &threadID, nil)
	if err != nil {
		utils.InternalServerError(c, "Failed to check report status")
		return
	}

	if hasReported {
		utils.Conflict(c, "You have already reported this thread")
		return
	}

	// Create report
	report := &models.Report{
		ReporterID:  userID.(primitive.ObjectID),
		ThreadID:    &threadID,
		ReportType:  req.ReportType,
		Category:    req.Category,
		Description: req.Description,
		Evidence:    req.Evidence,
		Status:      "pending",
		Priority:    determinePriority(req.ReportType, req.Category),
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
	}

	err = h.interactionRepo.CreateReport(c.Request.Context(), report)
	if err != nil {
		utils.InternalServerError(c, "Failed to submit report")
		return
	}

	logger.WithUserID(userID.(primitive.ObjectID)).WithField("thread_id", threadID).WithField("report_type", req.ReportType).Info("Thread reported")

	utils.SuccessResponse(c, http.StatusOK, "Report submitted successfully", gin.H{
		"report_id": report.ID,
		"message":   "Thank you for your report. We will review it and take appropriate action.",
	})
}

// Bookmark management
func (h *InteractionHandler) GetBookmarks(c *gin.Context) {
	userID, exists := c.Get("user_id")
	if !exists {
		utils.Unauthorized(c, "User not authenticated")
		return
	}

	params := utils.GetPaginationParams(c)
	folderID := c.Query("folder_id")

	var folderObjID *primitive.ObjectID
	if folderID != "" {
		if id, err := primitive.ObjectIDFromHex(folderID); err == nil {
			folderObjID = &id
		} else {
			utils.BadRequest(c, "Invalid folder ID")
			return
		}
	}

	result, err := h.interactionRepo.GetBookmarks(c.Request.Context(), userID.(primitive.ObjectID), folderObjID, params)
	if err != nil {
		utils.InternalServerError(c, "Failed to get bookmarks")
		return
	}

	utils.SuccessResponseWithMeta(c, http.StatusOK, "Bookmarks retrieved", result.Data, &utils.Meta{
		Pagination: result.Pagination,
	})
}

func (h *InteractionHandler) GetBookmarkFolders(c *gin.Context) {
	userID, exists := c.Get("user_id")
	if !exists {
		utils.Unauthorized(c, "User not authenticated")
		return
	}

	params := utils.GetPaginationParams(c)

	result, err := h.interactionRepo.GetBookmarkFolders(c.Request.Context(), userID.(primitive.ObjectID), params)
	if err != nil {
		utils.InternalServerError(c, "Failed to get bookmark folders")
		return
	}

	utils.SuccessResponseWithMeta(c, http.StatusOK, "Bookmark folders retrieved", result.Data, &utils.Meta{
		Pagination: result.Pagination,
	})
}

func (h *InteractionHandler) CreateBookmarkFolder(c *gin.Context) {
	var req struct {
		Name        string `json:"name" binding:"required,max=50"`
		Description string `json:"description" binding:"max=200"`
		Color       string `json:"color"`
		Icon        string `json:"icon"`
		IsPrivate   bool   `json:"is_private"`
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

	folder := &models.BookmarkFolder{
		UserID:      userID.(primitive.ObjectID),
		Name:        req.Name,
		Description: req.Description,
		Color:       req.Color,
		Icon:        req.Icon,
		IsPrivate:   req.IsPrivate,
		ItemsCount:  0,
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
	}

	err := h.interactionRepo.CreateBookmarkFolder(c.Request.Context(), folder)
	if err != nil {
		utils.InternalServerError(c, "Failed to create bookmark folder")
		return
	}

	utils.SuccessResponse(c, http.StatusCreated, "Bookmark folder created successfully", gin.H{
		"folder": folder,
	})
}

func (h *InteractionHandler) UpdateBookmarkFolder(c *gin.Context) {
	folderIDStr := c.Param("folder_id")
	folderID, err := primitive.ObjectIDFromHex(folderIDStr)
	if err != nil {
		utils.BadRequest(c, "Invalid folder ID")
		return
	}

	var req struct {
		Name        string `json:"name" binding:"max=50"`
		Description string `json:"description" binding:"max=200"`
		Color       string `json:"color"`
		Icon        string `json:"icon"`
		IsPrivate   *bool  `json:"is_private"`
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

	folder, err := h.interactionRepo.UpdateBookmarkFolder(c.Request.Context(), folderID, userID.(primitive.ObjectID), &repository.UpdateBookmarkFolderRequest{
		Name:        req.Name,
		Description: req.Description,
		Color:       req.Color,
		Icon:        req.Icon,
		IsPrivate:   req.IsPrivate,
	})

	if err != nil {
		if errors.IsAppError(err) {
			appErr := err.(*errors.AppError)
			utils.ErrorResponse(c, appErr.StatusCode, appErr.Code, appErr.Message)
		} else {
			utils.InternalServerError(c, "Failed to update bookmark folder")
		}
		return
	}

	utils.SuccessResponse(c, http.StatusOK, "Bookmark folder updated successfully", gin.H{
		"folder": folder,
	})
}

func (h *InteractionHandler) DeleteBookmarkFolder(c *gin.Context) {
	folderIDStr := c.Param("folder_id")
	folderID, err := primitive.ObjectIDFromHex(folderIDStr)
	if err != nil {
		utils.BadRequest(c, "Invalid folder ID")
		return
	}

	userID, exists := c.Get("user_id")
	if !exists {
		utils.Unauthorized(c, "User not authenticated")
		return
	}

	err = h.interactionRepo.DeleteBookmarkFolder(c.Request.Context(), folderID, userID.(primitive.ObjectID))
	if err != nil {
		if errors.IsAppError(err) {
			appErr := err.(*errors.AppError)
			utils.ErrorResponse(c, appErr.StatusCode, appErr.Code, appErr.Message)
		} else {
			utils.InternalServerError(c, "Failed to delete bookmark folder")
		}
		return
	}

	utils.SuccessResponse(c, http.StatusOK, "Bookmark folder deleted successfully", nil)
}

func (h *InteractionHandler) MoveBookmark(c *gin.Context) {
	bookmarkIDStr := c.Param("bookmark_id")
	bookmarkID, err := primitive.ObjectIDFromHex(bookmarkIDStr)
	if err != nil {
		utils.BadRequest(c, "Invalid bookmark ID")
		return
	}

	var req struct {
		FolderID *string `json:"folder_id"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		// folder_id can be null to remove from folder
	}

	userID, exists := c.Get("user_id")
	if !exists {
		utils.Unauthorized(c, "User not authenticated")
		return
	}

	var folderID *primitive.ObjectID
	if req.FolderID != nil {
		if id, err := primitive.ObjectIDFromHex(*req.FolderID); err == nil {
			// Verify folder belongs to user
			if hasFolder, err := h.interactionRepo.HasBookmarkFolder(c.Request.Context(), userID.(primitive.ObjectID), id); err == nil && hasFolder {
				folderID = &id
			} else {
				utils.BadRequest(c, "Invalid folder ID")
				return
			}
		} else {
			utils.BadRequest(c, "Invalid folder ID format")
			return
		}
	}

	err = h.interactionRepo.MoveBookmark(c.Request.Context(), bookmarkID, userID.(primitive.ObjectID), folderID)
	if err != nil {
		if errors.IsAppError(err) {
			appErr := err.(*errors.AppError)
			utils.ErrorResponse(c, appErr.StatusCode, appErr.Code, appErr.Message)
		} else {
			utils.InternalServerError(c, "Failed to move bookmark")
		}
		return
	}

	utils.SuccessResponse(c, http.StatusOK, "Bookmark moved successfully", nil)
}

// Poll interactions
func (h *InteractionHandler) VoteInPoll(c *gin.Context) {
	threadIDStr := c.Param("thread_id")
	threadID, err := primitive.ObjectIDFromHex(threadIDStr)
	if err != nil {
		utils.BadRequest(c, "Invalid thread ID")
		return
	}

	var req struct {
		Options []string `json:"options" binding:"required,min=1"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		utils.BadRequest(c, "At least one option must be selected")
		return
	}

	userID, exists := c.Get("user_id")
	if !exists {
		utils.Unauthorized(c, "User not authenticated")
		return
	}

	// Convert option IDs
	optionIDs := make([]primitive.ObjectID, len(req.Options))
	for i, optionStr := range req.Options {
		if id, err := primitive.ObjectIDFromHex(optionStr); err == nil {
			optionIDs[i] = id
		} else {
			utils.BadRequest(c, "Invalid option ID: "+optionStr)
			return
		}
	}

	err = h.interactionRepo.VoteInPoll(c.Request.Context(), &models.PollVote{
		UserID:   userID.(primitive.ObjectID),
		ThreadID: threadID,
		Options:  optionIDs,
		VotedAt:  time.Now(),
	})

	if err != nil {
		if errors.IsAppError(err) {
			appErr := err.(*errors.AppError)
			utils.ErrorResponse(c, appErr.StatusCode, appErr.Code, appErr.Message)
		} else {
			utils.InternalServerError(c, "Failed to vote in poll")
		}
		return
	}

	logger.WithUserID(userID.(primitive.ObjectID)).WithField("thread_id", threadID).Info("Poll vote cast")

	utils.SuccessResponse(c, http.StatusOK, "Vote cast successfully", nil)
}

func (h *InteractionHandler) RemovePollVote(c *gin.Context) {
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

	err = h.interactionRepo.RemovePollVote(c.Request.Context(), userID.(primitive.ObjectID), threadID)
	if err != nil {
		if errors.IsAppError(err) {
			appErr := err.(*errors.AppError)
			utils.ErrorResponse(c, appErr.StatusCode, appErr.Code, appErr.Message)
		} else {
			utils.InternalServerError(c, "Failed to remove poll vote")
		}
		return
	}

	utils.SuccessResponse(c, http.StatusOK, "Vote removed successfully", nil)
}

func (h *InteractionHandler) GetPollResults(c *gin.Context) {
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

	results, err := h.interactionRepo.GetPollResults(c.Request.Context(), threadID, currentUserID)
	if err != nil {
		if errors.IsAppError(err) {
			appErr := err.(*errors.AppError)
			utils.ErrorResponse(c, appErr.StatusCode, appErr.Code, appErr.Message)
		} else {
			utils.InternalServerError(c, "Failed to get poll results")
		}
		return
	}

	utils.SuccessResponse(c, http.StatusOK, "Poll results retrieved", gin.H{
		"results": results,
	})
}

// Helper function to determine report priority
func determinePriority(reportType, category string) string {
	urgentTypes := []string{"violence", "hate_speech", "harassment", "sexual_content"}
	highTypes := []string{"spam", "misinformation"}

	for _, t := range urgentTypes {
		if reportType == t || category == t {
			return "urgent"
		}
	}

	for _, t := range highTypes {
		if reportType == t || category == t {
			return "high"
		}
	}

	return "medium"
}
