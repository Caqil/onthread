package services

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/redis/go-redis/v9"
	"go.mongodb.org/mongo-driver/bson/primitive"

	"onthread/internal/models"
	"onthread/internal/repository"
	"onthread/internal/utils"
	"onthread/pkg/constants"
	"onthread/pkg/errors"
	"onthread/pkg/logger"
)

// ThreadService interface defines all thread-related operations
type ThreadService interface {
	// Core CRUD operations
	CreateThread(ctx context.Context, req *CreateThreadRequest) (*models.Thread, error)
	GetThread(ctx context.Context, threadID primitive.ObjectID, currentUserID *primitive.ObjectID) (*models.Thread, error)
	UpdateThread(ctx context.Context, threadID, userID primitive.ObjectID, req *UpdateThreadRequest) (*models.Thread, error)
	DeleteThread(ctx context.Context, threadID, userID primitive.ObjectID) error
	RestoreThread(ctx context.Context, threadID, userID primitive.ObjectID) (*models.Thread, error)

	// Timeline and feeds
	GetPublicTimeline(ctx context.Context, currentUserID *primitive.ObjectID, params *utils.PaginationParams) (*utils.PaginationResult, error)
	GetUserFeed(ctx context.Context, userID primitive.ObjectID, algorithm string, params *utils.PaginationParams) (*utils.PaginationResult, error)
	GetFollowingFeed(ctx context.Context, userID primitive.ObjectID, params *utils.PaginationParams) (*utils.PaginationResult, error)
	GetTrendingThreads(ctx context.Context, currentUserID *primitive.ObjectID, timeframe string, params *utils.PaginationParams) (*utils.PaginationResult, error)

	// Search and discovery
	SearchThreads(ctx context.Context, query string, currentUserID *primitive.ObjectID, filters *SearchFilters, params *utils.PaginationParams) (*utils.PaginationResult, error)

	// Thread interactions
	GetThreadReplies(ctx context.Context, threadID primitive.ObjectID, currentUserID *primitive.ObjectID, params *utils.PaginationParams) (*utils.PaginationResult, error)
	GetThreadQuotes(ctx context.Context, threadID primitive.ObjectID, currentUserID *primitive.ObjectID, params *utils.PaginationParams) (*utils.PaginationResult, error)
	GetThreadReposts(ctx context.Context, threadID primitive.ObjectID, params *utils.PaginationParams) (*utils.PaginationResult, error)
	GetThreadLikes(ctx context.Context, threadID primitive.ObjectID, params *utils.PaginationParams) (*utils.PaginationResult, error)

	// Hashtags and mentions
	GetHashtagThreads(ctx context.Context, hashtag string, currentUserID *primitive.ObjectID, params *utils.PaginationParams) (*utils.PaginationResult, error)
	GetTrendingHashtags(ctx context.Context, timeframe string, limit int) ([]*HashtagInfo, error)
	GetMentionThreads(ctx context.Context, username string, currentUserID *primitive.ObjectID, params *utils.PaginationParams) (*utils.PaginationResult, error)
	GetMentionsFeed(ctx context.Context, userID primitive.ObjectID, params *utils.PaginationParams) (*utils.PaginationResult, error)

	// List feed
	GetListFeed(ctx context.Context, userID, listID primitive.ObjectID, params *utils.PaginationParams) (*utils.PaginationResult, error)

	// Thread moderation
	PinThread(ctx context.Context, threadID, userID primitive.ObjectID) error
	UnpinThread(ctx context.Context, threadID, userID primitive.ObjectID) error
	HideThread(ctx context.Context, threadID, userID primitive.ObjectID) error
	UnhideThread(ctx context.Context, threadID, userID primitive.ObjectID) error
	UpdateThreadVisibility(ctx context.Context, threadID, userID primitive.ObjectID, visibility string) error
	UpdateReplySettings(ctx context.Context, threadID, userID primitive.ObjectID, replySettings string) error

	// Scheduled threads
	GetScheduledThreads(ctx context.Context, userID primitive.ObjectID, params *utils.PaginationParams) (*utils.PaginationResult, error)
	ScheduleThread(ctx context.Context, req *ScheduleThreadRequest) (*models.Thread, error)
	UpdateScheduledThread(ctx context.Context, threadID, userID primitive.ObjectID, req *UpdateScheduledThreadRequest) (*models.Thread, error)
	CancelScheduledThread(ctx context.Context, threadID, userID primitive.ObjectID) error
	PublishScheduledThread(ctx context.Context, threadID, userID primitive.ObjectID) (*models.Thread, error)

	// Drafts
	GetDrafts(ctx context.Context, userID primitive.ObjectID, params *utils.PaginationParams) (*utils.PaginationResult, error)
	SaveDraft(ctx context.Context, req *SaveDraftRequest) (*models.Thread, error)
	UpdateDraft(ctx context.Context, draftID, userID primitive.ObjectID, req *UpdateDraftRequest) (*models.Thread, error)
	DeleteDraft(ctx context.Context, draftID, userID primitive.ObjectID) error
	PublishDraft(ctx context.Context, draftID, userID primitive.ObjectID) (*models.Thread, error)

	// Analytics
	GetThreadAnalytics(ctx context.Context, threadID, userID primitive.ObjectID) (*ThreadAnalytics, error)
	GetUserThreadAnalytics(ctx context.Context, userID primitive.ObjectID, timeframe string) (*UserThreadAnalytics, error)

	// Admin operations
	GetAllThreads(ctx context.Context, params *utils.PaginationParams, filter string) (*utils.PaginationResult, error)
	GetReportedThreads(ctx context.Context, params *utils.PaginationParams) (*utils.PaginationResult, error)
	GetFlaggedThreads(ctx context.Context, params *utils.PaginationParams) (*utils.PaginationResult, error)
	GetThreadReports(ctx context.Context, threadID primitive.ObjectID, params *utils.PaginationParams) (*utils.PaginationResult, error)
	ModerateThread(ctx context.Context, threadID, adminID primitive.ObjectID, action, reason string) error
	FeatureThread(ctx context.Context, threadID, adminID primitive.ObjectID) error
	UnfeatureThread(ctx context.Context, threadID, adminID primitive.ObjectID) error
	LockThread(ctx context.Context, threadID, adminID primitive.ObjectID, reason string) error
	UnlockThread(ctx context.Context, threadID, adminID primitive.ObjectID) error
	AdminDeleteThread(ctx context.Context, threadID, adminID primitive.ObjectID, reason string) error
	AdminRestoreThread(ctx context.Context, threadID, adminID primitive.ObjectID, reason string) (*models.Thread, error)

	// Utility methods
	CanReply(ctx context.Context, threadID, userID primitive.ObjectID) (bool, error)
	IncrementLikesCount(ctx context.Context, threadID primitive.ObjectID, delta int) error
	IncrementRepliesCount(ctx context.Context, threadID primitive.ObjectID, delta int) error
	IncrementRepostsCount(ctx context.Context, threadID primitive.ObjectID, delta int) error
	IncrementViewsCount(ctx context.Context, threadID primitive.ObjectID, delta int) error
}

// Request/Response structs
type CreateThreadRequest struct {
	AuthorID       primitive.ObjectID  `json:"author_id"`
	Content        string              `json:"content"`
	MediaFiles     []models.Media      `json:"media_files"`
	Type           string              `json:"type"`
	ParentID       *primitive.ObjectID `json:"parent_id,omitempty"`
	QuotedThreadID *primitive.ObjectID `json:"quoted_thread_id,omitempty"`
	Hashtags       []string            `json:"hashtags"`
	Mentions       []string            `json:"mentions"`
	Visibility     string              `json:"visibility"`
	ReplySettings  string              `json:"reply_settings"`
	Location       *models.Location    `json:"location,omitempty"`
	Poll           *models.Poll        `json:"poll,omitempty"`
	ScheduledAt    *time.Time          `json:"scheduled_at,omitempty"`
	ContentWarning string              `json:"content_warning"`
	IsSensitive    bool                `json:"is_sensitive"`
}

type UpdateThreadRequest struct {
	Content        string           `json:"content"`
	MediaFiles     []models.Media   `json:"media_files"`
	Hashtags       []string         `json:"hashtags"`
	Mentions       []string         `json:"mentions"`
	Location       *models.Location `json:"location,omitempty"`
	ContentWarning string           `json:"content_warning"`
	IsSensitive    bool             `json:"is_sensitive"`
	EditReason     string           `json:"edit_reason"`
}

type ScheduleThreadRequest struct {
	AuthorID       primitive.ObjectID `json:"author_id"`
	Content        string             `json:"content"`
	MediaFiles     []models.Media     `json:"media_files"`
	Hashtags       []string           `json:"hashtags"`
	Mentions       []string           `json:"mentions"`
	Visibility     string             `json:"visibility"`
	ReplySettings  string             `json:"reply_settings"`
	Location       *models.Location   `json:"location,omitempty"`
	Poll           *models.Poll       `json:"poll,omitempty"`
	ScheduledAt    time.Time          `json:"scheduled_at"`
	ContentWarning string             `json:"content_warning"`
	IsSensitive    bool               `json:"is_sensitive"`
}

type UpdateScheduledThreadRequest struct {
	Content        string           `json:"content"`
	MediaFiles     []models.Media   `json:"media_files"`
	Hashtags       []string         `json:"hashtags"`
	Mentions       []string         `json:"mentions"`
	Visibility     string           `json:"visibility"`
	ReplySettings  string           `json:"reply_settings"`
	Location       *models.Location `json:"location,omitempty"`
	Poll           *models.Poll     `json:"poll,omitempty"`
	ScheduledAt    *time.Time       `json:"scheduled_at,omitempty"`
	ContentWarning string           `json:"content_warning"`
	IsSensitive    bool             `json:"is_sensitive"`
}

type SaveDraftRequest struct {
	AuthorID       primitive.ObjectID `json:"author_id"`
	Content        string             `json:"content"`
	MediaFiles     []models.Media     `json:"media_files"`
	Hashtags       []string           `json:"hashtags"`
	Mentions       []string           `json:"mentions"`
	Visibility     string             `json:"visibility"`
	ReplySettings  string             `json:"reply_settings"`
	Location       *models.Location   `json:"location,omitempty"`
	Poll           *models.Poll       `json:"poll,omitempty"`
	ContentWarning string             `json:"content_warning"`
	IsSensitive    bool               `json:"is_sensitive"`
}

type UpdateDraftRequest struct {
	Content        string           `json:"content"`
	MediaFiles     []models.Media   `json:"media_files"`
	Hashtags       []string         `json:"hashtags"`
	Mentions       []string         `json:"mentions"`
	Visibility     string           `json:"visibility"`
	ReplySettings  string           `json:"reply_settings"`
	Location       *models.Location `json:"location,omitempty"`
	Poll           *models.Poll     `json:"poll,omitempty"`
	ContentWarning string           `json:"content_warning"`
	IsSensitive    bool             `json:"is_sensitive"`
}

type SearchFilters struct {
	Type      string `json:"type"`
	From      string `json:"from"`
	HasMedia  bool   `json:"has_media"`
	Language  string `json:"language"`
	SinceDate string `json:"since_date"`
	UntilDate string `json:"until_date"`
}

type HashtagInfo struct {
	Hashtag string `json:"hashtag"`
	Count   int64  `json:"count"`
	Trend   string `json:"trend"` // "up", "down", "stable"
}

type ThreadAnalytics struct {
	ThreadID       primitive.ObjectID `json:"thread_id"`
	Views          int64              `json:"views"`
	Likes          int64              `json:"likes"`
	Reposts        int64              `json:"reposts"`
	Replies        int64              `json:"replies"`
	Quotes         int64              `json:"quotes"`
	Shares         int64              `json:"shares"`
	Bookmarks      int64              `json:"bookmarks"`
	EngagementRate float64            `json:"engagement_rate"`
	ReachEstimate  int64              `json:"reach_estimate"`
	ViewsByHour    map[string]int64   `json:"views_by_hour"`
	TopCountries   map[string]int64   `json:"top_countries"`
	Demographics   map[string]int64   `json:"demographics"`
}

type UserThreadAnalytics struct {
	UserID           primitive.ObjectID `json:"user_id"`
	TotalThreads     int64              `json:"total_threads"`
	TotalViews       int64              `json:"total_views"`
	TotalLikes       int64              `json:"total_likes"`
	TotalReposts     int64              `json:"total_reposts"`
	TotalReplies     int64              `json:"total_replies"`
	AvgEngagement    float64            `json:"avg_engagement"`
	TopPerforming    []*models.Thread   `json:"top_performing"`
	EngagementTrend  map[string]int64   `json:"engagement_trend"`
	PostingFrequency map[string]int64   `json:"posting_frequency"`
}

// Implementation
type threadService struct {
	threadRepo      repository.ThreadRepository
	userRepo        repository.UserRepository
	interactionRepo repository.InteractionRepository
	redis           *redis.Client
	logger          *logger.Logger
}

// NewThreadService creates a new thread service
func NewThreadService(
	threadRepo repository.ThreadRepository,
	userRepo repository.UserRepository,
	interactionRepo repository.InteractionRepository,
	redis *redis.Client,
) ThreadService {
	return &threadService{
		threadRepo:      threadRepo,
		userRepo:        userRepo,
		interactionRepo: interactionRepo,
		redis:           redis,
		logger:          logger.NewComponentLogger("ThreadService"),
	}
}

// CreateThread creates a new thread
func (s *threadService) CreateThread(ctx context.Context, req *CreateThreadRequest) (*models.Thread, error) {
	// Validate author exists
	author, err := s.userRepo.GetByID(ctx, req.AuthorID)
	if err != nil {
		return nil, errors.NewNotFoundError("Author not found")
	}

	// Check if user is suspended or banned
	if author.IsSuspended {
		return nil, errors.NewForbiddenError("Account is suspended")
	}

	// Validate parent thread if replying
	if req.ParentID != nil {
		parentThread, err := s.threadRepo.GetByID(ctx, *req.ParentID)
		if err != nil {
			return nil, errors.NewNotFoundError("Parent thread not found")
		}

		// Check reply permissions
		canReply, err := s.canReplyToThread(ctx, parentThread, req.AuthorID)
		if err != nil {
			return nil, err
		}
		if !canReply {
			return nil, errors.NewForbiddenError("Cannot reply to this thread")
		}
	}

	// Validate quoted thread if quoting
	if req.QuotedThreadID != nil {
		_, err := s.threadRepo.GetByID(ctx, *req.QuotedThreadID)
		if err != nil {
			return nil, errors.NewNotFoundError("Quoted thread not found")
		}
	}

	// Create thread model
	thread := &models.Thread{
		ID:             primitive.NewObjectID(),
		AuthorID:       req.AuthorID,
		Content:        req.Content,
		MediaFiles:     req.MediaFiles,
		Type:           req.Type,
		ParentID:       req.ParentID,
		QuotedThreadID: req.QuotedThreadID,
		Hashtags:       req.Hashtags,
		Mentions:       s.usernamesToObjectIDs(ctx, req.Mentions),
		Visibility:     req.Visibility,
		ReplySettings:  req.ReplySettings,
		Location:       req.Location,
		Poll:           req.Poll,
		ContentWarning: req.ContentWarning,
		IsSensitive:    req.IsSensitive,
		CreatedAt:      time.Now(),
		UpdatedAt:      time.Now(),
	}

	// Handle scheduled threads
	if req.ScheduledAt != nil {
		thread.ScheduledAt = req.ScheduledAt
		thread.IsScheduled = true
		thread.Status = "scheduled"
	} else {
		thread.Status = "published"
	}

	// Extract and process hashtags
	extractedHashtags := s.extractHashtags(req.Content)
	thread.Hashtags = append(thread.Hashtags, extractedHashtags...)
	thread.Hashtags = s.deduplicateStrings(thread.Hashtags)

	// Extract and process mentions
	extractedMentions := s.extractMentions(req.Content)
	allMentions := append(req.Mentions, extractedMentions...)
	dedupedMentions := s.deduplicateStrings(allMentions)
	thread.Mentions = s.usernamesToObjectIDs(ctx, dedupedMentions)

	// Set language (basic detection)
	thread.Language = s.detectLanguage(req.Content)

	// Create thread in database
	err = s.threadRepo.Create(ctx, thread)
	if err != nil {
		s.logger.WithError(err).Error("Failed to create thread")
		return nil, errors.NewInternalError("Failed to create thread", err)
	}

	// Update parent thread reply count if this is a reply
	if req.ParentID != nil {
		go s.IncrementRepliesCount(ctx, *req.ParentID, 1)
	}

	// Update quoted thread quote count if this is a quote
	if req.QuotedThreadID != nil {
		go s.IncrementQuotesCount(ctx, *req.QuotedThreadID, 1)
	}

	// Cache the thread
	go s.cacheThread(ctx, thread)

	s.logger.WithFields(map[string]interface{}{
		"thread_id": thread.ID,
		"author_id": thread.AuthorID,
		"type":      thread.Type,
	}).Info("Thread created successfully")

	return thread, nil
}

// GetThread retrieves a thread by ID
func (s *threadService) GetThread(ctx context.Context, threadID primitive.ObjectID, currentUserID *primitive.ObjectID) (*models.Thread, error) {
	// Try to get from cache first
	if thread := s.getCachedThread(ctx, threadID); thread != nil {
		return s.enrichThread(ctx, thread, currentUserID)
	}

	// Get from database
	thread, err := s.threadRepo.GetByID(ctx, threadID)
	if err != nil {
		return nil, errors.NewNotFoundError("Thread not found")
	}

	// Check visibility permissions
	if !s.canViewThread(ctx, thread, currentUserID) {
		return nil, errors.NewNotFoundError("Thread not found")
	}

	// Enrich with additional data
	enrichedThread, err := s.enrichThread(ctx, thread, currentUserID)
	if err != nil {
		return nil, err
	}

	// Increment view count
	if currentUserID != nil {
		go s.IncrementViewsCount(ctx, threadID, 1)
		go s.recordThreadView(ctx, threadID, *currentUserID)
	}

	// Cache the thread
	go s.cacheThread(ctx, thread)

	return enrichedThread, nil
}

// UpdateThread updates an existing thread
func (s *threadService) UpdateThread(ctx context.Context, threadID, userID primitive.ObjectID, req *UpdateThreadRequest) (*models.Thread, error) {
	// Get existing thread
	thread, err := s.threadRepo.GetByID(ctx, threadID)
	if err != nil {
		return nil, errors.NewNotFoundError("Thread not found")
	}

	// Check ownership
	if thread.AuthorID != userID {
		return nil, errors.NewForbiddenError("You can only edit your own threads")
	}

	// Check if thread can be edited (time limit, etc.)
	if !s.canEditThread(thread) {
		return nil, errors.NewForbiddenError("Thread can no longer be edited")
	}

	// Store original content for edit history
	editHistory := models.EditHistory{
		Content:    thread.Content,
		MediaFiles: thread.MediaFiles,
		EditedAt:   time.Now(),
		EditReason: req.EditReason,
	}
	thread.EditHistory = append(thread.EditHistory, editHistory)

	// Update fields
	thread.Content = req.Content
	thread.MediaFiles = req.MediaFiles
	thread.Location = req.Location
	thread.ContentWarning = req.ContentWarning
	thread.IsSensitive = req.IsSensitive
	thread.UpdatedAt = time.Now()
	thread.IsEdited = true

	// Update hashtags and mentions
	extractedHashtags := s.extractHashtags(req.Content)
	thread.Hashtags = append(req.Hashtags, extractedHashtags...)
	thread.Hashtags = s.deduplicateStrings(thread.Hashtags)

	extractedMentions := s.extractMentions(req.Content)
	thread.Mentions = append(req.Mentions, extractedMentions...)
	thread.Mentions = s.deduplicateStrings(thread.Mentions)

	// Update in database
	err = s.threadRepo.Update(ctx, thread)
	if err != nil {
		s.logger.WithError(err).Error("Failed to update thread")
		return nil, errors.NewInternalError("Failed to update thread", err)
	}

	// Clear cache
	go s.clearThreadCache(ctx, threadID)

	s.logger.WithFields(map[string]interface{}{
		"thread_id": threadID,
		"user_id":   userID,
	}).Info("Thread updated successfully")

	return thread, nil
}

// DeleteThread deletes a thread
func (s *threadService) DeleteThread(ctx context.Context, threadID, userID primitive.ObjectID) error {
	// Get thread
	thread, err := s.threadRepo.GetByID(ctx, threadID)
	if err != nil {
		return errors.NewNotFoundError("Thread not found")
	}

	// Check ownership
	if thread.AuthorID != userID {
		return errors.NewForbiddenError("You can only delete your own threads")
	}

	// Soft delete
	err = s.threadRepo.SoftDelete(ctx, threadID)
	if err != nil {
		s.logger.WithError(err).Error("Failed to delete thread")
		return errors.NewInternalError("Failed to delete thread", err)
	}

	// Clear cache
	go s.clearThreadCache(ctx, threadID)

	s.logger.WithFields(map[string]interface{}{
		"thread_id": threadID,
		"user_id":   userID,
	}).Info("Thread deleted successfully")

	return nil
}

// RestoreThread restores a deleted thread
func (s *threadService) RestoreThread(ctx context.Context, threadID, userID primitive.ObjectID) (*models.Thread, error) {
	// Get thread
	thread, err := s.threadRepo.GetByID(ctx, threadID)
	if err != nil {
		return nil, errors.NewNotFoundError("Thread not found")
	}

	// Check ownership
	if thread.AuthorID != userID {
		return nil, errors.NewForbiddenError("You can only restore your own threads")
	}

	// Check if thread is actually deleted
	if thread.Status != "deleted" {
		return nil, errors.NewBadRequestError("Thread is not deleted")
	}

	// Restore
	thread.Status = "published"
	thread.UpdatedAt = time.Now()

	err = s.threadRepo.Update(ctx, thread)
	if err != nil {
		s.logger.WithError(err).Error("Failed to restore thread")
		return nil, errors.NewInternalError("Failed to restore thread", err)
	}

	// Clear cache
	go s.clearThreadCache(ctx, threadID)

	s.logger.WithFields(map[string]interface{}{
		"thread_id": threadID,
		"user_id":   userID,
	}).Info("Thread restored successfully")

	return thread, nil
}

// GetPublicTimeline returns the public timeline
func (s *threadService) GetPublicTimeline(ctx context.Context, currentUserID *primitive.ObjectID, params *utils.PaginationParams) (*utils.PaginationResult, error) {
	// Get public threads
	result, err := s.threadRepo.GetPublicTimeline(ctx, currentUserID, params)
	if err != nil {
		s.logger.WithError(err).Error("Failed to get public timeline")
		return nil, errors.NewInternalError("Failed to get public timeline", err)
	}

	// Enrich threads
	if threads, ok := result.Data.([]*models.Thread); ok {
		for i, thread := range threads {
			enriched, err := s.enrichThread(ctx, thread, currentUserID)
			if err != nil {
				s.logger.WithError(err).Error("Failed to enrich thread")
				continue
			}
			threads[i] = enriched
		}
	}

	return result, nil
}

// GetUserFeed returns the user's personalized feed
func (s *threadService) GetUserFeed(ctx context.Context, userID primitive.ObjectID, algorithm string, params *utils.PaginationParams) (*utils.PaginationResult, error) {
	var result *utils.PaginationResult
	var err error

	switch algorithm {
	case "chronological":
		result, err = s.threadRepo.GetUserFeedChronological(ctx, userID, params)
	case "recommended":
		result, err = s.threadRepo.GetUserFeedRecommended(ctx, userID, params)
	default:
		result, err = s.threadRepo.GetUserFeedChronological(ctx, userID, params)
	}

	if err != nil {
		s.logger.WithError(err).Error("Failed to get user feed")
		return nil, errors.NewInternalError("Failed to get user feed", err)
	}

	// Enrich threads
	if threads, ok := result.Data.([]*models.Thread); ok {
		for i, thread := range threads {
			enriched, err := s.enrichThread(ctx, thread, &userID)
			if err != nil {
				s.logger.WithError(err).Error("Failed to enrich thread")
				continue
			}
			threads[i] = enriched
		}
	}

	return result, nil
}

// GetFollowingFeed returns threads from users the user follows
func (s *threadService) GetFollowingFeed(ctx context.Context, userID primitive.ObjectID, params *utils.PaginationParams) (*utils.PaginationResult, error) {
	result, err := s.threadRepo.GetFollowingFeed(ctx, userID, params)
	if err != nil {
		s.logger.WithError(err).Error("Failed to get following feed")
		return nil, errors.NewInternalError("Failed to get following feed", err)
	}

	// Enrich threads
	if threads, ok := result.Data.([]*models.Thread); ok {
		for i, thread := range threads {
			enriched, err := s.enrichThread(ctx, thread, &userID)
			if err != nil {
				s.logger.WithError(err).Error("Failed to enrich thread")
				continue
			}
			threads[i] = enriched
		}
	}

	return result, nil
}

// GetTrendingThreads returns trending threads
func (s *threadService) GetTrendingThreads(ctx context.Context, currentUserID *primitive.ObjectID, timeframe string, params *utils.PaginationParams) (*utils.PaginationResult, error) {
	result, err := s.threadRepo.GetTrendingThreads(ctx, currentUserID, timeframe, params)
	if err != nil {
		s.logger.WithError(err).Error("Failed to get trending threads")
		return nil, errors.NewInternalError("Failed to get trending threads", err)
	}

	// Enrich threads
	if threads, ok := result.Data.([]*models.Thread); ok {
		for i, thread := range threads {
			enriched, err := s.enrichThread(ctx, thread, currentUserID)
			if err != nil {
				s.logger.WithError(err).Error("Failed to enrich thread")
				continue
			}
			threads[i] = enriched
		}
	}

	return result, nil
}

// SearchThreads searches for threads
func (s *threadService) SearchThreads(ctx context.Context, query string, currentUserID *primitive.ObjectID, filters *SearchFilters, params *utils.PaginationParams) (*utils.PaginationResult, error) {
	result, err := s.threadRepo.SearchThreads(ctx, query, currentUserID, filters, params)
	if err != nil {
		s.logger.WithError(err).Error("Failed to search threads")
		return nil, errors.NewInternalError("Failed to search threads", err)
	}

	// Enrich threads
	if threads, ok := result.Data.([]*models.Thread); ok {
		for i, thread := range threads {
			enriched, err := s.enrichThread(ctx, thread, currentUserID)
			if err != nil {
				s.logger.WithError(err).Error("Failed to enrich thread")
				continue
			}
			threads[i] = enriched
		}
	}

	return result, nil
}

// GetThreadReplies returns replies to a thread
func (s *threadService) GetThreadReplies(ctx context.Context, threadID primitive.ObjectID, currentUserID *primitive.ObjectID, params *utils.PaginationParams) (*utils.PaginationResult, error) {
	result, err := s.threadRepo.GetThreadReplies(ctx, threadID, currentUserID, params)
	if err != nil {
		s.logger.WithError(err).Error("Failed to get thread replies")
		return nil, errors.NewInternalError("Failed to get thread replies", err)
	}

	// Enrich threads
	if threads, ok := result.Data.([]*models.Thread); ok {
		for i, thread := range threads {
			enriched, err := s.enrichThread(ctx, thread, currentUserID)
			if err != nil {
				s.logger.WithError(err).Error("Failed to enrich thread")
				continue
			}
			threads[i] = enriched
		}
	}

	return result, nil
}

// GetThreadQuotes returns quote threads
func (s *threadService) GetThreadQuotes(ctx context.Context, threadID primitive.ObjectID, currentUserID *primitive.ObjectID, params *utils.PaginationParams) (*utils.PaginationResult, error) {
	result, err := s.threadRepo.GetThreadQuotes(ctx, threadID, currentUserID, params)
	if err != nil {
		s.logger.WithError(err).Error("Failed to get thread quotes")
		return nil, errors.NewInternalError("Failed to get thread quotes", err)
	}

	// Enrich threads
	if threads, ok := result.Data.([]*models.Thread); ok {
		for i, thread := range threads {
			enriched, err := s.enrichThread(ctx, thread, currentUserID)
			if err != nil {
				s.logger.WithError(err).Error("Failed to enrich thread")
				continue
			}
			threads[i] = enriched
		}
	}

	return result, nil
}

// GetThreadReposts returns users who reposted a thread
func (s *threadService) GetThreadReposts(ctx context.Context, threadID primitive.ObjectID, params *utils.PaginationParams) (*utils.PaginationResult, error) {
	result, err := s.threadRepo.GetThreadReposts(ctx, threadID, params)
	if err != nil {
		s.logger.WithError(err).Error("Failed to get thread reposts")
		return nil, errors.NewInternalError("Failed to get thread reposts", err)
	}

	return result, nil
}

// GetThreadLikes returns users who liked a thread
func (s *threadService) GetThreadLikes(ctx context.Context, threadID primitive.ObjectID, params *utils.PaginationParams) (*utils.PaginationResult, error) {
	result, err := s.threadRepo.GetThreadLikes(ctx, threadID, params)
	if err != nil {
		s.logger.WithError(err).Error("Failed to get thread likes")
		return nil, errors.NewInternalError("Failed to get thread likes", err)
	}

	return result, nil
}

// GetHashtagThreads returns threads with a specific hashtag
func (s *threadService) GetHashtagThreads(ctx context.Context, hashtag string, currentUserID *primitive.ObjectID, params *utils.PaginationParams) (*utils.PaginationResult, error) {
	// Normalize hashtag
	hashtag = strings.ToLower(strings.TrimPrefix(hashtag, "#"))

	result, err := s.threadRepo.GetHashtagThreads(ctx, hashtag, currentUserID, params)
	if err != nil {
		s.logger.WithError(err).Error("Failed to get hashtag threads")
		return nil, errors.NewInternalError("Failed to get hashtag threads", err)
	}

	// Enrich threads
	if threads, ok := result.Data.([]*models.Thread); ok {
		for i, thread := range threads {
			enriched, err := s.enrichThread(ctx, thread, currentUserID)
			if err != nil {
				s.logger.WithError(err).Error("Failed to enrich thread")
				continue
			}
			threads[i] = enriched
		}
	}

	return result, nil
}

// GetTrendingHashtags returns trending hashtags
func (s *threadService) GetTrendingHashtags(ctx context.Context, timeframe string, limit int) ([]*HashtagInfo, error) {
	hashtags, err := s.threadRepo.GetTrendingHashtags(ctx, timeframe, limit)
	if err != nil {
		s.logger.WithError(err).Error("Failed to get trending hashtags")
		return nil, errors.NewInternalError("Failed to get trending hashtags", err)
	}

	return hashtags, nil
}

// GetMentionThreads returns threads mentioning a user
func (s *threadService) GetMentionThreads(ctx context.Context, username string, currentUserID *primitive.ObjectID, params *utils.PaginationParams) (*utils.PaginationResult, error) {
	result, err := s.threadRepo.GetMentionThreads(ctx, username, currentUserID, params)
	if err != nil {
		s.logger.WithError(err).Error("Failed to get mention threads")
		return nil, errors.NewInternalError("Failed to get mention threads", err)
	}

	// Enrich threads
	if threads, ok := result.Data.([]*models.Thread); ok {
		for i, thread := range threads {
			enriched, err := s.enrichThread(ctx, thread, currentUserID)
			if err != nil {
				s.logger.WithError(err).Error("Failed to enrich thread")
				continue
			}
			threads[i] = enriched
		}
	}

	return result, nil
}

// GetMentionsFeed returns threads mentioning the current user
func (s *threadService) GetMentionsFeed(ctx context.Context, userID primitive.ObjectID, params *utils.PaginationParams) (*utils.PaginationResult, error) {
	// Get user to get username
	user, err := s.userRepo.GetByID(ctx, userID)
	if err != nil {
		return nil, errors.NewNotFoundError("User not found")
	}

	result, err := s.threadRepo.GetMentionThreads(ctx, user.Username, &userID, params)
	if err != nil {
		s.logger.WithError(err).Error("Failed to get mentions feed")
		return nil, errors.NewInternalError("Failed to get mentions feed", err)
	}

	// Enrich threads
	if threads, ok := result.Data.([]*models.Thread); ok {
		for i, thread := range threads {
			enriched, err := s.enrichThread(ctx, thread, &userID)
			if err != nil {
				s.logger.WithError(err).Error("Failed to enrich thread")
				continue
			}
			threads[i] = enriched
		}
	}

	return result, nil
}

// GetListFeed returns threads from users in a list
func (s *threadService) GetListFeed(ctx context.Context, userID, listID primitive.ObjectID, params *utils.PaginationParams) (*utils.PaginationResult, error) {
	// Check if user owns the list or has access to it
	list, err := s.userRepo.GetList(ctx, listID)
	if err != nil {
		return nil, errors.NewNotFoundError("List not found")
	}

	if list.OwnerID != userID && list.Visibility == "private" {
		return nil, errors.NewForbiddenError("Access denied to this list")
	}

	result, err := s.threadRepo.GetListFeed(ctx, listID, &userID, params)
	if err != nil {
		s.logger.WithError(err).Error("Failed to get list feed")
		return nil, errors.NewInternalError("Failed to get list feed", err)
	}

	// Enrich threads
	if threads, ok := result.Data.([]*models.Thread); ok {
		for i, thread := range threads {
			enriched, err := s.enrichThread(ctx, thread, &userID)
			if err != nil {
				s.logger.WithError(err).Error("Failed to enrich thread")
				continue
			}
			threads[i] = enriched
		}
	}

	return result, nil
}

// Thread moderation methods
func (s *threadService) PinThread(ctx context.Context, threadID, userID primitive.ObjectID) error {
	thread, err := s.threadRepo.GetByID(ctx, threadID)
	if err != nil {
		return errors.NewNotFoundError("Thread not found")
	}

	if thread.AuthorID != userID {
		return errors.NewForbiddenError("You can only pin your own threads")
	}

	return s.threadRepo.PinThread(ctx, threadID, userID)
}

func (s *threadService) UnpinThread(ctx context.Context, threadID, userID primitive.ObjectID) error {
	thread, err := s.threadRepo.GetByID(ctx, threadID)
	if err != nil {
		return errors.NewNotFoundError("Thread not found")
	}

	if thread.AuthorID != userID {
		return errors.NewForbiddenError("You can only unpin your own threads")
	}

	return s.threadRepo.UnpinThread(ctx, threadID, userID)
}

func (s *threadService) HideThread(ctx context.Context, threadID, userID primitive.ObjectID) error {
	return s.threadRepo.HideThread(ctx, threadID, userID)
}

func (s *threadService) UnhideThread(ctx context.Context, threadID, userID primitive.ObjectID) error {
	return s.threadRepo.UnhideThread(ctx, threadID, userID)
}

func (s *threadService) UpdateThreadVisibility(ctx context.Context, threadID, userID primitive.ObjectID, visibility string) error {
	thread, err := s.threadRepo.GetByID(ctx, threadID)
	if err != nil {
		return errors.NewNotFoundError("Thread not found")
	}

	if thread.AuthorID != userID {
		return errors.NewForbiddenError("You can only update visibility of your own threads")
	}

	return s.threadRepo.UpdateVisibility(ctx, threadID, visibility)
}

func (s *threadService) UpdateReplySettings(ctx context.Context, threadID, userID primitive.ObjectID, replySettings string) error {
	thread, err := s.threadRepo.GetByID(ctx, threadID)
	if err != nil {
		return errors.NewNotFoundError("Thread not found")
	}

	if thread.AuthorID != userID {
		return errors.NewForbiddenError("You can only update reply settings of your own threads")
	}

	return s.threadRepo.UpdateReplySettings(ctx, threadID, replySettings)
}

// Scheduled threads
func (s *threadService) GetScheduledThreads(ctx context.Context, userID primitive.ObjectID, params *utils.PaginationParams) (*utils.PaginationResult, error) {
	result, err := s.threadRepo.GetScheduledThreads(ctx, userID, params)
	if err != nil {
		s.logger.WithError(err).Error("Failed to get scheduled threads")
		return nil, errors.NewInternalError("Failed to get scheduled threads", err)
	}

	return result, nil
}

func (s *threadService) ScheduleThread(ctx context.Context, req *ScheduleThreadRequest) (*models.Thread, error) {
	// Convert to CreateThreadRequest
	createReq := &CreateThreadRequest{
		AuthorID:       req.AuthorID,
		Content:        req.Content,
		MediaFiles:     req.MediaFiles,
		Type:           "thread",
		Hashtags:       req.Hashtags,
		Mentions:       req.Mentions,
		Visibility:     req.Visibility,
		ReplySettings:  req.ReplySettings,
		Location:       req.Location,
		Poll:           req.Poll,
		ScheduledAt:    &req.ScheduledAt,
		ContentWarning: req.ContentWarning,
		IsSensitive:    req.IsSensitive,
	}

	return s.CreateThread(ctx, createReq)
}

func (s *threadService) UpdateScheduledThread(ctx context.Context, threadID, userID primitive.ObjectID, req *UpdateScheduledThreadRequest) (*models.Thread, error) {
	thread, err := s.threadRepo.GetByID(ctx, threadID)
	if err != nil {
		return nil, errors.NewNotFoundError("Thread not found")
	}

	if thread.AuthorID != userID {
		return nil, errors.NewForbiddenError("You can only update your own scheduled threads")
	}

	if thread.Status != "scheduled" {
		return nil, errors.NewBadRequestError("Thread is not scheduled")
	}

	// Update fields
	if req.Content != "" {
		thread.Content = req.Content
	}
	if req.MediaFiles != nil {
		thread.MediaFiles = req.MediaFiles
	}
	if req.Hashtags != nil {
		thread.Hashtags = req.Hashtags
	}
	if req.Mentions != nil {
		thread.Mentions = req.Mentions
	}
	if req.Visibility != "" {
		thread.Visibility = req.Visibility
	}
	if req.ReplySettings != "" {
		thread.ReplySettings = req.ReplySettings
	}
	if req.Location != nil {
		thread.Location = req.Location
	}
	if req.Poll != nil {
		thread.Poll = req.Poll
	}
	if req.ScheduledAt != nil {
		thread.ScheduledAt = req.ScheduledAt
	}
	thread.ContentWarning = req.ContentWarning
	thread.IsSensitive = req.IsSensitive
	thread.UpdatedAt = time.Now()

	err = s.threadRepo.Update(ctx, thread)
	if err != nil {
		s.logger.WithError(err).Error("Failed to update scheduled thread")
		return nil, errors.NewInternalError("Failed to update scheduled thread", err)
	}

	return thread, nil
}

func (s *threadService) CancelScheduledThread(ctx context.Context, threadID, userID primitive.ObjectID) error {
	thread, err := s.threadRepo.GetByID(ctx, threadID)
	if err != nil {
		return errors.NewNotFoundError("Thread not found")
	}

	if thread.AuthorID != userID {
		return errors.NewForbiddenError("You can only cancel your own scheduled threads")
	}

	if thread.Status != "scheduled" {
		return errors.NewBadRequestError("Thread is not scheduled")
	}

	return s.threadRepo.Delete(ctx, threadID)
}

func (s *threadService) PublishScheduledThread(ctx context.Context, threadID, userID primitive.ObjectID) (*models.Thread, error) {
	thread, err := s.threadRepo.GetByID(ctx, threadID)
	if err != nil {
		return nil, errors.NewNotFoundError("Thread not found")
	}

	if thread.AuthorID != userID {
		return nil, errors.NewForbiddenError("You can only publish your own scheduled threads")
	}

	if thread.Status != "scheduled" {
		return nil, errors.NewBadRequestError("Thread is not scheduled")
	}

	// Update status
	thread.Status = "published"
	thread.IsScheduled = false
	thread.ScheduledAt = nil
	thread.UpdatedAt = time.Now()

	err = s.threadRepo.Update(ctx, thread)
	if err != nil {
		s.logger.WithError(err).Error("Failed to publish scheduled thread")
		return nil, errors.NewInternalError("Failed to publish scheduled thread", err)
	}

	return thread, nil
}

// Draft methods
func (s *threadService) GetDrafts(ctx context.Context, userID primitive.ObjectID, params *utils.PaginationParams) (*utils.PaginationResult, error) {
	result, err := s.threadRepo.GetDrafts(ctx, userID, params)
	if err != nil {
		s.logger.WithError(err).Error("Failed to get drafts")
		return nil, errors.NewInternalError("Failed to get drafts", err)
	}

	return result, nil
}

func (s *threadService) SaveDraft(ctx context.Context, req *SaveDraftRequest) (*models.Thread, error) {
	thread := &models.Thread{
		ID:             primitive.NewObjectID(),
		AuthorID:       req.AuthorID,
		Content:        req.Content,
		MediaFiles:     req.MediaFiles,
		Type:           "thread",
		Hashtags:       req.Hashtags,
		Mentions:       req.Mentions,
		Visibility:     req.Visibility,
		ReplySettings:  req.ReplySettings,
		Location:       req.Location,
		Poll:           req.Poll,
		ContentWarning: req.ContentWarning,
		IsSensitive:    req.IsSensitive,
		Status:         "draft",
		CreatedAt:      time.Now(),
		UpdatedAt:      time.Now(),
	}

	err := s.threadRepo.Create(ctx, thread)
	if err != nil {
		s.logger.WithError(err).Error("Failed to save draft")
		return nil, errors.NewInternalError("Failed to save draft", err)
	}

	return thread, nil
}

func (s *threadService) UpdateDraft(ctx context.Context, draftID, userID primitive.ObjectID, req *UpdateDraftRequest) (*models.Thread, error) {
	draft, err := s.threadRepo.GetByID(ctx, draftID)
	if err != nil {
		return nil, errors.NewNotFoundError("Draft not found")
	}

	if draft.AuthorID != userID {
		return nil, errors.NewForbiddenError("You can only update your own drafts")
	}

	if draft.Status != "draft" {
		return nil, errors.NewBadRequestError("Thread is not a draft")
	}

	// Update fields
	draft.Content = req.Content
	draft.MediaFiles = req.MediaFiles
	draft.Hashtags = req.Hashtags
	draft.Mentions = req.Mentions
	draft.Visibility = req.Visibility
	draft.ReplySettings = req.ReplySettings
	draft.Location = req.Location
	draft.Poll = req.Poll
	draft.ContentWarning = req.ContentWarning
	draft.IsSensitive = req.IsSensitive
	draft.UpdatedAt = time.Now()

	err = s.threadRepo.Update(ctx, draft)
	if err != nil {
		s.logger.WithError(err).Error("Failed to update draft")
		return nil, errors.NewInternalError("Failed to update draft", err)
	}

	return draft, nil
}

func (s *threadService) DeleteDraft(ctx context.Context, draftID, userID primitive.ObjectID) error {
	draft, err := s.threadRepo.GetByID(ctx, draftID)
	if err != nil {
		return errors.NewNotFoundError("Draft not found")
	}

	if draft.AuthorID != userID {
		return errors.NewForbiddenError("You can only delete your own drafts")
	}

	if draft.Status != "draft" {
		return errors.NewBadRequestError("Thread is not a draft")
	}

	return s.threadRepo.Delete(ctx, draftID)
}

func (s *threadService) PublishDraft(ctx context.Context, draftID, userID primitive.ObjectID) (*models.Thread, error) {
	draft, err := s.threadRepo.GetByID(ctx, draftID)
	if err != nil {
		return nil, errors.NewNotFoundError("Draft not found")
	}

	if draft.AuthorID != userID {
		return nil, errors.NewForbiddenError("You can only publish your own drafts")
	}

	if draft.Status != "draft" {
		return nil, errors.NewBadRequestError("Thread is not a draft")
	}

	// Update status
	draft.Status = "published"
	draft.UpdatedAt = time.Now()

	err = s.threadRepo.Update(ctx, draft)
	if err != nil {
		s.logger.WithError(err).Error("Failed to publish draft")
		return nil, errors.NewInternalError("Failed to publish draft", err)
	}

	return draft, nil
}

// Analytics methods
func (s *threadService) GetThreadAnalytics(ctx context.Context, threadID, userID primitive.ObjectID) (*ThreadAnalytics, error) {
	thread, err := s.threadRepo.GetByID(ctx, threadID)
	if err != nil {
		return nil, errors.NewNotFoundError("Thread not found")
	}

	if thread.AuthorID != userID {
		return nil, errors.NewForbiddenError("You can only view analytics for your own threads")
	}

	analytics, err := s.threadRepo.GetThreadAnalytics(ctx, threadID)
	if err != nil {
		s.logger.WithError(err).Error("Failed to get thread analytics")
		return nil, errors.NewInternalError("Failed to get thread analytics", err)
	}

	return analytics, nil
}

func (s *threadService) GetUserThreadAnalytics(ctx context.Context, userID primitive.ObjectID, timeframe string) (*UserThreadAnalytics, error) {
	analytics, err := s.threadRepo.GetUserThreadAnalytics(ctx, userID, timeframe)
	if err != nil {
		s.logger.WithError(err).Error("Failed to get user thread analytics")
		return nil, errors.NewInternalError("Failed to get user thread analytics", err)
	}

	return analytics, nil
}

// Admin operations
func (s *threadService) GetAllThreads(ctx context.Context, params *utils.PaginationParams, filter string) (*utils.PaginationResult, error) {
	result, err := s.threadRepo.GetAllThreads(ctx, params, filter)
	if err != nil {
		s.logger.WithError(err).Error("Failed to get all threads")
		return nil, errors.NewInternalError("Failed to get all threads", err)
	}

	return result, nil
}

func (s *threadService) GetReportedThreads(ctx context.Context, params *utils.PaginationParams) (*utils.PaginationResult, error) {
	result, err := s.threadRepo.GetReportedThreads(ctx, params)
	if err != nil {
		s.logger.WithError(err).Error("Failed to get reported threads")
		return nil, errors.NewInternalError("Failed to get reported threads", err)
	}

	return result, nil
}

func (s *threadService) GetFlaggedThreads(ctx context.Context, params *utils.PaginationParams) (*utils.PaginationResult, error) {
	result, err := s.threadRepo.GetFlaggedThreads(ctx, params)
	if err != nil {
		s.logger.WithError(err).Error("Failed to get flagged threads")
		return nil, errors.NewInternalError("Failed to get flagged threads", err)
	}

	return result, nil
}

func (s *threadService) GetThreadReports(ctx context.Context, threadID primitive.ObjectID, params *utils.PaginationParams) (*utils.PaginationResult, error) {
	result, err := s.threadRepo.GetThreadReports(ctx, threadID, params)
	if err != nil {
		s.logger.WithError(err).Error("Failed to get thread reports")
		return nil, errors.NewInternalError("Failed to get thread reports", err)
	}

	return result, nil
}

func (s *threadService) ModerateThread(ctx context.Context, threadID, adminID primitive.ObjectID, action, reason string) error {
	err := s.threadRepo.ModerateThread(ctx, threadID, adminID, action, reason)
	if err != nil {
		s.logger.WithError(err).Error("Failed to moderate thread")
		return errors.NewInternalError("Failed to moderate thread", err)
	}

	return nil
}

func (s *threadService) FeatureThread(ctx context.Context, threadID, adminID primitive.ObjectID) error {
	return s.threadRepo.FeatureThread(ctx, threadID, adminID)
}

func (s *threadService) UnfeatureThread(ctx context.Context, threadID, adminID primitive.ObjectID) error {
	return s.threadRepo.UnfeatureThread(ctx, threadID, adminID)
}

func (s *threadService) LockThread(ctx context.Context, threadID, adminID primitive.ObjectID, reason string) error {
	return s.threadRepo.LockThread(ctx, threadID, adminID, reason)
}

func (s *threadService) UnlockThread(ctx context.Context, threadID, adminID primitive.ObjectID) error {
	return s.threadRepo.UnlockThread(ctx, threadID, adminID)
}

func (s *threadService) AdminDeleteThread(ctx context.Context, threadID, adminID primitive.ObjectID, reason string) error {
	return s.threadRepo.AdminDeleteThread(ctx, threadID, adminID, reason)
}

func (s *threadService) AdminRestoreThread(ctx context.Context, threadID, adminID primitive.ObjectID, reason string) (*models.Thread, error) {
	thread, err := s.threadRepo.AdminRestoreThread(ctx, threadID, adminID, reason)
	if err != nil {
		s.logger.WithError(err).Error("Failed to restore thread")
		return nil, errors.NewInternalError("Failed to restore thread", err)
	}

	return thread, nil
}

// Utility methods
func (s *threadService) CanReply(ctx context.Context, threadID, userID primitive.ObjectID) (bool, error) {
	thread, err := s.threadRepo.GetByID(ctx, threadID)
	if err != nil {
		return false, err
	}

	return s.canReplyToThread(ctx, thread, userID)
}

func (s *threadService) IncrementLikesCount(ctx context.Context, threadID primitive.ObjectID, delta int) error {
	return s.threadRepo.IncrementLikesCount(ctx, threadID, delta)
}

func (s *threadService) IncrementRepliesCount(ctx context.Context, threadID primitive.ObjectID, delta int) error {
	return s.threadRepo.IncrementRepliesCount(ctx, threadID, delta)
}

func (s *threadService) IncrementRepostsCount(ctx context.Context, threadID primitive.ObjectID, delta int) error {
	return s.threadRepo.IncrementRepostsCount(ctx, threadID, delta)
}

func (s *threadService) IncrementViewsCount(ctx context.Context, threadID primitive.ObjectID, delta int) error {
	return s.threadRepo.IncrementViewsCount(ctx, threadID, delta)
}

func (s *threadService) IncrementQuotesCount(ctx context.Context, threadID primitive.ObjectID, delta int) error {
	return s.threadRepo.IncrementQuotesCount(ctx, threadID, delta)
}

// Helper methods

// usernamesToObjectIDs converts a slice of usernames to a slice of user ObjectIDs.
func (s *threadService) usernamesToObjectIDs(ctx context.Context, usernames []string) []primitive.ObjectID {
	var ids []primitive.ObjectID
	for _, username := range usernames {
		user, err := s.userRepo.GetByUsername(ctx, username)
		if err == nil {
			ids = append(ids, user.ID)
		}
	}
	return ids
}

func (s *threadService) enrichThread(ctx context.Context, thread *models.Thread, currentUserID *primitive.ObjectID) (*models.Thread, error) {
	// Get author information
	author, err := s.userRepo.GetByID(ctx, thread.AuthorID)
	if err == nil {
		thread.Author = author
	}

	// Get parent thread if it's a reply
	if thread.ParentID != nil {
		parentThread, err := s.threadRepo.GetByID(ctx, *thread.ParentID)
		if err == nil {
			thread.ParentThread = parentThread
		}
	}

	// Get quoted thread if it's a quote
	if thread.QuotedThreadID != nil {
		quotedThread, err := s.threadRepo.GetByID(ctx, *thread.QuotedThreadID)
		if err == nil {
			thread.QuotedThread = quotedThread
		}
	}

	// Set interaction flags for current user
	if currentUserID != nil {
		thread.IsLiked, _ = s.interactionRepo.HasLiked(ctx, *currentUserID, thread.ID)
		thread.IsReposted, _ = s.interactionRepo.HasReposted(ctx, *currentUserID, thread.ID)
		thread.IsBookmarked, _ = s.interactionRepo.HasBookmarked(ctx, *currentUserID, thread.ID)

		// Set permission flags
		thread.CanReply, _ = s.canReplyToThread(ctx, thread, *currentUserID)
		thread.CanRepost = s.canRepostThread(ctx, thread, *currentUserID)
	}

	return thread, nil
}

func (s *threadService) canViewThread(ctx context.Context, thread *models.Thread, currentUserID *primitive.ObjectID) bool {
	// Public threads are always viewable
	if thread.Visibility == "public" {
		return true
	}

	// If not authenticated, can only view public threads
	if currentUserID == nil {
		return false
	}

	// Author can always view their own threads
	if thread.AuthorID == *currentUserID {
		return true
	}

	// Handle followers-only visibility
	if thread.Visibility == "followers" {
		// Check if current user follows the author
		isFollowing, err := s.userRepo.GetFollow(ctx, *currentUserID, thread.AuthorID)
		return err == nil && isFollowing.IsAccepted
	}

	// Handle mentioned-only visibility
	if thread.Visibility == "mentioned" {
		// Get current user username
		user, err := s.userRepo.GetByID(ctx, *currentUserID)
		if err != nil {
			return false
		}

		// Check if user is mentioned
		for _, mention := range thread.Mentions {
			if mention == user.Username {
				return true
			}
		}
		return false
	}

	return false
}

func (s *threadService) canReplyToThread(ctx context.Context, thread *models.Thread, userID primitive.ObjectID) (bool, error) {
	// Check reply settings
	switch thread.ReplySettings {
	case "none":
		return false, nil
	case "everyone":
		return true, nil
	case "following":
		// Check if thread author follows the user
		follow, err := s.userRepo.GetFollow(ctx, thread.AuthorID, userID)
		if err != nil {
			return false, nil
		}
		return follow.IsAccepted, nil
	case "mentioned":
		// Get user to check username
		user, err := s.userRepo.GetByID(ctx, userID)
		if err != nil {
			return false, err
		}

		// Check if user is mentioned
		for _, mention := range thread.Mentions {
			if mention == user.Username {
				return true, nil
			}
		}
		return false, nil
	default:
		return true, nil
	}
}

func (s *threadService) canRepostThread(ctx context.Context, thread *models.Thread, userID primitive.ObjectID) bool {
	// Can't repost your own thread
	if thread.AuthorID == userID {
		return false
	}

	// Check visibility
	return s.canViewThread(ctx, thread, &userID)
}

func (s *threadService) canEditThread(thread *models.Thread) bool {
	// Can't edit threads older than 24 hours
	editDeadline := thread.CreatedAt.Add(24 * time.Hour)
	return time.Now().Before(editDeadline)
}

func (s *threadService) extractHashtags(content string) []string {
	var hashtags []string
	words := strings.Fields(content)

	for _, word := range words {
		if strings.HasPrefix(word, "#") && len(word) > 1 {
			hashtag := strings.ToLower(strings.TrimPrefix(word, "#"))
			// Remove punctuation
			hashtag = strings.Trim(hashtag, ".,!?;:")
			if hashtag != "" {
				hashtags = append(hashtags, hashtag)
			}
		}
	}

	return hashtags
}

func (s *threadService) extractMentions(content string) []string {
	var mentions []string
	words := strings.Fields(content)

	for _, word := range words {
		if strings.HasPrefix(word, "@") && len(word) > 1 {
			mention := strings.TrimPrefix(word, "@")
			// Remove punctuation
			mention = strings.Trim(mention, ".,!?;:")
			if mention != "" {
				mentions = append(mentions, mention)
			}
		}
	}

	return mentions
}

func (s *threadService) deduplicateStrings(slice []string) []string {
	keys := make(map[string]bool)
	var result []string

	for _, item := range slice {
		if !keys[item] {
			keys[item] = true
			result = append(result, item)
		}
	}

	return result
}

func (s *threadService) detectLanguage(content string) string {
	// Simple language detection - in a real implementation,
	// you might use a proper language detection library
	if len(content) == 0 {
		return "en"
	}

	// For now, just return English as default
	return "en"
}

// Cache helper methods
func (s *threadService) cacheThread(ctx context.Context, thread *models.Thread) {
	if s.redis == nil {
		return
	}

	key := fmt.Sprintf("%sthread:%s", constants.RedisKeyPrefix, thread.ID.Hex())
	// In a real implementation, you would serialize the thread and cache it
	// For now, we'll skip the implementation
}

func (s *threadService) getCachedThread(ctx context.Context, threadID primitive.ObjectID) *models.Thread {
	if s.redis == nil {
		return nil
	}

	// In a real implementation, you would get from cache and deserialize
	// For now, we'll skip the implementation
	return nil
}

func (s *threadService) clearThreadCache(ctx context.Context, threadID primitive.ObjectID) {
	if s.redis == nil {
		return
	}

	key := fmt.Sprintf("%sthread:%s", constants.RedisKeyPrefix, threadID.Hex())
	s.redis.Del(ctx, key)
}

func (s *threadService) recordThreadView(ctx context.Context, threadID, userID primitive.ObjectID) {
	// Record thread view for analytics
	view := &models.ThreadView{
		ThreadID: threadID,
		UserID:   userID,
		ViewedAt: time.Now(),
		Source:   "api", // This could be passed from the request
	}

	// In a real implementation, you would save this to the database
	_ = view
}
