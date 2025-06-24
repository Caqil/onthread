package repository

import (
	"context"
	"errors"
	"time"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"

	"onthread/internal/models"
	"onthread/internal/services"
	"onthread/internal/utils"
	"onthread/pkg/constants"
	"onthread/pkg/logger"
)

// ThreadRepository interface defines all thread database operations
type ThreadRepository interface {
	// Core CRUD operations
	Create(ctx context.Context, thread *models.Thread) error
	GetByID(ctx context.Context, id primitive.ObjectID) (*models.Thread, error)
	Update(ctx context.Context, thread *models.Thread) error
	Delete(ctx context.Context, id primitive.ObjectID) error
	SoftDelete(ctx context.Context, id primitive.ObjectID) error

	// Timeline and feeds
	GetPublicTimeline(ctx context.Context, currentUserID *primitive.ObjectID, params *utils.PaginationParams) (*utils.PaginationResult, error)
	GetUserFeedChronological(ctx context.Context, userID primitive.ObjectID, params *utils.PaginationParams) (*utils.PaginationResult, error)
	GetUserFeedRecommended(ctx context.Context, userID primitive.ObjectID, params *utils.PaginationParams) (*utils.PaginationResult, error)
	GetFollowingFeed(ctx context.Context, userID primitive.ObjectID, params *utils.PaginationParams) (*utils.PaginationResult, error)
	GetTrendingThreads(ctx context.Context, currentUserID *primitive.ObjectID, timeframe string, params *utils.PaginationParams) (*utils.PaginationResult, error)

	// Search and discovery
	SearchThreads(ctx context.Context, query string, currentUserID *primitive.ObjectID, filters *services.SearchFilters, params *utils.PaginationParams) (*utils.PaginationResult, error)

	// Thread interactions
	GetThreadReplies(ctx context.Context, threadID primitive.ObjectID, currentUserID *primitive.ObjectID, params *utils.PaginationParams) (*utils.PaginationResult, error)
	GetThreadQuotes(ctx context.Context, threadID primitive.ObjectID, currentUserID *primitive.ObjectID, params *utils.PaginationParams) (*utils.PaginationResult, error)
	GetThreadReposts(ctx context.Context, threadID primitive.ObjectID, params *utils.PaginationParams) (*utils.PaginationResult, error)
	GetThreadLikes(ctx context.Context, threadID primitive.ObjectID, params *utils.PaginationParams) (*utils.PaginationResult, error)

	// Hashtags and mentions
	GetHashtagThreads(ctx context.Context, hashtag string, currentUserID *primitive.ObjectID, params *utils.PaginationParams) (*utils.PaginationResult, error)
	GetTrendingHashtags(ctx context.Context, timeframe string, limit int) ([]*services.HashtagInfo, error)
	GetMentionThreads(ctx context.Context, username string, currentUserID *primitive.ObjectID, params *utils.PaginationParams) (*utils.PaginationResult, error)

	// List feed
	GetListFeed(ctx context.Context, listID primitive.ObjectID, currentUserID *primitive.ObjectID, params *utils.PaginationParams) (*utils.PaginationResult, error)

	// Thread moderation
	PinThread(ctx context.Context, threadID, userID primitive.ObjectID) error
	UnpinThread(ctx context.Context, threadID, userID primitive.ObjectID) error
	HideThread(ctx context.Context, threadID, userID primitive.ObjectID) error
	UnhideThread(ctx context.Context, threadID, userID primitive.ObjectID) error
	UpdateVisibility(ctx context.Context, threadID primitive.ObjectID, visibility string) error
	UpdateReplySettings(ctx context.Context, threadID primitive.ObjectID, replySettings string) error

	// Scheduled threads and drafts
	GetScheduledThreads(ctx context.Context, userID primitive.ObjectID, params *utils.PaginationParams) (*utils.PaginationResult, error)
	GetDrafts(ctx context.Context, userID primitive.ObjectID, params *utils.PaginationParams) (*utils.PaginationResult, error)

	// Analytics
	GetThreadAnalytics(ctx context.Context, threadID primitive.ObjectID) (*services.ThreadAnalytics, error)
	GetUserThreadAnalytics(ctx context.Context, userID primitive.ObjectID, timeframe string) (*services.UserThreadAnalytics, error)

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
	IncrementLikesCount(ctx context.Context, threadID primitive.ObjectID, delta int) error
	IncrementRepliesCount(ctx context.Context, threadID primitive.ObjectID, delta int) error
	IncrementRepostsCount(ctx context.Context, threadID primitive.ObjectID, delta int) error
	IncrementQuotesCount(ctx context.Context, threadID primitive.ObjectID, delta int) error
	IncrementViewsCount(ctx context.Context, threadID primitive.ObjectID, delta int) error
	IncrementSharesCount(ctx context.Context, threadID primitive.ObjectID, delta int) error
	IncrementBookmarksCount(ctx context.Context, threadID primitive.ObjectID, delta int) error

	// Batch operations
	GetThreadsByIDs(ctx context.Context, threadIDs []primitive.ObjectID) ([]*models.Thread, error)
	GetThreadsByUserID(ctx context.Context, userID primitive.ObjectID, params *utils.PaginationParams) (*utils.PaginationResult, error)
}

// threadRepository implements ThreadRepository interface
type threadRepository struct {
	database                    *mongo.Database
	threadsCollection           *mongo.Collection
	threadViewsCollection       *mongo.Collection
	reportsCollection           *mongo.Collection
	moderationActionsCollection *mongo.Collection
	logger                      *logger.Logger
}

// NewThreadRepository creates a new thread repository
func NewThreadRepository(database *mongo.Database) ThreadRepository {
	return &threadRepository{
		database:                    database,
		threadsCollection:           database.Collection(constants.ThreadsCollection),
		threadViewsCollection:       database.Collection(constants.ThreadViewsCollection),
		reportsCollection:           database.Collection(constants.ReportsCollection),
		moderationActionsCollection: database.Collection(constants.ModerationActionsCollection),
		logger:                      logger.NewComponentLogger("ThreadRepository"),
	}
}

// Create creates a new thread
func (r *threadRepository) Create(ctx context.Context, thread *models.Thread) error {
	if thread.ID.IsZero() {
		thread.ID = primitive.NewObjectID()
	}

	_, err := r.threadsCollection.InsertOne(ctx, thread)
	if err != nil {
		r.logger.WithError(err).Error("Failed to create thread")
		return err
	}

	r.logger.WithField("thread_id", thread.ID).Info("Thread created successfully")
	return nil
}

// GetByID retrieves a thread by ID
func (r *threadRepository) GetByID(ctx context.Context, id primitive.ObjectID) (*models.Thread, error) {
	var thread models.Thread
	err := r.threadsCollection.FindOne(ctx, bson.M{"_id": id}).Decode(&thread)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			return nil, errors.New("thread not found")
		}
		r.logger.WithError(err).WithField("thread_id", id).Error("Failed to get thread by ID")
		return nil, err
	}

	return &thread, nil
}

// Update updates an existing thread
func (r *threadRepository) Update(ctx context.Context, thread *models.Thread) error {
	filter := bson.M{"_id": thread.ID}
	update := bson.M{"$set": thread}

	result, err := r.threadsCollection.UpdateOne(ctx, filter, update)
	if err != nil {
		r.logger.WithError(err).WithField("thread_id", thread.ID).Error("Failed to update thread")
		return err
	}

	if result.MatchedCount == 0 {
		return errors.New("thread not found")
	}

	return nil
}

// Delete permanently deletes a thread
func (r *threadRepository) Delete(ctx context.Context, id primitive.ObjectID) error {
	result, err := r.threadsCollection.DeleteOne(ctx, bson.M{"_id": id})
	if err != nil {
		r.logger.WithError(err).WithField("thread_id", id).Error("Failed to delete thread")
		return err
	}

	if result.DeletedCount == 0 {
		return errors.New("thread not found")
	}

	return nil
}

// SoftDelete soft deletes a thread
func (r *threadRepository) SoftDelete(ctx context.Context, id primitive.ObjectID) error {
	filter := bson.M{"_id": id}
	update := bson.M{
		"$set": bson.M{
			"status":     "deleted",
			"deleted_at": time.Now(),
			"updated_at": time.Now(),
		},
	}

	result, err := r.threadsCollection.UpdateOne(ctx, filter, update)
	if err != nil {
		r.logger.WithError(err).WithField("thread_id", id).Error("Failed to soft delete thread")
		return err
	}

	if result.MatchedCount == 0 {
		return errors.New("thread not found")
	}

	return nil
}

// GetPublicTimeline returns the public timeline
func (r *threadRepository) GetPublicTimeline(ctx context.Context, currentUserID *primitive.ObjectID, params *utils.PaginationParams) (*utils.PaginationResult, error) {
	pipeline := []bson.M{
		{
			"$match": bson.M{
				"visibility": "public",
				"status":     "published",
			},
		},
		{
			"$sort": bson.M{
				"created_at": -1,
			},
		},
	}

	return r.aggregateWithPagination(ctx, pipeline, params)
}

// GetUserFeedChronological returns chronological user feed
func (r *threadRepository) GetUserFeedChronological(ctx context.Context, userID primitive.ObjectID, params *utils.PaginationParams) (*utils.PaginationResult, error) {
	pipeline := []bson.M{
		{
			"$match": bson.M{
				"status": "published",
				"$or": []bson.M{
					{"visibility": "public"},
					{"author_id": userID},
					{
						"$and": []bson.M{
							{"visibility": "followers"},
							// In a real implementation, you'd check if user follows the author
						},
					},
				},
			},
		},
		{
			"$sort": bson.M{
				"created_at": -1,
			},
		},
	}

	return r.aggregateWithPagination(ctx, pipeline, params)
}

// GetUserFeedRecommended returns recommended user feed
func (r *threadRepository) GetUserFeedRecommended(ctx context.Context, userID primitive.ObjectID, params *utils.PaginationParams) (*utils.PaginationResult, error) {
	// For now, use the same as chronological with engagement-based sorting
	pipeline := []bson.M{
		{
			"$match": bson.M{
				"status": "published",
				"$or": []bson.M{
					{"visibility": "public"},
					{"author_id": userID},
				},
			},
		},
		{
			"$addFields": bson.M{
				"engagement_score": bson.M{
					"$add": []interface{}{
						"$likes_count",
						bson.M{"$multiply": []interface{}{"$reposts_count", 2}},
						bson.M{"$multiply": []interface{}{"$replies_count", 3}},
					},
				},
			},
		},
		{
			"$sort": bson.M{
				"engagement_score": -1,
				"created_at":       -1,
			},
		},
	}

	return r.aggregateWithPagination(ctx, pipeline, params)
}

// GetFollowingFeed returns threads from users the user follows
func (r *threadRepository) GetFollowingFeed(ctx context.Context, userID primitive.ObjectID, params *utils.PaginationParams) (*utils.PaginationResult, error) {
	pipeline := []bson.M{
		{
			"$lookup": bson.M{
				"from":         constants.FollowsCollection,
				"localField":   "author_id",
				"foreignField": "followed_id",
				"as":           "follow_info",
			},
		},
		{
			"$match": bson.M{
				"status": "published",
				"$or": []bson.M{
					{
						"$and": []bson.M{
							{"follow_info.follower_id": userID},
							{"follow_info.is_accepted": true},
						},
					},
					{"author_id": userID}, // Include user's own threads
				},
			},
		},
		{
			"$sort": bson.M{
				"created_at": -1,
			},
		},
	}

	return r.aggregateWithPagination(ctx, pipeline, params)
}

// GetTrendingThreads returns trending threads
func (r *threadRepository) GetTrendingThreads(ctx context.Context, currentUserID *primitive.ObjectID, timeframe string, params *utils.PaginationParams) (*utils.PaginationResult, error) {
	// Calculate time threshold based on timeframe
	var timeThreshold time.Time
	switch timeframe {
	case "1h":
		timeThreshold = time.Now().Add(-1 * time.Hour)
	case "24h":
		timeThreshold = time.Now().Add(-24 * time.Hour)
	case "7d":
		timeThreshold = time.Now().Add(-7 * 24 * time.Hour)
	default:
		timeThreshold = time.Now().Add(-24 * time.Hour)
	}

	pipeline := []bson.M{
		{
			"$match": bson.M{
				"visibility": "public",
				"status":     "published",
				"created_at": bson.M{"$gte": timeThreshold},
			},
		},
		{
			"$addFields": bson.M{
				"trend_score": bson.M{
					"$add": []interface{}{
						bson.M{"$multiply": []interface{}{"$likes_count", 1}},
						bson.M{"$multiply": []interface{}{"$reposts_count", 3}},
						bson.M{"$multiply": []interface{}{"$replies_count", 2}},
						bson.M{"$multiply": []interface{}{"$views_count", 0.1}},
					},
				},
			},
		},
		{
			"$sort": bson.M{
				"trend_score": -1,
				"created_at":  -1,
			},
		},
	}

	return r.aggregateWithPagination(ctx, pipeline, params)
}

// SearchThreads searches for threads
func (r *threadRepository) SearchThreads(ctx context.Context, query string, currentUserID *primitive.ObjectID, filters *services.SearchFilters, params *utils.PaginationParams) (*utils.PaginationResult, error) {
	matchConditions := bson.M{
		"status": "published",
		"$text":  bson.M{"$search": query},
	}

	// Apply filters
	if filters.Type != "" {
		matchConditions["type"] = filters.Type
	}

	if filters.From != "" {
		// Look up user by username and get their ID
		userCollection := r.database.Collection(constants.UsersCollection)
		var user models.User
		err := userCollection.FindOne(ctx, bson.M{"username": filters.From}).Decode(&user)
		if err == nil {
			matchConditions["author_id"] = user.ID
		}
	}

	if filters.HasMedia {
		matchConditions["media_files"] = bson.M{"$exists": true, "$ne": []interface{}{}}
	}

	if filters.Language != "" {
		matchConditions["language"] = filters.Language
	}

	if filters.SinceDate != "" {
		if sinceTime, err := time.Parse("2006-01-02", filters.SinceDate); err == nil {
			matchConditions["created_at"] = bson.M{"$gte": sinceTime}
		}
	}

	if filters.UntilDate != "" {
		if untilTime, err := time.Parse("2006-01-02", filters.UntilDate); err == nil {
			if existingTimeFilter, exists := matchConditions["created_at"]; exists {
				if timeFilter, ok := existingTimeFilter.(bson.M); ok {
					timeFilter["$lte"] = untilTime
				}
			} else {
				matchConditions["created_at"] = bson.M{"$lte": untilTime}
			}
		}
	}

	pipeline := []bson.M{
		{"$match": matchConditions},
		{"$sort": bson.M{"score": bson.M{"$meta": "textScore"}, "created_at": -1}},
	}

	return r.aggregateWithPagination(ctx, pipeline, params)
}

// GetThreadReplies returns replies to a thread
func (r *threadRepository) GetThreadReplies(ctx context.Context, threadID primitive.ObjectID, currentUserID *primitive.ObjectID, params *utils.PaginationParams) (*utils.PaginationResult, error) {
	pipeline := []bson.M{
		{
			"$match": bson.M{
				"parent_id": threadID,
				"status":    "published",
			},
		},
		{
			"$sort": bson.M{
				"created_at": 1, // Oldest first for replies
			},
		},
	}

	return r.aggregateWithPagination(ctx, pipeline, params)
}

// GetThreadQuotes returns quote threads
func (r *threadRepository) GetThreadQuotes(ctx context.Context, threadID primitive.ObjectID, currentUserID *primitive.ObjectID, params *utils.PaginationParams) (*utils.PaginationResult, error) {
	pipeline := []bson.M{
		{
			"$match": bson.M{
				"quoted_thread_id": threadID,
				"status":           "published",
			},
		},
		{
			"$sort": bson.M{
				"created_at": -1,
			},
		},
	}

	return r.aggregateWithPagination(ctx, pipeline, params)
}

// GetThreadReposts returns users who reposted a thread
func (r *threadRepository) GetThreadReposts(ctx context.Context, threadID primitive.ObjectID, params *utils.PaginationParams) (*utils.PaginationResult, error) {
	repostsCollection := r.database.Collection(constants.RepostsCollection)

	pipeline := []bson.M{
		{
			"$match": bson.M{
				"thread_id": threadID,
			},
		},
		{
			"$lookup": bson.M{
				"from":         constants.UsersCollection,
				"localField":   "user_id",
				"foreignField": "_id",
				"as":           "user",
			},
		},
		{
			"$unwind": "$user",
		},
		{
			"$sort": bson.M{
				"reposted_at": -1,
			},
		},
		{
			"$replaceRoot": bson.M{
				"newRoot": "$user",
			},
		},
	}

	return r.aggregateWithPaginationFromCollection(ctx, repostsCollection, pipeline, params)
}

// GetThreadLikes returns users who liked a thread
func (r *threadRepository) GetThreadLikes(ctx context.Context, threadID primitive.ObjectID, params *utils.PaginationParams) (*utils.PaginationResult, error) {
	likesCollection := r.database.Collection(constants.LikesCollection)

	pipeline := []bson.M{
		{
			"$match": bson.M{
				"thread_id": threadID,
			},
		},
		{
			"$lookup": bson.M{
				"from":         constants.UsersCollection,
				"localField":   "user_id",
				"foreignField": "_id",
				"as":           "user",
			},
		},
		{
			"$unwind": "$user",
		},
		{
			"$sort": bson.M{
				"liked_at": -1,
			},
		},
		{
			"$replaceRoot": bson.M{
				"newRoot": "$user",
			},
		},
	}

	return r.aggregateWithPaginationFromCollection(ctx, likesCollection, pipeline, params)
}

// GetHashtagThreads returns threads with a specific hashtag
func (r *threadRepository) GetHashtagThreads(ctx context.Context, hashtag string, currentUserID *primitive.ObjectID, params *utils.PaginationParams) (*utils.PaginationResult, error) {
	pipeline := []bson.M{
		{
			"$match": bson.M{
				"hashtags":   hashtag,
				"status":     "published",
				"visibility": bson.M{"$in": []string{"public", "followers"}},
			},
		},
		{
			"$sort": bson.M{
				"created_at": -1,
			},
		},
	}

	return r.aggregateWithPagination(ctx, pipeline, params)
}

// GetTrendingHashtags returns trending hashtags
func (r *threadRepository) GetTrendingHashtags(ctx context.Context, timeframe string, limit int) ([]*services.HashtagInfo, error) {
	// Calculate time threshold
	var timeThreshold time.Time
	switch timeframe {
	case "1h":
		timeThreshold = time.Now().Add(-1 * time.Hour)
	case "24h":
		timeThreshold = time.Now().Add(-24 * time.Hour)
	case "7d":
		timeThreshold = time.Now().Add(-7 * 24 * time.Hour)
	default:
		timeThreshold = time.Now().Add(-24 * time.Hour)
	}

	pipeline := []bson.M{
		{
			"$match": bson.M{
				"created_at": bson.M{"$gte": timeThreshold},
				"status":     "published",
				"visibility": "public",
			},
		},
		{
			"$unwind": "$hashtags",
		},
		{
			"$group": bson.M{
				"_id":   "$hashtags",
				"count": bson.M{"$sum": 1},
			},
		},
		{
			"$sort": bson.M{
				"count": -1,
			},
		},
		{
			"$limit": limit,
		},
	}

	cursor, err := r.threadsCollection.Aggregate(ctx, pipeline)
	if err != nil {
		r.logger.WithError(err).Error("Failed to get trending hashtags")
		return nil, err
	}
	defer cursor.Close(ctx)

	var results []bson.M
	if err := cursor.All(ctx, &results); err != nil {
		return nil, err
	}

	var hashtags []*services.HashtagInfo
	for _, result := range results {
		hashtag := &services.HashtagInfo{
			Hashtag: result["_id"].(string),
			Count:   result["count"].(int64),
			Trend:   "stable", // In a real implementation, you'd calculate the trend
		}
		hashtags = append(hashtags, hashtag)
	}

	return hashtags, nil
}

// GetMentionThreads returns threads mentioning a user
func (r *threadRepository) GetMentionThreads(ctx context.Context, username string, currentUserID *primitive.ObjectID, params *utils.PaginationParams) (*utils.PaginationResult, error) {
	pipeline := []bson.M{
		{
			"$match": bson.M{
				"mentions": username,
				"status":   "published",
			},
		},
		{
			"$sort": bson.M{
				"created_at": -1,
			},
		},
	}

	return r.aggregateWithPagination(ctx, pipeline, params)
}

// GetListFeed returns threads from users in a list
func (r *threadRepository) GetListFeed(ctx context.Context, listID primitive.ObjectID, currentUserID *primitive.ObjectID, params *utils.PaginationParams) (*utils.PaginationResult, error) {
	pipeline := []bson.M{
		{
			"$lookup": bson.M{
				"from":         constants.ListMembersCollection,
				"localField":   "author_id",
				"foreignField": "user_id",
				"as":           "list_membership",
			},
		},
		{
			"$match": bson.M{
				"list_membership.list_id": listID,
				"status":                  "published",
			},
		},
		{
			"$sort": bson.M{
				"created_at": -1,
			},
		},
	}

	return r.aggregateWithPagination(ctx, pipeline, params)
}

// Thread moderation methods
func (r *threadRepository) PinThread(ctx context.Context, threadID, userID primitive.ObjectID) error {
	// First unpin any currently pinned thread by this user
	_, err := r.threadsCollection.UpdateMany(ctx,
		bson.M{"author_id": userID, "is_pinned": true},
		bson.M{"$set": bson.M{"is_pinned": false, "updated_at": time.Now()}})
	if err != nil {
		return err
	}

	// Pin the specified thread
	filter := bson.M{"_id": threadID, "author_id": userID}
	update := bson.M{"$set": bson.M{"is_pinned": true, "updated_at": time.Now()}}

	result, err := r.threadsCollection.UpdateOne(ctx, filter, update)
	if err != nil {
		return err
	}

	if result.MatchedCount == 0 {
		return errors.New("thread not found or not owned by user")
	}

	return nil
}

func (r *threadRepository) UnpinThread(ctx context.Context, threadID, userID primitive.ObjectID) error {
	filter := bson.M{"_id": threadID, "author_id": userID}
	update := bson.M{"$set": bson.M{"is_pinned": false, "updated_at": time.Now()}}

	result, err := r.threadsCollection.UpdateOne(ctx, filter, update)
	if err != nil {
		return err
	}

	if result.MatchedCount == 0 {
		return errors.New("thread not found or not owned by user")
	}

	return nil
}

func (r *threadRepository) HideThread(ctx context.Context, threadID, userID primitive.ObjectID) error {
	// This would typically be stored in a user_hidden_threads collection
	// For now, we'll just add the user to a hidden_by array in the thread
	filter := bson.M{"_id": threadID}
	update := bson.M{
		"$addToSet": bson.M{"hidden_by": userID},
		"$set":      bson.M{"updated_at": time.Now()},
	}

	_, err := r.threadsCollection.UpdateOne(ctx, filter, update)
	return err
}

func (r *threadRepository) UnhideThread(ctx context.Context, threadID, userID primitive.ObjectID) error {
	filter := bson.M{"_id": threadID}
	update := bson.M{
		"$pull": bson.M{"hidden_by": userID},
		"$set":  bson.M{"updated_at": time.Now()},
	}

	_, err := r.threadsCollection.UpdateOne(ctx, filter, update)
	return err
}

func (r *threadRepository) UpdateVisibility(ctx context.Context, threadID primitive.ObjectID, visibility string) error {
	filter := bson.M{"_id": threadID}
	update := bson.M{"$set": bson.M{"visibility": visibility, "updated_at": time.Now()}}

	result, err := r.threadsCollection.UpdateOne(ctx, filter, update)
	if err != nil {
		return err
	}

	if result.MatchedCount == 0 {
		return errors.New("thread not found")
	}

	return nil
}

func (r *threadRepository) UpdateReplySettings(ctx context.Context, threadID primitive.ObjectID, replySettings string) error {
	filter := bson.M{"_id": threadID}
	update := bson.M{"$set": bson.M{"reply_settings": replySettings, "updated_at": time.Now()}}

	result, err := r.threadsCollection.UpdateOne(ctx, filter, update)
	if err != nil {
		return err
	}

	if result.MatchedCount == 0 {
		return errors.New("thread not found")
	}

	return nil
}

// Scheduled threads and drafts
func (r *threadRepository) GetScheduledThreads(ctx context.Context, userID primitive.ObjectID, params *utils.PaginationParams) (*utils.PaginationResult, error) {
	pipeline := []bson.M{
		{
			"$match": bson.M{
				"author_id":    userID,
				"status":       "scheduled",
				"is_scheduled": true,
			},
		},
		{
			"$sort": bson.M{
				"scheduled_at": 1,
			},
		},
	}

	return r.aggregateWithPagination(ctx, pipeline, params)
}

func (r *threadRepository) GetDrafts(ctx context.Context, userID primitive.ObjectID, params *utils.PaginationParams) (*utils.PaginationResult, error) {
	pipeline := []bson.M{
		{
			"$match": bson.M{
				"author_id": userID,
				"status":    "draft",
			},
		},
		{
			"$sort": bson.M{
				"updated_at": -1,
			},
		},
	}

	return r.aggregateWithPagination(ctx, pipeline, params)
}

// Analytics methods
func (r *threadRepository) GetThreadAnalytics(ctx context.Context, threadID primitive.ObjectID) (*services.ThreadAnalytics, error) {
	thread, err := r.GetByID(ctx, threadID)
	if err != nil {
		return nil, err
	}

	// Get views from thread_views collection
	viewsCount, err := r.threadViewsCollection.CountDocuments(ctx, bson.M{"thread_id": threadID})
	if err != nil {
		viewsCount = 0
	}

	// Calculate engagement rate
	totalEngagement := thread.LikesCount + thread.RepostsCount + thread.RepliesCount
	engagementRate := 0.0
	if viewsCount > 0 {
		engagementRate = float64(totalEngagement) / float64(viewsCount) * 100
	}

	analytics := &services.ThreadAnalytics{
		ThreadID:       threadID,
		Views:          viewsCount,
		Likes:          thread.LikesCount,
		Reposts:        thread.RepostsCount,
		Replies:        thread.RepliesCount,
		Quotes:         thread.QuotesCount,
		Shares:         thread.SharesCount,
		Bookmarks:      thread.BookmarksCount,
		EngagementRate: engagementRate,
		ReachEstimate:  viewsCount * 2, // Simple estimation
		ViewsByHour:    make(map[string]int64),
		TopCountries:   make(map[string]int64),
		Demographics:   make(map[string]int64),
	}

	return analytics, nil
}

func (r *threadRepository) GetUserThreadAnalytics(ctx context.Context, userID primitive.ObjectID, timeframe string) (*services.UserThreadAnalytics, error) {
	// Calculate time threshold
	var timeThreshold time.Time
	switch timeframe {
	case "7d":
		timeThreshold = time.Now().Add(-7 * 24 * time.Hour)
	case "30d":
		timeThreshold = time.Now().Add(-30 * 24 * time.Hour)
	case "90d":
		timeThreshold = time.Now().Add(-90 * 24 * time.Hour)
	default:
		timeThreshold = time.Now().Add(-30 * 24 * time.Hour)
	}

	// Aggregate user's thread statistics
	pipeline := []bson.M{
		{
			"$match": bson.M{
				"author_id":  userID,
				"status":     "published",
				"created_at": bson.M{"$gte": timeThreshold},
			},
		},
		{
			"$group": bson.M{
				"_id":           nil,
				"total_threads": bson.M{"$sum": 1},
				"total_views":   bson.M{"$sum": "$views_count"},
				"total_likes":   bson.M{"$sum": "$likes_count"},
				"total_reposts": bson.M{"$sum": "$reposts_count"},
				"total_replies": bson.M{"$sum": "$replies_count"},
			},
		},
	}

	cursor, err := r.threadsCollection.Aggregate(ctx, pipeline)
	if err != nil {
		return nil, err
	}
	defer cursor.Close(ctx)

	var result bson.M
	if cursor.Next(ctx) {
		cursor.Decode(&result)
	}

	if result == nil {
		result = bson.M{
			"total_threads": int64(0),
			"total_views":   int64(0),
			"total_likes":   int64(0),
			"total_reposts": int64(0),
			"total_replies": int64(0),
		}
	}

	totalThreads := result["total_threads"].(int64)
	totalViews := result["total_views"].(int64)
	totalLikes := result["total_likes"].(int64)
	totalReposts := result["total_reposts"].(int64)
	totalReplies := result["total_replies"].(int64)

	// Calculate average engagement
	avgEngagement := 0.0
	if totalThreads > 0 {
		avgEngagement = float64(totalLikes+totalReposts+totalReplies) / float64(totalThreads)
	}

	analytics := &services.UserThreadAnalytics{
		UserID:           userID,
		TotalThreads:     totalThreads,
		TotalViews:       totalViews,
		TotalLikes:       totalLikes,
		TotalReposts:     totalReposts,
		TotalReplies:     totalReplies,
		AvgEngagement:    avgEngagement,
		TopPerforming:    []*models.Thread{},
		EngagementTrend:  make(map[string]int64),
		PostingFrequency: make(map[string]int64),
	}

	return analytics, nil
}

// Admin operations
func (r *threadRepository) GetAllThreads(ctx context.Context, params *utils.PaginationParams, filter string) (*utils.PaginationResult, error) {
	matchFilter := bson.M{}

	switch filter {
	case "published":
		matchFilter["status"] = "published"
	case "deleted":
		matchFilter["status"] = "deleted"
	case "scheduled":
		matchFilter["status"] = "scheduled"
	case "draft":
		matchFilter["status"] = "draft"
	case "reported":
		matchFilter["is_reported"] = true
	case "flagged":
		matchFilter["is_flagged"] = true
	}

	pipeline := []bson.M{
		{"$match": matchFilter},
		{"$sort": bson.M{"created_at": -1}},
	}

	return r.aggregateWithPagination(ctx, pipeline, params)
}

func (r *threadRepository) GetReportedThreads(ctx context.Context, params *utils.PaginationParams) (*utils.PaginationResult, error) {
	pipeline := []bson.M{
		{
			"$lookup": bson.M{
				"from":         constants.ReportsCollection,
				"localField":   "_id",
				"foreignField": "target_id",
				"as":           "reports",
			},
		},
		{
			"$match": bson.M{
				"reports": bson.M{"$ne": []interface{}{}},
			},
		},
		{
			"$addFields": bson.M{
				"reports_count": bson.M{"$size": "$reports"},
			},
		},
		{
			"$sort": bson.M{
				"reports_count": -1,
				"created_at":    -1,
			},
		},
	}

	return r.aggregateWithPagination(ctx, pipeline, params)
}

func (r *threadRepository) GetFlaggedThreads(ctx context.Context, params *utils.PaginationParams) (*utils.PaginationResult, error) {
	pipeline := []bson.M{
		{
			"$match": bson.M{
				"is_flagged": true,
			},
		},
		{
			"$sort": bson.M{
				"flagged_at": -1,
			},
		},
	}

	return r.aggregateWithPagination(ctx, pipeline, params)
}

func (r *threadRepository) GetThreadReports(ctx context.Context, threadID primitive.ObjectID, params *utils.PaginationParams) (*utils.PaginationResult, error) {
	pipeline := []bson.M{
		{
			"$match": bson.M{
				"target_id":   threadID,
				"target_type": "thread",
			},
		},
		{
			"$lookup": bson.M{
				"from":         constants.UsersCollection,
				"localField":   "reporter_id",
				"foreignField": "_id",
				"as":           "reporter",
			},
		},
		{
			"$unwind": "$reporter",
		},
		{
			"$sort": bson.M{
				"created_at": -1,
			},
		},
	}

	return r.aggregateWithPaginationFromCollection(ctx, r.reportsCollection, pipeline, params)
}

func (r *threadRepository) ModerateThread(ctx context.Context, threadID, adminID primitive.ObjectID, action, reason string) error {
	// Record moderation action
	moderationAction := bson.M{
		"_id":       primitive.NewObjectID(),
		"admin_id":  adminID,
		"target_id": threadID,
		"action":    action,
		"reason":    reason,
		"timestamp": time.Now(),
	}

	_, err := r.moderationActionsCollection.InsertOne(ctx, moderationAction)
	if err != nil {
		return err
	}

	// Apply the moderation action
	update := bson.M{"$set": bson.M{"updated_at": time.Now()}}

	switch action {
	case "approve":
		update["$set"].(bson.M)["is_flagged"] = false
	case "remove":
		update["$set"].(bson.M)["status"] = "removed"
	case "flag":
		update["$set"].(bson.M)["is_flagged"] = true
	case "warn":
		update["$set"].(bson.M)["has_warning"] = true
	}

	_, err = r.threadsCollection.UpdateOne(ctx, bson.M{"_id": threadID}, update)
	return err
}

func (r *threadRepository) FeatureThread(ctx context.Context, threadID, adminID primitive.ObjectID) error {
	filter := bson.M{"_id": threadID}
	update := bson.M{
		"$set": bson.M{
			"is_featured": true,
			"featured_by": adminID,
			"featured_at": time.Now(),
			"updated_at":  time.Now(),
		},
	}

	_, err := r.threadsCollection.UpdateOne(ctx, filter, update)
	return err
}

func (r *threadRepository) UnfeatureThread(ctx context.Context, threadID, adminID primitive.ObjectID) error {
	filter := bson.M{"_id": threadID}
	update := bson.M{
		"$set": bson.M{
			"is_featured": false,
			"updated_at":  time.Now(),
		},
		"$unset": bson.M{
			"featured_by": "",
			"featured_at": "",
		},
	}

	_, err := r.threadsCollection.UpdateOne(ctx, filter, update)
	return err
}

func (r *threadRepository) LockThread(ctx context.Context, threadID, adminID primitive.ObjectID, reason string) error {
	filter := bson.M{"_id": threadID}
	update := bson.M{
		"$set": bson.M{
			"is_locked":   true,
			"locked_by":   adminID,
			"locked_at":   time.Now(),
			"lock_reason": reason,
			"updated_at":  time.Now(),
		},
	}

	_, err := r.threadsCollection.UpdateOne(ctx, filter, update)
	return err
}

func (r *threadRepository) UnlockThread(ctx context.Context, threadID, adminID primitive.ObjectID) error {
	filter := bson.M{"_id": threadID}
	update := bson.M{
		"$set": bson.M{
			"is_locked":  false,
			"updated_at": time.Now(),
		},
		"$unset": bson.M{
			"locked_by":   "",
			"locked_at":   "",
			"lock_reason": "",
		},
	}

	_, err := r.threadsCollection.UpdateOne(ctx, filter, update)
	return err
}

func (r *threadRepository) AdminDeleteThread(ctx context.Context, threadID, adminID primitive.ObjectID, reason string) error {
	filter := bson.M{"_id": threadID}
	update := bson.M{
		"$set": bson.M{
			"status":          "admin_deleted",
			"deleted_by":      adminID,
			"deleted_at":      time.Now(),
			"deletion_reason": reason,
			"updated_at":      time.Now(),
		},
	}

	_, err := r.threadsCollection.UpdateOne(ctx, filter, update)
	return err
}

func (r *threadRepository) AdminRestoreThread(ctx context.Context, threadID, adminID primitive.ObjectID, reason string) (*models.Thread, error) {
	filter := bson.M{"_id": threadID}
	update := bson.M{
		"$set": bson.M{
			"status":             "published",
			"restored_by":        adminID,
			"restored_at":        time.Now(),
			"restoration_reason": reason,
			"updated_at":         time.Now(),
		},
		"$unset": bson.M{
			"deleted_by":      "",
			"deleted_at":      "",
			"deletion_reason": "",
		},
	}

	_, err := r.threadsCollection.UpdateOne(ctx, filter, update)
	if err != nil {
		return nil, err
	}

	return r.GetByID(ctx, threadID)
}

// Utility methods
func (r *threadRepository) IncrementLikesCount(ctx context.Context, threadID primitive.ObjectID, delta int) error {
	filter := bson.M{"_id": threadID}
	update := bson.M{
		"$inc": bson.M{"likes_count": delta},
		"$set": bson.M{"updated_at": time.Now()},
	}

	_, err := r.threadsCollection.UpdateOne(ctx, filter, update)
	return err
}

func (r *threadRepository) IncrementRepliesCount(ctx context.Context, threadID primitive.ObjectID, delta int) error {
	filter := bson.M{"_id": threadID}
	update := bson.M{
		"$inc": bson.M{"replies_count": delta},
		"$set": bson.M{"updated_at": time.Now()},
	}

	_, err := r.threadsCollection.UpdateOne(ctx, filter, update)
	return err
}

func (r *threadRepository) IncrementRepostsCount(ctx context.Context, threadID primitive.ObjectID, delta int) error {
	filter := bson.M{"_id": threadID}
	update := bson.M{
		"$inc": bson.M{"reposts_count": delta},
		"$set": bson.M{"updated_at": time.Now()},
	}

	_, err := r.threadsCollection.UpdateOne(ctx, filter, update)
	return err
}

func (r *threadRepository) IncrementQuotesCount(ctx context.Context, threadID primitive.ObjectID, delta int) error {
	filter := bson.M{"_id": threadID}
	update := bson.M{
		"$inc": bson.M{"quotes_count": delta},
		"$set": bson.M{"updated_at": time.Now()},
	}

	_, err := r.threadsCollection.UpdateOne(ctx, filter, update)
	return err
}

func (r *threadRepository) IncrementViewsCount(ctx context.Context, threadID primitive.ObjectID, delta int) error {
	filter := bson.M{"_id": threadID}
	update := bson.M{
		"$inc": bson.M{"views_count": delta},
		"$set": bson.M{"updated_at": time.Now()},
	}

	_, err := r.threadsCollection.UpdateOne(ctx, filter, update)
	return err
}

func (r *threadRepository) IncrementSharesCount(ctx context.Context, threadID primitive.ObjectID, delta int) error {
	filter := bson.M{"_id": threadID}
	update := bson.M{
		"$inc": bson.M{"shares_count": delta},
		"$set": bson.M{"updated_at": time.Now()},
	}

	_, err := r.threadsCollection.UpdateOne(ctx, filter, update)
	return err
}

func (r *threadRepository) IncrementBookmarksCount(ctx context.Context, threadID primitive.ObjectID, delta int) error {
	filter := bson.M{"_id": threadID}
	update := bson.M{
		"$inc": bson.M{"bookmarks_count": delta},
		"$set": bson.M{"updated_at": time.Now()},
	}

	_, err := r.threadsCollection.UpdateOne(ctx, filter, update)
	return err
}

// Batch operations
func (r *threadRepository) GetThreadsByIDs(ctx context.Context, threadIDs []primitive.ObjectID) ([]*models.Thread, error) {
	filter := bson.M{"_id": bson.M{"$in": threadIDs}}
	cursor, err := r.threadsCollection.Find(ctx, filter)
	if err != nil {
		return nil, err
	}
	defer cursor.Close(ctx)

	var threads []*models.Thread
	if err := cursor.All(ctx, &threads); err != nil {
		return nil, err
	}

	return threads, nil
}

func (r *threadRepository) GetThreadsByUserID(ctx context.Context, userID primitive.ObjectID, params *utils.PaginationParams) (*utils.PaginationResult, error) {
	pipeline := []bson.M{
		{
			"$match": bson.M{
				"author_id": userID,
				"status":    "published",
			},
		},
		{
			"$sort": bson.M{
				"created_at": -1,
			},
		},
	}

	return r.aggregateWithPagination(ctx, pipeline, params)
}

// Helper methods
func (r *threadRepository) aggregateWithPagination(ctx context.Context, pipeline []bson.M, params *utils.PaginationParams) (*utils.PaginationResult, error) {
	return r.aggregateWithPaginationFromCollection(ctx, r.threadsCollection, pipeline, params)
}

func (r *threadRepository) aggregateWithPaginationFromCollection(ctx context.Context, collection *mongo.Collection, pipeline []bson.M, params *utils.PaginationParams) (*utils.PaginationResult, error) {
	// Count total documents
	countPipeline := append(pipeline, bson.M{"$count": "total"})
	countCursor, err := collection.Aggregate(ctx, countPipeline)
	if err != nil {
		r.logger.WithError(err).Error("Failed to count documents")
		return nil, err
	}
	defer countCursor.Close(ctx)

	var countResult []bson.M
	if err := countCursor.All(ctx, &countResult); err != nil {
		return nil, err
	}

	var total int64
	if len(countResult) > 0 {
		if count, ok := countResult[0]["total"].(int32); ok {
			total = int64(count)
		}
	}

	// Add pagination to pipeline
	skip := (params.Page - 1) * params.Limit
	pipeline = append(pipeline,
		bson.M{"$skip": skip},
		bson.M{"$limit": params.Limit},
	)

	cursor, err := collection.Aggregate(ctx, pipeline)
	if err != nil {
		r.logger.WithError(err).Error("Failed to aggregate documents")
		return nil, err
	}
	defer cursor.Close(ctx)

	var threads []*models.Thread
	if err := cursor.All(ctx, &threads); err != nil {
		r.logger.WithError(err).Error("Failed to decode documents")
		return nil, err
	}

	return &utils.PaginationResult{
		Data:       threads,
		Pagination: utils.CalculatePaginationMeta(params.Page, params.Limit, total),
	}, nil
}
