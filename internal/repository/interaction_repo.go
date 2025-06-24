package repository

import (
	"context"
	"time"

	"errors"

	"go.mongodb.org/mongo-driver/bson/primitive"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"

	"onthread/internal/models"
	"onthread/internal/utils"
	"onthread/pkg/constants"
	"onthread/pkg/logger"
)

// InteractionRepository interface defines all interaction-related database operations
type InteractionRepository interface {
	// Like operations
	CreateLike(ctx context.Context, like *models.Like) error
	DeleteLike(ctx context.Context, userID, threadID primitive.ObjectID) error
	HasLiked(ctx context.Context, userID, threadID primitive.ObjectID) (bool, error)
	GetLikesByUser(ctx context.Context, userID primitive.ObjectID, params *utils.PaginationParams) (*utils.PaginationResult, error)
	GetLikesByThread(ctx context.Context, threadID primitive.ObjectID, params *utils.PaginationParams) (*utils.PaginationResult, error)

	// Repost operations
	CreateRepost(ctx context.Context, repost *models.Repost) error
	DeleteRepost(ctx context.Context, userID, threadID primitive.ObjectID) error
	HasReposted(ctx context.Context, userID, threadID primitive.ObjectID) (bool, error)
	GetRepostsByUser(ctx context.Context, userID primitive.ObjectID, params *utils.PaginationParams) (*utils.PaginationResult, error)
	GetRepostsByThread(ctx context.Context, threadID primitive.ObjectID, params *utils.PaginationParams) (*utils.PaginationResult, error)

	// Bookmark operations
	CreateBookmark(ctx context.Context, bookmark *models.Bookmark) error
	DeleteBookmark(ctx context.Context, userID, threadID primitive.ObjectID) error
	HasBookmarked(ctx context.Context, userID, threadID primitive.ObjectID) (bool, error)
	GetBookmarks(ctx context.Context, userID primitive.ObjectID, folderID *primitive.ObjectID, params *utils.PaginationParams) (*utils.PaginationResult, error)
	UpdateBookmark(ctx context.Context, userID, threadID primitive.ObjectID, req *UpdateBookmarkRequest) (*models.Bookmark, error)
	MoveBookmark(ctx context.Context, userID primitive.ObjectID, bookmarkID primitive.ObjectID, folderID *primitive.ObjectID) error

	// Bookmark folder operations
	CreateBookmarkFolder(ctx context.Context, folder *models.BookmarkFolder) error
	UpdateBookmarkFolder(ctx context.Context, folderID, userID primitive.ObjectID, req *UpdateBookmarkFolderRequest) (*models.BookmarkFolder, error)
	DeleteBookmarkFolder(ctx context.Context, folderID, userID primitive.ObjectID) error
	GetBookmarkFolders(ctx context.Context, userID primitive.ObjectID, params *utils.PaginationParams) (*utils.PaginationResult, error)
	HasBookmarkFolder(ctx context.Context, userID, folderID primitive.ObjectID) (bool, error)

	// Share operations
	CreateShare(ctx context.Context, share *models.Share) error
	GetSharesByThread(ctx context.Context, threadID primitive.ObjectID, params *utils.PaginationParams) (*utils.PaginationResult, error)

	// Report operations
	CreateReport(ctx context.Context, report *models.Report) error
	GetReportsByThread(ctx context.Context, threadID primitive.ObjectID, params *utils.PaginationParams) (*utils.PaginationResult, error)
	GetReportsByUser(ctx context.Context, userID primitive.ObjectID, params *utils.PaginationParams) (*utils.PaginationResult, error)
	UpdateReportStatus(ctx context.Context, reportID primitive.ObjectID, status, resolution string) error

	// Poll operations
	CreatePollVote(ctx context.Context, vote *models.PollVote) error
	DeletePollVote(ctx context.Context, userID, pollID primitive.ObjectID) error
	HasVotedInPoll(ctx context.Context, userID, pollID primitive.ObjectID) (bool, error)
	GetPollVotes(ctx context.Context, pollID primitive.ObjectID, params *utils.PaginationParams) (*utils.PaginationResult, error)
	UpdatePollVoteCounts(ctx context.Context, pollID primitive.ObjectID, optionID primitive.ObjectID, delta int) error

	// View operations
	RecordThreadView(ctx context.Context, view *models.ThreadView) error
	GetViewsByThread(ctx context.Context, threadID primitive.ObjectID, params *utils.PaginationParams) (*utils.PaginationResult, error)
	GetViewsByUser(ctx context.Context, userID primitive.ObjectID, params *utils.PaginationParams) (*utils.PaginationResult, error)
}

// Request/Response structs for repository operations
type UpdateBookmarkRequest struct {
	Notes    string              `json:"notes"`
	FolderID *primitive.ObjectID `json:"folder_id"`
}

type UpdateBookmarkFolderRequest struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	Color       string `json:"color"`
	Icon        string `json:"icon"`
	IsPrivate   *bool  `json:"is_private"`
}

// InteractionModels represents models used in interactions
// These models should match the ones defined in models package

// Like represents a thread like
type Like struct {
	ID       primitive.ObjectID `bson:"_id,omitempty" json:"id"`
	UserID   primitive.ObjectID `bson:"user_id" json:"user_id"`
	ThreadID primitive.ObjectID `bson:"thread_id" json:"thread_id"`
	LikedAt  time.Time          `bson:"liked_at" json:"liked_at"`
}

// Repost represents a thread repost
type Repost struct {
	ID         primitive.ObjectID `bson:"_id,omitempty" json:"id"`
	UserID     primitive.ObjectID `bson:"user_id" json:"user_id"`
	ThreadID   primitive.ObjectID `bson:"thread_id" json:"thread_id"`
	Comment    string             `bson:"comment,omitempty" json:"comment,omitempty"`
	RepostedAt time.Time          `bson:"reposted_at" json:"reposted_at"`
}

// Bookmark represents a thread bookmark
type Bookmark struct {
	ID        primitive.ObjectID  `bson:"_id,omitempty" json:"id"`
	UserID    primitive.ObjectID  `bson:"user_id" json:"user_id"`
	ThreadID  primitive.ObjectID  `bson:"thread_id" json:"thread_id"`
	FolderID  *primitive.ObjectID `bson:"folder_id,omitempty" json:"folder_id,omitempty"`
	Notes     string              `bson:"notes,omitempty" json:"notes,omitempty"`
	CreatedAt time.Time           `bson:"created_at" json:"created_at"`
	UpdatedAt time.Time           `bson:"updated_at" json:"updated_at"`
}

// BookmarkFolder represents a bookmark folder
type BookmarkFolder struct {
	ID          primitive.ObjectID `bson:"_id,omitempty" json:"id"`
	UserID      primitive.ObjectID `bson:"user_id" json:"user_id"`
	Name        string             `bson:"name" json:"name"`
	Description string             `bson:"description,omitempty" json:"description,omitempty"`
	Color       string             `bson:"color,omitempty" json:"color,omitempty"`
	Icon        string             `bson:"icon,omitempty" json:"icon,omitempty"`
	IsPrivate   bool               `bson:"is_private" json:"is_private"`
	ItemsCount  int64              `bson:"items_count" json:"items_count"`
	CreatedAt   time.Time          `bson:"created_at" json:"created_at"`
	UpdatedAt   time.Time          `bson:"updated_at" json:"updated_at"`
}

// Share represents a thread share
type Share struct {
	ID       primitive.ObjectID `bson:"_id,omitempty" json:"id"`
	UserID   primitive.ObjectID `bson:"user_id" json:"user_id"`
	ThreadID primitive.ObjectID `bson:"thread_id" json:"thread_id"`
	Platform string             `bson:"platform" json:"platform"` // "twitter", "facebook", "email", etc.
	SharedAt time.Time          `bson:"shared_at" json:"shared_at"`
}

// Report represents a content report
type Report struct {
	ID          primitive.ObjectID  `bson:"_id,omitempty" json:"id"`
	ReporterID  primitive.ObjectID  `bson:"reporter_id" json:"reporter_id"`
	TargetType  string              `bson:"target_type" json:"target_type"` // "thread", "user", "message"
	TargetID    *primitive.ObjectID `bson:"target_id,omitempty" json:"target_id,omitempty"`
	ThreadID    *primitive.ObjectID `bson:"thread_id,omitempty" json:"thread_id,omitempty"`
	UserID      *primitive.ObjectID `bson:"user_id,omitempty" json:"user_id,omitempty"`
	ReportType  string              `bson:"report_type" json:"report_type"`
	Category    string              `bson:"category" json:"category"`
	Description string              `bson:"description" json:"description"`
	Evidence    []map[string]string `bson:"evidence,omitempty" json:"evidence,omitempty"`
	Status      string              `bson:"status" json:"status"`     // "pending", "reviewed", "resolved", "dismissed"
	Priority    string              `bson:"priority" json:"priority"` // "low", "medium", "high", "urgent"
	Resolution  string              `bson:"resolution,omitempty" json:"resolution,omitempty"`
	ReviewerID  *primitive.ObjectID `bson:"reviewer_id,omitempty" json:"reviewer_id,omitempty"`
	ReviewedAt  *time.Time          `bson:"reviewed_at,omitempty" json:"reviewed_at,omitempty"`
	CreatedAt   time.Time           `bson:"created_at" json:"created_at"`
	UpdatedAt   time.Time           `bson:"updated_at" json:"updated_at"`
}

// PollVote represents a vote in a poll
type PollVote struct {
	ID       primitive.ObjectID   `bson:"_id,omitempty" json:"id"`
	PollID   primitive.ObjectID   `bson:"poll_id" json:"poll_id"`
	UserID   primitive.ObjectID   `bson:"user_id" json:"user_id"`
	ThreadID primitive.ObjectID   `bson:"thread_id" json:"thread_id"`
	Options  []primitive.ObjectID `bson:"options" json:"options"`
	VotedAt  time.Time            `bson:"voted_at" json:"voted_at"`
}

// ThreadView represents a thread view record
type ThreadView struct {
	ID       primitive.ObjectID `bson:"_id,omitempty" json:"id"`
	ThreadID primitive.ObjectID `bson:"thread_id" json:"thread_id"`
	UserID   primitive.ObjectID `bson:"user_id" json:"user_id"`
	ViewedAt time.Time          `bson:"viewed_at" json:"viewed_at"`
	Duration int64              `bson:"duration" json:"duration"` // milliseconds
	Source   string             `bson:"source" json:"source"`     // "timeline", "profile", "search", "direct"
}

// interactionRepository implements InteractionRepository interface
type interactionRepository struct {
	database                  *mongo.Database
	likesCollection           *mongo.Collection
	repostsCollection         *mongo.Collection
	bookmarksCollection       *mongo.Collection
	bookmarkFoldersCollection *mongo.Collection
	sharesCollection          *mongo.Collection
	reportsCollection         *mongo.Collection
	pollVotesCollection       *mongo.Collection
	threadViewsCollection     *mongo.Collection
	logger                    *logger.Logger
}

// NewInteractionRepository creates a new interaction repository
func NewInteractionRepository(database *mongo.Database) InteractionRepository {
	return &interactionRepository{
		database:                  database,
		likesCollection:           database.Collection(constants.LikesCollection),
		repostsCollection:         database.Collection(constants.RepostsCollection),
		bookmarksCollection:       database.Collection(constants.BookmarksCollection),
		bookmarkFoldersCollection: database.Collection(constants.BookmarkFoldersCollection),
		sharesCollection:          database.Collection(constants.SharesCollection),
		reportsCollection:         database.Collection(constants.ReportsCollection),
		pollVotesCollection:       database.Collection(constants.PollVotesCollection),
		threadViewsCollection:     database.Collection(constants.ThreadViewsCollection),
		logger:                    logger.NewComponentLogger("InteractionRepository"),
	}
}

// Like operations
func (r *interactionRepository) CreateLike(ctx context.Context, like *models.Like) error {
	if like.ID.IsZero() {
		like.ID = primitive.NewObjectID()
	}

	_, err := r.likesCollection.InsertOne(ctx, like)
	if err != nil {
		if mongo.IsDuplicateKeyError(err) {
			return errors.New("thread already liked")
		}
		r.logger.WithError(err).Error("Failed to create like")
		return err
	}

	r.logger.WithFields(map[string]interface{}{
		"like_id":   like.ID,
		"user_id":   like.UserID,
		"thread_id": like.ThreadID,
	}).Info("Like created successfully")

	return nil
}

func (r *interactionRepository) DeleteLike(ctx context.Context, userID, threadID primitive.ObjectID) error {
	filter := bson.M{
		"user_id":   userID,
		"thread_id": threadID,
	}

	result, err := r.likesCollection.DeleteOne(ctx, filter)
	if err != nil {
		r.logger.WithError(err).Error("Failed to delete like")
		return err
	}

	if result.DeletedCount == 0 {
		return errors.New("like not found")
	}

	r.logger.WithFields(map[string]interface{}{
		"user_id":   userID,
		"thread_id": threadID,
	}).Info("Like deleted successfully")

	return nil
}

func (r *interactionRepository) HasLiked(ctx context.Context, userID, threadID primitive.ObjectID) (bool, error) {
	filter := bson.M{
		"user_id":   userID,
		"thread_id": threadID,
	}

	count, err := r.likesCollection.CountDocuments(ctx, filter)
	if err != nil {
		r.logger.WithError(err).Error("Failed to check like status")
		return false, err
	}

	return count > 0, nil
}

func (r *interactionRepository) GetLikesByUser(ctx context.Context, userID primitive.ObjectID, params *utils.PaginationParams) (*utils.PaginationResult, error) {
	pipeline := []bson.M{
		{
			"$match": bson.M{
				"user_id": userID,
			},
		},
		{
			"$lookup": bson.M{
				"from":         constants.ThreadsCollection,
				"localField":   "thread_id",
				"foreignField": "_id",
				"as":           "thread",
			},
		},
		{
			"$unwind": "$thread",
		},
		{
			"$sort": bson.M{
				"liked_at": -1,
			},
		},
		{
			"$replaceRoot": bson.M{
				"newRoot": "$thread",
			},
		},
	}

	return r.aggregateWithPagination(ctx, r.likesCollection, pipeline, params)
}

func (r *interactionRepository) GetLikesByThread(ctx context.Context, threadID primitive.ObjectID, params *utils.PaginationParams) (*utils.PaginationResult, error) {
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

	return r.aggregateWithPagination(ctx, r.likesCollection, pipeline, params)
}

// Repost operations
func (r *interactionRepository) CreateRepost(ctx context.Context, repost *models.Repost) error {
	if repost.ID.IsZero() {
		repost.ID = primitive.NewObjectID()
	}

	_, err := r.repostsCollection.InsertOne(ctx, repost)
	if err != nil {
		if mongo.IsDuplicateKeyError(err) {
			return errors.New("thread already reposted")
		}
		r.logger.WithError(err).Error("Failed to create repost")
		return err
	}

	r.logger.WithFields(map[string]interface{}{
		"repost_id": repost.ID,
		"user_id":   repost.UserID,
		"thread_id": repost.ThreadID,
	}).Info("Repost created successfully")

	return nil
}

func (r *interactionRepository) DeleteRepost(ctx context.Context, userID, threadID primitive.ObjectID) error {
	filter := bson.M{
		"user_id":   userID,
		"thread_id": threadID,
	}

	result, err := r.repostsCollection.DeleteOne(ctx, filter)
	if err != nil {
		r.logger.WithError(err).Error("Failed to delete repost")
		return err
	}

	if result.DeletedCount == 0 {
		return errors.New("repost not found")
	}

	r.logger.WithFields(map[string]interface{}{
		"user_id":   userID,
		"thread_id": threadID,
	}).Info("Repost deleted successfully")

	return nil
}

func (r *interactionRepository) HasReposted(ctx context.Context, userID, threadID primitive.ObjectID) (bool, error) {
	filter := bson.M{
		"user_id":   userID,
		"thread_id": threadID,
	}

	count, err := r.repostsCollection.CountDocuments(ctx, filter)
	if err != nil {
		r.logger.WithError(err).Error("Failed to check repost status")
		return false, err
	}

	return count > 0, nil
}

func (r *interactionRepository) GetRepostsByUser(ctx context.Context, userID primitive.ObjectID, params *utils.PaginationParams) (*utils.PaginationResult, error) {
	pipeline := []bson.M{
		{
			"$match": bson.M{
				"user_id": userID,
			},
		},
		{
			"$lookup": bson.M{
				"from":         constants.ThreadsCollection,
				"localField":   "thread_id",
				"foreignField": "_id",
				"as":           "thread",
			},
		},
		{
			"$unwind": "$thread",
		},
		{
			"$sort": bson.M{
				"reposted_at": -1,
			},
		},
		{
			"$replaceRoot": bson.M{
				"newRoot": "$thread",
			},
		},
	}

	return r.aggregateWithPagination(ctx, r.repostsCollection, pipeline, params)
}

func (r *interactionRepository) GetRepostsByThread(ctx context.Context, threadID primitive.ObjectID, params *utils.PaginationParams) (*utils.PaginationResult, error) {
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

	return r.aggregateWithPagination(ctx, r.repostsCollection, pipeline, params)
}

// Bookmark operations
func (r *interactionRepository) CreateBookmark(ctx context.Context, bookmark *models.Bookmark) error {
	if bookmark.ID.IsZero() {
		bookmark.ID = primitive.NewObjectID()
	}

	_, err := r.bookmarksCollection.InsertOne(ctx, bookmark)
	if err != nil {
		if mongo.IsDuplicateKeyError(err) {
			return errors.New("thread already bookmarked")
		}
		r.logger.WithError(err).Error("Failed to create bookmark")
		return err
	}

	// Update folder items count if bookmark is in a folder
	if bookmark.FolderID != nil {
		go r.updateFolderItemsCount(context.Background(), *bookmark.FolderID, 1)
	}

	r.logger.WithFields(map[string]interface{}{
		"bookmark_id": bookmark.ID,
		"user_id":     bookmark.UserID,
		"thread_id":   bookmark.ThreadID,
		"folder_id":   bookmark.FolderID,
	}).Info("Bookmark created successfully")

	return nil
}

func (r *interactionRepository) DeleteBookmark(ctx context.Context, userID, threadID primitive.ObjectID) error {
	// Get bookmark to check folder
	var bookmark models.Bookmark
	filter := bson.M{
		"user_id":   userID,
		"thread_id": threadID,
	}

	err := r.bookmarksCollection.FindOne(ctx, filter).Decode(&bookmark)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			return errors.New("bookmark not found")
		}
		return err
	}

	// Delete bookmark
	result, err := r.bookmarksCollection.DeleteOne(ctx, filter)
	if err != nil {
		r.logger.WithError(err).Error("Failed to delete bookmark")
		return err
	}

	if result.DeletedCount == 0 {
		return errors.New("bookmark not found")
	}

	// Update folder items count if bookmark was in a folder
	if bookmark.FolderID != nil {
		go r.updateFolderItemsCount(context.Background(), *bookmark.FolderID, -1)
	}

	r.logger.WithFields(map[string]interface{}{
		"user_id":   userID,
		"thread_id": threadID,
	}).Info("Bookmark deleted successfully")

	return nil
}

func (r *interactionRepository) HasBookmarked(ctx context.Context, userID, threadID primitive.ObjectID) (bool, error) {
	filter := bson.M{
		"user_id":   userID,
		"thread_id": threadID,
	}

	count, err := r.bookmarksCollection.CountDocuments(ctx, filter)
	if err != nil {
		r.logger.WithError(err).Error("Failed to check bookmark status")
		return false, err
	}

	return count > 0, nil
}

func (r *interactionRepository) GetBookmarks(ctx context.Context, userID primitive.ObjectID, folderID *primitive.ObjectID, params *utils.PaginationParams) (*utils.PaginationResult, error) {
	matchFilter := bson.M{"user_id": userID}

	if folderID != nil {
		matchFilter["folder_id"] = *folderID
	} else {
		// Get bookmarks without folder
		matchFilter["folder_id"] = bson.M{"$exists": false}
	}

	pipeline := []bson.M{
		{
			"$match": matchFilter,
		},
		{
			"$lookup": bson.M{
				"from":         constants.ThreadsCollection,
				"localField":   "thread_id",
				"foreignField": "_id",
				"as":           "thread",
			},
		},
		{
			"$unwind": "$thread",
		},
		{
			"$sort": bson.M{
				"created_at": -1,
			},
		},
		{
			"$addFields": bson.M{
				"thread.bookmark_notes": "$notes",
				"thread.bookmarked_at":  "$created_at",
			},
		},
		{
			"$replaceRoot": bson.M{
				"newRoot": "$thread",
			},
		},
	}

	return r.aggregateWithPagination(ctx, r.bookmarksCollection, pipeline, params)
}

func (r *interactionRepository) UpdateBookmark(ctx context.Context, userID, threadID primitive.ObjectID, req *UpdateBookmarkRequest) (*models.Bookmark, error) {
	filter := bson.M{
		"user_id":   userID,
		"thread_id": threadID,
	}

	update := bson.M{
		"$set": bson.M{
			"notes":      req.Notes,
			"updated_at": time.Now(),
		},
	}

	if req.FolderID != nil {
		update["$set"].(bson.M)["folder_id"] = *req.FolderID
	}

	result, err := r.bookmarksCollection.UpdateOne(ctx, filter, update)
	if err != nil {
		r.logger.WithError(err).Error("Failed to update bookmark")
		return nil, err
	}

	if result.MatchedCount == 0 {
		return nil, errors.New("bookmark not found")
	}

	// Get updated bookmark
	var bookmark models.Bookmark
	err = r.bookmarksCollection.FindOne(ctx, filter).Decode(&bookmark)
	if err != nil {
		return nil, err
	}

	return &bookmark, nil
}

func (r *interactionRepository) MoveBookmark(ctx context.Context, userID primitive.ObjectID, bookmarkID primitive.ObjectID, folderID *primitive.ObjectID) error {
	filter := bson.M{
		"_id":     bookmarkID,
		"user_id": userID,
	}

	update := bson.M{
		"$set": bson.M{
			"updated_at": time.Now(),
		},
	}

	if folderID != nil {
		update["$set"].(bson.M)["folder_id"] = *folderID
	} else {
		update["$unset"] = bson.M{"folder_id": ""}
	}

	result, err := r.bookmarksCollection.UpdateOne(ctx, filter, update)
	if err != nil {
		r.logger.WithError(err).Error("Failed to move bookmark")
		return err
	}

	if result.MatchedCount == 0 {
		return errors.New("bookmark not found")
	}

	return nil
}

// Bookmark folder operations
func (r *interactionRepository) CreateBookmarkFolder(ctx context.Context, folder *models.BookmarkFolder) error {
	if folder.ID.IsZero() {
		folder.ID = primitive.NewObjectID()
	}

	_, err := r.bookmarkFoldersCollection.InsertOne(ctx, folder)
	if err != nil {
		r.logger.WithError(err).Error("Failed to create bookmark folder")
		return err
	}

	r.logger.WithFields(map[string]interface{}{
		"folder_id": folder.ID,
		"user_id":   folder.UserID,
		"name":      folder.Name,
	}).Info("Bookmark folder created successfully")

	return nil
}

func (r *interactionRepository) UpdateBookmarkFolder(ctx context.Context, folderID, userID primitive.ObjectID, req *UpdateBookmarkFolderRequest) (*models.BookmarkFolder, error) {
	filter := bson.M{
		"_id":     folderID,
		"user_id": userID,
	}

	update := bson.M{
		"$set": bson.M{
			"updated_at": time.Now(),
		},
	}

	// Only update provided fields
	if req.Name != "" {
		update["$set"].(bson.M)["name"] = req.Name
	}
	if req.Description != "" {
		update["$set"].(bson.M)["description"] = req.Description
	}
	if req.Color != "" {
		update["$set"].(bson.M)["color"] = req.Color
	}
	if req.Icon != "" {
		update["$set"].(bson.M)["icon"] = req.Icon
	}
	if req.IsPrivate != nil {
		update["$set"].(bson.M)["is_private"] = *req.IsPrivate
	}

	result, err := r.bookmarkFoldersCollection.UpdateOne(ctx, filter, update)
	if err != nil {
		r.logger.WithError(err).Error("Failed to update bookmark folder")
		return nil, err
	}

	if result.MatchedCount == 0 {
		return nil, errors.New("bookmark folder not found")
	}

	// Get updated folder
	var folder models.BookmarkFolder
	err = r.bookmarkFoldersCollection.FindOne(ctx, filter).Decode(&folder)
	if err != nil {
		return nil, err
	}

	return &folder, nil
}

func (r *interactionRepository) DeleteBookmarkFolder(ctx context.Context, folderID, userID primitive.ObjectID) error {
	// Start transaction to move bookmarks and delete folder
	session, err := r.database.Client().StartSession()
	if err != nil {
		return err
	}
	defer session.EndSession(context.Background())

	_, err = session.WithTransaction(context.Background(), func(sc mongo.SessionContext) (interface{}, error) {
		// Move all bookmarks in this folder to no folder
		bookmarkFilter := bson.M{
			"user_id":   userID,
			"folder_id": folderID,
		}
		bookmarkUpdate := bson.M{
			"$unset": bson.M{"folder_id": ""},
			"$set":   bson.M{"updated_at": time.Now()},
		}

		_, err := r.bookmarksCollection.UpdateMany(sc, bookmarkFilter, bookmarkUpdate)
		if err != nil {
			return nil, err
		}

		// Delete the folder
		folderFilter := bson.M{
			"_id":     folderID,
			"user_id": userID,
		}

		result, err := r.bookmarkFoldersCollection.DeleteOne(sc, folderFilter)
		if err != nil {
			return nil, err
		}

		if result.DeletedCount == 0 {
			return nil, errors.New("bookmark folder not found")
		}

		return nil, nil
	})

	if err != nil {
		r.logger.WithError(err).WithField("folder_id", folderID).Error("Failed to delete bookmark folder")
		return err
	}

	return nil
}

func (r *interactionRepository) GetBookmarkFolders(ctx context.Context, userID primitive.ObjectID, params *utils.PaginationParams) (*utils.PaginationResult, error) {
	filter := bson.M{"user_id": userID}

	// Count total documents
	total, err := r.bookmarkFoldersCollection.CountDocuments(ctx, filter)
	if err != nil {
		r.logger.WithError(err).Error("Failed to count bookmark folders")
		return nil, err
	}

	// Calculate skip
	skip := (params.Page - 1) * params.Limit

	// Find options
	findOptions := options.Find().
		SetSkip(int64(skip)).
		SetLimit(int64(params.Limit)).
		SetSort(bson.M{"created_at": -1})

	cursor, err := r.bookmarkFoldersCollection.Find(ctx, filter, findOptions)
	if err != nil {
		r.logger.WithError(err).Error("Failed to get bookmark folders")
		return nil, err
	}
	defer cursor.Close(ctx)

	var folders []*models.BookmarkFolder
	if err := cursor.All(ctx, &folders); err != nil {
		r.logger.WithError(err).Error("Failed to decode bookmark folders")
		return nil, err
	}

	return &utils.PaginationResult{
		Data:       folders,
		Pagination: utils.CalculatePaginationMeta(params.Page, params.Limit, total),
	}, nil
}

func (r *interactionRepository) HasBookmarkFolder(ctx context.Context, userID, folderID primitive.ObjectID) (bool, error) {
	filter := bson.M{
		"_id":     folderID,
		"user_id": userID,
	}

	count, err := r.bookmarkFoldersCollection.CountDocuments(ctx, filter)
	if err != nil {
		r.logger.WithError(err).Error("Failed to check bookmark folder")
		return false, err
	}

	return count > 0, nil
}

// Share operations
func (r *interactionRepository) CreateShare(ctx context.Context, share *models.Share) error {
	if share.ID.IsZero() {
		share.ID = primitive.NewObjectID()
	}

	_, err := r.sharesCollection.InsertOne(ctx, share)
	if err != nil {
		r.logger.WithError(err).Error("Failed to create share")
		return err
	}

	r.logger.WithFields(map[string]interface{}{
		"share_id":  share.ID,
		"user_id":   share.UserID,
		"thread_id": share.ThreadID,
		"platform":  share.Platform,
	}).Info("Share created successfully")

	return nil
}

func (r *interactionRepository) GetSharesByThread(ctx context.Context, threadID primitive.ObjectID, params *utils.PaginationParams) (*utils.PaginationResult, error) {
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
				"shared_at": -1,
			},
		},
	}

	return r.aggregateWithPagination(ctx, r.sharesCollection, pipeline, params)
}

// Report operations
func (r *interactionRepository) CreateReport(ctx context.Context, report *models.Report) error {
	if report.ID.IsZero() {
		report.ID = primitive.NewObjectID()
	}

	_, err := r.reportsCollection.InsertOne(ctx, report)
	if err != nil {
		r.logger.WithError(err).Error("Failed to create report")
		return err
	}

	r.logger.WithFields(map[string]interface{}{
		"report_id":   report.ID,
		"reporter_id": report.ReporterID,
		"target_type": report.TargetType,
		"target_id":   report.TargetID,
		"report_type": report.ReportType,
		"category":    report.Category,
	}).Info("Report created successfully")

	return nil
}

func (r *interactionRepository) GetReportsByThread(ctx context.Context, threadID primitive.ObjectID, params *utils.PaginationParams) (*utils.PaginationResult, error) {
	pipeline := []bson.M{
		{
			"$match": bson.M{
				"thread_id":   threadID,
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

	return r.aggregateWithPagination(ctx, r.reportsCollection, pipeline, params)
}

func (r *interactionRepository) GetReportsByUser(ctx context.Context, userID primitive.ObjectID, params *utils.PaginationParams) (*utils.PaginationResult, error) {
	pipeline := []bson.M{
		{
			"$match": bson.M{
				"reporter_id": userID,
			},
		},
		{
			"$sort": bson.M{
				"created_at": -1,
			},
		},
	}

	return r.aggregateWithPagination(ctx, r.reportsCollection, pipeline, params)
}

func (r *interactionRepository) UpdateReportStatus(ctx context.Context, reportID primitive.ObjectID, status, resolution string) error {
	filter := bson.M{"_id": reportID}
	update := bson.M{
		"$set": bson.M{
			"status":      status,
			"resolution":  resolution,
			"reviewed_at": time.Now(),
			"updated_at":  time.Now(),
		},
	}

	result, err := r.reportsCollection.UpdateOne(ctx, filter, update)
	if err != nil {
		r.logger.WithError(err).Error("Failed to update report status")
		return err
	}

	if result.MatchedCount == 0 {
		return errors.New("report not found")
	}

	return nil
}

// Poll operations
func (r *interactionRepository) CreatePollVote(ctx context.Context, vote *models.PollVote) error {
	if vote.ID.IsZero() {
		vote.ID = primitive.NewObjectID()
	}

	_, err := r.pollVotesCollection.InsertOne(ctx, vote)
	if err != nil {
		if mongo.IsDuplicateKeyError(err) {
			return errors.New("already voted in this poll")
		}
		r.logger.WithError(err).Error("Failed to create poll vote")
		return err
	}

	r.logger.WithFields(map[string]interface{}{
		"vote_id":   vote.ID,
		"user_id":   vote.UserID,
		"poll_id":   vote.PollID,
		"thread_id": vote.ThreadID,
		"options":   vote.Options,
	}).Info("Poll vote created successfully")

	return nil
}

func (r *interactionRepository) DeletePollVote(ctx context.Context, userID, pollID primitive.ObjectID) error {
	filter := bson.M{
		"user_id": userID,
		"poll_id": pollID,
	}

	result, err := r.pollVotesCollection.DeleteOne(ctx, filter)
	if err != nil {
		r.logger.WithError(err).Error("Failed to delete poll vote")
		return err
	}

	if result.DeletedCount == 0 {
		return errors.New("poll vote not found")
	}

	return nil
}

func (r *interactionRepository) HasVotedInPoll(ctx context.Context, userID, pollID primitive.ObjectID) (bool, error) {
	filter := bson.M{
		"user_id": userID,
		"poll_id": pollID,
	}

	count, err := r.pollVotesCollection.CountDocuments(ctx, filter)
	if err != nil {
		r.logger.WithError(err).Error("Failed to check poll vote status")
		return false, err
	}

	return count > 0, nil
}

func (r *interactionRepository) GetPollVotes(ctx context.Context, pollID primitive.ObjectID, params *utils.PaginationParams) (*utils.PaginationResult, error) {
	pipeline := []bson.M{
		{
			"$match": bson.M{
				"poll_id": pollID,
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
				"voted_at": -1,
			},
		},
	}

	return r.aggregateWithPagination(ctx, r.pollVotesCollection, pipeline, params)
}

func (r *interactionRepository) UpdatePollVoteCounts(ctx context.Context, pollID primitive.ObjectID, optionID primitive.ObjectID, delta int) error {
	// This would typically update the poll option vote count in the threads collection
	// For now, we'll skip this implementation as it requires complex aggregation
	return nil
}

// View operations
func (r *interactionRepository) RecordThreadView(ctx context.Context, view *models.ThreadView) error {
	if view.ID.IsZero() {
		view.ID = primitive.NewObjectID()
	}

	// Use upsert to avoid duplicate views from the same user in a short time
	filter := bson.M{
		"thread_id": view.ThreadID,
		"user_id":   view.UserID,
		"viewed_at": bson.M{
			"$gte": time.Now().Add(-1 * time.Hour), // Only consider views in the last hour
		},
	}

	update := bson.M{
		"$setOnInsert": view,
		"$set": bson.M{
			"viewed_at": view.ViewedAt,
			"duration":  view.Duration,
		},
	}

	opts := options.Update().SetUpsert(true)
	_, err := r.threadViewsCollection.UpdateOne(ctx, filter, update, opts)
	if err != nil {
		r.logger.WithError(err).Error("Failed to record thread view")
		return err
	}

	return nil
}

func (r *interactionRepository) GetViewsByThread(ctx context.Context, threadID primitive.ObjectID, params *utils.PaginationParams) (*utils.PaginationResult, error) {
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
				"viewed_at": -1,
			},
		},
	}

	return r.aggregateWithPagination(ctx, r.threadViewsCollection, pipeline, params)
}

func (r *interactionRepository) GetViewsByUser(ctx context.Context, userID primitive.ObjectID, params *utils.PaginationParams) (*utils.PaginationResult, error) {
	pipeline := []bson.M{
		{
			"$match": bson.M{
				"user_id": userID,
			},
		},
		{
			"$lookup": bson.M{
				"from":         constants.ThreadsCollection,
				"localField":   "thread_id",
				"foreignField": "_id",
				"as":           "thread",
			},
		},
		{
			"$unwind": "$thread",
		},
		{
			"$sort": bson.M{
				"viewed_at": -1,
			},
		},
		{
			"$replaceRoot": bson.M{
				"newRoot": "$thread",
			},
		},
	}

	return r.aggregateWithPagination(ctx, r.threadViewsCollection, pipeline, params)
}

// Helper methods
func (r *interactionRepository) aggregateWithPagination(ctx context.Context, collection *mongo.Collection, pipeline []bson.M, params *utils.PaginationParams) (*utils.PaginationResult, error) {
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

	var results []interface{}
	if err := cursor.All(ctx, &results); err != nil {
		r.logger.WithError(err).Error("Failed to decode documents")
		return nil, err
	}

	return &utils.PaginationResult{
		Data:       results,
		Pagination: utils.CalculatePaginationMeta(params.Page, params.Limit, total),
	}, nil
}

func (r *interactionRepository) updateFolderItemsCount(ctx context.Context, folderID primitive.ObjectID, delta int) {
	filter := bson.M{"_id": folderID}
	update := bson.M{
		"$inc": bson.M{"items_count": delta},
		"$set": bson.M{"updated_at": time.Now()},
	}

	_, err := r.bookmarkFoldersCollection.UpdateOne(ctx, filter, update)
	if err != nil {
		r.logger.WithError(err).WithField("folder_id", folderID).Error("Failed to update folder items count")
	}
}
