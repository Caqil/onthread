package repository

import (
	"context"
	"errors"
	"time"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"

	"onthread/internal/models"
	"onthread/internal/utils"
	"onthread/pkg/constants"
	"onthread/pkg/logger"
)

// UserRepository interface (already defined in user_service.go, but included here for completeness)
type UserRepository interface {
	// Basic CRUD
	Create(ctx context.Context, user *models.User) error
	GetByID(ctx context.Context, id primitive.ObjectID) (*models.User, error)
	GetByUsername(ctx context.Context, username string) (*models.User, error)
	GetByEmail(ctx context.Context, email string) (*models.User, error)
	Update(ctx context.Context, user *models.User) error
	Delete(ctx context.Context, id primitive.ObjectID) error

	// Search and discovery
	Search(ctx context.Context, query string, params *utils.PaginationParams) (*utils.PaginationResult, error)
	GetPopular(ctx context.Context, params *utils.PaginationParams) (*utils.PaginationResult, error)
	GetSuggestions(ctx context.Context, userID primitive.ObjectID, limit int) ([]*models.User, error)

	// Follow operations
	CreateFollow(ctx context.Context, follow *models.Follow) error
	DeleteFollow(ctx context.Context, followerID, followedID primitive.ObjectID) error
	GetFollow(ctx context.Context, followerID, followedID primitive.ObjectID) (*models.Follow, error)
	GetFollowers(ctx context.Context, userID primitive.ObjectID, params *utils.PaginationParams) (*utils.PaginationResult, error)
	GetFollowing(ctx context.Context, userID primitive.ObjectID, params *utils.PaginationParams) (*utils.PaginationResult, error)
	GetFollowRequests(ctx context.Context, userID primitive.ObjectID, params *utils.PaginationParams) (*utils.PaginationResult, error)
	AcceptFollowRequest(ctx context.Context, followerID, followedID primitive.ObjectID) error
	DeclineFollowRequest(ctx context.Context, followerID, followedID primitive.ObjectID) error
	UpdateFollowCounts(ctx context.Context, userID primitive.ObjectID, followersDelta, followingDelta int) error

	// Block/Mute operations
	CreateBlock(ctx context.Context, block *models.Block) error
	DeleteBlock(ctx context.Context, blockerID, blockedID primitive.ObjectID) error
	GetBlockedUsers(ctx context.Context, userID primitive.ObjectID, params *utils.PaginationParams) (*utils.PaginationResult, error)
	IsBlocked(ctx context.Context, blockerID, blockedID primitive.ObjectID) (bool, error)
	CreateMute(ctx context.Context, mute *models.Mute) error
	DeleteMute(ctx context.Context, userID, mutedID primitive.ObjectID) error
	GetMutedUsers(ctx context.Context, userID primitive.ObjectID, params *utils.PaginationParams) (*utils.PaginationResult, error)

	// List operations
	CreateList(ctx context.Context, list *models.UserList) error
	GetList(ctx context.Context, listID primitive.ObjectID) (*models.UserList, error)
	UpdateList(ctx context.Context, list *models.UserList) error
	DeleteList(ctx context.Context, listID primitive.ObjectID) error
	GetUserLists(ctx context.Context, userID primitive.ObjectID, params *utils.PaginationParams) (*utils.PaginationResult, error)
	AddListMember(ctx context.Context, member *models.ListMember) error
	RemoveListMember(ctx context.Context, listID, userID primitive.ObjectID) error
	GetListMembers(ctx context.Context, listID primitive.ObjectID, params *utils.PaginationParams) (*utils.PaginationResult, error)

	// Admin operations
	GetAll(ctx context.Context, params *utils.PaginationParams, filter string) (*utils.PaginationResult, error)
	Suspend(ctx context.Context, userID primitive.ObjectID, until *time.Time) error
	Unsuspend(ctx context.Context, userID primitive.ObjectID) error
	Ban(ctx context.Context, userID primitive.ObjectID, until *time.Time) error
	Unban(ctx context.Context, userID primitive.ObjectID) error
}

// userRepository implements UserRepository interface
type userRepository struct {
	database              *mongo.Database
	usersCollection       *mongo.Collection
	followsCollection     *mongo.Collection
	blocksCollection      *mongo.Collection
	mutesCollection       *mongo.Collection
	listsCollection       *mongo.Collection
	listMembersCollection *mongo.Collection
	logger                *logger.Logger
}

// NewUserRepository creates a new user repository
func NewUserRepository(database *mongo.Database) UserRepository {
	return &userRepository{
		database:              database,
		blocksCollection:      database.Collection(constants.BlocksCollection),
		mutesCollection:       database.Collection(constants.MutesCollection),
		listsCollection:       database.Collection(constants.UserListsCollection),
		listMembersCollection: database.Collection(constants.ListMembersCollection),
		logger:                logger.NewComponentLogger("UserRepository"),
	}
}

// Create creates a new user
func (r *userRepository) Create(ctx context.Context, user *models.User) error {
	if user.ID.IsZero() {
		user.ID = primitive.NewObjectID()
	}

	_, err := r.usersCollection.InsertOne(ctx, user)
	if err != nil {
		if mongo.IsDuplicateKeyError(err) {
			return errors.New("user already exists")
		}
		r.logger.WithError(err).Error("Failed to create user")
		return err
	}

	r.logger.WithField("user_id", user.ID).Info("User created successfully")
	return nil
}

// GetByID retrieves a user by ID
func (r *userRepository) GetByID(ctx context.Context, id primitive.ObjectID) (*models.User, error) {
	var user models.User
	err := r.usersCollection.FindOne(ctx, bson.M{"_id": id}).Decode(&user)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			return nil, errors.New("user not found")
		}
		r.logger.WithError(err).WithField("user_id", id).Error("Failed to get user by ID")
		return nil, err
	}

	return &user, nil
}

// GetByUsername retrieves a user by username
func (r *userRepository) GetByUsername(ctx context.Context, username string) (*models.User, error) {
	var user models.User
	filter := bson.M{"username": bson.M{"$regex": "^" + username + "$", "$options": "i"}}

	err := r.usersCollection.FindOne(ctx, filter).Decode(&user)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			return nil, errors.New("user not found")
		}
		r.logger.WithError(err).WithField("username", username).Error("Failed to get user by username")
		return nil, err
	}

	return &user, nil
}

// GetByEmail retrieves a user by email
func (r *userRepository) GetByEmail(ctx context.Context, email string) (*models.User, error) {
	var user models.User
	filter := bson.M{"email": bson.M{"$regex": "^" + email + "$", "$options": "i"}}

	err := r.usersCollection.FindOne(ctx, filter).Decode(&user)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			return nil, errors.New("user not found")
		}
		r.logger.WithError(err).WithField("email", email).Error("Failed to get user by email")
		return nil, err
	}

	return &user, nil
}

// Update updates a user
func (r *userRepository) Update(ctx context.Context, user *models.User) error {
	filter := bson.M{"_id": user.ID}
	update := bson.M{"$set": user}

	result, err := r.usersCollection.UpdateOne(ctx, filter, update)
	if err != nil {
		r.logger.WithError(err).WithField("user_id", user.ID).Error("Failed to update user")
		return err
	}

	if result.MatchedCount == 0 {
		return errors.New("user not found")
	}

	return nil
}

// Delete deletes a user
func (r *userRepository) Delete(ctx context.Context, id primitive.ObjectID) error {
	filter := bson.M{"_id": id}

	result, err := r.usersCollection.DeleteOne(ctx, filter)
	if err != nil {
		r.logger.WithError(err).WithField("user_id", id).Error("Failed to delete user")
		return err
	}

	if result.DeletedCount == 0 {
		return errors.New("user not found")
	}

	return nil
}

// Search searches for users
func (r *userRepository) Search(ctx context.Context, query string, params *utils.PaginationParams) (*utils.PaginationResult, error) {
	filter := bson.M{
		"$or": []bson.M{
			{"username": bson.M{"$regex": query, "$options": "i"}},
			{"display_name": bson.M{"$regex": query, "$options": "i"}},
			{"bio": bson.M{"$regex": query, "$options": "i"}},
		},
		"is_active": true,
	}

	// Count total documents
	total, err := r.usersCollection.CountDocuments(ctx, filter)
	if err != nil {
		r.logger.WithError(err).Error("Failed to count users for search")
		return nil, err
	}

	// Calculate skip
	skip := (params.Page - 1) * params.Limit

	// Find options
	findOptions := options.Find().
		SetSkip(int64(skip)).
		SetLimit(int64(params.Limit)).
		SetSort(bson.M{"followers_count": -1}) // Sort by popularity

	cursor, err := r.usersCollection.Find(ctx, filter, findOptions)
	if err != nil {
		r.logger.WithError(err).Error("Failed to search users")
		return nil, err
	}
	defer cursor.Close(ctx)

	var users []*models.User
	if err := cursor.All(ctx, &users); err != nil {
		r.logger.WithError(err).Error("Failed to decode search results")
		return nil, err
	}

	return &utils.PaginationResult{
		Data:       users,
		Pagination: utils.CalculatePaginationMeta(params.Page, params.Limit, total),
	}, nil
}

// GetPopular gets popular users
func (r *userRepository) GetPopular(ctx context.Context, params *utils.PaginationParams) (*utils.PaginationResult, error) {
	filter := bson.M{
		"is_active":       true,
		"followers_count": bson.M{"$gt": 0},
	}

	// Count total documents
	total, err := r.usersCollection.CountDocuments(ctx, filter)
	if err != nil {
		r.logger.WithError(err).Error("Failed to count popular users")
		return nil, err
	}

	// Calculate skip
	skip := (params.Page - 1) * params.Limit

	// Find options
	findOptions := options.Find().
		SetSkip(int64(skip)).
		SetLimit(int64(params.Limit)).
		SetSort(bson.M{"followers_count": -1})

	cursor, err := r.usersCollection.Find(ctx, filter, findOptions)
	if err != nil {
		r.logger.WithError(err).Error("Failed to get popular users")
		return nil, err
	}
	defer cursor.Close(ctx)

	var users []*models.User
	if err := cursor.All(ctx, &users); err != nil {
		r.logger.WithError(err).Error("Failed to decode popular users")
		return nil, err
	}

	return &utils.PaginationResult{
		Data:       users,
		Pagination: utils.CalculatePaginationMeta(params.Page, params.Limit, total),
	}, nil
}

// GetSuggestions gets user suggestions
func (r *userRepository) GetSuggestions(ctx context.Context, userID primitive.ObjectID, limit int) ([]*models.User, error) {
	// Get users that the current user's following are following
	pipeline := []bson.M{
		// Find who the user is following
		{"$match": bson.M{"follower_id": userID, "is_accepted": true}},
		// Look up who those people are following
		{"$lookup": bson.M{
			"from":         constants.FollowsCollection,
			"localField":   "followed_id",
			"foreignField": "follower_id",
			"as":           "their_following",
		}},
		// Unwind the their_following array
		{"$unwind": "$their_following"},
		// Group by the users being followed and count
		{"$group": bson.M{
			"_id":   "$their_following.followed_id",
			"count": bson.M{"$sum": 1},
		}},
		// Exclude the current user
		{"$match": bson.M{"_id": bson.M{"$ne": userID}}},
		// Sort by count (most mutual follows first)
		{"$sort": bson.M{"count": -1}},
		// Limit results
		{"$limit": limit},
		// Lookup user details
		{"$lookup": bson.M{
			"from":         constants.UsersCollection,
			"localField":   "_id",
			"foreignField": "_id",
			"as":           "user",
		}},
		{"$unwind": "$user"},
		// Only active users
		{"$match": bson.M{"user.is_active": true}},
		// Return just the user
		{"$replaceRoot": bson.M{"newRoot": "$user"}},
	}

	cursor, err := r.followsCollection.Aggregate(ctx, pipeline)
	if err != nil {
		r.logger.WithError(err).Error("Failed to get user suggestions")
		return nil, err
	}
	defer cursor.Close(ctx)

	var users []*models.User
	if err := cursor.All(ctx, &users); err != nil {
		r.logger.WithError(err).Error("Failed to decode user suggestions")
		return nil, err
	}

	// If we don't have enough suggestions, add some popular users
	if len(users) < limit {
		remaining := limit - len(users)
		popularParams := &utils.PaginationParams{
			Page:  1,
			Limit: remaining,
		}

		popularResult, err := r.GetPopular(ctx, popularParams)
		if err == nil {
			if popularUsers, ok := popularResult.Data.([]*models.User); ok {
				// Filter out users already in suggestions and the current user
				existingIDs := make(map[primitive.ObjectID]bool)
				existingIDs[userID] = true
				for _, user := range users {
					existingIDs[user.ID] = true
				}

				for _, user := range popularUsers {
					if !existingIDs[user.ID] && len(users) < limit {
						users = append(users, user)
					}
				}
			}
		}
	}

	return users, nil
}

// Follow operations

// CreateFollow creates a follow relationship
func (r *userRepository) CreateFollow(ctx context.Context, follow *models.Follow) error {
	if follow.ID.IsZero() {
		follow.ID = primitive.NewObjectID()
	}

	_, err := r.followsCollection.InsertOne(ctx, follow)
	if err != nil {
		if mongo.IsDuplicateKeyError(err) {
			return errors.New("already following user")
		}
		r.logger.WithError(err).Error("Failed to create follow")
		return err
	}

	return nil
}

// DeleteFollow deletes a follow relationship
func (r *userRepository) DeleteFollow(ctx context.Context, followerID, followedID primitive.ObjectID) error {
	filter := bson.M{
		"follower_id": followerID,
		"followed_id": followedID,
	}

	result, err := r.followsCollection.DeleteOne(ctx, filter)
	if err != nil {
		r.logger.WithError(err).Error("Failed to delete follow")
		return err
	}

	if result.DeletedCount == 0 {
		return errors.New("follow relationship not found")
	}

	return nil
}

// GetFollow retrieves a follow relationship
func (r *userRepository) GetFollow(ctx context.Context, followerID, followedID primitive.ObjectID) (*models.Follow, error) {
	var follow models.Follow
	filter := bson.M{
		"follower_id": followerID,
		"followed_id": followedID,
	}

	err := r.followsCollection.FindOne(ctx, filter).Decode(&follow)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			return nil, errors.New("follow relationship not found")
		}
		r.logger.WithError(err).Error("Failed to get follow")
		return nil, err
	}

	return &follow, nil
}

// GetFollowers gets user followers
func (r *userRepository) GetFollowers(ctx context.Context, userID primitive.ObjectID, params *utils.PaginationParams) (*utils.PaginationResult, error) {
	// Pipeline to get followers with user details
	pipeline := []bson.M{
		{"$match": bson.M{
			"followed_id": userID,
			"is_accepted": true,
		}},
		{"$lookup": bson.M{
			"from":         constants.UsersCollection,
			"localField":   "follower_id",
			"foreignField": "_id",
			"as":           "follower",
		}},
		{"$unwind": "$follower"},
		{"$match": bson.M{"follower.is_active": true}},
		{"$sort": bson.M{"created_at": -1}},
	}

	// Count total
	countPipeline := append(pipeline, bson.M{"$count": "total"})
	countCursor, err := r.followsCollection.Aggregate(ctx, countPipeline)
	if err != nil {
		r.logger.WithError(err).Error("Failed to count followers")
		return nil, err
	}
	defer countCursor.Close(ctx)

	var totalResult []bson.M
	if err := countCursor.All(ctx, &totalResult); err != nil {
		return nil, err
	}

	var total int64
	if len(totalResult) > 0 {
		if count, ok := totalResult[0]["total"].(int32); ok {
			total = int64(count)
		}
	}

	// Add pagination to pipeline
	skip := (params.Page - 1) * params.Limit
	pipeline = append(pipeline,
		bson.M{"$skip": skip},
		bson.M{"$limit": params.Limit},
		bson.M{"$replaceRoot": bson.M{"newRoot": "$follower"}},
	)

	cursor, err := r.followsCollection.Aggregate(ctx, pipeline)
	if err != nil {
		r.logger.WithError(err).Error("Failed to get followers")
		return nil, err
	}
	defer cursor.Close(ctx)

	var users []*models.User
	if err := cursor.All(ctx, &users); err != nil {
		r.logger.WithError(err).Error("Failed to decode followers")
		return nil, err
	}

	return &utils.PaginationResult{
		Data:       users,
		Pagination: utils.CalculatePaginationMeta(params.Page, params.Limit, total),
	}, nil
}

// GetFollowing gets users being followed
func (r *userRepository) GetFollowing(ctx context.Context, userID primitive.ObjectID, params *utils.PaginationParams) (*utils.PaginationResult, error) {
	// Pipeline to get following with user details
	pipeline := []bson.M{
		{"$match": bson.M{
			"follower_id": userID,
			"is_accepted": true,
		}},
		{"$lookup": bson.M{
			"from":         constants.UsersCollection,
			"localField":   "followed_id",
			"foreignField": "_id",
			"as":           "followed",
		}},
		{"$unwind": "$followed"},
		{"$match": bson.M{"followed.is_active": true}},
		{"$sort": bson.M{"created_at": -1}},
	}

	// Count total
	countPipeline := append(pipeline, bson.M{"$count": "total"})
	countCursor, err := r.followsCollection.Aggregate(ctx, countPipeline)
	if err != nil {
		r.logger.WithError(err).Error("Failed to count following")
		return nil, err
	}
	defer countCursor.Close(ctx)

	var totalResult []bson.M
	if err := countCursor.All(ctx, &totalResult); err != nil {
		return nil, err
	}

	var total int64
	if len(totalResult) > 0 {
		if count, ok := totalResult[0]["total"].(int32); ok {
			total = int64(count)
		}
	}

	// Add pagination to pipeline
	skip := (params.Page - 1) * params.Limit
	pipeline = append(pipeline,
		bson.M{"$skip": skip},
		bson.M{"$limit": params.Limit},
		bson.M{"$replaceRoot": bson.M{"newRoot": "$followed"}},
	)

	cursor, err := r.followsCollection.Aggregate(ctx, pipeline)
	if err != nil {
		r.logger.WithError(err).Error("Failed to get following")
		return nil, err
	}
	defer cursor.Close(ctx)

	var users []*models.User
	if err := cursor.All(ctx, &users); err != nil {
		r.logger.WithError(err).Error("Failed to decode following")
		return nil, err
	}

	return &utils.PaginationResult{
		Data:       users,
		Pagination: utils.CalculatePaginationMeta(params.Page, params.Limit, total),
	}, nil
}

// GetFollowRequests gets pending follow requests
func (r *userRepository) GetFollowRequests(ctx context.Context, userID primitive.ObjectID, params *utils.PaginationParams) (*utils.PaginationResult, error) {
	// Pipeline to get follow requests with user details
	pipeline := []bson.M{
		{"$match": bson.M{
			"followed_id": userID,
			"is_accepted": false,
		}},
		{"$lookup": bson.M{
			"from":         constants.UsersCollection,
			"localField":   "follower_id",
			"foreignField": "_id",
			"as":           "follower",
		}},
		{"$unwind": "$follower"},
		{"$match": bson.M{"follower.is_active": true}},
		{"$sort": bson.M{"created_at": -1}},
	}

	// Count total
	countPipeline := append(pipeline, bson.M{"$count": "total"})
	countCursor, err := r.followsCollection.Aggregate(ctx, countPipeline)
	if err != nil {
		r.logger.WithError(err).Error("Failed to count follow requests")
		return nil, err
	}
	defer countCursor.Close(ctx)

	var totalResult []bson.M
	if err := countCursor.All(ctx, &totalResult); err != nil {
		return nil, err
	}

	var total int64
	if len(totalResult) > 0 {
		if count, ok := totalResult[0]["total"].(int32); ok {
			total = int64(count)
		}
	}

	// Add pagination to pipeline
	skip := (params.Page - 1) * params.Limit
	pipeline = append(pipeline,
		bson.M{"$skip": skip},
		bson.M{"$limit": params.Limit},
		bson.M{"$replaceRoot": bson.M{"newRoot": "$follower"}},
	)

	cursor, err := r.followsCollection.Aggregate(ctx, pipeline)
	if err != nil {
		r.logger.WithError(err).Error("Failed to get follow requests")
		return nil, err
	}
	defer cursor.Close(ctx)

	var users []*models.User
	if err := cursor.All(ctx, &users); err != nil {
		r.logger.WithError(err).Error("Failed to decode follow requests")
		return nil, err
	}

	return &utils.PaginationResult{
		Data:       users,
		Pagination: utils.CalculatePaginationMeta(params.Page, params.Limit, total),
	}, nil
}

// AcceptFollowRequest accepts a follow request
func (r *userRepository) AcceptFollowRequest(ctx context.Context, followerID, followedID primitive.ObjectID) error {
	filter := bson.M{
		"follower_id": followerID,
		"followed_id": followedID,
		"is_accepted": false,
	}

	update := bson.M{
		"$set": bson.M{"is_accepted": true},
	}

	result, err := r.followsCollection.UpdateOne(ctx, filter, update)
	if err != nil {
		r.logger.WithError(err).Error("Failed to accept follow request")
		return err
	}

	if result.MatchedCount == 0 {
		return errors.New("follow request not found")
	}

	return nil
}

// DeclineFollowRequest declines a follow request
func (r *userRepository) DeclineFollowRequest(ctx context.Context, followerID, followedID primitive.ObjectID) error {
	filter := bson.M{
		"follower_id": followerID,
		"followed_id": followedID,
		"is_accepted": false,
	}

	result, err := r.followsCollection.DeleteOne(ctx, filter)
	if err != nil {
		r.logger.WithError(err).Error("Failed to decline follow request")
		return err
	}

	if result.DeletedCount == 0 {
		return errors.New("follow request not found")
	}

	return nil
}

// UpdateFollowCounts updates user follow counts
func (r *userRepository) UpdateFollowCounts(ctx context.Context, userID primitive.ObjectID, followersDelta, followingDelta int) error {
	filter := bson.M{"_id": userID}
	update := bson.M{
		"$inc": bson.M{
			"followers_count": followersDelta,
			"following_count": followingDelta,
		},
	}

	_, err := r.usersCollection.UpdateOne(ctx, filter, update)
	if err != nil {
		r.logger.WithError(err).Error("Failed to update follow counts")
		return err
	}

	return nil
}

// Block/Mute operations

// CreateBlock creates a block relationship
func (r *userRepository) CreateBlock(ctx context.Context, block *models.Block) error {
	if block.ID.IsZero() {
		block.ID = primitive.NewObjectID()
	}

	_, err := r.blocksCollection.InsertOne(ctx, block)
	if err != nil {
		if mongo.IsDuplicateKeyError(err) {
			return errors.New("user already blocked")
		}
		r.logger.WithError(err).Error("Failed to create block")
		return err
	}

	return nil
}

// DeleteBlock deletes a block relationship
func (r *userRepository) DeleteBlock(ctx context.Context, blockerID, blockedID primitive.ObjectID) error {
	filter := bson.M{
		"blocker_id": blockerID,
		"blocked_id": blockedID,
	}

	result, err := r.blocksCollection.DeleteOne(ctx, filter)
	if err != nil {
		r.logger.WithError(err).Error("Failed to delete block")
		return err
	}

	if result.DeletedCount == 0 {
		return errors.New("block relationship not found")
	}

	return nil
}

// GetBlockedUsers gets blocked users
func (r *userRepository) GetBlockedUsers(ctx context.Context, userID primitive.ObjectID, params *utils.PaginationParams) (*utils.PaginationResult, error) {
	// Pipeline to get blocked users with user details
	pipeline := []bson.M{
		{"$match": bson.M{"blocker_id": userID}},
		{"$lookup": bson.M{
			"from":         constants.UsersCollection,
			"localField":   "blocked_id",
			"foreignField": "_id",
			"as":           "blocked_user",
		}},
		{"$unwind": "$blocked_user"},
		{"$sort": bson.M{"created_at": -1}},
	}

	// Count total
	countPipeline := append(pipeline, bson.M{"$count": "total"})
	countCursor, err := r.blocksCollection.Aggregate(ctx, countPipeline)
	if err != nil {
		r.logger.WithError(err).Error("Failed to count blocked users")
		return nil, err
	}
	defer countCursor.Close(ctx)

	var totalResult []bson.M
	if err := countCursor.All(ctx, &totalResult); err != nil {
		return nil, err
	}

	var total int64
	if len(totalResult) > 0 {
		if count, ok := totalResult[0]["total"].(int32); ok {
			total = int64(count)
		}
	}

	// Add pagination to pipeline
	skip := (params.Page - 1) * params.Limit
	pipeline = append(pipeline,
		bson.M{"$skip": skip},
		bson.M{"$limit": params.Limit},
		bson.M{"$replaceRoot": bson.M{"newRoot": "$blocked_user"}},
	)

	cursor, err := r.blocksCollection.Aggregate(ctx, pipeline)
	if err != nil {
		r.logger.WithError(err).Error("Failed to get blocked users")
		return nil, err
	}
	defer cursor.Close(ctx)

	var users []*models.User
	if err := cursor.All(ctx, &users); err != nil {
		r.logger.WithError(err).Error("Failed to decode blocked users")
		return nil, err
	}

	return &utils.PaginationResult{
		Data:       users,
		Pagination: utils.CalculatePaginationMeta(params.Page, params.Limit, total),
	}, nil
}

// IsBlocked checks if a user is blocked
func (r *userRepository) IsBlocked(ctx context.Context, blockerID, blockedID primitive.ObjectID) (bool, error) {
	filter := bson.M{
		"blocker_id": blockerID,
		"blocked_id": blockedID,
	}

	count, err := r.blocksCollection.CountDocuments(ctx, filter)
	if err != nil {
		r.logger.WithError(err).Error("Failed to check block status")
		return false, err
	}

	return count > 0, nil
}

// CreateMute creates a mute relationship
func (r *userRepository) CreateMute(ctx context.Context, mute *models.Mute) error {
	if mute.ID.IsZero() {
		mute.ID = primitive.NewObjectID()
	}

	_, err := r.mutesCollection.InsertOne(ctx, mute)
	if err != nil {
		if mongo.IsDuplicateKeyError(err) {
			return errors.New("user already muted")
		}
		r.logger.WithError(err).Error("Failed to create mute")
		return err
	}

	return nil
}

// DeleteMute deletes a mute relationship
func (r *userRepository) DeleteMute(ctx context.Context, userID, mutedID primitive.ObjectID) error {
	filter := bson.M{
		"user_id":  userID,
		"muted_id": mutedID,
	}

	result, err := r.mutesCollection.DeleteOne(ctx, filter)
	if err != nil {
		r.logger.WithError(err).Error("Failed to delete mute")
		return err
	}

	if result.DeletedCount == 0 {
		return errors.New("mute relationship not found")
	}

	return nil
}

// GetMutedUsers gets muted users
func (r *userRepository) GetMutedUsers(ctx context.Context, userID primitive.ObjectID, params *utils.PaginationParams) (*utils.PaginationResult, error) {
	// Pipeline to get muted users with user details
	pipeline := []bson.M{
		{"$match": bson.M{
			"user_id": userID,
			"$or": []bson.M{
				{"duration": bson.M{"$exists": false}},
				{"duration": nil},
				{"duration": bson.M{"$gt": time.Now()}},
			},
		}},
		{"$lookup": bson.M{
			"from":         constants.UsersCollection,
			"localField":   "muted_id",
			"foreignField": "_id",
			"as":           "muted_user",
		}},
		{"$unwind": "$muted_user"},
		{"$sort": bson.M{"created_at": -1}},
	}

	// Count total
	countPipeline := append(pipeline, bson.M{"$count": "total"})
	countCursor, err := r.mutesCollection.Aggregate(ctx, countPipeline)
	if err != nil {
		r.logger.WithError(err).Error("Failed to count muted users")
		return nil, err
	}
	defer countCursor.Close(ctx)

	var totalResult []bson.M
	if err := countCursor.All(ctx, &totalResult); err != nil {
		return nil, err
	}

	var total int64
	if len(totalResult) > 0 {
		if count, ok := totalResult[0]["total"].(int32); ok {
			total = int64(count)
		}
	}

	// Add pagination to pipeline
	skip := (params.Page - 1) * params.Limit
	pipeline = append(pipeline,
		bson.M{"$skip": skip},
		bson.M{"$limit": params.Limit},
		bson.M{"$replaceRoot": bson.M{"newRoot": "$muted_user"}},
	)

	cursor, err := r.mutesCollection.Aggregate(ctx, pipeline)
	if err != nil {
		r.logger.WithError(err).Error("Failed to get muted users")
		return nil, err
	}
	defer cursor.Close(ctx)

	var users []*models.User
	if err := cursor.All(ctx, &users); err != nil {
		r.logger.WithError(err).Error("Failed to decode muted users")
		return nil, err
	}

	return &utils.PaginationResult{
		Data:       users,
		Pagination: utils.CalculatePaginationMeta(params.Page, params.Limit, total),
	}, nil
}

// List operations

// CreateList creates a user list
func (r *userRepository) CreateList(ctx context.Context, list *models.UserList) error {
	if list.ID.IsZero() {
		list.ID = primitive.NewObjectID()
	}

	_, err := r.listsCollection.InsertOne(ctx, list)
	if err != nil {
		r.logger.WithError(err).Error("Failed to create list")
		return err
	}

	return nil
}

// GetList retrieves a list by ID
func (r *userRepository) GetList(ctx context.Context, listID primitive.ObjectID) (*models.UserList, error) {
	var list models.UserList
	err := r.listsCollection.FindOne(ctx, bson.M{"_id": listID}).Decode(&list)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			return nil, errors.New("list not found")
		}
		r.logger.WithError(err).WithField("list_id", listID).Error("Failed to get list")
		return nil, err
	}

	return &list, nil
}

// UpdateList updates a list
func (r *userRepository) UpdateList(ctx context.Context, list *models.UserList) error {
	filter := bson.M{"_id": list.ID}
	update := bson.M{"$set": list}

	result, err := r.listsCollection.UpdateOne(ctx, filter, update)
	if err != nil {
		r.logger.WithError(err).WithField("list_id", list.ID).Error("Failed to update list")
		return err
	}

	if result.MatchedCount == 0 {
		return errors.New("list not found")
	}

	return nil
}

// DeleteList deletes a list
func (r *userRepository) DeleteList(ctx context.Context, listID primitive.ObjectID) error {
	// Start a transaction to delete list and its members
	session, err := r.database.Client().StartSession()
	if err != nil {
		return err
	}
	defer session.EndSession(context.Background())

	_, err = session.WithTransaction(context.Background(), func(sc mongo.SessionContext) (interface{}, error) {
		// Delete the list
		listResult, err := r.listsCollection.DeleteOne(sc, bson.M{"_id": listID})
		if err != nil {
			return nil, err
		}

		if listResult.DeletedCount == 0 {
			return nil, errors.New("list not found")
		}

		// Delete all list members
		_, err = r.listMembersCollection.DeleteMany(sc, bson.M{"list_id": listID})
		return nil, err
	})

	if err != nil {
		r.logger.WithError(err).WithField("list_id", listID).Error("Failed to delete list")
		return err
	}

	return nil
}

// GetUserLists gets lists owned by a user
func (r *userRepository) GetUserLists(ctx context.Context, userID primitive.ObjectID, params *utils.PaginationParams) (*utils.PaginationResult, error) {
	filter := bson.M{"owner_id": userID}

	// Count total documents
	total, err := r.listsCollection.CountDocuments(ctx, filter)
	if err != nil {
		r.logger.WithError(err).Error("Failed to count user lists")
		return nil, err
	}

	// Calculate skip
	skip := (params.Page - 1) * params.Limit

	// Find options
	findOptions := options.Find().
		SetSkip(int64(skip)).
		SetLimit(int64(params.Limit)).
		SetSort(bson.M{"created_at": -1})

	cursor, err := r.listsCollection.Find(ctx, filter, findOptions)
	if err != nil {
		r.logger.WithError(err).Error("Failed to get user lists")
		return nil, err
	}
	defer cursor.Close(ctx)

	var lists []*models.UserList
	if err := cursor.All(ctx, &lists); err != nil {
		r.logger.WithError(err).Error("Failed to decode user lists")
		return nil, err
	}

	return &utils.PaginationResult{
		Data:       lists,
		Pagination: utils.CalculatePaginationMeta(params.Page, params.Limit, total),
	}, nil
}

// AddListMember adds a member to a list
func (r *userRepository) AddListMember(ctx context.Context, member *models.ListMember) error {
	if member.ID.IsZero() {
		member.ID = primitive.NewObjectID()
	}

	_, err := r.listMembersCollection.InsertOne(ctx, member)
	if err != nil {
		if mongo.IsDuplicateKeyError(err) {
			return errors.New("user already in list")
		}
		r.logger.WithError(err).Error("Failed to add list member")
		return err
	}

	// Update list members count
	filter := bson.M{"_id": member.ListID}
	update := bson.M{"$inc": bson.M{"members_count": 1}}
	_, err = r.listsCollection.UpdateOne(ctx, filter, update)
	if err != nil {
		r.logger.WithError(err).Error("Failed to update list members count")
	}

	return nil
}

// RemoveListMember removes a member from a list
func (r *userRepository) RemoveListMember(ctx context.Context, listID, userID primitive.ObjectID) error {
	filter := bson.M{
		"list_id": listID,
		"user_id": userID,
	}

	result, err := r.listMembersCollection.DeleteOne(ctx, filter)
	if err != nil {
		r.logger.WithError(err).Error("Failed to remove list member")
		return err
	}

	if result.DeletedCount == 0 {
		return errors.New("user not in list")
	}

	// Update list members count
	listFilter := bson.M{"_id": listID}
	update := bson.M{"$inc": bson.M{"members_count": -1}}
	_, err = r.listsCollection.UpdateOne(ctx, listFilter, update)
	if err != nil {
		r.logger.WithError(err).Error("Failed to update list members count")
	}

	return nil
}

// GetListMembers gets members of a list
func (r *userRepository) GetListMembers(ctx context.Context, listID primitive.ObjectID, params *utils.PaginationParams) (*utils.PaginationResult, error) {
	// Pipeline to get list members with user details
	pipeline := []bson.M{
		{"$match": bson.M{"list_id": listID}},
		{"$lookup": bson.M{
			"from":         constants.UsersCollection,
			"localField":   "user_id",
			"foreignField": "_id",
			"as":           "user",
		}},
		{"$unwind": "$user"},
		{"$match": bson.M{"user.is_active": true}},
		{"$sort": bson.M{"added_at": -1}},
	}

	// Count total
	countPipeline := append(pipeline, bson.M{"$count": "total"})
	countCursor, err := r.listMembersCollection.Aggregate(ctx, countPipeline)
	if err != nil {
		r.logger.WithError(err).Error("Failed to count list members")
		return nil, err
	}
	defer countCursor.Close(ctx)

	var totalResult []bson.M
	if err := countCursor.All(ctx, &totalResult); err != nil {
		return nil, err
	}

	var total int64
	if len(totalResult) > 0 {
		if count, ok := totalResult[0]["total"].(int32); ok {
			total = int64(count)
		}
	}

	// Add pagination to pipeline
	skip := (params.Page - 1) * params.Limit
	pipeline = append(pipeline,
		bson.M{"$skip": skip},
		bson.M{"$limit": params.Limit},
		bson.M{"$replaceRoot": bson.M{"newRoot": "$user"}},
	)

	cursor, err := r.listMembersCollection.Aggregate(ctx, pipeline)
	if err != nil {
		r.logger.WithError(err).Error("Failed to get list members")
		return nil, err
	}
	defer cursor.Close(ctx)

	var users []*models.User
	if err := cursor.All(ctx, &users); err != nil {
		r.logger.WithError(err).Error("Failed to decode list members")
		return nil, err
	}

	return &utils.PaginationResult{
		Data:       users,
		Pagination: utils.CalculatePaginationMeta(params.Page, params.Limit, total),
	}, nil
}

// Admin operations

// GetAll gets all users (admin only)
func (r *userRepository) GetAll(ctx context.Context, params *utils.PaginationParams, filter string) (*utils.PaginationResult, error) {
	// Build filter
	mongoFilter := bson.M{}

	// Apply filters based on filter string
	switch filter {
	case "active":
		mongoFilter["is_active"] = true
	case "inactive":
		mongoFilter["is_active"] = false
	case "verified":
		mongoFilter["is_verified"] = true
	case "suspended":
		mongoFilter["is_suspended"] = true
	}

	// Count total documents
	total, err := r.usersCollection.CountDocuments(ctx, mongoFilter)
	if err != nil {
		r.logger.WithError(err).Error("Failed to count all users")
		return nil, err
	}

	// Calculate skip
	skip := (params.Page - 1) * params.Limit

	// Find options
	findOptions := options.Find().
		SetSkip(int64(skip)).
		SetLimit(int64(params.Limit)).
		SetSort(bson.M{"created_at": -1})

	cursor, err := r.usersCollection.Find(ctx, mongoFilter, findOptions)
	if err != nil {
		r.logger.WithError(err).Error("Failed to get all users")
		return nil, err
	}
	defer cursor.Close(ctx)

	var users []*models.User
	if err := cursor.All(ctx, &users); err != nil {
		r.logger.WithError(err).Error("Failed to decode all users")
		return nil, err
	}

	return &utils.PaginationResult{
		Data:       users,
		Pagination: utils.CalculatePaginationMeta(params.Page, params.Limit, total),
	}, nil
}

// Suspend suspends a user
func (r *userRepository) Suspend(ctx context.Context, userID primitive.ObjectID, until *time.Time) error {
	filter := bson.M{"_id": userID}
	update := bson.M{
		"$set": bson.M{
			"is_suspended":    true,
			"suspended_until": until,
		},
	}

	result, err := r.usersCollection.UpdateOne(ctx, filter, update)
	if err != nil {
		r.logger.WithError(err).WithField("user_id", userID).Error("Failed to suspend user")
		return err
	}

	if result.MatchedCount == 0 {
		return errors.New("user not found")
	}

	return nil
}

// Unsuspend unsuspends a user
func (r *userRepository) Unsuspend(ctx context.Context, userID primitive.ObjectID) error {
	filter := bson.M{"_id": userID}
	update := bson.M{
		"$set": bson.M{
			"is_suspended": false,
		},
		"$unset": bson.M{
			"suspended_until": "",
		},
	}

	result, err := r.usersCollection.UpdateOne(ctx, filter, update)
	if err != nil {
		r.logger.WithError(err).WithField("user_id", userID).Error("Failed to unsuspend user")
		return err
	}

	if result.MatchedCount == 0 {
		return errors.New("user not found")
	}

	return nil
}

// Ban bans a user
func (r *userRepository) Ban(ctx context.Context, userID primitive.ObjectID, until *time.Time) error {
	filter := bson.M{"_id": userID}
	update := bson.M{
		"$set": bson.M{
			"is_banned":    true,
			"banned_until": until,
			"is_active":    false,
		},
	}

	result, err := r.usersCollection.UpdateOne(ctx, filter, update)
	if err != nil {
		r.logger.WithError(err).WithField("user_id", userID).Error("Failed to ban user")
		return err
	}

	if result.MatchedCount == 0 {
		return errors.New("user not found")
	}

	return nil
}

// Unban unbans a user
func (r *userRepository) Unban(ctx context.Context, userID primitive.ObjectID) error {
	filter := bson.M{"_id": userID}
	update := bson.M{
		"$set": bson.M{
			"is_active": true,
		},
		"$unset": bson.M{
			"is_banned":    "",
			"banned_until": "",
		},
	}

	result, err := r.usersCollection.UpdateOne(ctx, filter, update)
	if err != nil {
		r.logger.WithError(err).WithField("user_id", userID).Error("Failed to unban user")
		return err
	}

	if result.MatchedCount == 0 {
		return errors.New("user not found")
	}

	return nil
}
