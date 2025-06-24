package services

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	"go.mongodb.org/mongo-driver/bson/primitive"
	"golang.org/x/crypto/bcrypt"

	"onthread/internal/models"
	"onthread/internal/repository"
	"onthread/internal/utils"
	"onthread/pkg/errors"
	"onthread/pkg/logger"
)

// UserService interface defines all user-related operations
type UserService interface {
	// User CRUD operations
	GetUserByID(ctx context.Context, userID primitive.ObjectID) (*models.User, error)
	GetUserByUsername(ctx context.Context, username string, currentUserID *primitive.ObjectID) (*models.User, error)
	GetUserByEmail(ctx context.Context, email string) (*models.User, error)
	CreateUser(ctx context.Context, req *CreateUserRequest) (*models.User, error)
	UpdateProfile(ctx context.Context, userID primitive.ObjectID, req *UpdateProfileRequest) (*models.User, error)
	UpdateAvatar(ctx context.Context, userID primitive.ObjectID, avatarURL string) (*models.User, error)
	UpdateCover(ctx context.Context, userID primitive.ObjectID, coverURL string) (*models.User, error)
	RemoveAvatar(ctx context.Context, userID primitive.ObjectID) (*models.User, error)
	RemoveCover(ctx context.Context, userID primitive.ObjectID) (*models.User, error)

	// User search and discovery
	SearchUsers(ctx context.Context, query string, params *utils.PaginationParams) (*utils.PaginationResult, error)
	GetPopularUsers(ctx context.Context, params *utils.PaginationParams) (*utils.PaginationResult, error)
	GetUserSuggestions(ctx context.Context, userID primitive.ObjectID) ([]*models.User, error)

	// User settings
	GetSettings(ctx context.Context, userID primitive.ObjectID) (*models.UserSettings, error)
	UpdateSettings(ctx context.Context, userID primitive.ObjectID, settings *models.UserSettings) (*models.UserSettings, error)
	GetPrivacySettings(ctx context.Context, userID primitive.ObjectID) (*PrivacySettings, error)
	UpdatePrivacySettings(ctx context.Context, userID primitive.ObjectID, req *PrivacySettingsRequest) error

	// Follow system
	FollowUser(ctx context.Context, followerID primitive.ObjectID, username string) (*FollowResult, error)
	UnfollowUser(ctx context.Context, followerID primitive.ObjectID, username string) error
	GetFollowers(ctx context.Context, username string, currentUserID *primitive.ObjectID, params *utils.PaginationParams) (*utils.PaginationResult, error)
	GetFollowing(ctx context.Context, username string, currentUserID *primitive.ObjectID, params *utils.PaginationParams) (*utils.PaginationResult, error)
	GetFollowRequests(ctx context.Context, userID primitive.ObjectID, params *utils.PaginationParams) (*utils.PaginationResult, error)
	AcceptFollowRequest(ctx context.Context, userID, requesterID primitive.ObjectID) error
	DeclineFollowRequest(ctx context.Context, userID, requesterID primitive.ObjectID) error

	// Block and mute system
	BlockUser(ctx context.Context, blockerID primitive.ObjectID, username, reason string) error
	UnblockUser(ctx context.Context, blockerID primitive.ObjectID, username string) error
	GetBlockedUsers(ctx context.Context, userID primitive.ObjectID, params *utils.PaginationParams) (*utils.PaginationResult, error)
	MuteUser(ctx context.Context, userID primitive.ObjectID, username string, duration *time.Duration) error
	UnmuteUser(ctx context.Context, userID primitive.ObjectID, username string) error
	GetMutedUsers(ctx context.Context, userID primitive.ObjectID, params *utils.PaginationParams) (*utils.PaginationResult, error)

	// User content
	GetUserThreads(ctx context.Context, username string, currentUserID *primitive.ObjectID, params *utils.PaginationParams) (*utils.PaginationResult, error)
	GetUserReplies(ctx context.Context, username string, currentUserID *primitive.ObjectID, params *utils.PaginationParams) (*utils.PaginationResult, error)
	GetUserMedia(ctx context.Context, username string, currentUserID *primitive.ObjectID, params *utils.PaginationParams) (*utils.PaginationResult, error)
	GetUserLikes(ctx context.Context, username string, currentUserID *primitive.ObjectID, params *utils.PaginationParams) (*utils.PaginationResult, error)

	// Account management
	DeactivateAccount(ctx context.Context, userID primitive.ObjectID, password, reason string) error
	ReactivateAccount(ctx context.Context, userID primitive.ObjectID, password string) error
	DeleteAccount(ctx context.Context, userID primitive.ObjectID, password string) error
	RequestDataExport(ctx context.Context, userID primitive.ObjectID) (string, error)

	// Analytics and activity
	GetUserAnalytics(ctx context.Context, userID primitive.ObjectID) (*UserAnalytics, error)
	GetUserActivity(ctx context.Context, userID primitive.ObjectID, params *utils.PaginationParams) (*utils.PaginationResult, error)

	// Lists management
	GetUserLists(ctx context.Context, userID primitive.ObjectID, params *utils.PaginationParams) (*utils.PaginationResult, error)
	CreateList(ctx context.Context, userID primitive.ObjectID, req *CreateListRequest) (*models.UserList, error)
	GetList(ctx context.Context, userID, listID primitive.ObjectID) (*models.UserList, error)
	UpdateList(ctx context.Context, userID, listID primitive.ObjectID, req *UpdateListRequest) (*models.UserList, error)
	DeleteList(ctx context.Context, userID, listID primitive.ObjectID) error
	AddListMember(ctx context.Context, userID, listID primitive.ObjectID, username string) error
	RemoveListMember(ctx context.Context, userID, listID, memberID primitive.ObjectID) error
	GetListMembers(ctx context.Context, userID, listID primitive.ObjectID, params *utils.PaginationParams) (*utils.PaginationResult, error)
	FollowList(ctx context.Context, userID, listID primitive.ObjectID) error
	UnfollowList(ctx context.Context, userID, listID primitive.ObjectID) error

	// Verification
	RequestVerification(ctx context.Context, userID primitive.ObjectID, req *VerificationRequest) error
	GetVerificationStatus(ctx context.Context, userID primitive.ObjectID) (*VerificationStatus, error)

	// Admin operations
	GetAllUsers(ctx context.Context, params *utils.PaginationParams, filter string) (*utils.PaginationResult, error)
	VerifyUser(ctx context.Context, userID, adminID primitive.ObjectID, badgeType, reason string) error
	UnverifyUser(ctx context.Context, userID, adminID primitive.ObjectID, reason string) error
	SuspendUser(ctx context.Context, userID, adminID primitive.ObjectID, reason string, duration *time.Duration) error
	UnsuspendUser(ctx context.Context, userID, adminID primitive.ObjectID, reason string) error
	BanUser(ctx context.Context, userID, adminID primitive.ObjectID, reason string, duration *time.Duration) error
	UnbanUser(ctx context.Context, userID, adminID primitive.ObjectID, reason string) error
	GetUserActivityAdmin(ctx context.Context, userID primitive.ObjectID, params *utils.PaginationParams, filter string) (*utils.PaginationResult, error)
}

// Request/Response structs
type CreateUserRequest struct {
	Username    string `json:"username" validate:"required,min=3,max=30"`
	Email       string `json:"email" validate:"required,email"`
	Password    string `json:"password" validate:"required,min=8"`
	DisplayName string `json:"display_name" validate:"max=50"`
	Bio         string `json:"bio" validate:"max=500"`
}

type UpdateProfileRequest struct {
	DisplayName *string           `json:"display_name,omitempty"`
	Bio         *string           `json:"bio,omitempty"`
	Location    *string           `json:"location,omitempty"`
	Website     *string           `json:"website,omitempty"`
	Links       []models.UserLink `json:"links,omitempty"`
}

type PrivacySettingsRequest struct {
	IsPrivate            bool `json:"is_private"`
	ShowActivity         bool `json:"show_activity"`
	AllowTagging         bool `json:"allow_tagging"`
	AllowMessageRequests bool `json:"allow_message_requests"`
}

type PrivacySettings struct {
	IsPrivate            bool `json:"is_private"`
	ShowActivity         bool `json:"show_activity"`
	AllowTagging         bool `json:"allow_tagging"`
	AllowMessageRequests bool `json:"allow_message_requests"`
}

type FollowResult struct {
	IsPending  bool      `json:"is_pending"`
	FollowedAt time.Time `json:"followed_at"`
}

type CreateListRequest struct {
	Name        string `json:"name" validate:"required,max=50"`
	Description string `json:"description" validate:"max=200"`
	IsPrivate   bool   `json:"is_private"`
}

type UpdateListRequest struct {
	Name        *string `json:"name,omitempty"`
	Description *string `json:"description,omitempty"`
	IsPrivate   *bool   `json:"is_private,omitempty"`
}

type VerificationStatus struct {
	Status      string     `json:"status"`
	RequestedAt time.Time  `json:"requested_at"`
	ReviewedAt  *time.Time `json:"reviewed_at,omitempty"`
	Reason      string     `json:"reason,omitempty"`
}

type UserAnalytics struct {
	TotalThreads   int64           `json:"total_threads"`
	TotalLikes     int64           `json:"total_likes"`
	TotalReposts   int64           `json:"total_reposts"`
	TotalFollowers int64           `json:"total_followers"`
	TotalFollowing int64           `json:"total_following"`
	ProfileViews   int64           `json:"profile_views"`
	ThreadViews    int64           `json:"thread_views"`
	EngagementRate float64         `json:"engagement_rate"`
	TopHashtags    []string        `json:"top_hashtags"`
	ActivityTrend  []DailyActivity `json:"activity_trend"`
}

type DailyActivity struct {
	Date    time.Time `json:"date"`
	Threads int64     `json:"threads"`
	Likes   int64     `json:"likes"`
	Reposts int64     `json:"reposts"`
}

// UserRepository interface for database operations
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
type VerificationEvidence struct {
	Type string `json:"type" validate:"required"`
	URL  string `json:"url" validate:"required,url"`
}

type VerificationRequest struct {
	Category    string                 `json:"category"`
	Description string                 `json:"description"`
	Evidence    []VerificationEvidence `json:"evidence"`
}

// Implementation
type userService struct {
	userRepo   UserRepository
	threadRepo repository.ThreadRepository
	logger     *logger.Logger
}

func NewUserService(userRepo UserRepository, threadRepo repository.ThreadRepository) UserService {
	return &userService{
		userRepo:   userRepo,
		threadRepo: threadRepo,
		logger:     logger.WithComponent("UserService"),
	}
}

// GetUserByID retrieves a user by ID
func (s *userService) GetUserByID(ctx context.Context, userID primitive.ObjectID) (*models.User, error) {
	user, err := s.userRepo.GetByID(ctx, userID)
	if err != nil {
		s.logger.WithError(err).WithField("user_id", userID).Error("Failed to get user by ID")
		return nil, errors.NewNotFoundError("User not found")
	}
	return user, nil
}

// GetUserByUsername retrieves a user by username
func (s *userService) GetUserByUsername(ctx context.Context, username string, currentUserID *primitive.ObjectID) (*models.User, error) {
	user, err := s.userRepo.GetByUsername(ctx, username)
	if err != nil {
		s.logger.WithError(err).WithField("username", username).Error("Failed to get user by username")
		return nil, errors.NewNotFoundError("User not found")
	}

	// Check if user is private and current user is not following
	if user.IsPrivate && currentUserID != nil {
		if *currentUserID != user.ID {
			follow, err := s.userRepo.GetFollow(ctx, *currentUserID, user.ID)
			if err != nil || !follow.IsAccepted {
				// Return limited profile for private users
				return &models.User{
					ID:             user.ID,
					Username:       user.Username,
					DisplayName:    user.DisplayName,
					ProfilePicture: user.ProfilePicture,
					IsPrivate:      user.IsPrivate,
					IsVerified:     user.IsVerified,
					FollowersCount: user.FollowersCount,
					FollowingCount: user.FollowingCount,
				}, nil
			}
		}
	}

	return user, nil
}

// GetUserByEmail retrieves a user by email
func (s *userService) GetUserByEmail(ctx context.Context, email string) (*models.User, error) {
	user, err := s.userRepo.GetByEmail(ctx, email)
	if err != nil {
		s.logger.WithError(err).WithField("email", email).Error("Failed to get user by email")
		return nil, errors.NewNotFoundError("User not found")
	}
	return user, nil
}

// CreateUser creates a new user
func (s *userService) CreateUser(ctx context.Context, req *CreateUserRequest) (*models.User, error) {
	// Check if username already exists
	existingUser, _ := s.userRepo.GetByUsername(ctx, req.Username)
	if existingUser != nil {
		return nil, errors.NewConflictError("Username already exists")
	}

	// Check if email already exists
	existingUser, _ = s.userRepo.GetByEmail(ctx, req.Email)
	if existingUser != nil {
		return nil, errors.NewConflictError("Email already exists")
	}

	// Hash password
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		s.logger.WithError(err).Error("Failed to hash password")
		return nil, errors.NewInternalError("Failed to create user", err)
	}

	// Generate verification token
	tokenBytes := make([]byte, 32)
	if _, err := rand.Read(tokenBytes); err != nil {
		s.logger.WithError(err).Error("Failed to generate verification token")
		return nil, errors.NewInternalError("Failed to create user", err)
	}
	verificationToken := hex.EncodeToString(tokenBytes)

	user := &models.User{
		ID:           primitive.NewObjectID(),
		Username:     strings.ToLower(req.Username),
		Email:        strings.ToLower(req.Email),
		PasswordHash: string(hashedPassword),
		DisplayName:  req.DisplayName,
		Bio:          req.Bio,
		IsActive:     true,
		JoinedAt:     time.Now(),
		LastActiveAt: time.Now(),
		Settings: models.UserSettings{
			Language:             "en",
			Theme:                "light",
			EmailNotifications:   true,
			PushNotifications:    true,
			ShowActivity:         true,
			AllowMessageRequests: true,
		},
		Metadata: models.UserMetadata{
			EmailVerified:     false,
			VerificationToken: verificationToken,
		},
	}

	if err := s.userRepo.Create(ctx, user); err != nil {
		s.logger.WithError(err).WithField("username", req.Username).Error("Failed to create user")
		return nil, errors.NewInternalError("Failed to create user", err)
	}

	s.logger.WithField("user_id", user.ID).Info("User created successfully")
	return user, nil
}

// UpdateProfile updates user profile information
func (s *userService) UpdateProfile(ctx context.Context, userID primitive.ObjectID, req *UpdateProfileRequest) (*models.User, error) {
	user, err := s.userRepo.GetByID(ctx, userID)
	if err != nil {
		return nil, errors.NewNotFoundError("User not found")
	}

	// Update fields if provided
	if req.DisplayName != nil {
		user.DisplayName = *req.DisplayName
	}
	if req.Bio != nil {
		user.Bio = *req.Bio
	}
	if req.Location != nil {
		user.Location = *req.Location
	}
	if req.Website != nil {
		user.Website = *req.Website
	}
	if req.Links != nil {
		user.Links = req.Links
	}

	if err := s.userRepo.Update(ctx, user); err != nil {
		s.logger.WithError(err).WithField("user_id", userID).Error("Failed to update profile")
		return nil, errors.NewInternalError("Failed to update profile", err)
	}

	s.logger.WithField("user_id", userID).Info("Profile updated successfully")
	return user, nil
}

// UpdateAvatar updates user avatar
func (s *userService) UpdateAvatar(ctx context.Context, userID primitive.ObjectID, avatarURL string) (*models.User, error) {
	user, err := s.userRepo.GetByID(ctx, userID)
	if err != nil {
		return nil, errors.NewNotFoundError("User not found")
	}

	user.ProfilePicture = avatarURL

	if err := s.userRepo.Update(ctx, user); err != nil {
		s.logger.WithError(err).WithField("user_id", userID).Error("Failed to update avatar")
		return nil, errors.NewInternalError("Failed to update avatar", err)
	}

	return user, nil
}

// UpdateCover updates user cover image
func (s *userService) UpdateCover(ctx context.Context, userID primitive.ObjectID, coverURL string) (*models.User, error) {
	user, err := s.userRepo.GetByID(ctx, userID)
	if err != nil {
		return nil, errors.NewNotFoundError("User not found")
	}

	user.CoverImage = coverURL

	if err := s.userRepo.Update(ctx, user); err != nil {
		s.logger.WithError(err).WithField("user_id", userID).Error("Failed to update cover")
		return nil, errors.NewInternalError("Failed to update cover", err)
	}

	return user, nil
}

// RemoveAvatar removes user avatar
func (s *userService) RemoveAvatar(ctx context.Context, userID primitive.ObjectID) (*models.User, error) {
	user, err := s.userRepo.GetByID(ctx, userID)
	if err != nil {
		return nil, errors.NewNotFoundError("User not found")
	}

	user.ProfilePicture = ""

	if err := s.userRepo.Update(ctx, user); err != nil {
		s.logger.WithError(err).WithField("user_id", userID).Error("Failed to remove avatar")
		return nil, errors.NewInternalError("Failed to remove avatar", err)
	}

	return user, nil
}

// RemoveCover removes user cover image
func (s *userService) RemoveCover(ctx context.Context, userID primitive.ObjectID) (*models.User, error) {
	user, err := s.userRepo.GetByID(ctx, userID)
	if err != nil {
		return nil, errors.NewNotFoundError("User not found")
	}

	user.CoverImage = ""

	if err := s.userRepo.Update(ctx, user); err != nil {
		s.logger.WithError(err).WithField("user_id", userID).Error("Failed to remove cover")
		return nil, errors.NewInternalError("Failed to remove cover", err)
	}

	return user, nil
}

// SearchUsers searches for users
func (s *userService) SearchUsers(ctx context.Context, query string, params *utils.PaginationParams) (*utils.PaginationResult, error) {
	result, err := s.userRepo.Search(ctx, query, params)
	if err != nil {
		s.logger.WithError(err).WithField("query", query).Error("Failed to search users")
		return nil, errors.NewInternalError("Search failed", err)
	}
	return result, nil
}

// GetPopularUsers gets popular users
func (s *userService) GetPopularUsers(ctx context.Context, params *utils.PaginationParams) (*utils.PaginationResult, error) {
	result, err := s.userRepo.GetPopular(ctx, params)
	if err != nil {
		s.logger.WithError(err).Error("Failed to get popular users")
		return nil, errors.NewInternalError("Failed to get popular users", err)
	}
	return result, nil
}

// GetUserSuggestions gets user suggestions
func (s *userService) GetUserSuggestions(ctx context.Context, userID primitive.ObjectID) ([]*models.User, error) {
	suggestions, err := s.userRepo.GetSuggestions(ctx, userID, 10)
	if err != nil {
		s.logger.WithError(err).WithField("user_id", userID).Error("Failed to get user suggestions")
		return nil, errors.NewInternalError("Failed to get suggestions", err)
	}
	return suggestions, nil
}

// GetSettings retrieves user settings
func (s *userService) GetSettings(ctx context.Context, userID primitive.ObjectID) (*models.UserSettings, error) {
	user, err := s.userRepo.GetByID(ctx, userID)
	if err != nil {
		return nil, errors.NewNotFoundError("User not found")
	}
	return &user.Settings, nil
}

// UpdateSettings updates user settings
func (s *userService) UpdateSettings(ctx context.Context, userID primitive.ObjectID, settings *models.UserSettings) (*models.UserSettings, error) {
	user, err := s.userRepo.GetByID(ctx, userID)
	if err != nil {
		return nil, errors.NewNotFoundError("User not found")
	}

	user.Settings = *settings

	if err := s.userRepo.Update(ctx, user); err != nil {
		s.logger.WithError(err).WithField("user_id", userID).Error("Failed to update settings")
		return nil, errors.NewInternalError("Failed to update settings", err)
	}

	return &user.Settings, nil
}

// GetPrivacySettings retrieves privacy settings
func (s *userService) GetPrivacySettings(ctx context.Context, userID primitive.ObjectID) (*PrivacySettings, error) {
	user, err := s.userRepo.GetByID(ctx, userID)
	if err != nil {
		return nil, errors.NewNotFoundError("User not found")
	}

	return &PrivacySettings{
		IsPrivate:            user.IsPrivate,
		ShowActivity:         user.Settings.ShowActivity,
		AllowTagging:         user.Settings.AllowTagging,
		AllowMessageRequests: user.Settings.AllowMessageRequests,
	}, nil
}

// UpdatePrivacySettings updates privacy settings
func (s *userService) UpdatePrivacySettings(ctx context.Context, userID primitive.ObjectID, req *PrivacySettingsRequest) error {
	user, err := s.userRepo.GetByID(ctx, userID)
	if err != nil {
		return errors.NewNotFoundError("User not found")
	}

	user.IsPrivate = req.IsPrivate
	user.Settings.ShowActivity = req.ShowActivity
	user.Settings.AllowTagging = req.AllowTagging
	user.Settings.AllowMessageRequests = req.AllowMessageRequests

	if err := s.userRepo.Update(ctx, user); err != nil {
		s.logger.WithError(err).WithField("user_id", userID).Error("Failed to update privacy settings")
		return errors.NewInternalError("Failed to update privacy settings", err)
	}

	return nil
}

// FollowUser follows a user
func (s *userService) FollowUser(ctx context.Context, followerID primitive.ObjectID, username string) (*FollowResult, error) {
	// Get target user
	targetUser, err := s.userRepo.GetByUsername(ctx, username)
	if err != nil {
		return nil, errors.NewNotFoundError("User not found")
	}

	// Can't follow yourself
	if followerID == targetUser.ID {
		return nil, errors.NewBadRequestError("Cannot follow yourself")
	}

	// Check if already following
	existingFollow, _ := s.userRepo.GetFollow(ctx, followerID, targetUser.ID)
	if existingFollow != nil {
		return nil, errors.NewConflictError("Already following user")
	}

	// Check if blocked
	isBlocked, err := s.userRepo.IsBlocked(ctx, targetUser.ID, followerID)
	if err != nil {
		s.logger.WithError(err).Error("Failed to check block status")
	}
	if isBlocked {
		return nil, errors.NewForbiddenError("Cannot follow this user")
	}

	follow := &models.Follow{
		FollowerID: followerID,
		FollowedID: targetUser.ID,
		CreatedAt:  time.Now(),
		IsAccepted: !targetUser.IsPrivate, // Auto-accept for public accounts
	}

	if err := s.userRepo.CreateFollow(ctx, follow); err != nil {
		s.logger.WithError(err).Error("Failed to create follow")
		return nil, errors.NewInternalError("Failed to follow user", err)
	}

	// Update counts if accepted
	if follow.IsAccepted {
		s.userRepo.UpdateFollowCounts(ctx, followerID, 0, 1)
		s.userRepo.UpdateFollowCounts(ctx, targetUser.ID, 1, 0)
	}

	return &FollowResult{
		IsPending:  !follow.IsAccepted,
		FollowedAt: follow.CreatedAt,
	}, nil
}

// UnfollowUser unfollows a user
func (s *userService) UnfollowUser(ctx context.Context, followerID primitive.ObjectID, username string) error {
	// Get target user
	targetUser, err := s.userRepo.GetByUsername(ctx, username)
	if err != nil {
		return errors.NewNotFoundError("User not found")
	}

	// Check if following
	follow, err := s.userRepo.GetFollow(ctx, followerID, targetUser.ID)
	if err != nil || follow == nil {
		return errors.NewNotFoundError("Not following user")
	}

	if err := s.userRepo.DeleteFollow(ctx, followerID, targetUser.ID); err != nil {
		s.logger.WithError(err).Error("Failed to unfollow user")
		return errors.NewInternalError("Failed to unfollow user", err)
	}

	// Update counts if was accepted
	if follow.IsAccepted {
		s.userRepo.UpdateFollowCounts(ctx, followerID, 0, -1)
		s.userRepo.UpdateFollowCounts(ctx, targetUser.ID, -1, 0)
	}

	return nil
}

// GetFollowers gets user followers
func (s *userService) GetFollowers(ctx context.Context, username string, currentUserID *primitive.ObjectID, params *utils.PaginationParams) (*utils.PaginationResult, error) {
	user, err := s.userRepo.GetByUsername(ctx, username)
	if err != nil {
		return nil, errors.NewNotFoundError("User not found")
	}

	// Check privacy
	if user.IsPrivate && currentUserID != nil && *currentUserID != user.ID {
		follow, err := s.userRepo.GetFollow(ctx, *currentUserID, user.ID)
		if err != nil || !follow.IsAccepted {
			return nil, errors.NewForbiddenError("Cannot view followers of private account")
		}
	}

	result, err := s.userRepo.GetFollowers(ctx, user.ID, params)
	if err != nil {
		s.logger.WithError(err).Error("Failed to get followers")
		return nil, errors.NewInternalError("Failed to get followers", err)
	}

	return result, nil
}

// GetFollowing gets users being followed
func (s *userService) GetFollowing(ctx context.Context, username string, currentUserID *primitive.ObjectID, params *utils.PaginationParams) (*utils.PaginationResult, error) {
	user, err := s.userRepo.GetByUsername(ctx, username)
	if err != nil {
		return nil, errors.NewNotFoundError("User not found")
	}

	// Check privacy
	if user.IsPrivate && currentUserID != nil && *currentUserID != user.ID {
		follow, err := s.userRepo.GetFollow(ctx, *currentUserID, user.ID)
		if err != nil || !follow.IsAccepted {
			return nil, errors.NewForbiddenError("Cannot view following of private account")
		}
	}

	result, err := s.userRepo.GetFollowing(ctx, user.ID, params)
	if err != nil {
		s.logger.WithError(err).Error("Failed to get following")
		return nil, errors.NewInternalError("Failed to get following", err)
	}

	return result, nil
}

// GetFollowRequests gets pending follow requests
func (s *userService) GetFollowRequests(ctx context.Context, userID primitive.ObjectID, params *utils.PaginationParams) (*utils.PaginationResult, error) {
	result, err := s.userRepo.GetFollowRequests(ctx, userID, params)
	if err != nil {
		s.logger.WithError(err).Error("Failed to get follow requests")
		return nil, errors.NewInternalError("Failed to get follow requests", err)
	}
	return result, nil
}

// AcceptFollowRequest accepts a follow request
func (s *userService) AcceptFollowRequest(ctx context.Context, userID, requesterID primitive.ObjectID) error {
	if err := s.userRepo.AcceptFollowRequest(ctx, requesterID, userID); err != nil {
		s.logger.WithError(err).Error("Failed to accept follow request")
		return errors.NewInternalError("Failed to accept follow request", err)
	}

	// Update counts
	s.userRepo.UpdateFollowCounts(ctx, requesterID, 0, 1)
	s.userRepo.UpdateFollowCounts(ctx, userID, 1, 0)

	return nil
}

// DeclineFollowRequest declines a follow request
func (s *userService) DeclineFollowRequest(ctx context.Context, userID, requesterID primitive.ObjectID) error {
	if err := s.userRepo.DeclineFollowRequest(ctx, requesterID, userID); err != nil {
		s.logger.WithError(err).Error("Failed to decline follow request")
		return errors.NewInternalError("Failed to decline follow request", err)
	}
	return nil
}

// BlockUser blocks a user
func (s *userService) BlockUser(ctx context.Context, blockerID primitive.ObjectID, username, reason string) error {
	// Get target user
	targetUser, err := s.userRepo.GetByUsername(ctx, username)
	if err != nil {
		return errors.NewNotFoundError("User not found")
	}

	// Can't block yourself
	if blockerID == targetUser.ID {
		return errors.NewBadRequestError("Cannot block yourself")
	}

	block := &models.Block{
		BlockerID: blockerID,
		BlockedID: targetUser.ID,
		Reason:    reason,
		CreatedAt: time.Now(),
	}

	if err := s.userRepo.CreateBlock(ctx, block); err != nil {
		s.logger.WithError(err).Error("Failed to create block")
		return errors.NewInternalError("Failed to block user", err)
	}

	// Remove any existing follow relationships
	s.userRepo.DeleteFollow(ctx, blockerID, targetUser.ID)
	s.userRepo.DeleteFollow(ctx, targetUser.ID, blockerID)

	return nil
}

// UnblockUser unblocks a user
func (s *userService) UnblockUser(ctx context.Context, blockerID primitive.ObjectID, username string) error {
	// Get target user
	targetUser, err := s.userRepo.GetByUsername(ctx, username)
	if err != nil {
		return errors.NewNotFoundError("User not found")
	}

	if err := s.userRepo.DeleteBlock(ctx, blockerID, targetUser.ID); err != nil {
		s.logger.WithError(err).Error("Failed to unblock user")
		return errors.NewInternalError("Failed to unblock user", err)
	}

	return nil
}

// GetBlockedUsers gets blocked users
func (s *userService) GetBlockedUsers(ctx context.Context, userID primitive.ObjectID, params *utils.PaginationParams) (*utils.PaginationResult, error) {
	result, err := s.userRepo.GetBlockedUsers(ctx, userID, params)
	if err != nil {
		s.logger.WithError(err).Error("Failed to get blocked users")
		return nil, errors.NewInternalError("Failed to get blocked users", err)
	}
	return result, nil
}

// MuteUser mutes a user
func (s *userService) MuteUser(ctx context.Context, userID primitive.ObjectID, username string, duration *time.Duration) error {
	// Get target user
	targetUser, err := s.userRepo.GetByUsername(ctx, username)
	if err != nil {
		return errors.NewNotFoundError("User not found")
	}

	// Can't mute yourself
	if userID == targetUser.ID {
		return errors.NewBadRequestError("Cannot mute yourself")
	}

	var muteDuration *time.Time
	if duration != nil {
		until := time.Now().Add(*duration)
		muteDuration = &until
	}

	mute := &models.Mute{
		UserID:    userID,
		MutedID:   targetUser.ID,
		Duration:  muteDuration,
		CreatedAt: time.Now(),
	}

	if err := s.userRepo.CreateMute(ctx, mute); err != nil {
		s.logger.WithError(err).Error("Failed to create mute")
		return errors.NewInternalError("Failed to mute user", err)
	}

	return nil
}

// UnmuteUser unmutes a user
func (s *userService) UnmuteUser(ctx context.Context, userID primitive.ObjectID, username string) error {
	// Get target user
	targetUser, err := s.userRepo.GetByUsername(ctx, username)
	if err != nil {
		return errors.NewNotFoundError("User not found")
	}

	if err := s.userRepo.DeleteMute(ctx, userID, targetUser.ID); err != nil {
		s.logger.WithError(err).Error("Failed to unmute user")
		return errors.NewInternalError("Failed to unmute user", err)
	}

	return nil
}

// GetMutedUsers gets muted users
func (s *userService) GetMutedUsers(ctx context.Context, userID primitive.ObjectID, params *utils.PaginationParams) (*utils.PaginationResult, error) {
	result, err := s.userRepo.GetMutedUsers(ctx, userID, params)
	if err != nil {
		s.logger.WithError(err).Error("Failed to get muted users")
		return nil, errors.NewInternalError("Failed to get muted users", err)
	}
	return result, nil
}

// GetUserThreads gets threads by a user
func (s *userService) GetUserThreads(ctx context.Context, username string, currentUserID *primitive.ObjectID, params *utils.PaginationParams) (*utils.PaginationResult, error) {
	user, err := s.userRepo.GetByUsername(ctx, username)
	if err != nil {
		return nil, errors.NewNotFoundError("User not found")
	}

	// Check privacy and permissions
	if user.IsPrivate && currentUserID != nil && *currentUserID != user.ID {
		follow, err := s.userRepo.GetFollow(ctx, *currentUserID, user.ID)
		if err != nil || !follow.IsAccepted {
			return &utils.PaginationResult{
				Data:       []*models.Thread{},
				Pagination: utils.CalculatePaginationMeta(params.Page, params.Limit, 0),
			}, nil
		}
	}

	// This would typically call threadRepo.GetByUserID
	// For now, return empty result
	return &utils.PaginationResult{
		Data:       []*models.Thread{},
		Pagination: utils.CalculatePaginationMeta(params.Page, params.Limit, 0),
	}, nil
}

// GetUserReplies gets replies by a user
func (s *userService) GetUserReplies(ctx context.Context, username string, currentUserID *primitive.ObjectID, params *utils.PaginationParams) (*utils.PaginationResult, error) {
	user, err := s.userRepo.GetByUsername(ctx, username)
	if err != nil {
		return nil, errors.NewNotFoundError("User not found")
	}

	// Similar privacy checks as GetUserThreads
	if user.IsPrivate && currentUserID != nil && *currentUserID != user.ID {
		follow, err := s.userRepo.GetFollow(ctx, *currentUserID, user.ID)
		if err != nil || !follow.IsAccepted {
			return &utils.PaginationResult{
				Data:       []*models.Thread{},
				Pagination: utils.CalculatePaginationMeta(params.Page, params.Limit, 0),
			}, nil
		}
	}

	return &utils.PaginationResult{
		Data:       []*models.Thread{},
		Pagination: utils.CalculatePaginationMeta(params.Page, params.Limit, 0),
	}, nil
}

// GetUserMedia gets media posts by a user
func (s *userService) GetUserMedia(ctx context.Context, username string, currentUserID *primitive.ObjectID, params *utils.PaginationParams) (*utils.PaginationResult, error) {
	user, err := s.userRepo.GetByUsername(ctx, username)
	if err != nil {
		return nil, errors.NewNotFoundError("User not found")
	}

	// Similar privacy checks
	if user.IsPrivate && currentUserID != nil && *currentUserID != user.ID {
		follow, err := s.userRepo.GetFollow(ctx, *currentUserID, user.ID)
		if err != nil || !follow.IsAccepted {
			return &utils.PaginationResult{
				Data:       []*models.Thread{},
				Pagination: utils.CalculatePaginationMeta(params.Page, params.Limit, 0),
			}, nil
		}
	}

	return &utils.PaginationResult{
		Data:       []*models.Thread{},
		Pagination: utils.CalculatePaginationMeta(params.Page, params.Limit, 0),
	}, nil
}

// GetUserLikes gets threads liked by a user
func (s *userService) GetUserLikes(ctx context.Context, username string, currentUserID *primitive.ObjectID, params *utils.PaginationParams) (*utils.PaginationResult, error) {
	user, err := s.userRepo.GetByUsername(ctx, username)
	if err != nil {
		return nil, errors.NewNotFoundError("User not found")
	}

	// Likes are usually private unless user settings allow it
	if currentUserID == nil || *currentUserID != user.ID {
		if !user.Settings.ShowActivity {
			return &utils.PaginationResult{
				Data:       []*models.Thread{},
				Pagination: utils.CalculatePaginationMeta(params.Page, params.Limit, 0),
			}, nil
		}
	}

	return &utils.PaginationResult{
		Data:       []*models.Thread{},
		Pagination: utils.CalculatePaginationMeta(params.Page, params.Limit, 0),
	}, nil
}

// DeactivateAccount deactivates user account
func (s *userService) DeactivateAccount(ctx context.Context, userID primitive.ObjectID, password, reason string) error {
	user, err := s.userRepo.GetByID(ctx, userID)
	if err != nil {
		return errors.NewNotFoundError("User not found")
	}

	// Verify password
	if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(password)); err != nil {
		return errors.NewUnauthorizedError("Invalid password")
	}

	user.IsActive = false

	if err := s.userRepo.Update(ctx, user); err != nil {
		s.logger.WithError(err).WithField("user_id", userID).Error("Failed to deactivate account")
		return errors.NewInternalError("Failed to deactivate account", err)
	}

	s.logger.WithField("user_id", userID).WithField("reason", reason).Info("Account deactivated")
	return nil
}

// ReactivateAccount reactivates user account
func (s *userService) ReactivateAccount(ctx context.Context, userID primitive.ObjectID, password string) error {
	user, err := s.userRepo.GetByID(ctx, userID)
	if err != nil {
		return errors.NewNotFoundError("User not found")
	}

	// Verify password
	if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(password)); err != nil {
		return errors.NewUnauthorizedError("Invalid password")
	}

	user.IsActive = true

	if err := s.userRepo.Update(ctx, user); err != nil {
		s.logger.WithError(err).WithField("user_id", userID).Error("Failed to reactivate account")
		return errors.NewInternalError("Failed to reactivate account", err)
	}

	s.logger.WithField("user_id", userID).Info("Account reactivated")
	return nil
}

// DeleteAccount initiates account deletion
func (s *userService) DeleteAccount(ctx context.Context, userID primitive.ObjectID, password string) error {
	user, err := s.userRepo.GetByID(ctx, userID)
	if err != nil {
		return errors.NewNotFoundError("User not found")
	}

	// Verify password
	if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(password)); err != nil {
		return errors.NewUnauthorizedError("Invalid password")
	}

	// Mark for deletion (actual deletion would be handled by background job)
	user.IsActive = false
	// Add deletion timestamp to metadata or create separate deletion record

	if err := s.userRepo.Update(ctx, user); err != nil {
		s.logger.WithError(err).WithField("user_id", userID).Error("Failed to initiate account deletion")
		return errors.NewInternalError("Failed to delete account", err)
	}

	s.logger.WithField("user_id", userID).Info("Account deletion initiated")
	return nil
}

// RequestDataExport initiates data export for user
func (s *userService) RequestDataExport(ctx context.Context, userID primitive.ObjectID) (string, error) {
	// Generate export ID and queue export job
	exportID := primitive.NewObjectID().Hex()
	exportURL := fmt.Sprintf("/api/v1/users/export/%s", exportID)

	// In real implementation, this would queue a background job to generate the export
	s.logger.WithField("user_id", userID).WithField("export_id", exportID).Info("Data export requested")

	return exportURL, nil
}

// GetUserAnalytics gets user analytics
func (s *userService) GetUserAnalytics(ctx context.Context, userID primitive.ObjectID) (*UserAnalytics, error) {
	user, err := s.userRepo.GetByID(ctx, userID)
	if err != nil {
		return nil, errors.NewNotFoundError("User not found")
	}

	// In real implementation, this would aggregate data from various sources
	analytics := &UserAnalytics{
		TotalThreads:   user.ThreadsCount,
		TotalFollowers: user.FollowersCount,
		TotalFollowing: user.FollowingCount,
		ProfileViews:   0,
		ThreadViews:    0,
		EngagementRate: 0.0,
		TopHashtags:    []string{},
		ActivityTrend:  []DailyActivity{},
	}

	return analytics, nil
}

// GetUserActivity gets user activity history
func (s *userService) GetUserActivity(ctx context.Context, userID primitive.ObjectID, params *utils.PaginationParams) (*utils.PaginationResult, error) {
	// In real implementation, this would fetch from activity/audit logs
	return &utils.PaginationResult{
		Data:       []interface{}{},
		Pagination: utils.CalculatePaginationMeta(params.Page, params.Limit, 0),
	}, nil
}

// List management methods
func (s *userService) GetUserLists(ctx context.Context, userID primitive.ObjectID, params *utils.PaginationParams) (*utils.PaginationResult, error) {
	result, err := s.userRepo.GetUserLists(ctx, userID, params)
	if err != nil {
		s.logger.WithError(err).Error("Failed to get user lists")
		return nil, errors.NewInternalError("Failed to get user lists", err)
	}
	return result, nil
}

func (s *userService) CreateList(ctx context.Context, userID primitive.ObjectID, req *CreateListRequest) (*models.UserList, error) {
	list := &models.UserList{
		ID:          primitive.NewObjectID(),
		OwnerID:     userID,
		Name:        req.Name,
		Description: req.Description,
		IsPrivate:   req.IsPrivate,
		Members:     []primitive.ObjectID{},
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
	}

	if err := s.userRepo.CreateList(ctx, list); err != nil {
		s.logger.WithError(err).Error("Failed to create list")
		return nil, errors.NewInternalError("Failed to create list", err)
	}

	return list, nil
}

func (s *userService) GetList(ctx context.Context, userID, listID primitive.ObjectID) (*models.UserList, error) {
	list, err := s.userRepo.GetList(ctx, listID)
	if err != nil {
		return nil, errors.NewNotFoundError("List not found")
	}

	// Check ownership or privacy
	if list.OwnerID != userID && list.IsPrivate {
		return nil, errors.NewForbiddenError("Cannot access private list")
	}

	return list, nil
}

func (s *userService) UpdateList(ctx context.Context, userID, listID primitive.ObjectID, req *UpdateListRequest) (*models.UserList, error) {
	list, err := s.userRepo.GetList(ctx, listID)
	if err != nil {
		return nil, errors.NewNotFoundError("List not found")
	}

	if list.OwnerID != userID {
		return nil, errors.NewForbiddenError("Cannot modify list")
	}

	// Update fields if provided
	if req.Name != nil {
		list.Name = *req.Name
	}
	if req.Description != nil {
		list.Description = *req.Description
	}
	if req.IsPrivate != nil {
		list.IsPrivate = *req.IsPrivate
	}

	list.UpdatedAt = time.Now()

	if err := s.userRepo.UpdateList(ctx, list); err != nil {
		s.logger.WithError(err).Error("Failed to update list")
		return nil, errors.NewInternalError("Failed to update list", err)
	}

	return list, nil
}

func (s *userService) DeleteList(ctx context.Context, userID, listID primitive.ObjectID) error {
	list, err := s.userRepo.GetList(ctx, listID)
	if err != nil {
		return errors.NewNotFoundError("List not found")
	}

	if list.OwnerID != userID {
		return errors.NewForbiddenError("Cannot delete list")
	}

	if err := s.userRepo.DeleteList(ctx, listID); err != nil {
		s.logger.WithError(err).Error("Failed to delete list")
		return errors.NewInternalError("Failed to delete list", err)
	}

	return nil
}

func (s *userService) AddListMember(ctx context.Context, userID, listID primitive.ObjectID, username string) error {
	// Verify list ownership
	list, err := s.userRepo.GetList(ctx, listID)
	if err != nil {
		return errors.NewNotFoundError("List not found")
	}

	if list.OwnerID != userID {
		return errors.NewForbiddenError("Cannot modify list")
	}

	// Get target user
	targetUser, err := s.userRepo.GetByUsername(ctx, username)
	if err != nil {
		return errors.NewNotFoundError("User not found")
	}

	member := &models.ListMember{
		ListID:  listID,
		UserID:  targetUser.ID,
		AddedBy: userID,
		AddedAt: time.Now(),
	}

	if err := s.userRepo.AddListMember(ctx, member); err != nil {
		s.logger.WithError(err).Error("Failed to add list member")
		return errors.NewInternalError("Failed to add member to list", err)
	}

	return nil
}

func (s *userService) RemoveListMember(ctx context.Context, userID, listID, memberID primitive.ObjectID) error {
	// Verify list ownership
	list, err := s.userRepo.GetList(ctx, listID)
	if err != nil {
		return errors.NewNotFoundError("List not found")
	}

	if list.OwnerID != userID {
		return errors.NewForbiddenError("Cannot modify list")
	}

	if err := s.userRepo.RemoveListMember(ctx, listID, memberID); err != nil {
		s.logger.WithError(err).Error("Failed to remove list member")
		return errors.NewInternalError("Failed to remove member from list", err)
	}

	return nil
}

func (s *userService) GetListMembers(ctx context.Context, userID, listID primitive.ObjectID, params *utils.PaginationParams) (*utils.PaginationResult, error) {
	// Check list access
	list, err := s.userRepo.GetList(ctx, listID)
	if err != nil {
		return nil, errors.NewNotFoundError("List not found")
	}

	if list.OwnerID != userID && list.IsPrivate {
		return nil, errors.NewForbiddenError("Cannot access private list")
	}

	result, err := s.userRepo.GetListMembers(ctx, listID, params)
	if err != nil {
		s.logger.WithError(err).Error("Failed to get list members")
		return nil, errors.NewInternalError("Failed to get list members", err)
	}

	return result, nil
}

func (s *userService) FollowList(ctx context.Context, userID, listID primitive.ObjectID) error {
	// Check if list exists and is accessible
	list, err := s.userRepo.GetList(ctx, listID)
	if err != nil {
		return errors.NewNotFoundError("List not found")
	}

	if list.IsPrivate && list.OwnerID != userID {
		return errors.NewForbiddenError("Cannot follow private list")
	}

	// Implementation would create list follow record
	s.logger.WithField("user_id", userID).WithField("list_id", listID).Info("User followed list")
	return nil
}

func (s *userService) UnfollowList(ctx context.Context, userID, listID primitive.ObjectID) error {
	// Implementation would remove list follow record
	s.logger.WithField("user_id", userID).WithField("list_id", listID).Info("User unfollowed list")
	return nil
}

// Verification methods
func (s *userService) RequestVerification(ctx context.Context, userID primitive.ObjectID, req *VerificationRequest) error {
	user, err := s.userRepo.GetByID(ctx, userID)
	if err != nil {
		return errors.NewNotFoundError("User not found")
	}

	if user.IsVerified {
		return errors.NewConflictError("User is already verified")
	}

	// Implementation would create verification request record
	s.logger.WithField("user_id", userID).WithField("category", req.Category).Info("Verification request submitted")
	return nil
}

func (s *userService) GetVerificationStatus(ctx context.Context, userID primitive.ObjectID) (*VerificationStatus, error) {
	// Implementation would fetch verification status from database
	return &VerificationStatus{
		Status:      "pending",
		RequestedAt: time.Now(),
	}, nil
}

// Admin operations
func (s *userService) GetAllUsers(ctx context.Context, params *utils.PaginationParams, filter string) (*utils.PaginationResult, error) {
	result, err := s.userRepo.GetAll(ctx, params, filter)
	if err != nil {
		s.logger.WithError(err).Error("Failed to get all users")
		return nil, errors.NewInternalError("Failed to get users", err)
	}
	return result, nil
}

func (s *userService) VerifyUser(ctx context.Context, userID, adminID primitive.ObjectID, badgeType, reason string) error {
	user, err := s.userRepo.GetByID(ctx, userID)
	if err != nil {
		return errors.NewNotFoundError("User not found")
	}

	user.IsVerified = true
	if badgeType != "" {
		badge := models.Badge{
			Type:        badgeType,
			Name:        "Verified",
			Icon:        "verified",
			Color:       "#1DA1F2",
			Description: reason,
			AwardedAt:   time.Now(),
		}
		user.Badges = append(user.Badges, badge)
	}

	if err := s.userRepo.Update(ctx, user); err != nil {
		s.logger.WithError(err).Error("Failed to verify user")
		return errors.NewInternalError("Failed to verify user", err)
	}

	s.logger.WithFields(map[string]interface{}{
		"user_id":  userID,
		"admin_id": adminID,
		"reason":   reason,
	}).Info("User verified")

	return nil
}

func (s *userService) UnverifyUser(ctx context.Context, userID, adminID primitive.ObjectID, reason string) error {
	user, err := s.userRepo.GetByID(ctx, userID)
	if err != nil {
		return errors.NewNotFoundError("User not found")
	}

	user.IsVerified = false
	// Remove verification badges
	badges := []models.Badge{}
	for _, badge := range user.Badges {
		if badge.Type != "verified" {
			badges = append(badges, badge)
		}
	}
	user.Badges = badges

	if err := s.userRepo.Update(ctx, user); err != nil {
		s.logger.WithError(err).Error("Failed to unverify user")
		return errors.NewInternalError("Failed to unverify user", err)
	}

	s.logger.WithFields(map[string]interface{}{
		"user_id":  userID,
		"admin_id": adminID,
		"reason":   reason,
	}).Info("User unverified")

	return nil
}

func (s *userService) SuspendUser(ctx context.Context, userID, adminID primitive.ObjectID, reason string, duration *time.Duration) error {
	user, err := s.userRepo.GetByID(ctx, userID)
	if err != nil {
		return errors.NewNotFoundError("User not found")
	}

	user.IsSuspended = true

	var until *time.Time
	if duration != nil {
		suspendUntil := time.Now().Add(*duration)
		until = &suspendUntil
	}

	if err := s.userRepo.Suspend(ctx, userID, until); err != nil {
		s.logger.WithError(err).Error("Failed to suspend user")
		return errors.NewInternalError("Failed to suspend user", err)
	}

	s.logger.WithFields(map[string]interface{}{
		"user_id":  userID,
		"admin_id": adminID,
		"reason":   reason,
		"duration": duration,
	}).Info("User suspended")

	return nil
}

func (s *userService) UnsuspendUser(ctx context.Context, userID, adminID primitive.ObjectID, reason string) error {
	if err := s.userRepo.Unsuspend(ctx, userID); err != nil {
		s.logger.WithError(err).Error("Failed to unsuspend user")
		return errors.NewInternalError("Failed to unsuspend user", err)
	}

	s.logger.WithFields(map[string]interface{}{
		"user_id":  userID,
		"admin_id": adminID,
		"reason":   reason,
	}).Info("User unsuspended")

	return nil
}

func (s *userService) BanUser(ctx context.Context, userID, adminID primitive.ObjectID, reason string, duration *time.Duration) error {
	var until *time.Time
	if duration != nil {
		banUntil := time.Now().Add(*duration)
		until = &banUntil
	}

	if err := s.userRepo.Ban(ctx, userID, until); err != nil {
		s.logger.WithError(err).Error("Failed to ban user")
		return errors.NewInternalError("Failed to ban user", err)
	}

	s.logger.WithFields(map[string]interface{}{
		"user_id":  userID,
		"admin_id": adminID,
		"reason":   reason,
		"duration": duration,
	}).Info("User banned")

	return nil
}

func (s *userService) UnbanUser(ctx context.Context, userID, adminID primitive.ObjectID, reason string) error {
	if err := s.userRepo.Unban(ctx, userID); err != nil {
		s.logger.WithError(err).Error("Failed to unban user")
		return errors.NewInternalError("Failed to unban user", err)
	}

	s.logger.WithFields(map[string]interface{}{
		"user_id":  userID,
		"admin_id": adminID,
		"reason":   reason,
	}).Info("User unbanned")

	return nil
}

func (s *userService) GetUserActivityAdmin(ctx context.Context, userID primitive.ObjectID, params *utils.PaginationParams, filter string) (*utils.PaginationResult, error) {
	// Implementation would fetch detailed admin view of user activity
	return &utils.PaginationResult{
		Data:       []interface{}{},
		Pagination: utils.CalculatePaginationMeta(params.Page, params.Limit, 0),
	}, nil
}
