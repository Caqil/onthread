package handlers

import (
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"go.mongodb.org/mongo-driver/bson/primitive"

	"onthread/internal/models"
	"onthread/internal/services"
	"onthread/internal/utils"
	"onthread/pkg/errors"
)

type UserHandler struct {
	userService services.UserService
	authService services.AuthService
}

func NewUserHandler(userService services.UserService, authService services.AuthService) *UserHandler {
	return &UserHandler{
		userService: userService,
		authService: authService,
	}
}

// GetUserByUsername returns user by username
func (h *UserHandler) GetUserByUsername(c *gin.Context) {
	username := c.Param("username")
	if username == "" {
		utils.BadRequest(c, "Username is required")
		return
	}

	// Get current user ID if authenticated
	var currentUserID *primitive.ObjectID
	if userID, exists := c.Get("user_id"); exists {
		id := userID.(primitive.ObjectID)
		currentUserID = &id
	}

	user, err := h.userService.GetUserByUsername(c.Request.Context(), username, currentUserID)
	if err != nil {
		if errors.IsAppError(err) {
			appErr := err.(*errors.AppError)
			utils.ErrorResponse(c, appErr.StatusCode, appErr.Code, appErr.Message)
		} else {
			utils.NotFound(c, "User not found")
		}
		return
	}

	utils.SuccessResponse(c, http.StatusOK, "User retrieved successfully", gin.H{
		"user": user,
	})
}

// SearchUsers searches for users
func (h *UserHandler) SearchUsers(c *gin.Context) {
	params := utils.GetPaginationParams(c)
	query := c.Query("q")

	if query == "" {
		utils.BadRequest(c, "Search query is required")
		return
	}

	result, err := h.userService.SearchUsers(c.Request.Context(), query, params)
	if err != nil {
		utils.InternalServerError(c, "Search failed")
		return
	}

	utils.SuccessResponseWithMeta(c, http.StatusOK, "Users found", result.Data, &utils.Meta{
		Pagination: result.Pagination,
	})
}

// GetSuggestions returns user suggestions
func (h *UserHandler) GetSuggestions(c *gin.Context) {
	userID, exists := c.Get("user_id")
	if !exists {
		// Return popular users for non-authenticated users
		result, err := h.userService.GetPopularUsers(c.Request.Context(), utils.GetPaginationParams(c))
		if err != nil {
			utils.InternalServerError(c, "Failed to get suggestions")
			return
		}

		utils.SuccessResponse(c, http.StatusOK, "User suggestions", gin.H{
			"users": result.Data,
		})
		return
	}

	suggestions, err := h.userService.GetUserSuggestions(c.Request.Context(), userID.(primitive.ObjectID))
	if err != nil {
		utils.InternalServerError(c, "Failed to get suggestions")
		return
	}

	utils.SuccessResponse(c, http.StatusOK, "User suggestions", gin.H{
		"users": suggestions,
	})
}

// GetProfile returns user's own profile
func (h *UserHandler) GetProfile(c *gin.Context) {
	userID, exists := c.Get("user_id")
	if !exists {
		utils.Unauthorized(c, "User not authenticated")
		return
	}

	user, err := h.userService.GetUserByID(c.Request.Context(), userID.(primitive.ObjectID))
	if err != nil {
		utils.NotFound(c, "User not found")
		return
	}

	utils.SuccessResponse(c, http.StatusOK, "Profile retrieved", gin.H{
		"user": user,
	})
}

// UpdateProfile updates user profile
func (h *UserHandler) UpdateProfile(c *gin.Context) {
	var req struct {
		DisplayName string            `json:"display_name" binding:"max=50"`
		Bio         string            `json:"bio" binding:"max=500"`
		Location    string            `json:"location" binding:"max=100"`
		Website     string            `json:"website" binding:"url_optional,max=200"`
		Links       []models.UserLink `json:"links"`
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

	user, err := h.userService.UpdateProfile(c.Request.Context(), userID.(primitive.ObjectID), &services.UpdateProfileRequest{
		DisplayName: &req.DisplayName,
		Bio:         &req.Bio,
		Location:    &req.Location,
		Website:     &req.Website,
		Links:       req.Links,
	})

	if err != nil {
		if errors.IsAppError(err) {
			appErr := err.(*errors.AppError)
			utils.ErrorResponse(c, appErr.StatusCode, appErr.Code, appErr.Message)
		} else {
			utils.InternalServerError(c, "Failed to update profile")
		}
		return
	}

	utils.SuccessResponse(c, http.StatusOK, "Profile updated successfully", gin.H{
		"user": user,
	})
}

// UpdateAvatar updates user avatar
func (h *UserHandler) UpdateAvatar(c *gin.Context) {
	var req struct {
		AvatarURL string `json:"avatar_url" binding:"required,url"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		utils.BadRequest(c, "Valid avatar URL is required")
		return
	}

	userID, exists := c.Get("user_id")
	if !exists {
		utils.Unauthorized(c, "User not authenticated")
		return
	}

	user, err := h.userService.UpdateAvatar(c.Request.Context(), userID.(primitive.ObjectID), req.AvatarURL)
	if err != nil {
		utils.InternalServerError(c, "Failed to update avatar")
		return
	}

	utils.SuccessResponse(c, http.StatusOK, "Avatar updated successfully", gin.H{
		"user": user,
	})
}

// UpdateCover updates user cover image
func (h *UserHandler) UpdateCover(c *gin.Context) {
	var req struct {
		CoverURL string `json:"cover_url" binding:"required,url"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		utils.BadRequest(c, "Valid cover URL is required")
		return
	}

	userID, exists := c.Get("user_id")
	if !exists {
		utils.Unauthorized(c, "User not authenticated")
		return
	}

	user, err := h.userService.UpdateCover(c.Request.Context(), userID.(primitive.ObjectID), req.CoverURL)
	if err != nil {
		utils.InternalServerError(c, "Failed to update cover")
		return
	}

	utils.SuccessResponse(c, http.StatusOK, "Cover updated successfully", gin.H{
		"user": user,
	})
}

// RemoveAvatar removes user avatar
func (h *UserHandler) RemoveAvatar(c *gin.Context) {
	userID, exists := c.Get("user_id")
	if !exists {
		utils.Unauthorized(c, "User not authenticated")
		return
	}

	_, err := h.userService.RemoveAvatar(c.Request.Context(), userID.(primitive.ObjectID))
	if err != nil {
		utils.InternalServerError(c, "Failed to remove avatar")
		return
	}

	utils.SuccessResponse(c, http.StatusOK, "Avatar removed successfully", nil)
}

// RemoveCover removes user cover image
func (h *UserHandler) RemoveCover(c *gin.Context) {
	userID, exists := c.Get("user_id")
	if !exists {
		utils.Unauthorized(c, "User not authenticated")
		return
	}

	_, err := h.userService.RemoveCover(c.Request.Context(), userID.(primitive.ObjectID))
	if err != nil {
		utils.InternalServerError(c, "Failed to remove cover")
		return
	}

	utils.SuccessResponse(c, http.StatusOK, "Cover removed successfully", nil)
}

// GetSettings returns user settings
func (h *UserHandler) GetSettings(c *gin.Context) {
	userID, exists := c.Get("user_id")
	if !exists {
		utils.Unauthorized(c, "User not authenticated")
		return
	}

	settings, err := h.userService.GetSettings(c.Request.Context(), userID.(primitive.ObjectID))
	if err != nil {
		utils.InternalServerError(c, "Failed to get settings")
		return
	}

	utils.SuccessResponse(c, http.StatusOK, "Settings retrieved", gin.H{
		"settings": settings,
	})
}

// UpdateSettings updates user settings
func (h *UserHandler) UpdateSettings(c *gin.Context) {
	var req models.UserSettings

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

	_, err := h.userService.UpdateSettings(c.Request.Context(), userID.(primitive.ObjectID), &req)
	if err != nil {
		utils.InternalServerError(c, "Failed to update settings")
		return
	}

	utils.SuccessResponse(c, http.StatusOK, "Settings updated successfully", nil)
}

// GetPrivacySettings returns privacy settings
func (h *UserHandler) GetPrivacySettings(c *gin.Context) {
	userID, exists := c.Get("user_id")
	if !exists {
		utils.Unauthorized(c, "User not authenticated")
		return
	}

	settings, err := h.userService.GetPrivacySettings(c.Request.Context(), userID.(primitive.ObjectID))
	if err != nil {
		utils.InternalServerError(c, "Failed to get privacy settings")
		return
	}

	utils.SuccessResponse(c, http.StatusOK, "Privacy settings retrieved", gin.H{
		"privacy": settings,
	})
}

// UpdatePrivacySettings updates privacy settings
func (h *UserHandler) UpdatePrivacySettings(c *gin.Context) {
	var req struct {
		IsPrivate            bool `json:"is_private"`
		ShowActivity         bool `json:"show_activity"`
		AllowTagging         bool `json:"allow_tagging"`
		AllowMessageRequests bool `json:"allow_message_requests"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		utils.BadRequest(c, "Invalid privacy settings")
		return
	}

	userID, exists := c.Get("user_id")
	if !exists {
		utils.Unauthorized(c, "User not authenticated")
		return
	}

	err := h.userService.UpdatePrivacySettings(c.Request.Context(), userID.(primitive.ObjectID), &services.PrivacySettingsRequest{
		IsPrivate:            req.IsPrivate,
		ShowActivity:         req.ShowActivity,
		AllowTagging:         req.AllowTagging,
		AllowMessageRequests: req.AllowMessageRequests,
	})

	if err != nil {
		utils.InternalServerError(c, "Failed to update privacy settings")
		return
	}

	utils.SuccessResponse(c, http.StatusOK, "Privacy settings updated successfully", nil)
}

// FollowUser follows a user
func (h *UserHandler) FollowUser(c *gin.Context) {
	username := c.Param("username")
	if username == "" {
		utils.BadRequest(c, "Username is required")
		return
	}

	userID, exists := c.Get("user_id")
	if !exists {
		utils.Unauthorized(c, "User not authenticated")
		return
	}

	result, err := h.userService.FollowUser(c.Request.Context(), userID.(primitive.ObjectID), username)
	if err != nil {
		if errors.IsAppError(err) {
			appErr := err.(*errors.AppError)
			utils.ErrorResponse(c, appErr.StatusCode, appErr.Code, appErr.Message)
		} else {
			utils.InternalServerError(c, "Failed to follow user")
		}
		return
	}

	message := "User followed successfully"
	if result.IsPending {
		message = "Follow request sent"
	}

	utils.SuccessResponse(c, http.StatusOK, message, gin.H{
		"is_pending":  result.IsPending,
		"followed_at": result.FollowedAt,
	})
}

// UnfollowUser unfollows a user
func (h *UserHandler) UnfollowUser(c *gin.Context) {
	username := c.Param("username")
	if username == "" {
		utils.BadRequest(c, "Username is required")
		return
	}

	userID, exists := c.Get("user_id")
	if !exists {
		utils.Unauthorized(c, "User not authenticated")
		return
	}

	err := h.userService.UnfollowUser(c.Request.Context(), userID.(primitive.ObjectID), username)
	if err != nil {
		if errors.IsAppError(err) {
			appErr := err.(*errors.AppError)
			utils.ErrorResponse(c, appErr.StatusCode, appErr.Code, appErr.Message)
		} else {
			utils.InternalServerError(c, "Failed to unfollow user")
		}
		return
	}

	utils.SuccessResponse(c, http.StatusOK, "User unfollowed successfully", nil)
}

// GetFollowers returns user's followers
func (h *UserHandler) GetFollowers(c *gin.Context) {
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

	result, err := h.userService.GetFollowers(c.Request.Context(), username, currentUserID, params)
	if err != nil {
		if errors.IsAppError(err) {
			appErr := err.(*errors.AppError)
			utils.ErrorResponse(c, appErr.StatusCode, appErr.Code, appErr.Message)
		} else {
			utils.InternalServerError(c, "Failed to get followers")
		}
		return
	}

	utils.SuccessResponseWithMeta(c, http.StatusOK, "Followers retrieved", result.Data, &utils.Meta{
		Pagination: result.Pagination,
	})
}

// GetFollowing returns users that the user is following
func (h *UserHandler) GetFollowing(c *gin.Context) {
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

	result, err := h.userService.GetFollowing(c.Request.Context(), username, currentUserID, params)
	if err != nil {
		if errors.IsAppError(err) {
			appErr := err.(*errors.AppError)
			utils.ErrorResponse(c, appErr.StatusCode, appErr.Code, appErr.Message)
		} else {
			utils.InternalServerError(c, "Failed to get following")
		}
		return
	}

	utils.SuccessResponseWithMeta(c, http.StatusOK, "Following retrieved", result.Data, &utils.Meta{
		Pagination: result.Pagination,
	})
}

// GetMyFollowers returns current user's followers
func (h *UserHandler) GetMyFollowers(c *gin.Context) {
	userID, exists := c.Get("user_id")
	if !exists {
		utils.Unauthorized(c, "User not authenticated")
		return
	}

	params := utils.GetPaginationParams(c)

	user, err := h.userService.GetUserByID(c.Request.Context(), userID.(primitive.ObjectID))
	if err != nil {
		utils.InternalServerError(c, "Failed to get user")
		return
	}

	result, err := h.userService.GetFollowers(c.Request.Context(), user.Username, nil, params)
	if err != nil {
		utils.InternalServerError(c, "Failed to get followers")
		return
	}

	utils.SuccessResponseWithMeta(c, http.StatusOK, "Followers retrieved", result.Data, &utils.Meta{
		Pagination: result.Pagination,
	})
}

// GetMyFollowing returns users that current user is following
func (h *UserHandler) GetMyFollowing(c *gin.Context) {
	userID, exists := c.Get("user_id")
	if !exists {
		utils.Unauthorized(c, "User not authenticated")
		return
	}

	params := utils.GetPaginationParams(c)

	result, err := h.userService.GetFollowing(c.Request.Context(), userID.(primitive.ObjectID).Hex(), nil, params)
	if err != nil {
		utils.InternalServerError(c, "Failed to get following")
		return
	}

	utils.SuccessResponseWithMeta(c, http.StatusOK, "Following retrieved", result.Data, &utils.Meta{
		Pagination: result.Pagination,
	})
}

// GetFollowRequests returns pending follow requests
func (h *UserHandler) GetFollowRequests(c *gin.Context) {
	userID, exists := c.Get("user_id")
	if !exists {
		utils.Unauthorized(c, "User not authenticated")
		return
	}

	params := utils.GetPaginationParams(c)

	result, err := h.userService.GetFollowRequests(c.Request.Context(), userID.(primitive.ObjectID), params)
	if err != nil {
		utils.InternalServerError(c, "Failed to get follow requests")
		return
	}

	utils.SuccessResponseWithMeta(c, http.StatusOK, "Follow requests retrieved", result.Data, &utils.Meta{
		Pagination: result.Pagination,
	})
}

// AcceptFollowRequest accepts a follow request
func (h *UserHandler) AcceptFollowRequest(c *gin.Context) {
	requesterIDStr := c.Param("user_id")
	requesterID, err := primitive.ObjectIDFromHex(requesterIDStr)
	if err != nil {
		utils.BadRequest(c, "Invalid user ID")
		return
	}

	userID, exists := c.Get("user_id")
	if !exists {
		utils.Unauthorized(c, "User not authenticated")
		return
	}

	err = h.userService.AcceptFollowRequest(c.Request.Context(), userID.(primitive.ObjectID), requesterID)
	if err != nil {
		if errors.IsAppError(err) {
			appErr := err.(*errors.AppError)
			utils.ErrorResponse(c, appErr.StatusCode, appErr.Code, appErr.Message)
		} else {
			utils.InternalServerError(c, "Failed to accept follow request")
		}
		return
	}

	utils.SuccessResponse(c, http.StatusOK, "Follow request accepted", nil)
}

// DeclineFollowRequest declines a follow request
func (h *UserHandler) DeclineFollowRequest(c *gin.Context) {
	requesterIDStr := c.Param("user_id")
	requesterID, err := primitive.ObjectIDFromHex(requesterIDStr)
	if err != nil {
		utils.BadRequest(c, "Invalid user ID")
		return
	}

	userID, exists := c.Get("user_id")
	if !exists {
		utils.Unauthorized(c, "User not authenticated")
		return
	}

	err = h.userService.DeclineFollowRequest(c.Request.Context(), userID.(primitive.ObjectID), requesterID)
	if err != nil {
		if errors.IsAppError(err) {
			appErr := err.(*errors.AppError)
			utils.ErrorResponse(c, appErr.StatusCode, appErr.Code, appErr.Message)
		} else {
			utils.InternalServerError(c, "Failed to decline follow request")
		}
		return
	}

	utils.SuccessResponse(c, http.StatusOK, "Follow request declined", nil)
}

// BlockUser blocks a user
func (h *UserHandler) BlockUser(c *gin.Context) {
	username := c.Param("username")
	if username == "" {
		utils.BadRequest(c, "Username is required")
		return
	}

	var req struct {
		Reason string `json:"reason" binding:"max=200"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		// Reason is optional
	}

	userID, exists := c.Get("user_id")
	if !exists {
		utils.Unauthorized(c, "User not authenticated")
		return
	}

	err := h.userService.BlockUser(c.Request.Context(), userID.(primitive.ObjectID), username, req.Reason)
	if err != nil {
		if errors.IsAppError(err) {
			appErr := err.(*errors.AppError)
			utils.ErrorResponse(c, appErr.StatusCode, appErr.Code, appErr.Message)
		} else {
			utils.InternalServerError(c, "Failed to block user")
		}
		return
	}

	utils.SuccessResponse(c, http.StatusOK, "User blocked successfully", nil)
}

// UnblockUser unblocks a user
func (h *UserHandler) UnblockUser(c *gin.Context) {
	username := c.Param("username")
	if username == "" {
		utils.BadRequest(c, "Username is required")
		return
	}

	userID, exists := c.Get("user_id")
	if !exists {
		utils.Unauthorized(c, "User not authenticated")
		return
	}

	err := h.userService.UnblockUser(c.Request.Context(), userID.(primitive.ObjectID), username)
	if err != nil {
		if errors.IsAppError(err) {
			appErr := err.(*errors.AppError)
			utils.ErrorResponse(c, appErr.StatusCode, appErr.Code, appErr.Message)
		} else {
			utils.InternalServerError(c, "Failed to unblock user")
		}
		return
	}

	utils.SuccessResponse(c, http.StatusOK, "User unblocked successfully", nil)
}

// GetBlockedUsers returns blocked users
func (h *UserHandler) GetBlockedUsers(c *gin.Context) {
	userID, exists := c.Get("user_id")
	if !exists {
		utils.Unauthorized(c, "User not authenticated")
		return
	}

	params := utils.GetPaginationParams(c)

	result, err := h.userService.GetBlockedUsers(c.Request.Context(), userID.(primitive.ObjectID), params)
	if err != nil {
		utils.InternalServerError(c, "Failed to get blocked users")
		return
	}

	utils.SuccessResponseWithMeta(c, http.StatusOK, "Blocked users retrieved", result.Data, &utils.Meta{
		Pagination: result.Pagination,
	})
}

// MuteUser mutes a user
func (h *UserHandler) MuteUser(c *gin.Context) {
	username := c.Param("username")
	if username == "" {
		utils.BadRequest(c, "Username is required")
		return
	}

	var req struct {
		Duration *int64 `json:"duration"` // Duration in seconds, nil for permanent
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		// Duration is optional
	}

	userID, exists := c.Get("user_id")
	if !exists {
		utils.Unauthorized(c, "User not authenticated")
		return
	}

	var duration *time.Duration
	if req.Duration != nil {
		d := time.Duration(*req.Duration) * time.Second
		duration = &d
	}

	err := h.userService.MuteUser(c.Request.Context(), userID.(primitive.ObjectID), username, duration)
	if err != nil {
		if errors.IsAppError(err) {
			appErr := err.(*errors.AppError)
			utils.ErrorResponse(c, appErr.StatusCode, appErr.Code, appErr.Message)
		} else {
			utils.InternalServerError(c, "Failed to mute user")
		}
		return
	}

	utils.SuccessResponse(c, http.StatusOK, "User muted successfully", nil)
}

// UnmuteUser unmutes a user
func (h *UserHandler) UnmuteUser(c *gin.Context) {
	username := c.Param("username")
	if username == "" {
		utils.BadRequest(c, "Username is required")
		return
	}

	userID, exists := c.Get("user_id")
	if !exists {
		utils.Unauthorized(c, "User not authenticated")
		return
	}

	err := h.userService.UnmuteUser(c.Request.Context(), userID.(primitive.ObjectID), username)
	if err != nil {
		if errors.IsAppError(err) {
			appErr := err.(*errors.AppError)
			utils.ErrorResponse(c, appErr.StatusCode, appErr.Code, appErr.Message)
		} else {
			utils.InternalServerError(c, "Failed to unmute user")
		}
		return
	}

	utils.SuccessResponse(c, http.StatusOK, "User unmuted successfully", nil)
}

// GetMutedUsers returns muted users
func (h *UserHandler) GetMutedUsers(c *gin.Context) {
	userID, exists := c.Get("user_id")
	if !exists {
		utils.Unauthorized(c, "User not authenticated")
		return
	}

	params := utils.GetPaginationParams(c)

	result, err := h.userService.GetMutedUsers(c.Request.Context(), userID.(primitive.ObjectID), params)
	if err != nil {
		utils.InternalServerError(c, "Failed to get muted users")
		return
	}

	utils.SuccessResponseWithMeta(c, http.StatusOK, "Muted users retrieved", result.Data, &utils.Meta{
		Pagination: result.Pagination,
	})
}

// GetUserThreads returns threads by a specific user
func (h *UserHandler) GetUserThreads(c *gin.Context) {
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

	result, err := h.userService.GetUserThreads(c.Request.Context(), username, currentUserID, params)
	if err != nil {
		if errors.IsAppError(err) {
			appErr := err.(*errors.AppError)
			utils.ErrorResponse(c, appErr.StatusCode, appErr.Code, appErr.Message)
		} else {
			utils.InternalServerError(c, "Failed to get user threads")
		}
		return
	}

	utils.SuccessResponseWithMeta(c, http.StatusOK, "User threads retrieved", result.Data, &utils.Meta{
		Pagination: result.Pagination,
	})
}

// GetUserReplies returns replies by a specific user
func (h *UserHandler) GetUserReplies(c *gin.Context) {
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

	result, err := h.userService.GetUserReplies(c.Request.Context(), username, currentUserID, params)
	if err != nil {
		if errors.IsAppError(err) {
			appErr := err.(*errors.AppError)
			utils.ErrorResponse(c, appErr.StatusCode, appErr.Code, appErr.Message)
		} else {
			utils.InternalServerError(c, "Failed to get user replies")
		}
		return
	}

	utils.SuccessResponseWithMeta(c, http.StatusOK, "User replies retrieved", result.Data, &utils.Meta{
		Pagination: result.Pagination,
	})
}

// GetUserMedia returns media posts by a specific user
func (h *UserHandler) GetUserMedia(c *gin.Context) {
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

	result, err := h.userService.GetUserMedia(c.Request.Context(), username, currentUserID, params)
	if err != nil {
		if errors.IsAppError(err) {
			appErr := err.(*errors.AppError)
			utils.ErrorResponse(c, appErr.StatusCode, appErr.Code, appErr.Message)
		} else {
			utils.InternalServerError(c, "Failed to get user media")
		}
		return
	}

	utils.SuccessResponseWithMeta(c, http.StatusOK, "User media retrieved", result.Data, &utils.Meta{
		Pagination: result.Pagination,
	})
}

// GetUserLikes returns threads liked by a specific user
func (h *UserHandler) GetUserLikes(c *gin.Context) {
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

	result, err := h.userService.GetUserLikes(c.Request.Context(), username, currentUserID, params)
	if err != nil {
		if errors.IsAppError(err) {
			appErr := err.(*errors.AppError)
			utils.ErrorResponse(c, appErr.StatusCode, appErr.Code, appErr.Message)
		} else {
			utils.InternalServerError(c, "Failed to get user likes")
		}
		return
	}

	utils.SuccessResponseWithMeta(c, http.StatusOK, "User likes retrieved", result.Data, &utils.Meta{
		Pagination: result.Pagination,
	})
}

// Account management
func (h *UserHandler) DeactivateAccount(c *gin.Context) {
	var req struct {
		Password string `json:"password" binding:"required"`
		Reason   string `json:"reason" binding:"max=500"`
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

	err := h.userService.DeactivateAccount(c.Request.Context(), userID.(primitive.ObjectID), req.Password, req.Reason)
	if err != nil {
		if errors.IsAppError(err) {
			appErr := err.(*errors.AppError)
			utils.ErrorResponse(c, appErr.StatusCode, appErr.Code, appErr.Message)
		} else {
			utils.InternalServerError(c, "Failed to deactivate account")
		}
		return
	}

	utils.SuccessResponse(c, http.StatusOK, "Account deactivated successfully", nil)
}

func (h *UserHandler) ReactivateAccount(c *gin.Context) {
	var req struct {
		Password string `json:"password" binding:"required"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		utils.BadRequest(c, "Password is required")
		return
	}

	userID, exists := c.Get("user_id")
	if !exists {
		utils.Unauthorized(c, "User not authenticated")
		return
	}

	err := h.userService.ReactivateAccount(c.Request.Context(), userID.(primitive.ObjectID), req.Password)
	if err != nil {
		if errors.IsAppError(err) {
			appErr := err.(*errors.AppError)
			utils.ErrorResponse(c, appErr.StatusCode, appErr.Code, appErr.Message)
		} else {
			utils.InternalServerError(c, "Failed to reactivate account")
		}
		return
	}

	utils.SuccessResponse(c, http.StatusOK, "Account reactivated successfully", nil)
}

func (h *UserHandler) DeleteAccount(c *gin.Context) {
	var req struct {
		Password     string `json:"password" binding:"required"`
		Confirmation string `json:"confirmation" binding:"required"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		errors := utils.GetValidationErrors(err)
		utils.ValidationErrorResponse(c, errors)
		return
	}

	if req.Confirmation != "DELETE" {
		utils.BadRequest(c, "Must type 'DELETE' to confirm account deletion")
		return
	}

	userID, exists := c.Get("user_id")
	if !exists {
		utils.Unauthorized(c, "User not authenticated")
		return
	}

	err := h.userService.DeleteAccount(c.Request.Context(), userID.(primitive.ObjectID), req.Password)
	if err != nil {
		if errors.IsAppError(err) {
			appErr := err.(*errors.AppError)
			utils.ErrorResponse(c, appErr.StatusCode, appErr.Code, appErr.Message)
		} else {
			utils.InternalServerError(c, "Failed to delete account")
		}
		return
	}

	utils.SuccessResponse(c, http.StatusOK, "Account deletion initiated. All data will be permanently removed within 30 days.", nil)
}

func (h *UserHandler) ExportData(c *gin.Context) {
	userID, exists := c.Get("user_id")
	if !exists {
		utils.Unauthorized(c, "User not authenticated")
		return
	}

	exportURL, err := h.userService.RequestDataExport(c.Request.Context(), userID.(primitive.ObjectID))
	if err != nil {
		utils.InternalServerError(c, "Failed to initiate data export")
		return
	}

	utils.SuccessResponse(c, http.StatusOK, "Data export initiated", gin.H{
		"export_url": exportURL,
		"message":    "Your data export will be available for download shortly. You will receive an email when it's ready.",
	})
}

// User analytics
func (h *UserHandler) GetUserAnalytics(c *gin.Context) {
	userID, exists := c.Get("user_id")
	if !exists {
		utils.Unauthorized(c, "User not authenticated")
		return
	}

	analytics, err := h.userService.GetUserAnalytics(c.Request.Context(), userID.(primitive.ObjectID))
	if err != nil {
		utils.InternalServerError(c, "Failed to get user analytics")
		return
	}

	utils.SuccessResponse(c, http.StatusOK, "User analytics retrieved", gin.H{
		"analytics": analytics,
	})
}

func (h *UserHandler) GetUserActivity(c *gin.Context) {
	userID, exists := c.Get("user_id")
	if !exists {
		utils.Unauthorized(c, "User not authenticated")
		return
	}

	params := utils.GetPaginationParams(c)

	activity, err := h.userService.GetUserActivity(c.Request.Context(), userID.(primitive.ObjectID), params)
	if err != nil {
		utils.InternalServerError(c, "Failed to get user activity")
		return
	}

	utils.SuccessResponseWithMeta(c, http.StatusOK, "User activity retrieved", activity.Data, &utils.Meta{
		Pagination: activity.Pagination,
	})
}

// Lists management
func (h *UserHandler) GetUserLists(c *gin.Context) {
	userID, exists := c.Get("user_id")
	if !exists {
		utils.Unauthorized(c, "User not authenticated")
		return
	}

	params := utils.GetPaginationParams(c)

	result, err := h.userService.GetUserLists(c.Request.Context(), userID.(primitive.ObjectID), params)
	if err != nil {
		utils.InternalServerError(c, "Failed to get user lists")
		return
	}

	utils.SuccessResponseWithMeta(c, http.StatusOK, "User lists retrieved", result.Data, &utils.Meta{
		Pagination: result.Pagination,
	})
}

func (h *UserHandler) CreateList(c *gin.Context) {
	var req struct {
		Name        string `json:"name" binding:"required,max=50"`
		Description string `json:"description" binding:"max=200"`
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

	list, err := h.userService.CreateList(c.Request.Context(), userID.(primitive.ObjectID), &services.CreateListRequest{
		Name:        req.Name,
		Description: req.Description,
		IsPrivate:   req.IsPrivate,
	})

	if err != nil {
		utils.InternalServerError(c, "Failed to create list")
		return
	}

	utils.SuccessResponse(c, http.StatusCreated, "List created successfully", gin.H{
		"list": list,
	})
}

func (h *UserHandler) GetList(c *gin.Context) {
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

	list, err := h.userService.GetList(c.Request.Context(), userID.(primitive.ObjectID), listID)
	if err != nil {
		if errors.IsAppError(err) {
			appErr := err.(*errors.AppError)
			utils.ErrorResponse(c, appErr.StatusCode, appErr.Code, appErr.Message)
		} else {
			utils.NotFound(c, "List not found")
		}
		return
	}

	utils.SuccessResponse(c, http.StatusOK, "List retrieved", gin.H{
		"list": list,
	})
}

func (h *UserHandler) UpdateList(c *gin.Context) {
	listIDStr := c.Param("list_id")
	listID, err := primitive.ObjectIDFromHex(listIDStr)
	if err != nil {
		utils.BadRequest(c, "Invalid list ID")
		return
	}

	var req struct {
		Name        string `json:"name" binding:"max=50"`
		Description string `json:"description" binding:"max=200"`
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

	list, err := h.userService.UpdateList(c.Request.Context(), userID.(primitive.ObjectID), listID, &services.UpdateListRequest{
		Name:        &req.Name,
		Description: &req.Description,
		IsPrivate:   req.IsPrivate,
	})

	if err != nil {
		if errors.IsAppError(err) {
			appErr := err.(*errors.AppError)
			utils.ErrorResponse(c, appErr.StatusCode, appErr.Code, appErr.Message)
		} else {
			utils.InternalServerError(c, "Failed to update list")
		}
		return
	}

	utils.SuccessResponse(c, http.StatusOK, "List updated successfully", gin.H{
		"list": list,
	})
}

func (h *UserHandler) DeleteList(c *gin.Context) {
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

	err = h.userService.DeleteList(c.Request.Context(), userID.(primitive.ObjectID), listID)
	if err != nil {
		if errors.IsAppError(err) {
			appErr := err.(*errors.AppError)
			utils.ErrorResponse(c, appErr.StatusCode, appErr.Code, appErr.Message)
		} else {
			utils.InternalServerError(c, "Failed to delete list")
		}
		return
	}

	utils.SuccessResponse(c, http.StatusOK, "List deleted successfully", nil)
}

func (h *UserHandler) AddListMember(c *gin.Context) {
	listIDStr := c.Param("list_id")
	listID, err := primitive.ObjectIDFromHex(listIDStr)
	if err != nil {
		utils.BadRequest(c, "Invalid list ID")
		return
	}

	var req struct {
		Username string `json:"username" binding:"required"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		utils.BadRequest(c, "Username is required")
		return
	}

	userID, exists := c.Get("user_id")
	if !exists {
		utils.Unauthorized(c, "User not authenticated")
		return
	}

	err = h.userService.AddListMember(c.Request.Context(), userID.(primitive.ObjectID), listID, req.Username)
	if err != nil {
		if errors.IsAppError(err) {
			appErr := err.(*errors.AppError)
			utils.ErrorResponse(c, appErr.StatusCode, appErr.Code, appErr.Message)
		} else {
			utils.InternalServerError(c, "Failed to add list member")
		}
		return
	}

	utils.SuccessResponse(c, http.StatusOK, "Member added to list successfully", nil)
}

func (h *UserHandler) RemoveListMember(c *gin.Context) {
	listIDStr := c.Param("list_id")
	listID, err := primitive.ObjectIDFromHex(listIDStr)
	if err != nil {
		utils.BadRequest(c, "Invalid list ID")
		return
	}

	memberIDStr := c.Param("user_id")
	memberID, err := primitive.ObjectIDFromHex(memberIDStr)
	if err != nil {
		utils.BadRequest(c, "Invalid user ID")
		return
	}

	userID, exists := c.Get("user_id")
	if !exists {
		utils.Unauthorized(c, "User not authenticated")
		return
	}

	err = h.userService.RemoveListMember(c.Request.Context(), userID.(primitive.ObjectID), listID, memberID)
	if err != nil {
		if errors.IsAppError(err) {
			appErr := err.(*errors.AppError)
			utils.ErrorResponse(c, appErr.StatusCode, appErr.Code, appErr.Message)
		} else {
			utils.InternalServerError(c, "Failed to remove list member")
		}
		return
	}

	utils.SuccessResponse(c, http.StatusOK, "Member removed from list successfully", nil)
}

func (h *UserHandler) GetListMembers(c *gin.Context) {
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

	result, err := h.userService.GetListMembers(c.Request.Context(), userID.(primitive.ObjectID), listID, params)
	if err != nil {
		if errors.IsAppError(err) {
			appErr := err.(*errors.AppError)
			utils.ErrorResponse(c, appErr.StatusCode, appErr.Code, appErr.Message)
		} else {
			utils.InternalServerError(c, "Failed to get list members")
		}
		return
	}

	utils.SuccessResponseWithMeta(c, http.StatusOK, "List members retrieved", result.Data, &utils.Meta{
		Pagination: result.Pagination,
	})
}

func (h *UserHandler) FollowList(c *gin.Context) {
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

	err = h.userService.FollowList(c.Request.Context(), userID.(primitive.ObjectID), listID)
	if err != nil {
		if errors.IsAppError(err) {
			appErr := err.(*errors.AppError)
			utils.ErrorResponse(c, appErr.StatusCode, appErr.Code, appErr.Message)
		} else {
			utils.InternalServerError(c, "Failed to follow list")
		}
		return
	}

	utils.SuccessResponse(c, http.StatusOK, "List followed successfully", nil)
}

func (h *UserHandler) UnfollowList(c *gin.Context) {
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

	err = h.userService.UnfollowList(c.Request.Context(), userID.(primitive.ObjectID), listID)
	if err != nil {
		if errors.IsAppError(err) {
			appErr := err.(*errors.AppError)
			utils.ErrorResponse(c, appErr.StatusCode, appErr.Code, appErr.Message)
		} else {
			utils.InternalServerError(c, "Failed to unfollow list")
		}
		return
	}

	utils.SuccessResponse(c, http.StatusOK, "List unfollowed successfully", nil)
}

// Verification
func (h *UserHandler) RequestVerification(c *gin.Context) {
	var req struct {
		Category    string                          `json:"category" binding:"required"`
		Description string                          `json:"description" binding:"required,max=1000"`
		Evidence    []services.VerificationEvidence `json:"evidence" binding:"required,min=1,max=5"`
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

	err := h.userService.RequestVerification(c.Request.Context(), userID.(primitive.ObjectID), &services.VerificationRequest{
		Category:    req.Category,
		Description: req.Description,
		Evidence:    req.Evidence,
	})

	if err != nil {
		if errors.IsAppError(err) {
			appErr := err.(*errors.AppError)
			utils.ErrorResponse(c, appErr.StatusCode, appErr.Code, appErr.Message)
		} else {
			utils.InternalServerError(c, "Failed to submit verification request")
		}
		return
	}

	utils.SuccessResponse(c, http.StatusOK, "Verification request submitted successfully", gin.H{
		"message": "Your verification request has been submitted and is under review. You will be notified of the decision.",
	})
}

func (h *UserHandler) GetVerificationStatus(c *gin.Context) {
	userID, exists := c.Get("user_id")
	if !exists {
		utils.Unauthorized(c, "User not authenticated")
		return
	}

	status, err := h.userService.GetVerificationStatus(c.Request.Context(), userID.(primitive.ObjectID))
	if err != nil {
		utils.InternalServerError(c, "Failed to get verification status")
		return
	}

	utils.SuccessResponse(c, http.StatusOK, "Verification status retrieved", gin.H{
		"status": status,
	})
}

// Admin user management functions
func (h *UserHandler) GetAllUsers(c *gin.Context) {
	params := utils.GetPaginationParams(c)
	filter := c.Query("filter")

	result, err := h.userService.GetAllUsers(c.Request.Context(), params, filter)
	if err != nil {
		utils.InternalServerError(c, "Failed to get users")
		return
	}

	utils.SuccessResponseWithMeta(c, http.StatusOK, "Users retrieved", result.Data, &utils.Meta{
		Pagination: result.Pagination,
	})
}

func (h *UserHandler) GetUserByID(c *gin.Context) {
	userIDStr := c.Param("user_id")
	userID, err := primitive.ObjectIDFromHex(userIDStr)
	if err != nil {
		utils.BadRequest(c, "Invalid user ID")
		return
	}

	user, err := h.userService.GetUserByID(c.Request.Context(), userID)
	if err != nil {
		utils.NotFound(c, "User not found")
		return
	}

	utils.SuccessResponse(c, http.StatusOK, "User retrieved", gin.H{
		"user": user,
	})
}

func (h *UserHandler) VerifyUser(c *gin.Context) {
	userIDStr := c.Param("user_id")
	userID, err := primitive.ObjectIDFromHex(userIDStr)
	if err != nil {
		utils.BadRequest(c, "Invalid user ID")
		return
	}

	var req struct {
		BadgeType string `json:"badge_type"`
		Reason    string `json:"reason" binding:"required"`
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

	err = h.userService.VerifyUser(c.Request.Context(), userID, adminID.(primitive.ObjectID), req.BadgeType, req.Reason)
	if err != nil {
		utils.InternalServerError(c, "Failed to verify user")
		return
	}

	utils.SuccessResponse(c, http.StatusOK, "User verified successfully", nil)
}

func (h *UserHandler) UnverifyUser(c *gin.Context) {
	userIDStr := c.Param("user_id")
	userID, err := primitive.ObjectIDFromHex(userIDStr)
	if err != nil {
		utils.BadRequest(c, "Invalid user ID")
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

	err = h.userService.UnverifyUser(c.Request.Context(), userID, adminID.(primitive.ObjectID), req.Reason)
	if err != nil {
		utils.InternalServerError(c, "Failed to unverify user")
		return
	}

	utils.SuccessResponse(c, http.StatusOK, "User verification removed successfully", nil)
}

func (h *UserHandler) SuspendUser(c *gin.Context) {
	userIDStr := c.Param("user_id")
	userID, err := primitive.ObjectIDFromHex(userIDStr)
	if err != nil {
		utils.BadRequest(c, "Invalid user ID")
		return
	}

	var req struct {
		Reason   string `json:"reason" binding:"required"`
		Duration *int64 `json:"duration"` // Duration in hours, nil for indefinite
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

	var duration *time.Duration
	if req.Duration != nil {
		d := time.Duration(*req.Duration) * time.Hour
		duration = &d
	}

	err = h.userService.SuspendUser(c.Request.Context(), userID, adminID.(primitive.ObjectID), req.Reason, duration)
	if err != nil {
		utils.InternalServerError(c, "Failed to suspend user")
		return
	}

	utils.SuccessResponse(c, http.StatusOK, "User suspended successfully", nil)
}

func (h *UserHandler) UnsuspendUser(c *gin.Context) {
	userIDStr := c.Param("user_id")
	userID, err := primitive.ObjectIDFromHex(userIDStr)
	if err != nil {
		utils.BadRequest(c, "Invalid user ID")
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

	err = h.userService.UnsuspendUser(c.Request.Context(), userID, adminID.(primitive.ObjectID), req.Reason)
	if err != nil {
		utils.InternalServerError(c, "Failed to unsuspend user")
		return
	}

	utils.SuccessResponse(c, http.StatusOK, "User unsuspended successfully", nil)
}

func (h *UserHandler) BanUser(c *gin.Context) {
	userIDStr := c.Param("user_id")
	userID, err := primitive.ObjectIDFromHex(userIDStr)
	if err != nil {
		utils.BadRequest(c, "Invalid user ID")
		return
	}

	var req struct {
		Reason    string `json:"reason" binding:"required"`
		Permanent bool   `json:"permanent"`
		Duration  *int64 `json:"duration"` // Duration in hours if not permanent
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

	var duration *time.Duration
	if !req.Permanent && req.Duration != nil {
		d := time.Duration(*req.Duration) * time.Hour
		duration = &d
	}

	err = h.userService.BanUser(c.Request.Context(), userID, adminID.(primitive.ObjectID), req.Reason, duration)
	if err != nil {
		utils.InternalServerError(c, "Failed to ban user")
		return
	}

	utils.SuccessResponse(c, http.StatusOK, "User banned successfully", nil)
}

func (h *UserHandler) UnbanUser(c *gin.Context) {
	userIDStr := c.Param("user_id")
	userID, err := primitive.ObjectIDFromHex(userIDStr)
	if err != nil {
		utils.BadRequest(c, "Invalid user ID")
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

	err = h.userService.UnbanUser(c.Request.Context(), userID, adminID.(primitive.ObjectID), req.Reason)
	if err != nil {
		utils.InternalServerError(c, "Failed to unban user")
		return
	}

	utils.SuccessResponse(c, http.StatusOK, "User unbanned successfully", nil)
}

func (h *UserHandler) GetUserActivityAdmin(c *gin.Context) {
	userIDStr := c.Param("user_id")
	userID, err := primitive.ObjectIDFromHex(userIDStr)
	if err != nil {
		utils.BadRequest(c, "Invalid user ID")
		return
	}

	params := utils.GetPaginationParams(c)

	activity, err := h.userService.GetUserActivityAdmin(c.Request.Context(), userID, params, "")
	if err != nil {
		utils.InternalServerError(c, "Failed to get user activity")
		return
	}

	utils.SuccessResponseWithMeta(c, http.StatusOK, "User activity retrieved", activity.Data, &utils.Meta{
		Pagination: activity.Pagination,
	})
}

func (h *UserHandler) GetUserSessions(c *gin.Context) {
	userIDStr := c.Param("user_id")
	userID, err := primitive.ObjectIDFromHex(userIDStr)
	if err != nil {
		utils.BadRequest(c, "Invalid user ID")
		return
	}

	sessions, err := h.authService.GetActiveSessions(c.Request.Context(), userID)
	if err != nil {
		utils.InternalServerError(c, "Failed to get user sessions")
		return
	}

	utils.SuccessResponse(c, http.StatusOK, "User sessions retrieved", gin.H{
		"sessions": sessions,
	})
}

func (h *UserHandler) RevokeUserSessions(c *gin.Context) {
	userIDStr := c.Param("user_id")
	userID, err := primitive.ObjectIDFromHex(userIDStr)
	if err != nil {
		utils.BadRequest(c, "Invalid user ID")
		return
	}

	err = h.authService.LogoutAll(c.Request.Context(), userID)
	if err != nil {
		utils.InternalServerError(c, "Failed to revoke user sessions")
		return
	}

	utils.SuccessResponse(c, http.StatusOK, "All user sessions revoked successfully", nil)
}
