package handlers

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"go.mongodb.org/mongo-driver/bson/primitive"

	"onthread/internal/services"
	"onthread/internal/utils"
	"onthread/pkg/constants"
	"onthread/pkg/errors"
	"onthread/pkg/logger"
)

type AuthHandler struct {
	authService services.AuthService
	jwtManager  *utils.JWTManager
}

func NewAuthHandler(authService services.AuthService, jwtManager *utils.JWTManager) *AuthHandler {
	return &AuthHandler{
		authService: authService,
		jwtManager:  jwtManager,
	}
}

// Register handles user registration
func (h *AuthHandler) Register(c *gin.Context) {
	var req struct {
		Username        string `json:"username" binding:"required,min=3,max=30,username"`
		Email           string `json:"email" binding:"required,email"`
		Password        string `json:"password" binding:"required,strong_password"`
		DisplayName     string `json:"display_name" binding:"max=50"`
		AcceptedTerms   bool   `json:"accepted_terms" binding:"required"`
		AcceptedPrivacy bool   `json:"accepted_privacy" binding:"required"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		errors := utils.GetValidationErrors(err)
		utils.ValidationErrorResponse(c, errors)
		return
	}

	if !req.AcceptedTerms || !req.AcceptedPrivacy {
		utils.BadRequest(c, "Must accept terms and privacy policy")
		return
	}

	// Register user
	user, err := h.authService.Register(c.Request.Context(), &services.RegisterRequest{
		Username:    req.Username,
		Email:       req.Email,
		Password:    req.Password,
		DisplayName: req.DisplayName,
		IPAddress:   c.ClientIP(),
		UserAgent:   c.GetHeader("User-Agent"),
	})

	if err != nil {
		switch err := err.(type) {
		case *errors.AppError:
			utils.ErrorResponse(c, err.StatusCode, err.Code, err.Message)
		default:
			utils.InternalServerError(c, "Registration failed")
		}
		return
	}

	logger.WithUserID(user.ID).Info("User registered successfully")

	utils.SuccessResponse(c, http.StatusCreated, "User registered successfully", gin.H{
		"user": gin.H{
			"id":           user.ID,
			"username":     user.Username,
			"email":        user.Email,
			"display_name": user.DisplayName,
			"is_verified":  user.IsVerified,
			"created_at":   user.JoinedAt,
		},
		"next_step": "Please check your email to verify your account",
	})
}

// Login handles user authentication
func (h *AuthHandler) Login(c *gin.Context) {
	var req struct {
		Login    string `json:"login" binding:"required"` // email or username
		Password string `json:"password" binding:"required"`
		Remember bool   `json:"remember"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		errors := utils.GetValidationErrors(err)
		utils.ValidationErrorResponse(c, errors)
		return
	}

	// Authenticate user
	result, err := h.authService.Login(c.Request.Context(), &services.LoginRequest{
		Login:     req.Login,
		Password:  req.Password,
		IPAddress: c.ClientIP(),
		UserAgent: c.GetHeader("User-Agent"),
		Remember:  req.Remember,
	})

	if err != nil {
		switch err := err.(type) {
		case *errors.AppError:
			utils.ErrorResponse(c, err.StatusCode, err.Code, err.Message)
		default:
			utils.InternalServerError(c, "Login failed")
		}
		return
	}

	logger.WithUserID(result.User.ID).Info("User logged in successfully")

	utils.SuccessResponse(c, http.StatusOK, "Login successful", gin.H{
		"user": gin.H{
			"id":           result.User.ID,
			"username":     result.User.Username,
			"email":        result.User.Email,
			"display_name": result.User.DisplayName,
			"is_verified":  result.User.IsVerified,
			"avatar":       result.User.ProfilePicture,
		},
		"access_token":  result.AccessToken,
		"refresh_token": result.RefreshToken,
		"expires_in":    int64(h.jwtManager.GetTokenExpiry(constants.TokenTypeAccess).Seconds()),
	})
}

// RefreshToken handles token refresh
func (h *AuthHandler) RefreshToken(c *gin.Context) {
	var req struct {
		RefreshToken string `json:"refresh_token" binding:"required"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		utils.BadRequest(c, "Refresh token is required")
		return
	}

	// Refresh tokens
	result, err := h.authService.RefreshToken(c.Request.Context(), req.RefreshToken)
	if err != nil {
		switch err := err.(type) {
		case *errors.AppError:
			utils.ErrorResponse(c, err.StatusCode, err.Code, err.Message)
		default:
			utils.Unauthorized(c, "Invalid refresh token")
		}
		return
	}

	utils.SuccessResponse(c, http.StatusOK, "Token refreshed successfully", gin.H{
		"access_token":  result.AccessToken,
		"refresh_token": result.RefreshToken,
		"expires_in":    int64(h.jwtManager.GetTokenExpiry(constants.TokenTypeAccess).Seconds()),
	})
}

// ForgotPassword handles password reset request
func (h *AuthHandler) ForgotPassword(c *gin.Context) {
	var req struct {
		Email string `json:"email" binding:"required,email"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		utils.BadRequest(c, "Valid email is required")
		return
	}

	err := h.authService.ForgotPassword(c.Request.Context(), req.Email)
	if err != nil {
		// Don't reveal if email exists or not
		logger.WithError(err).Error("Forgot password error")
	}

	// Always return success to prevent email enumeration
	utils.SuccessResponse(c, http.StatusOK, "If the email exists, a password reset link has been sent", nil)
}

// ResetPassword handles password reset
func (h *AuthHandler) ResetPassword(c *gin.Context) {
	var req struct {
		Token       string `json:"token" binding:"required"`
		NewPassword string `json:"new_password" binding:"required,strong_password"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		errors := utils.GetValidationErrors(err)
		utils.ValidationErrorResponse(c, errors)
		return
	}

	err := h.authService.ResetPassword(c.Request.Context(), req.Token, req.NewPassword)
	if err != nil {
		switch err := err.(type) {
		case *errors.AppError:
			utils.ErrorResponse(c, err.StatusCode, err.Code, err.Message)
		default:
			utils.BadRequest(c, "Invalid or expired reset token")
		}
		return
	}

	utils.SuccessResponse(c, http.StatusOK, "Password reset successfully", nil)
}

// VerifyEmail handles email verification
func (h *AuthHandler) VerifyEmail(c *gin.Context) {
	var req struct {
		Token string `json:"token" binding:"required"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		utils.BadRequest(c, "Verification token is required")
		return
	}

	err := h.authService.VerifyEmail(c.Request.Context(), req.Token)
	if err != nil {
		switch err := err.(type) {
		case *errors.AppError:
			utils.ErrorResponse(c, err.StatusCode, err.Code, err.Message)
		default:
			utils.BadRequest(c, "Invalid or expired verification token")
		}
		return
	}

	utils.SuccessResponse(c, http.StatusOK, "Email verified successfully", nil)
}

// ResendVerification handles resending verification email
func (h *AuthHandler) ResendVerification(c *gin.Context) {
	var req struct {
		Email string `json:"email" binding:"required,email"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		utils.BadRequest(c, "Valid email is required")
		return
	}

	err := h.authService.ResendVerification(c.Request.Context(), req.Email)
	if err != nil {
		// Don't reveal if email exists or not
		logger.WithError(err).Error("Resend verification error")
	}

	utils.SuccessResponse(c, http.StatusOK, "If the email exists and is unverified, a verification email has been sent", nil)
}

// Logout handles user logout
func (h *AuthHandler) Logout(c *gin.Context) {
	token := c.GetHeader("Authorization")
	if token == "" {
		utils.BadRequest(c, "Authorization header required")
		return
	}

	tokenString, err := utils.ExtractTokenFromHeader(token)
	if err != nil {
		utils.BadRequest(c, "Invalid authorization header")
		return
	}

	err = h.authService.Logout(c.Request.Context(), tokenString)
	if err != nil {
		logger.WithError(err).Error("Logout error")
	}

	utils.SuccessResponse(c, http.StatusOK, "Logged out successfully", nil)
}

// LogoutAll handles logging out from all devices
func (h *AuthHandler) LogoutAll(c *gin.Context) {
	userID, exists := c.Get("user_id")
	if !exists {
		utils.Unauthorized(c, "User not authenticated")
		return
	}

	err := h.authService.LogoutAll(c.Request.Context(), userID.(primitive.ObjectID))
	if err != nil {
		utils.InternalServerError(c, "Failed to logout from all devices")
		return
	}

	utils.SuccessResponse(c, http.StatusOK, "Logged out from all devices", nil)
}

// ChangePassword handles password change
func (h *AuthHandler) ChangePassword(c *gin.Context) {
	var req struct {
		CurrentPassword string `json:"current_password" binding:"required"`
		NewPassword     string `json:"new_password" binding:"required,strong_password"`
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

	err := h.authService.ChangePassword(c.Request.Context(), userID.(primitive.ObjectID), req.CurrentPassword, req.NewPassword)
	if err != nil {
		switch err := err.(type) {
		case *errors.AppError:
			utils.ErrorResponse(c, err.StatusCode, err.Code, err.Message)
		default:
			utils.InternalServerError(c, "Failed to change password")
		}
		return
	}

	utils.SuccessResponse(c, http.StatusOK, "Password changed successfully", nil)
}

// GetCurrentUser returns current authenticated user
func (h *AuthHandler) GetCurrentUser(c *gin.Context) {
	userID, exists := c.Get("user_id")
	if !exists {
		utils.Unauthorized(c, "User not authenticated")
		return
	}

	user, err := h.authService.GetUserByID(c.Request.Context(), userID.(primitive.ObjectID))
	if err != nil {
		utils.NotFound(c, "User not found")
		return
	}

	utils.SuccessResponse(c, http.StatusOK, "Current user retrieved", gin.H{
		"user": gin.H{
			"id":              user.ID,
			"username":        user.Username,
			"email":           user.Email,
			"display_name":    user.DisplayName,
			"bio":             user.Bio,
			"avatar":          user.ProfilePicture,
			"cover":           user.CoverImage,
			"is_verified":     user.IsVerified,
			"is_private":      user.IsPrivate,
			"followers_count": user.FollowersCount,
			"following_count": user.FollowingCount,
			"threads_count":   user.ThreadsCount,
			"location":        user.Location,
			"website":         user.Website,
			"joined_at":       user.JoinedAt,
			"settings":        user.Settings,
		},
	})
}

// GetActiveSessions returns user's active sessions
func (h *AuthHandler) GetActiveSessions(c *gin.Context) {
	userID, exists := c.Get("user_id")
	if !exists {
		utils.Unauthorized(c, "User not authenticated")
		return
	}

	sessions, err := h.authService.GetActiveSessions(c.Request.Context(), userID.(primitive.ObjectID))
	if err != nil {
		utils.InternalServerError(c, "Failed to get active sessions")
		return
	}

	utils.SuccessResponse(c, http.StatusOK, "Active sessions retrieved", gin.H{
		"sessions": sessions,
	})
}

// RevokeSession revokes a specific session
func (h *AuthHandler) RevokeSession(c *gin.Context) {
	sessionID := c.Param("session_id")
	if sessionID == "" {
		utils.BadRequest(c, "Session ID is required")
		return
	}

	userID, exists := c.Get("user_id")
	if !exists {
		utils.Unauthorized(c, "User not authenticated")
		return
	}

	err := h.authService.RevokeSession(c.Request.Context(), userID.(primitive.ObjectID), sessionID)
	if err != nil {
		utils.InternalServerError(c, "Failed to revoke session")
		return
	}

	utils.SuccessResponse(c, http.StatusOK, "Session revoked successfully", nil)
}

// OAuth handlers
func (h *AuthHandler) GoogleOAuth(c *gin.Context) {
	url := h.authService.GetGoogleOAuthURL(c.Request.Context())
	c.Redirect(http.StatusTemporaryRedirect, url)
}

func (h *AuthHandler) GoogleOAuthCallback(c *gin.Context) {
	code := c.Query("code")
	if code == "" {
		utils.BadRequest(c, "Authorization code required")
		return
	}

	result, err := h.authService.HandleGoogleOAuth(c.Request.Context(), code, c.ClientIP(), c.GetHeader("User-Agent"))
	if err != nil {
		utils.InternalServerError(c, "OAuth authentication failed")
		return
	}

	utils.SuccessResponse(c, http.StatusOK, "OAuth login successful", gin.H{
		"user":          result.User,
		"access_token":  result.AccessToken,
		"refresh_token": result.RefreshToken,
		"is_new_user":   result.IsNewUser,
	})
}

func (h *AuthHandler) GitHubOAuth(c *gin.Context) {
	url := h.authService.GetGitHubOAuthURL(c.Request.Context())
	c.Redirect(http.StatusTemporaryRedirect, url)
}

func (h *AuthHandler) GitHubOAuthCallback(c *gin.Context) {
	code := c.Query("code")
	if code == "" {
		utils.BadRequest(c, "Authorization code required")
		return
	}

	result, err := h.authService.HandleGitHubOAuth(c.Request.Context(), code, c.ClientIP(), c.GetHeader("User-Agent"))
	if err != nil {
		utils.InternalServerError(c, "OAuth authentication failed")
		return
	}

	utils.SuccessResponse(c, http.StatusOK, "OAuth login successful", gin.H{
		"user":          result.User,
		"access_token":  result.AccessToken,
		"refresh_token": result.RefreshToken,
		"is_new_user":   result.IsNewUser,
	})
}

// 2FA handlers
func (h *AuthHandler) Enable2FA(c *gin.Context) {
	userID, exists := c.Get("user_id")
	if !exists {
		utils.Unauthorized(c, "User not authenticated")
		return
	}

	result, err := h.authService.Enable2FA(c.Request.Context(), userID.(primitive.ObjectID))
	if err != nil {
		utils.InternalServerError(c, "Failed to enable 2FA")
		return
	}

	utils.SuccessResponse(c, http.StatusOK, "2FA setup initiated", gin.H{
		"qr_code":      result.QRCode,
		"secret":       result.Secret,
		"backup_codes": result.BackupCodes,
	})
}

func (h *AuthHandler) Disable2FA(c *gin.Context) {
	var req struct {
		Password string `json:"password" binding:"required"`
		Code     string `json:"code" binding:"required"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		utils.BadRequest(c, "Password and 2FA code required")
		return
	}

	userID, exists := c.Get("user_id")
	if !exists {
		utils.Unauthorized(c, "User not authenticated")
		return
	}

	err := h.authService.Disable2FA(c.Request.Context(), userID.(primitive.ObjectID), req.Password, req.Code)
	if err != nil {
		switch err := err.(type) {
		case *errors.AppError:
			utils.ErrorResponse(c, err.StatusCode, err.Code, err.Message)
		default:
			utils.InternalServerError(c, "Failed to disable 2FA")
		}
		return
	}

	utils.SuccessResponse(c, http.StatusOK, "2FA disabled successfully", nil)
}

func (h *AuthHandler) Verify2FA(c *gin.Context) {
	var req struct {
		Code string `json:"code" binding:"required"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		utils.BadRequest(c, "2FA code required")
		return
	}

	userID, exists := c.Get("user_id")
	if !exists {
		utils.Unauthorized(c, "User not authenticated")
		return
	}

	err := h.authService.Verify2FA(c.Request.Context(), userID.(primitive.ObjectID), req.Code)
	if err != nil {
		utils.BadRequest(c, "Invalid 2FA code")
		return
	}

	utils.SuccessResponse(c, http.StatusOK, "2FA verified successfully", nil)
}

func (h *AuthHandler) GetBackupCodes(c *gin.Context) {
	userID, exists := c.Get("user_id")
	if !exists {
		utils.Unauthorized(c, "User not authenticated")
		return
	}

	codes, err := h.authService.GetBackupCodes(c.Request.Context(), userID.(primitive.ObjectID))
	if err != nil {
		utils.InternalServerError(c, "Failed to get backup codes")
		return
	}

	utils.SuccessResponse(c, http.StatusOK, "Backup codes retrieved", gin.H{
		"backup_codes": codes,
	})
}

func (h *AuthHandler) RegenerateBackupCodes(c *gin.Context) {
	var req struct {
		Password string `json:"password" binding:"required"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		utils.BadRequest(c, "Password required")
		return
	}

	userID, exists := c.Get("user_id")
	if !exists {
		utils.Unauthorized(c, "User not authenticated")
		return
	}

	codes, err := h.authService.RegenerateBackupCodes(c.Request.Context(), userID.(primitive.ObjectID), req.Password)
	if err != nil {
		switch err := err.(type) {
		case *errors.AppError:
			utils.ErrorResponse(c, err.StatusCode, err.Code, err.Message)
		default:
			utils.InternalServerError(c, "Failed to regenerate backup codes")
		}
		return
	}

	utils.SuccessResponse(c, http.StatusOK, "Backup codes regenerated", gin.H{
		"backup_codes": codes,
	})
}
