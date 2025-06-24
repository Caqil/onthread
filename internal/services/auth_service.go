package services

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
	"go.mongodb.org/mongo-driver/bson/primitive"

	"onthread/internal/models"
	"onthread/internal/repository"
	"onthread/internal/utils"
	"onthread/pkg/constants"
	"onthread/pkg/errors"
	"onthread/pkg/logger"
)

// AuthService interface defines authentication service methods
type AuthService interface {
	// User Authentication
	Register(ctx context.Context, req *RegisterRequest) (*models.User, error)
	Login(ctx context.Context, req *LoginRequest) (*LoginResult, error)
	RefreshToken(ctx context.Context, refreshToken string) (*RefreshResult, error)
	Logout(ctx context.Context, token string) error
	LogoutAll(ctx context.Context, userID primitive.ObjectID) error

	// Password Management
	ForgotPassword(ctx context.Context, email string) error
	ResetPassword(ctx context.Context, token, newPassword string) error
	ChangePassword(ctx context.Context, userID primitive.ObjectID, currentPassword, newPassword string) error

	// Email Verification
	VerifyEmail(ctx context.Context, token string) error
	ResendVerification(ctx context.Context, email string) error

	// User Management
	GetUserByID(ctx context.Context, userID primitive.ObjectID) (*models.User, error)
	ValidateToken(ctx context.Context, token string) (primitive.ObjectID, error)

	// Session Management
	GetActiveSessions(ctx context.Context, userID primitive.ObjectID) ([]UserSession, error)
	RevokeSession(ctx context.Context, userID primitive.ObjectID, sessionID string) error

	// Two-Factor Authentication
	Enable2FA(ctx context.Context, userID primitive.ObjectID) (*TwoFactorResult, error)
	Disable2FA(ctx context.Context, userID primitive.ObjectID, password, code string) error
	Verify2FA(ctx context.Context, userID primitive.ObjectID, code string) error
	GetBackupCodes(ctx context.Context, userID primitive.ObjectID) ([]string, error)
	RegenerateBackupCodes(ctx context.Context, userID primitive.ObjectID, password string) ([]string, error)

	// OAuth
	GetGoogleOAuthURL(ctx context.Context) string
	HandleGoogleOAuth(ctx context.Context, code, ipAddress, userAgent string) (*OAuthResult, error)
	GetGitHubOAuthURL(ctx context.Context) string
	HandleGitHubOAuth(ctx context.Context, code, ipAddress, userAgent string) (*OAuthResult, error)

	// Admin Authentication
	AdminLogin(ctx context.Context, email, password string) (*models.Admin, string, error)
	AdminLogout(ctx context.Context, adminID primitive.ObjectID) error
}

// Request/Response Types
type RegisterRequest struct {
	Username    string
	Email       string
	Password    string
	DisplayName string
	IPAddress   string
	UserAgent   string
}

type LoginRequest struct {
	Login     string // email or username
	Password  string
	IPAddress string
	UserAgent string
	Remember  bool
}

type LoginResult struct {
	User         *models.User
	AccessToken  string
	RefreshToken string
	SessionID    string
}

type RefreshResult struct {
	AccessToken  string
	RefreshToken string
}

type TwoFactorResult struct {
	Secret      string
	QRCode      string
	BackupCodes []string
}

type OAuthResult struct {
	User         *models.User
	AccessToken  string
	RefreshToken string
	IsNewUser    bool
}

type UserSession struct {
	ID        string    `json:"id"`
	DeviceID  string    `json:"device_id"`
	UserAgent string    `json:"user_agent"`
	IPAddress string    `json:"ip_address"`
	CreatedAt time.Time `json:"created_at"`
	LastUsed  time.Time `json:"last_used"`
	IsCurrent bool      `json:"is_current"`
}

// AuthServiceImpl implements AuthService interface
type AuthServiceImpl struct {
	userRepo   repository.UserRepository
	adminRepo  repository.AdminRepository
	jwtManager *utils.JWTManager
	redis      *redis.Client
	config     *AuthConfig
}

type AuthConfig struct {
	// Email service configuration
	EmailService EmailService

	// OAuth configuration
	GoogleOAuth OAuthConfig
	GitHubOAuth OAuthConfig

	// 2FA configuration
	TOTPIssuer string

	// Rate limiting
	MaxLoginAttempts int
	LoginLockoutTime time.Duration
	MaxSessions      int
	SessionTTL       time.Duration

	// Security
	RequireEmailVerification   bool
	EnableBruteForceProtection bool
}

type OAuthConfig struct {
	ClientID     string
	ClientSecret string
	RedirectURL  string
	Scopes       []string
}

type EmailService interface {
	SendVerificationEmail(ctx context.Context, email, token string) error
	SendPasswordResetEmail(ctx context.Context, email, token string) error
	SendPasswordChangedEmail(ctx context.Context, email string) error
	SendSecurityAlert(ctx context.Context, email, message string) error
}

// NewAuthService creates a new AuthService instance
func NewAuthService(userRepo repository.UserRepository, adminRepo repository.AdminRepository, jwtManager *utils.JWTManager, redis *redis.Client) AuthService {
	return &AuthServiceImpl{
		userRepo:   userRepo,
		adminRepo:  adminRepo,
		jwtManager: jwtManager,
		redis:      redis,
		config:     defaultAuthConfig(),
	}
}

func defaultAuthConfig() *AuthConfig {
	return &AuthConfig{
		MaxLoginAttempts:           5,
		LoginLockoutTime:           15 * time.Minute,
		MaxSessions:                5,
		SessionTTL:                 30 * 24 * time.Hour, // 30 days
		RequireEmailVerification:   true,
		EnableBruteForceProtection: true,
		TOTPIssuer:                 "ThreadApp",
	}
}

// ===============================
// User Authentication Methods
// ===============================

func (s *AuthServiceImpl) Register(ctx context.Context, req *RegisterRequest) (*models.User, error) {
	// Validate password strength
	if err := utils.IsValidPassword(req.Password); err != nil {
		return nil, errors.NewValidationFieldError("password", err.Error())
	}

	// Check if email already exists
	existingUser, _ := s.userRepo.GetByEmail(ctx, req.Email)
	if existingUser != nil {
		return nil, errors.NewConflictError("User with this email already exists")
	}

	// Check if username already exists
	existingUser, _ = s.userRepo.GetByUsername(ctx, req.Username)
	if existingUser != nil {
		return nil, errors.NewConflictError("Username already taken")
	}

	// Hash password
	hashedPassword, err := utils.HashPassword(req.Password)
	if err != nil {
		return nil, errors.NewInternalError("Failed to hash password", err)
	}

	// Generate verification token
	verificationToken, err := utils.GenerateSecureID()
	if err != nil {
		return nil, errors.NewInternalError("Failed to generate verification token", err)
	}

	// Create user
	now := time.Now()
	user := &models.User{
		Username:       req.Username,
		Email:          req.Email,
		PasswordHash:   hashedPassword,
		DisplayName:    req.DisplayName,
		IsActive:       true,
		IsVerified:     false,
		IsSuspended:    false,
		FollowersCount: 0,
		FollowingCount: 0,
		ThreadsCount:   0,
		JoinedAt:       now,
		LastActiveAt:   now,
		Settings: models.UserSettings{
			Language:             "en",
			Theme:                "auto",
			EmailNotifications:   true,
			PushNotifications:    true,
			ShowActivity:         true,
			AllowMessageRequests: true,
			ShowReadReceipts:     true,
			AllowTagging:         true,
			ContentLanguages:     []string{"en"},
			SensitiveContent:     false,
			DataSaver:            false,
		},
		Metadata: models.UserMetadata{
			LoginCount:        1,
			RegistrationIP:    req.IPAddress,
			LastLoginIP:       req.IPAddress,
			TwoFactorEnabled:  false,
			EmailVerified:     false,
			VerificationToken: verificationToken,
		},
		DeviceTokens: []string{},
		Badges:       []models.Badge{},
		Links:        []models.UserLink{},
	}

	// Save user to database
	if err := s.userRepo.Create(ctx, user); err != nil {
		return nil, errors.NewInternalError("Failed to create user", err)
	}

	// Send verification email
	if s.config.RequireEmailVerification && s.config.EmailService != nil {
		if err := s.config.EmailService.SendVerificationEmail(ctx, user.Email, verificationToken); err != nil {
			logger.WithError(err).Error("Failed to send verification email")
		}
	}

	// Log registration
	logger.WithFields(logger.Fields{
		"user_id":  user.ID.Hex(),
		"username": user.Username,
		"email":    user.Email,
	}).Info("User registered successfully")

	return user, nil
}

func (s *AuthServiceImpl) Login(ctx context.Context, req *LoginRequest) (*LoginResult, error) {
	// Check for brute force protection
	if s.config.EnableBruteForceProtection {
		if locked, err := s.isLoginLocked(ctx, req.Login, req.IPAddress); err != nil {
			return nil, errors.NewInternalError("Failed to check login lock", err)
		} else if locked {
			return nil, errors.NewTooManyRequestsError("Too many failed login attempts. Please try again later.")
		}
	}

	// Find user by email or username
	var user *models.User
	var err error

	if strings.Contains(req.Login, "@") {
		user, err = s.userRepo.GetByEmail(ctx, req.Login)
	} else {
		user, err = s.userRepo.GetByUsername(ctx, req.Login)
	}

	if err != nil || user == nil {
		if s.config.EnableBruteForceProtection {
			s.recordFailedLogin(ctx, req.Login, req.IPAddress)
		}
		return nil, errors.NewUnauthorizedError("Invalid credentials")
	}

	// Verify password
	if err := utils.CheckPassword(req.Password, user.PasswordHash); err != nil {
		if s.config.EnableBruteForceProtection {
			s.recordFailedLogin(ctx, req.Login, req.IPAddress)
		}
		return nil, errors.NewUnauthorizedError("Invalid credentials")
	}

	// Check if user is active
	if !user.IsActive {
		return nil, errors.NewForbiddenError("Account is disabled")
	}

	// Check if user is suspended
	if user.IsSuspended {
		return nil, errors.NewForbiddenError("Account is suspended")
	}

	// Check email verification requirement
	if s.config.RequireEmailVerification && !user.Metadata.EmailVerified {
		return nil, errors.NewForbiddenError("Email verification required")
	}

	// Generate session ID
	sessionID := uuid.New().String()
	deviceID := s.generateDeviceID(req.UserAgent)

	// Generate tokens
	accessToken, err := s.jwtManager.GenerateAccessToken(
		user.ID, user.Username, user.Email, deviceID, sessionID,
	)
	if err != nil {
		return nil, errors.NewInternalError("Failed to generate access token", err)
	}

	refreshToken, err := s.jwtManager.GenerateRefreshToken(
		user.ID, user.Username, user.Email, deviceID, sessionID,
	)
	if err != nil {
		return nil, errors.NewInternalError("Failed to generate refresh token", err)
	}

	// Store session in Redis
	sessionData := map[string]interface{}{
		"user_id":    user.ID.Hex(),
		"device_id":  deviceID,
		"user_agent": req.UserAgent,
		"ip_address": req.IPAddress,
		"created_at": time.Now().Unix(),
		"last_used":  time.Now().Unix(),
	}

	sessionKey := fmt.Sprintf("%s%s", constants.UserSessionPrefix, sessionID)
	if err := s.redis.HMSet(ctx, sessionKey, sessionData).Err(); err != nil {
		logger.WithError(err).Error("Failed to store session in Redis")
	}

	sessionTTL := constants.SessionCacheTTL
	if req.Remember {
		sessionTTL = s.config.SessionTTL
	}
	s.redis.Expire(ctx, sessionKey, sessionTTL)

	// Update user login metadata
	now := time.Now()
	updateData := map[string]interface{}{
		"last_active_at":         now,
		"metadata.last_login_ip": req.IPAddress,
		"metadata.login_count":   user.Metadata.LoginCount + 1,
	}

	if err := s.userRepo.UpdateFields(ctx, user.ID, updateData); err != nil {
		logger.WithError(err).Error("Failed to update user login metadata")
	}

	// Clear failed login attempts
	if s.config.EnableBruteForceProtection {
		s.clearFailedLogins(ctx, req.Login, req.IPAddress)
	}

	// Log successful login
	logger.WithFields(logger.Fields{
		"user_id":    user.ID.Hex(),
		"username":   user.Username,
		"ip_address": req.IPAddress,
		"device_id":  deviceID,
	}).Info("User logged in successfully")

	return &LoginResult{
		User:         user,
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		SessionID:    sessionID,
	}, nil
}

func (s *AuthServiceImpl) RefreshToken(ctx context.Context, refreshToken string) (*RefreshResult, error) {
	// Validate refresh token
	claims, err := s.jwtManager.ValidateToken(refreshToken)
	if err != nil {
		return nil, errors.NewUnauthorizedError("Invalid refresh token")
	}

	if claims.TokenType != constants.TokenTypeRefresh {
		return nil, errors.NewUnauthorizedError("Invalid token type")
	}

	// Check if session exists
	sessionKey := fmt.Sprintf("%s%s", constants.UserSessionPrefix, claims.SessionID)
	exists := s.redis.Exists(ctx, sessionKey).Val()
	if exists == 0 {
		return nil, errors.NewUnauthorizedError("Session expired")
	}

	// Get user to verify they still exist and are active
	user, err := s.userRepo.GetByID(ctx, claims.UserID)
	if err != nil || user == nil {
		return nil, errors.NewUnauthorizedError("User not found")
	}

	if !user.IsActive || user.IsSuspended {
		return nil, errors.NewUnauthorizedError("Account is disabled")
	}

	// Generate new tokens
	newAccessToken, err := s.jwtManager.GenerateAccessToken(
		user.ID, user.Username, user.Email, claims.DeviceID, claims.SessionID,
	)
	if err != nil {
		return nil, errors.NewInternalError("Failed to generate access token", err)
	}

	newRefreshToken, err := s.jwtManager.GenerateRefreshToken(
		user.ID, user.Username, user.Email, claims.DeviceID, claims.SessionID,
	)
	if err != nil {
		return nil, errors.NewInternalError("Failed to generate refresh token", err)
	}

	// Update session last used time
	s.redis.HSet(ctx, sessionKey, "last_used", time.Now().Unix())

	return &RefreshResult{
		AccessToken:  newAccessToken,
		RefreshToken: newRefreshToken,
	}, nil
}

func (s *AuthServiceImpl) Logout(ctx context.Context, token string) error {
	// Validate token to get session ID
	claims, err := s.jwtManager.ValidateToken(token)
	if err != nil {
		return nil // Don't return error for invalid tokens during logout
	}

	// Remove session from Redis
	sessionKey := fmt.Sprintf("%s%s", constants.UserSessionPrefix, claims.SessionID)
	s.redis.Del(ctx, sessionKey)

	logger.WithFields(logger.Fields{
		"user_id":    claims.UserID.Hex(),
		"session_id": claims.SessionID,
	}).Info("User logged out")

	return nil
}

func (s *AuthServiceImpl) LogoutAll(ctx context.Context, userID primitive.ObjectID) error {
	// Get all sessions for the user
	pattern := fmt.Sprintf("%s*", constants.UserSessionPrefix)
	keys, err := s.redis.Keys(ctx, pattern).Result()
	if err != nil {
		return errors.NewInternalError("Failed to get user sessions", err)
	}

	// Filter sessions for this user and delete them
	userIDStr := userID.Hex()
	for _, key := range keys {
		sessionUserID := s.redis.HGet(ctx, key, "user_id").Val()
		if sessionUserID == userIDStr {
			s.redis.Del(ctx, key)
		}
	}

	logger.WithFields(logger.Fields{
		"user_id": userID.Hex(),
	}).Info("User logged out from all devices")

	return nil
}

// ===============================
// Password Management Methods
// ===============================

func (s *AuthServiceImpl) ForgotPassword(ctx context.Context, email string) error {
	user, err := s.userRepo.GetByEmail(ctx, email)
	if err != nil || user == nil {
		// Don't reveal if email exists
		return nil
	}

	// Generate reset token
	resetToken, err := s.jwtManager.GenerateResetToken(user.ID, user.Email)
	if err != nil {
		return errors.NewInternalError("Failed to generate reset token", err)
	}

	// Store reset token in user metadata
	updateData := map[string]interface{}{
		"metadata.password_reset_token":  resetToken,
		"metadata.password_reset_expiry": time.Now().Add(time.Hour),
	}

	if err := s.userRepo.UpdateFields(ctx, user.ID, updateData); err != nil {
		return errors.NewInternalError("Failed to store reset token", err)
	}

	// Send reset email
	if s.config.EmailService != nil {
		if err := s.config.EmailService.SendPasswordResetEmail(ctx, user.Email, resetToken); err != nil {
			logger.WithError(err).Error("Failed to send password reset email")
		}
	}

	logger.WithFields(logger.Fields{
		"user_id": user.ID.Hex(),
		"email":   user.Email,
	}).Info("Password reset requested")

	return nil
}

func (s *AuthServiceImpl) ResetPassword(ctx context.Context, token, newPassword string) error {
	// Validate password strength
	if err := utils.IsValidPassword(newPassword); err != nil {
		return errors.NewValidationFieldError("password", err.Error())
	}

	// Validate reset token
	claims, err := s.jwtManager.ValidateToken(token)
	if err != nil {
		return errors.NewUnauthorizedError("Invalid reset token")
	}

	if claims.TokenType != constants.TokenTypeReset {
		return errors.NewUnauthorizedError("Invalid token type")
	}

	// Get user and verify token
	user, err := s.userRepo.GetByID(ctx, claims.UserID)
	if err != nil || user == nil {
		return errors.NewNotFoundError("User not found")
	}

	// Check token expiry
	if user.Metadata.PasswordResetExpiry != nil && time.Now().After(*user.Metadata.PasswordResetExpiry) {
		return errors.NewUnauthorizedError("Reset token has expired")
	}

	if user.Metadata.PasswordResetToken != token {
		return errors.NewUnauthorizedError("Invalid reset token")
	}

	// Hash new password
	hashedPassword, err := utils.HashPassword(newPassword)
	if err != nil {
		return errors.NewInternalError("Failed to hash password", err)
	}

	// Update password and clear reset token
	updateData := map[string]interface{}{
		"password_hash":                  hashedPassword,
		"metadata.password_reset_token":  "",
		"metadata.password_reset_expiry": nil,
	}

	if err := s.userRepo.UpdateFields(ctx, user.ID, updateData); err != nil {
		return errors.NewInternalError("Failed to update password", err)
	}

	// Invalidate all sessions for security
	s.LogoutAll(ctx, user.ID)

	// Send password changed notification
	if s.config.EmailService != nil {
		if err := s.config.EmailService.SendPasswordChangedEmail(ctx, user.Email); err != nil {
			logger.WithError(err).Error("Failed to send password changed email")
		}
	}

	logger.WithFields(logger.Fields{
		"user_id": user.ID.Hex(),
	}).Info("Password reset successfully")

	return nil
}

func (s *AuthServiceImpl) ChangePassword(ctx context.Context, userID primitive.ObjectID, currentPassword, newPassword string) error {
	// Get user
	user, err := s.userRepo.GetByID(ctx, userID)
	if err != nil || user == nil {
		return errors.NewNotFoundError("User not found")
	}

	// Verify current password
	if err := utils.CheckPassword(currentPassword, user.PasswordHash); err != nil {
		return errors.NewUnauthorizedError("Current password is incorrect")
	}

	// Validate new password strength
	if err := utils.IsValidPassword(newPassword); err != nil {
		return errors.NewValidationFieldError("password", err.Error())
	}

	// Check if new password is different from current
	if err := utils.CheckPassword(newPassword, user.PasswordHash); err == nil {
		return errors.NewPasswordsMatchError()
	}

	// Hash new password
	hashedPassword, err := utils.HashPassword(newPassword)
	if err != nil {
		return errors.NewInternalError("Failed to hash password", err)
	}

	// Update password
	updateData := map[string]interface{}{
		"password_hash": hashedPassword,
	}

	if err := s.userRepo.UpdateFields(ctx, userID, updateData); err != nil {
		return errors.NewInternalError("Failed to update password", err)
	}

	// Send security notification
	if s.config.EmailService != nil {
		if err := s.config.EmailService.SendPasswordChangedEmail(ctx, user.Email); err != nil {
			logger.WithError(err).Error("Failed to send password changed email")
		}
	}

	logger.WithFields(logger.Fields{
		"user_id": userID.Hex(),
	}).Info("Password changed successfully")

	return nil
}

// ===============================
// Email Verification Methods
// ===============================

func (s *AuthServiceImpl) VerifyEmail(ctx context.Context, token string) error {
	// Validate verification token
	claims, err := s.jwtManager.ValidateToken(token)
	if err != nil {
		return errors.NewUnauthorizedError("Invalid verification token")
	}

	if claims.TokenType != constants.TokenTypeVerify {
		return errors.NewUnauthorizedError("Invalid token type")
	}

	// Get user
	user, err := s.userRepo.GetByID(ctx, claims.UserID)
	if err != nil || user == nil {
		return errors.NewNotFoundError("User not found")
	}

	// Check if already verified
	if user.Metadata.EmailVerified {
		return errors.NewConflictError("Email already verified")
	}

	// Verify token matches
	if user.Metadata.VerificationToken != token {
		return errors.NewUnauthorizedError("Invalid verification token")
	}

	// Mark email as verified
	updateData := map[string]interface{}{
		"metadata.email_verified":     true,
		"metadata.verification_token": "",
	}

	if err := s.userRepo.UpdateFields(ctx, claims.UserID, updateData); err != nil {
		return errors.NewInternalError("Failed to verify email", err)
	}

	logger.WithFields(logger.Fields{
		"user_id": claims.UserID.Hex(),
		"email":   claims.Email,
	}).Info("Email verified successfully")

	return nil
}

func (s *AuthServiceImpl) ResendVerification(ctx context.Context, email string) error {
	user, err := s.userRepo.GetByEmail(ctx, email)
	if err != nil || user == nil {
		// Don't reveal if email exists
		return nil
	}

	// Check if already verified
	if user.Metadata.EmailVerified {
		return nil // Don't reveal verification status
	}

	// Generate new verification token
	verificationToken, err := s.jwtManager.GenerateVerificationToken(user.ID, user.Email)
	if err != nil {
		return errors.NewInternalError("Failed to generate verification token", err)
	}

	// Update verification token
	updateData := map[string]interface{}{
		"metadata.verification_token": verificationToken,
	}

	if err := s.userRepo.UpdateFields(ctx, user.ID, updateData); err != nil {
		return errors.NewInternalError("Failed to store verification token", err)
	}

	// Send verification email
	if s.config.EmailService != nil {
		if err := s.config.EmailService.SendVerificationEmail(ctx, user.Email, verificationToken); err != nil {
			logger.WithError(err).Error("Failed to send verification email")
		}
	}

	logger.WithFields(logger.Fields{
		"user_id": user.ID.Hex(),
		"email":   user.Email,
	}).Info("Verification email resent")

	return nil
}

// ===============================
// User Management Methods
// ===============================

func (s *AuthServiceImpl) GetUserByID(ctx context.Context, userID primitive.ObjectID) (*models.User, error) {
	user, err := s.userRepo.GetByID(ctx, userID)
	if err != nil {
		return nil, errors.NewNotFoundError("User not found")
	}
	return user, nil
}

func (s *AuthServiceImpl) ValidateToken(ctx context.Context, token string) (primitive.ObjectID, error) {
	claims, err := s.jwtManager.ValidateToken(token)
	if err != nil {
		return primitive.NilObjectID, errors.NewUnauthorizedError("Invalid token")
	}
	return claims.UserID, nil
}

// ===============================
// Session Management Methods
// ===============================

func (s *AuthServiceImpl) GetActiveSessions(ctx context.Context, userID primitive.ObjectID) ([]UserSession, error) {
	pattern := fmt.Sprintf("%s*", constants.UserSessionPrefix)
	keys, err := s.redis.Keys(ctx, pattern).Result()
	if err != nil {
		return nil, errors.NewInternalError("Failed to get sessions", err)
	}

	var sessions []UserSession
	userIDStr := userID.Hex()

	for _, key := range keys {
		sessionData := s.redis.HGetAll(ctx, key).Val()
		if sessionData["user_id"] == userIDStr {
			sessionID := strings.TrimPrefix(key, constants.UserSessionPrefix)

			createdAt, _ := strconv.ParseInt(sessionData["created_at"], 10, 64)
			lastUsed, _ := strconv.ParseInt(sessionData["last_used"], 10, 64)

			session := UserSession{
				ID:        sessionID,
				DeviceID:  sessionData["device_id"],
				UserAgent: sessionData["user_agent"],
				IPAddress: sessionData["ip_address"],
				CreatedAt: time.Unix(createdAt, 0),
				LastUsed:  time.Unix(lastUsed, 0),
			}

			sessions = append(sessions, session)
		}
	}

	return sessions, nil
}

func (s *AuthServiceImpl) RevokeSession(ctx context.Context, userID primitive.ObjectID, sessionID string) error {
	sessionKey := fmt.Sprintf("%s%s", constants.UserSessionPrefix, sessionID)

	// Verify session belongs to user
	sessionUserID := s.redis.HGet(ctx, sessionKey, "user_id").Val()
	if sessionUserID != userID.Hex() {
		return errors.NewForbiddenError("Session does not belong to user")
	}

	// Delete session
	s.redis.Del(ctx, sessionKey)

	logger.WithFields(logger.Fields{
		"user_id":    userID.Hex(),
		"session_id": sessionID,
	}).Info("Session revoked")

	return nil
}

// ===============================
// Two-Factor Authentication Methods
// ===============================

func (s *AuthServiceImpl) Enable2FA(ctx context.Context, userID primitive.ObjectID) (*TwoFactorResult, error) {
	user, err := s.userRepo.GetByID(ctx, userID)
	if err != nil || user == nil {
		return nil, errors.NewNotFoundError("User not found")
	}

	if user.Metadata.TwoFactorEnabled {
		return nil, errors.NewConflictError("2FA already enabled")
	}

	// Generate TOTP secret (32 bytes = 160 bits for RFC6238)
	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		return nil, errors.NewInternalError("Failed to generate 2FA secret", err)
	}

	secretBase32 := base64.StdEncoding.EncodeToString(secret)

	// Generate QR code URL for Google Authenticator
	qrCodeURL := fmt.Sprintf(
		"otpauth://totp/%s:%s?secret=%s&issuer=%s",
		url.QueryEscape(s.config.TOTPIssuer),
		url.QueryEscape(user.Email),
		secretBase32,
		url.QueryEscape(s.config.TOTPIssuer),
	)

	// Generate backup codes
	backupCodes, err := s.generateBackupCodes()
	if err != nil {
		return nil, errors.NewInternalError("Failed to generate backup codes", err)
	}

	// Store 2FA data (temporarily - user needs to verify to enable)
	twoFAData := map[string]interface{}{
		"metadata.two_factor_secret":       secretBase32,
		"metadata.two_factor_backup_codes": backupCodes,
		"metadata.two_factor_enabled":      false, // Will be enabled after verification
	}

	if err := s.userRepo.UpdateFields(ctx, userID, twoFAData); err != nil {
		return nil, errors.NewInternalError("Failed to store 2FA data", err)
	}

	return &TwoFactorResult{
		Secret:      secretBase32,
		QRCode:      qrCodeURL,
		BackupCodes: backupCodes,
	}, nil
}

func (s *AuthServiceImpl) Disable2FA(ctx context.Context, userID primitive.ObjectID, password, code string) error {
	user, err := s.userRepo.GetByID(ctx, userID)
	if err != nil || user == nil {
		return errors.NewNotFoundError("User not found")
	}

	// Verify password
	if err := utils.CheckPassword(password, user.PasswordHash); err != nil {
		return errors.NewUnauthorizedError("Invalid password")
	}

	// Verify 2FA code
	if !s.verifyTOTPCode(user.Metadata.TwoFactorSecret, code) {
		// Check backup codes
		if !s.verifyBackupCode(user.Metadata.TwoFactorBackupCodes, code) {
			return errors.NewUnauthorizedError("Invalid 2FA code")
		}
	}

	// Disable 2FA
	updateData := map[string]interface{}{
		"metadata.two_factor_enabled":      false,
		"metadata.two_factor_secret":       "",
		"metadata.two_factor_backup_codes": []string{},
	}

	if err := s.userRepo.UpdateFields(ctx, userID, updateData); err != nil {
		return errors.NewInternalError("Failed to disable 2FA", err)
	}

	logger.WithFields(logger.Fields{
		"user_id": userID.Hex(),
	}).Info("2FA disabled")

	return nil
}

func (s *AuthServiceImpl) Verify2FA(ctx context.Context, userID primitive.ObjectID, code string) error {
	user, err := s.userRepo.GetByID(ctx, userID)
	if err != nil || user == nil {
		return errors.NewNotFoundError("User not found")
	}

	// Verify TOTP code
	if !s.verifyTOTPCode(user.Metadata.TwoFactorSecret, code) {
		// Check backup codes
		if !s.verifyBackupCode(user.Metadata.TwoFactorBackupCodes, code) {
			return errors.NewUnauthorizedError("Invalid 2FA code")
		}
		// Remove used backup code
		s.removeUsedBackupCode(ctx, userID, user.Metadata.TwoFactorBackupCodes, code)
	}

	// If this is first verification, enable 2FA
	if !user.Metadata.TwoFactorEnabled {
		updateData := map[string]interface{}{
			"metadata.two_factor_enabled": true,
		}
		s.userRepo.UpdateFields(ctx, userID, updateData)
	}

	return nil
}

func (s *AuthServiceImpl) GetBackupCodes(ctx context.Context, userID primitive.ObjectID) ([]string, error) {
	user, err := s.userRepo.GetByID(ctx, userID)
	if err != nil || user == nil {
		return nil, errors.NewNotFoundError("User not found")
	}

	return user.Metadata.TwoFactorBackupCodes, nil
}

func (s *AuthServiceImpl) RegenerateBackupCodes(ctx context.Context, userID primitive.ObjectID, password string) ([]string, error) {
	user, err := s.userRepo.GetByID(ctx, userID)
	if err != nil || user == nil {
		return nil, errors.NewNotFoundError("User not found")
	}

	// Verify password
	if err := utils.CheckPassword(password, user.PasswordHash); err != nil {
		return nil, errors.NewUnauthorizedError("Invalid password")
	}

	// Generate new backup codes
	backupCodes, err := s.generateBackupCodes()
	if err != nil {
		return nil, errors.NewInternalError("Failed to generate backup codes", err)
	}

	// Update backup codes
	updateData := map[string]interface{}{
		"metadata.two_factor_backup_codes": backupCodes,
	}

	if err := s.userRepo.UpdateFields(ctx, userID, updateData); err != nil {
		return nil, errors.NewInternalError("Failed to update backup codes", err)
	}

	logger.WithFields(logger.Fields{
		"user_id": userID.Hex(),
	}).Info("2FA backup codes regenerated")

	return backupCodes, nil
}

// ===============================
// OAuth Methods
// ===============================

func (s *AuthServiceImpl) GetGoogleOAuthURL(ctx context.Context) string {
	baseURL := "https://accounts.google.com/o/oauth2/auth"
	params := url.Values{
		"client_id":     {s.config.GoogleOAuth.ClientID},
		"redirect_uri":  {s.config.GoogleOAuth.RedirectURL},
		"scope":         {strings.Join(s.config.GoogleOAuth.Scopes, " ")},
		"response_type": {"code"},
		"access_type":   {"offline"},
		"prompt":        {"consent"},
	}
	return fmt.Sprintf("%s?%s", baseURL, params.Encode())
}

func (s *AuthServiceImpl) HandleGoogleOAuth(ctx context.Context, code, ipAddress, userAgent string) (*OAuthResult, error) {
	// This would implement Google OAuth flow
	// For brevity, returning placeholder implementation
	return nil, errors.NewNotImplementedError("Google OAuth not implemented")
}

func (s *AuthServiceImpl) GetGitHubOAuthURL(ctx context.Context) string {
	baseURL := "https://github.com/login/oauth/authorize"
	params := url.Values{
		"client_id":    {s.config.GitHubOAuth.ClientID},
		"redirect_uri": {s.config.GitHubOAuth.RedirectURL},
		"scope":        {strings.Join(s.config.GitHubOAuth.Scopes, " ")},
	}
	return fmt.Sprintf("%s?%s", baseURL, params.Encode())
}

func (s *AuthServiceImpl) HandleGitHubOAuth(ctx context.Context, code, ipAddress, userAgent string) (*OAuthResult, error) {
	// This would implement GitHub OAuth flow
	// For brevity, returning placeholder implementation
	return nil, errors.NewNotImplementedError("GitHub OAuth not implemented")
}

// ===============================
// Admin Authentication Methods
// ===============================

func (s *AuthServiceImpl) AdminLogin(ctx context.Context, email, password string) (*models.Admin, string, error) {
	admin, err := s.adminRepo.GetByEmail(ctx, email)
	if err != nil || admin == nil {
		return nil, "", errors.NewUnauthorizedError("Invalid credentials")
	}

	// Verify password
	if err := utils.CheckPassword(password, admin.PasswordHash); err != nil {
		return nil, "", errors.NewUnauthorizedError("Invalid credentials")
	}

	// Check if admin is active
	if !admin.IsActive {
		return nil, "", errors.NewForbiddenError("Admin account is disabled")
	}

	// Generate admin token
	sessionID := uuid.New().String()
	token, err := s.jwtManager.GenerateAdminToken(
		admin.ID, admin.Username, admin.Email, admin.Role, admin.Permissions, sessionID,
	)
	if err != nil {
		return nil, "", errors.NewInternalError("Failed to generate admin token", err)
	}

	// Store admin session
	sessionData := map[string]interface{}{
		"admin_id":   admin.ID.Hex(),
		"username":   admin.Username,
		"role":       admin.Role,
		"created_at": time.Now().Unix(),
		"last_used":  time.Now().Unix(),
	}

	sessionKey := fmt.Sprintf("%s%s", constants.AdminSessionPrefix, sessionID)
	s.redis.HMSet(ctx, sessionKey, sessionData)
	s.redis.Expire(ctx, sessionKey, constants.SessionCacheTTL)

	// Update admin last login
	now := time.Now()
	updateData := map[string]interface{}{
		"last_login_at": &now,
		"last_login_ip": "127.0.0.1", // You would pass this from request
	}
	s.adminRepo.UpdateFields(ctx, admin.ID, updateData)

	logger.WithFields(logger.Fields{
		"admin_id": admin.ID.Hex(),
		"email":    admin.Email,
		"role":     admin.Role,
	}).Info("Admin logged in")

	return admin, token, nil
}

func (s *AuthServiceImpl) AdminLogout(ctx context.Context, adminID primitive.ObjectID) error {
	// Find and remove admin session
	pattern := fmt.Sprintf("%s*", constants.AdminSessionPrefix)
	keys, err := s.redis.Keys(ctx, pattern).Result()
	if err != nil {
		return errors.NewInternalError("Failed to get admin sessions", err)
	}

	adminIDStr := adminID.Hex()
	for _, key := range keys {
		sessionAdminID := s.redis.HGet(ctx, key, "admin_id").Val()
		if sessionAdminID == adminIDStr {
			s.redis.Del(ctx, key)
		}
	}

	logger.WithFields(logger.Fields{
		"admin_id": adminID.Hex(),
	}).Info("Admin logged out")

	return nil
}

// ===============================
// Helper Methods
// ===============================

func (s *AuthServiceImpl) generateDeviceID(userAgent string) string {
	// Simple device ID generation based on user agent hash
	hash := sha256.Sum256([]byte(userAgent))
	return fmt.Sprintf("device_%x", hash[:8])
}

func (s *AuthServiceImpl) isLoginLocked(ctx context.Context, login, ipAddress string) (bool, error) {
	key := fmt.Sprintf("login_attempts:%s:%s", login, ipAddress)
	count := s.redis.Get(ctx, key).Val()

	if count == "" {
		return false, nil
	}

	attempts, err := strconv.Atoi(count)
	if err != nil {
		return false, err
	}

	return attempts >= s.config.MaxLoginAttempts, nil
}

func (s *AuthServiceImpl) recordFailedLogin(ctx context.Context, login, ipAddress string) {
	key := fmt.Sprintf("login_attempts:%s:%s", login, ipAddress)
	s.redis.Incr(ctx, key)
	s.redis.Expire(ctx, key, s.config.LoginLockoutTime)
}

func (s *AuthServiceImpl) clearFailedLogins(ctx context.Context, login, ipAddress string) {
	key := fmt.Sprintf("login_attempts:%s:%s", login, ipAddress)
	s.redis.Del(ctx, key)
}

func (s *AuthServiceImpl) generateBackupCodes() ([]string, error) {
	codes := make([]string, 10)
	for i := range codes {
		code := make([]byte, 6)
		if _, err := rand.Read(code); err != nil {
			return nil, err
		}
		codes[i] = fmt.Sprintf("%x", code)[:8]
	}
	return codes, nil
}

func (s *AuthServiceImpl) verifyTOTPCode(secret, code string) bool {
	// This would implement TOTP verification using RFC 6238
	// For brevity, returning placeholder implementation
	// You would use a library like "github.com/pquerna/otp/totp"
	return false
}

func (s *AuthServiceImpl) verifyBackupCode(backupCodes []string, code string) bool {
	for _, backupCode := range backupCodes {
		if backupCode == code {
			return true
		}
	}
	return false
}

func (s *AuthServiceImpl) removeUsedBackupCode(ctx context.Context, userID primitive.ObjectID, backupCodes []string, usedCode string) {
	var remainingCodes []string
	for _, code := range backupCodes {
		if code != usedCode {
			remainingCodes = append(remainingCodes, code)
		}
	}

	updateData := map[string]interface{}{
		"metadata.two_factor_backup_codes": remainingCodes,
	}
	s.userRepo.UpdateFields(ctx, userID, updateData)
}
